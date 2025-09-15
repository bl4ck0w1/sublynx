package utils

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type LogConfig struct {
	Level         string `json:"level" yaml:"level"`  
	Format        string `json:"format" yaml:"format"` 
	Output        string `json:"output" yaml:"output"` 
	FileLocation  string `json:"file_location" yaml:"file_location"`
	MaxSize       int    `json:"max_size" yaml:"max_size"`       
	MaxBackups    int    `json:"max_backups" yaml:"max_backups"`
	MaxAge        int    `json:"max_age" yaml:"max_age"`         
	Compress      bool   `json:"compress" yaml:"compress"`
	EnableConsole bool   `json:"enable_console" yaml:"enable_console"` 
}

type Logger struct {
	*logrus.Logger
	config     LogConfig
	mu         sync.RWMutex
	fileSink   io.WriteCloser 
	service    string
	version    string
	hostname   string
}

func NewLogger(config LogConfig, service, version string) (*Logger, error) {
	l := &Logger{
		Logger:   logrus.New(),
		config:   normalizeConfig(config),
		service:  service,
		version:  version,
		hostname: getHostname(),
	}

	level, err := logrus.ParseLevel(l.config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	l.SetLevel(level)

	switch strings.ToLower(l.config.Format) {
	case "json":
		l.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "severity",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "caller", 
			},
		})
	default: 
		l.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339Nano,
			FullTimestamp:   true,
			DisableColors:   true,
		})
	}

	if err := l.setOutput(); err != nil {
		return nil, err
	}

	l.AddHook(&CallerHook{})
	l.AddHook(&ServiceHook{
		Service:  service,
		Version:  version,
		Hostname: l.hostname,
	})

	return l, nil
}

func normalizeConfig(c LogConfig) LogConfig {
	c.Level = strings.ToLower(strings.TrimSpace(c.Level))
	if c.Level == "" {
		c.Level = "info"
	}
	c.Format = strings.ToLower(strings.TrimSpace(c.Format))
	if c.Format == "" {
		c.Format = "json"
	}
	c.Output = strings.ToLower(strings.TrimSpace(c.Output))
	if c.Output == "" {
		if c.EnableConsole {
			c.Output = "both"
		} else {
			c.Output = "file"
		}
	}
	return c
}

func (l *Logger) setOutput() error {
	var writers []io.Writer

	wantConsole := l.config.Output == "console" || l.config.Output == "both"
	wantFile := l.config.Output == "file" || l.config.Output == "both"

	if wantFile && l.config.FileLocation != "" {
		if err := os.MkdirAll(filepath.Dir(l.config.FileLocation), 0o755); err != nil {
			return err
		}
		lj := &lumberjack.Logger{
			Filename:   l.config.FileLocation,
			MaxSize:    max(1, l.config.MaxSize),     
			MaxBackups: max(0, l.config.MaxBackups), 
			MaxAge:     max(0, l.config.MaxAge),     
			Compress:   l.config.Compress,
		}
		l.fileSink = lj
		writers = append(writers, lj)
	}

	if wantConsole || (!wantFile && !wantConsole) {
		if tf, ok := l.Formatter.(*logrus.TextFormatter); ok {
			tf.DisableColors = false
		}
		writers = append(writers, os.Stdout)
	}

	if l.config.Format == "text" && l.config.Output == "both" {
		if tf, ok := l.Formatter.(*logrus.TextFormatter); ok {
			tf.DisableColors = true
		}
	}

	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	l.SetOutput(io.MultiWriter(writers...))
	return nil
}

func (l *Logger) Rotate() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if lj, ok := l.fileSink.(*lumberjack.Logger); ok {
		return lj.Rotate()
	}
	return nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fileSink != nil {
		if closer, ok := l.fileSink.(io.Closer); ok {
			return closer.Close()
		}
	}
	return nil
}

func (l *Logger) UpdateLevel(level string) {
	lvl, err := logrus.ParseLevel(strings.ToLower(strings.TrimSpace(level)))
	if err != nil {
		l.Warnf("invalid log level %q, keeping %s", level, l.Level.String())
		return
	}
	l.SetLevel(lvl)
}

func (l *Logger) WithRequestID(requestID string) *logrus.Entry {
	return l.WithField("request_id", requestID)
}

func (l *Logger) WithComponent(component string) *logrus.Entry {
	return l.WithField("component", component)
}

func (l *Logger) WithDuration(duration time.Duration) *logrus.Entry {
	return l.WithField("duration_ms", duration.Milliseconds())
}

func (l *Logger) Debugf(format string, args ...interface{}) { if l.IsLevelEnabled(logrus.DebugLevel) { l.Logger.Debugf(format, args...) } }
func (l *Logger) Infof(format string, args ...interface{})  { if l.IsLevelEnabled(logrus.InfoLevel) { l.Logger.Infof(format, args...) } }
func (l *Logger) Warnf(format string, args ...interface{})  { if l.IsLevelEnabled(logrus.WarnLevel) { l.Logger.Warnf(format, args...) } }
func (l *Logger) Errorf(format string, args ...interface{}) { if l.IsLevelEnabled(logrus.ErrorLevel) { l.Logger.Errorf(format, args...) } }
func (l *Logger) Fatalf(format string, args ...interface{}) { if l.IsLevelEnabled(logrus.FatalLevel) { l.Logger.Fatalf(format, args...) } }

type CallerHook struct{}

func (h *CallerHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *CallerHook) Fire(entry *logrus.Entry) error {
	if _, ok := entry.Data["caller"]; ok {
		return nil
	}

	const maxDepth = 25
	for i := 4; i < 4+maxDepth; i++ { 
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		fn := runtime.FuncForPC(pc)
		fnName := ""
		if fn != nil {
			fnName = fn.Name()
		}
		if strings.Contains(file, "/sirupsen/logrus") || strings.Contains(fnName, "utils.Logger") || strings.Contains(file, "/pkg/utils/logger.go") {
			continue
		}
		entry.Data["caller"] = map[string]interface{}{
			"file": file,
			"line": line,
			"func": shortFunc(fnName),
		}
		break
	}
	return nil
}

func shortFunc(full string) string {
	if idx := strings.LastIndex(full, "/"); idx >= 0 && idx+1 < len(full) {
		full = full[idx+1:]
	}
	return full
}

type ServiceHook struct {
	Service  string
	Version  string
	Hostname string
}

func (h *ServiceHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *ServiceHook) Fire(entry *logrus.Entry) error {
	entry.Data["service"] = h.Service
	entry.Data["version"] = h.Version
	entry.Data["hostname"] = h.Hostname
	return nil
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func DefaultLogger() *Logger {
	cfg := LogConfig{
		Level:        "info",
		Format:       "json",
		Output:       "both",
		FileLocation: "./logs/subnexus.log",
		MaxSize:      100,
		MaxBackups:   10,
		MaxAge:       30,
		Compress:     true,
	}
	logger, err := NewLogger(cfg, "subnexus", "1.0.0")
	if err != nil {
		fb := logrus.New()
		fb.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})
		return &Logger{Logger: fb}
	}
	return logger
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

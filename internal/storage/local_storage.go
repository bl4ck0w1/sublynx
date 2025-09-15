package storage

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type LocalStorage struct {
	baseDir     string
	logger      *logrus.Logger
	mu          sync.RWMutex
	compression bool
	retention   time.Duration
}

func NewLocalStorage(baseDir string, compression bool, retention time.Duration, logger *logrus.Logger) (*LocalStorage, error) {
	if logger == nil {
		logger = logrus.New()
	}

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	for _, dir := range []string{"results", "configs", "temp", "backups"} {
		if err := os.MkdirAll(filepath.Join(baseDir, dir), 0o755); err != nil {
			return nil, fmt.Errorf("failed to create %s directory: %w", dir, err)
		}
	}

	ls := &LocalStorage{
		baseDir:     baseDir,
		logger:      logger,
		compression: compression,
		retention:   retention,
	}

	if retention > 0 {
		go ls.cleanupOldFiles()
	}

	return ls, nil
}

func (ls *LocalStorage) SaveResult(result *models.ScanResult) error {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	resultDir := filepath.Join(ls.baseDir, "results", result.ScanID)
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		return fmt.Errorf("failed to create result directory: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	finalPath := filepath.Join(resultDir, fmt.Sprintf("result_%s.json", timestamp))

	tmpFile, err := os.CreateTemp(resultDir, ".result_*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	enc := json.NewEncoder(tmpFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return fmt.Errorf("encode result: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpFile.Name(), finalPath); err != nil {
		_ = os.Remove(tmpFile.Name())
		return fmt.Errorf("atomic rename: %w", err)
	}

	logPath := finalPath
	if ls.compression {
		compressedPath := finalPath + ".gz"
		if err := ls.compressFile(finalPath); err != nil {
			ls.logger.Warnf("Failed to compress result file: %v", err)
		} else {
			_ = os.Remove(finalPath)
			logPath = compressedPath
		}
	}

	ls.logger.Infof("Result saved to %s", logPath)
	return nil
}

func (ls *LocalStorage) LoadResult(scanID, fileName string) (*models.ScanResult, error) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	path := filepath.Join(ls.baseDir, "results", scanID, fileName)

	var toRead string
	var cleanup func()
	if strings.HasSuffix(strings.ToLower(fileName), ".gz") {
		tmp, err := ls.decompressFile(path)
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
		toRead = tmp
		cleanup = func() { _ = os.Remove(tmp) }
	} else {
		toRead = path
	}

	data, err := os.ReadFile(toRead)
	if cleanup != nil {
		cleanup()
	}
	if err != nil {
		return nil, fmt.Errorf("read result file: %w", err)
	}

	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}
	return &result, nil
}

func (ls *LocalStorage) ListResults() ([]*models.ScanResult, error) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	resultsDir := filepath.Join(ls.baseDir, "results")
	results := make([]*models.ScanResult, 0, 32)

	err := filepath.Walk(resultsDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}

		name := strings.ToLower(info.Name())
		if !(strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz")) {
			return nil
		}

		var r *models.ScanResult
		var err error
		if strings.HasSuffix(name, ".gz") {
			tmp, derr := ls.decompressFile(path)
			if derr != nil {
				ls.logger.Warnf("Failed to decompress %s: %v", path, derr)
				return nil
			}
			defer os.Remove(tmp)
			r, err = readResultFile(tmp)
		} else {
			r, err = readResultFile(path)
		}
		if err != nil {
			ls.logger.Warnf("Failed to parse result %s: %v", path, err)
			return nil
		}
		results = append(results, r)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk results directory: %w", err)
	}

	return results, nil
}

func readResultFile(path string) (*models.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r models.ScanResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}


func (ls *LocalStorage) SaveConfig(name string, config interface{}) error {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	configDir := filepath.Join(ls.baseDir, "configs")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	filePath := filepath.Join(configDir, fmt.Sprintf("%s.yaml", name))
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	ls.logger.Infof("Config saved to %s", filePath)
	return nil
}

func (ls *LocalStorage) LoadConfig(name string, config interface{}) error {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	filePath := filepath.Join(ls.baseDir, "configs", fmt.Sprintf("%s.yaml", name))
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	return nil
}

func (ls *LocalStorage) CreateBackup() (string, error) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	backupDir := filepath.Join(ls.baseDir, "backups")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("backup_%s.tar.gz", timestamp))

	f, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("create backup file: %w", err)
	}
	_ = f.Close()

	ls.logger.Infof("Backup created at %s", backupPath)
	return backupPath, nil
}

func (ls *LocalStorage) GetStorageStats() (map[string]interface{}, error) {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	stats := make(map[string]interface{})

	totalSize, err := ls.calculateDirectorySize(ls.baseDir)
	if err != nil {
		return nil, fmt.Errorf("calculate dir size: %w", err)
	}

	stats["total_size_bytes"] = totalSize
	stats["total_size_human"] = fmt.Sprintf("%.2f MB", float64(totalSize)/1024.0/1024.0)

	fileCounts := make(map[string]int)
	fileCounts["results"], _ = ls.countFiles(filepath.Join(ls.baseDir, "results"))
	fileCounts["configs"], _ = ls.countFiles(filepath.Join(ls.baseDir, "configs"))
	fileCounts["backups"], _ = ls.countFiles(filepath.Join(ls.baseDir, "backups"))

	stats["file_counts"] = fileCounts
	stats["compression_enabled"] = ls.compression
	stats["retention_period"] = ls.retention.String()

	return stats, nil
}

func (ls *LocalStorage) calculateDirectorySize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func (ls *LocalStorage) countFiles(path string) (int, error) {
	count := 0
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			count++
		}
		return nil
	})
	return count, err
}

func (ls *LocalStorage) compressFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open for compress: %w", err)
	}
	defer in.Close()

	outPath := path + ".gz"
	tmpPath := outPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create gzip temp: %w", err)
	}

	gzw, err := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	if err != nil {
		out.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("gzip writer: %w", err)
	}

	_, copyErr := io.Copy(gzw, in)
	closeErr1 := gzw.Close()
	closeErr2 := out.Close()

	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("gzip copy: %w", copyErr)
	}
	if closeErr1 != nil || closeErr2 != nil {
		_ = os.Remove(tmpPath)
		if closeErr1 != nil {
			return fmt.Errorf("close gzip: %w", closeErr1)
		}
		return fmt.Errorf("close file: %w", closeErr2)
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename gzip file: %w", err)
	}
	return nil
}

func (ls *LocalStorage) decompressFile(path string) (string, error) {
	in, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open gzip: %w", err)
	}
	defer in.Close()

	gzr, err := gzip.NewReader(in)
	if err != nil {
		return "", fmt.Errorf("gzip reader: %w", err)
	}
	defer gzr.Close()

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".result_*.json")
	if err != nil {
		return "", fmt.Errorf("create temp for decompress: %w", err)
	}
	defer tmp.Close()

	if _, err := io.Copy(tmp, gzr); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("decompress copy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("sync temp: %w", err)
	}

	return tmp.Name(), nil
}

func (ls *LocalStorage) cleanupOldFiles() {
	ticker := time.NewTicker(24 * time.Hour) 
	defer ticker.Stop()

	for range ticker.C {
		ls.mu.Lock()
		retention := ls.retention
		base := ls.baseDir
		ls.mu.Unlock()

		if retention == 0 {
			return
		}

		now := time.Now()
		cutoffResults := now.Add(-retention)
		ls.cleanupDirectory(filepath.Join(base, "results"), cutoffResults)
		ls.cleanupDirectory(filepath.Join(base, "backups"), now.Add(-retention*2))
		ls.cleanupDirectory(filepath.Join(base, "temp"), now.Add(-24*time.Hour))
	}
}

func (ls *LocalStorage) cleanupDirectory(path string, cutoffTime time.Time) {
	err := filepath.Walk(path, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.IsDir() && info.ModTime().Before(cutoffTime) {
			if err := os.Remove(p); err != nil {
				ls.logger.Warnf("Failed to remove old file %s: %v", p, err)
			} else {
				ls.logger.Infof("Removed old file: %s", p)
			}
		}
		return nil
	})
	if err != nil {
		ls.logger.Warnf("Failed to cleanup directory %s: %v", path, err)
	}
}

package utils

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
)

const (
	MaxInt = int(^uint(0) >> 1)
	MinInt = -MaxInt - 1
)

func Retry(attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		if i < attempts-1 {
			time.Sleep(delay)
			delay *= 2 
		}
	}
	return fmt.Errorf("after %d attempts, last error: %w", attempts, err)
}

func RetryWithContext(ctx context.Context, attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			err = fn()
			if err == nil {
				return nil
			}
			if i < attempts-1 {
				select {
				case <-time.After(delay):
					delay *= 2 
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
	return fmt.Errorf("after %d attempts, last error: %w", attempts, err)
}

func GenerateUUID() string {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 
	uuid[8] = (uuid[8] & 0x3f) | 0x80 
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func GenerateShortID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func IsValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	parts := strings.Split(domain, ".")
	re := regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if !re.MatchString(part) {
			return false
		}
		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
	}
	return true
}

func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	if u.Scheme == "" || u.Host == "" {
		return false
	}
	h := u.Hostname() 
	return IsValidIP(h) || IsValidDomain(h)
}

func StringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func IntInSlice(i int, slice []int) bool {
	for _, s := range slice {
		if s == i {
			return true
		}
	}
	return false
}

func RemoveDuplicates(slice []string) []string {
	seen := make(map[string]struct{}, len(slice))
	result := make([]string, 0, len(slice))
	for _, item := range slice {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func ReverseSlice(slice interface{}) {
	value := reflect.ValueOf(slice)
	if value.Kind() != reflect.Slice {
		return
	}
	length := value.Len()
	swap := reflect.Swapper(slice)
	for i, j := 0, length-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

func ParseDurationExtended(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}
	if dur, err := time.ParseDuration(s); err == nil {
		return dur, nil
	}
	re := regexp.MustCompile(`^(\d+)([smhdwMy])$`)
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid duration format: %s", s)
	}
	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("invalid duration value: %s", matches[1])
	}
	unit := matches[2]
	switch unit {
	case "s":
		return time.Duration(value) * time.Second, nil
	case "m":
		return time.Duration(value) * time.Minute, nil
	case "h":
		return time.Duration(value) * time.Hour, nil
	case "d":
		return time.Duration(value) * 24 * time.Hour, nil
	case "w":
		return time.Duration(value) * 7 * 24 * time.Hour, nil
	case "M":
		return time.Duration(value) * 30 * 24 * time.Hour, nil
	case "y":
		return time.Duration(value) * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown duration unit: %s", unit)
	}
}

func HumanizeDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	if d < time.Hour {
		minutes := d / time.Minute
		seconds := (d % time.Minute) / time.Second
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	if d < 24*time.Hour {
		hours := d / time.Hour
		minutes := (d % time.Hour) / time.Minute
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	days := d / (24 * time.Hour)
	hours := (d % (24 * time.Hour)) / time.Hour
	return fmt.Sprintf("%dd %dh", days, hours)
}

func HumanizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp])
}

func ReadFileJSON(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return nil
}

func WriteFileJSON(path string, v interface{}, indent bool) error {
	var (
		data []byte
		err  error
	)
	if indent {
		data, err = json.MarshalIndent(v, "", "  ")
	} else {
		data, err = json.Marshal(v)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

func CopyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

func SafeWriteFile(path string, data []byte, mode os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, mode); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func GetFunctionName() string {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return "unknown"
	}
	funcName := runtime.FuncForPC(pc).Name()
	if idx := strings.LastIndex(funcName, "."); idx >= 0 {
		funcName = funcName[idx+1:]
	}
	return funcName
}

func ParallelMap[T any, R any](items []T, fn func(T) R, workers int) []R {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	var wg sync.WaitGroup
	results := make([]R, len(items))
	ch := make(chan struct {
		index int
		item  T
	})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range ch {
				results[job.index] = fn(job.item)
			}
		}()
	}

	for i, item := range items {
		ch <- struct {
			index int
			item  T
		}{index: i, item: item}
	}
	close(ch)
	wg.Wait()
	return results
}

func BatchSlice[T any](slice []T, batchSize int) [][]T {
	if batchSize <= 0 {
		if len(slice) == 0 {
			return nil
		}
		return [][]T{slice}
	}
	var batches [][]T
	for i := 0; i < len(slice); i += batchSize {
		end := i + batchSize
		if end > len(slice) {
			end = len(slice)
		}
		batches = append(batches, slice[i:end])
	}
	return batches
}

func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}
}

func ParseKeyValueString(s string, separator string) (map[string]string, error) {
	result := make(map[string]string)
	if s == "" {
		return result, nil
	}
	pairs := strings.Split(s, separator)
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", pair)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("empty key in pair: %s", pair)
		}
		result[key] = value
	}
	return result, nil
}

func MapToKeyValueString(m map[string]string, separator string) string {
	if len(m) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(m))
	for key, value := range m {
		pairs = append(pairs, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(pairs, separator)
}

func GetEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func GetEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func GetEnvBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func MeasureExecutionTime(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}

func MeasureExecutionTimeWithResult(fn func() interface{}) (interface{}, time.Duration) {
	start := time.Now()
	result := fn()
	return result, time.Since(start)
}


func WithTimeout(timeout time.Duration, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("operation timed out after %v", timeout)
	}
}

func WithTimeoutContext(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(timeoutCtx)
}

func BasicLogger() *logrus.Logger {
	l := logrus.New()
	l.SetFormatter(&logrus.JSONFormatter{})
	l.SetLevel(logrus.InfoLevel)
	return l
}

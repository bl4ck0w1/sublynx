package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type ResultsRepository struct {
	storage  *LocalStorage
	logger   *logrus.Logger
	mu       sync.RWMutex
	cache    map[string]*models.ScanResult
	cacheTTL time.Duration
	index    map[string][]string 
}

func NewResultsRepository(storage *LocalStorage, cacheTTL time.Duration, logger *logrus.Logger) *ResultsRepository {
	if logger == nil {
		logger = logrus.New()
	}

	rr := &ResultsRepository{
		storage:  storage,
		logger:   logger,
		cache:    make(map[string]*models.ScanResult),
		cacheTTL: cacheTTL,
		index:    make(map[string][]string),
	}

	if err := rr.loadIndex(); err != nil {
		logger.Warnf("Failed to load results index: %v", err)
	}

	if cacheTTL > 0 {
		go rr.cleanupCache()
	}

	return rr
}

func (rr *ResultsRepository) Store(ctx context.Context, result *models.ScanResult) error {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	if err := rr.validateResult(result); err != nil {
		return fmt.Errorf("invalid result: %w", err)
	}

	if err := rr.storage.SaveResult(result); err != nil {
		return fmt.Errorf("failed to save result: %w", err)
	}

	rr.cache[result.ScanID] = result

	filename, err := rr.latestResultFilename(result.ScanID)
	if err != nil {
		rr.logger.Warnf("Failed to determine saved filename for scan %s: %v", result.ScanID, err)
	} else {
		if !contains(rr.index[result.ScanID], filename) {
			rr.index[result.ScanID] = append(rr.index[result.ScanID], filename)
		}
	}

	if err := rr.saveIndex(); err != nil {
		rr.logger.Warnf("Failed to save index: %v", err)
	}

	return nil
}

func (rr *ResultsRepository) FindByScanID(ctx context.Context, scanID string) ([]*models.ScanResult, error) {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	if result, exists := rr.cache[scanID]; exists {
		return []*models.ScanResult{result}, nil
	}

	filenames, exists := rr.index[scanID]
	if !exists || len(filenames) == 0 {
		return nil, fmt.Errorf("no results found for scan ID: %s", scanID)
	}

	var results []*models.ScanResult
	for _, filename := range filenames {
		r, err := rr.storage.LoadResult(scanID, filename)
		if err != nil {
			rr.logger.Warnf("Failed to load result %s: %v", filename, err)
			continue
		}
		results = append(results, r)
	}

	return results, nil
}

func (rr *ResultsRepository) FindByDomain(ctx context.Context, domain string) ([]*models.ScanResult, error) {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	var results []*models.ScanResult

	for scanID := range rr.index {
		if r, ok := rr.cache[scanID]; ok && r.TargetDomain == domain {
			results = append(results, r)
			continue
		}
		if latest, err := rr.latestResultFilename(scanID); err == nil && latest != "" {
			r, err := rr.storage.LoadResult(scanID, latest)
			if err == nil && r.TargetDomain == domain {
				results = append(results, r)
			} else if err != nil {
				rr.logger.Warnf("Failed loading latest result for %s: %v", scanID, err)
			}
		}
	}

	return results, nil
}

func (rr *ResultsRepository) FindByStatus(ctx context.Context, status string) ([]*models.ScanResult, error) {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	var results []*models.ScanResult

	for scanID := range rr.index {
		if r, ok := rr.cache[scanID]; ok {
			if r.Status == status {
				results = append(results, r)
			}
			continue
		}
		if latest, err := rr.latestResultFilename(scanID); err == nil && latest != "" {
			r, err := rr.storage.LoadResult(scanID, latest)
			if err != nil {
				rr.logger.Warnf("Failed to load result %s: %v", latest, err)
				continue
			}
			if r.Status == status {
				results = append(results, r)
			}
		}
	}

	return results, nil
}

func (rr *ResultsRepository) FindByTimeRange(ctx context.Context, startTime, endTime time.Time) ([]*models.ScanResult, error) {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	var results []*models.ScanResult

	for scanID := range rr.index {
		if r, ok := rr.cache[scanID]; ok {
			if !r.StartTime.Before(startTime) && !r.StartTime.After(endTime) {
				results = append(results, r)
			}
			continue
		}
		if latest, err := rr.latestResultFilename(scanID); err == nil && latest != "" {
			r, err := rr.storage.LoadResult(scanID, latest)
			if err != nil {
				rr.logger.Warnf("Failed to load result %s: %v", latest, err)
				continue
			}
			if !r.StartTime.Before(startTime) && !r.StartTime.After(endTime) {
				results = append(results, r)
			}
		}
	}

	return results, nil
}

func (rr *ResultsRepository) DeleteByScanID(ctx context.Context, scanID string) error {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	delete(rr.cache, scanID)

	if filenames, exists := rr.index[scanID]; exists {
		dir := filepath.Join(rr.storage.baseDir, "results", scanID)
		for _, name := range filenames {
			paths := []string{
				filepath.Join(dir, name),
			}
			if filepath.Ext(name) == ".json" {
				paths = append(paths, filepath.Join(dir, name+".gz"))
			}
			for _, p := range paths {
				if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
					rr.logger.Warnf("Failed to delete result file %s: %v", p, err)
				}
			}
		}
		delete(rr.index, scanID)
	}

	if err := rr.saveIndex(); err != nil {
		return fmt.Errorf("failed to save index: %w", err)
	}

	return nil
}

func (rr *ResultsRepository) GetStats(ctx context.Context) (map[string]interface{}, error) {
	rr.mu.RLock()
	defer rr.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_scans"] = len(rr.index)
	stats["cached_results"] = len(rr.cache)
	stats["cache_ttl"] = rr.cacheTTL.String()

	statusCounts := make(map[string]int)
	for scanID := range rr.index {
		if r, ok := rr.cache[scanID]; ok {
			statusCounts[r.Status]++
			continue
		}
		if latest, err := rr.latestResultFilename(scanID); err == nil && latest != "" {
			if r, err := rr.storage.LoadResult(scanID, latest); err == nil {
				statusCounts[r.Status]++
			}
		}
	}
	stats["results_by_status"] = statusCounts

	return stats, nil
}

func (rr *ResultsRepository) validateResult(result *models.ScanResult) error {
	if result.ScanID == "" {
		return fmt.Errorf("scan ID is required")
	}
	if result.TargetDomain == "" {
		return fmt.Errorf("target domain is required")
	}
	if result.StartTime.IsZero() {
		return fmt.Errorf("start time is required")
	}
	if result.Status == "" {
		return fmt.Errorf("status is required")
	}
	return nil
}

func (rr *ResultsRepository) generateFilename(result *models.ScanResult) string {
	timestamp := result.StartTime.Format("20060102_150405")
	return fmt.Sprintf("result_%s_%s.json", result.TargetDomain, timestamp)
}


func (rr *ResultsRepository) latestResultFilename(scanID string) (string, error) {
	dir := filepath.Join(rr.storage.baseDir, "results", scanID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read results dir: %w", err)
	}

	type fileInfo struct {
		name string
		mod  time.Time
		gz   bool
	}
	files := make([]fileInfo, 0, len(entries))
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		l := len(name)
		if l >= 5 && name[l-5:] == ".json" || (l >= 8 && name[l-8:] == ".json.gz") {
			info, err := de.Info()
			if err != nil {
				continue
			}
			files = append(files, fileInfo{
				name: name,
				mod:  info.ModTime(),
				gz:   strings.HasSuffix(strings.ToLower(name), ".gz"),
			})
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no result files found for scan %s", scanID)
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].mod.Equal(files[j].mod) {
			return files[i].gz && !files[j].gz
		}
		return files[i].mod.After(files[j].mod)
	})

	return files[0].name, nil
}

func (rr *ResultsRepository) loadIndex() error {
	indexPath := filepath.Join(rr.storage.baseDir, "results_index.json")

	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		rr.index = make(map[string][]string)
		return nil
	}

	data, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("failed to read index file: %w", err)
	}

	if err := json.Unmarshal(data, &rr.index); err != nil {
		return fmt.Errorf("failed to unmarshal index: %w", err)
	}
	return nil
}

func (rr *ResultsRepository) saveIndex() error {
	indexPath := filepath.Join(rr.storage.baseDir, "results_index.json")

	data, err := json.MarshalIndent(rr.index, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(indexPath), ".results_index_*.tmp")
	if err != nil {
		return fmt.Errorf("create temp index: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write temp index: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("sync temp index: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("close temp index: %w", err)
	}
	if err := os.Rename(tmp.Name(), indexPath); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("rename temp index: %w", err)
	}
	return nil
}

func (rr *ResultsRepository) cleanupCache() {
	ticker := time.NewTicker(rr.cacheTTL / 2)
	defer ticker.Stop()

	for range ticker.C {
		rr.mu.Lock()
		for scanID, result := range rr.cache {
			if time.Since(result.StartTime) > rr.cacheTTL {
				delete(rr.cache, scanID)
			}
		}
		rr.mu.Unlock()
	}
}

func contains(sl []string, s string) bool {
	for _, v := range sl {
		if v == s {
			return true
		}
	}
	return false
}

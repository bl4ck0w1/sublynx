package ctlogs

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type Monitor struct {
	fetcher      *Fetcher
	parser       *Parser
	logger       *logrus.Logger
	interval     time.Duration
	lastIndexes  map[string]int64 
	mu           sync.RWMutex
	callbacks    []func(models.CTLogEntry)
	shutdownChan chan struct{}
	isMonitoring bool
}

func NewMonitor(fetcher *Fetcher, parser *Parser, interval time.Duration, logger *logrus.Logger) *Monitor {
	if logger == nil {
		logger = logrus.New()
	}
	return &Monitor{
		fetcher:      fetcher,
		parser:       parser,
		logger:       logger,
		interval:     interval,
		lastIndexes:  make(map[string]int64),
		callbacks:    make([]func(models.CTLogEntry), 0),
		shutdownChan: make(chan struct{}),
	}
}

func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.isMonitoring {
		m.mu.Unlock()
		return fmt.Errorf("monitor is already running")
	}
	m.isMonitoring = true
	m.mu.Unlock()

	m.logger.Info("Starting CT log monitor")

	if err := m.initialSync(ctx); err != nil {
		return fmt.Errorf("initial sync failed: %w", err)
	}

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.checkForUpdates(ctx); err != nil {
				m.logger.Errorf("Error during CT log check: %v", err)
			}
		case <-m.shutdownChan:
			m.logger.Info("CT log monitor stopped")
			return nil
		case <-ctx.Done():
			m.logger.Info("CT log monitor stopped due to context cancellation")
			return nil
		}
	}
}

func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isMonitoring {
		close(m.shutdownChan)
		m.isMonitoring = false
	}
}

func (m *Monitor) initialSync(ctx context.Context) error {
	m.logger.Info("Performing initial sync with CT logs")

	m.fetcher.mu.RLock()
	defer m.fetcher.mu.RUnlock()

	g, ctx := errgroup.WithContext(ctx)
	for logID, lc := range m.fetcher.clients {
		logID := logID
		lc := lc

		g.Go(func() error {
			if err := m.fetcher.rateLimit.Wait(ctx); err != nil {
				return err
			}

			sth, err := lc.GetSTH(ctx)
			if err != nil {
				m.logger.Warnf("Failed to get STH for log %s: %v", logID, err)
				return nil 
			}

			m.mu.Lock()
			m.lastIndexes[logID] = int64(sth.TreeSize) - 1 
			m.mu.Unlock()

			m.logger.Infof("Initialized log %s with tree size %d", logID, sth.TreeSize)
			return nil
		})
	}
	return g.Wait()
}


func (m *Monitor) checkForUpdates(ctx context.Context) error {
	m.mu.RLock()
	lastIdxCopy := make(map[string]int64, len(m.lastIndexes))
	for k, v := range m.lastIndexes {
		lastIdxCopy[k] = v
	}
	m.mu.RUnlock()

	m.fetcher.mu.RLock()
	clientsCopy := make(map[string]*client.LogClient, len(m.fetcher.clients))
	for k, v := range m.fetcher.clients {
		clientsCopy[k] = v
	}
	m.fetcher.mu.RUnlock()

	var wg sync.WaitGroup
	var muErr sync.Mutex
	var errs []error

	for logID, lc := range clientsCopy {
		wg.Add(1)
		go func(logID string, lc *client.LogClient) {
			defer wg.Done()

			if err := m.fetcher.rateLimit.Wait(ctx); err != nil {
				muErr.Lock()
				errs = append(errs, fmt.Errorf("rate limit wait failed for log %s: %w", logID, err))
				muErr.Unlock()
				return
			}

			sth, err := lc.GetSTH(ctx)
			if err != nil {
				muErr.Lock()
				errs = append(errs, fmt.Errorf("failed to get STH for log %s: %w", logID, err))
				muErr.Unlock()
				return
			}

			currentSize := int64(sth.TreeSize)
			lastIndex := lastIdxCopy[logID]

			if currentSize <= lastIndex {
				return 
			}

			const batchSize int64 = 1000
			startIndex := lastIndex + 1
			endIndex := currentSize - 1

			m.logger.Infof("Found %d new entries in log %s", endIndex-startIndex+1, logID)

			for startIndex <= endIndex {
				if err := m.fetcher.rateLimit.Wait(ctx); err != nil {
					muErr.Lock()
					errs = append(errs, fmt.Errorf("rate limit wait failed for log %s: %w", logID, err))
					muErr.Unlock()
					return
				}

				batchEnd := startIndex + batchSize - 1
				if batchEnd > endIndex {
					batchEnd = endIndex
				}

				entries, err := lc.GetEntries(ctx, startIndex, batchEnd)
				if err != nil {
					muErr.Lock()
					errs = append(errs, fmt.Errorf("failed to get entries from log %s: %w", logID, err))
					muErr.Unlock()
					break
				}

				for _, e := range entries {
					leaf := ct.LeafEntry{
						Leaf:      e.Leaf,
						ExtraData: e.ExtraData,
					}

					raw, err := json.Marshal(leaf)
					if err != nil {
						m.logger.Warnf("Failed to marshal leaf entry for log %s: %v", logID, err)
						continue
					}

					ctEntry, err := m.parser.ParseAndValidate(ctx, raw)
					if err != nil {
						m.logger.Debugf("Failed to parse/validate entry from log %s: %v", logID, err)
						continue
					}
					if ctEntry != nil {
						ctEntry.LogID = logID
						m.notifyCallbacks(*ctEntry)
					}
				}

				startIndex = batchEnd + 1
			}

			m.mu.Lock()
			m.lastIndexes[logID] = endIndex
			m.mu.Unlock()
		}(logID, lc)
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("encountered %d errors during update check", len(errs))
	}
	return nil
}

func (m *Monitor) RegisterCallback(callback func(models.CTLogEntry)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, callback)
}

func (m *Monitor) notifyCallbacks(entry models.CTLogEntry) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cb := range m.callbacks {
		go cb(entry)
	}
}

func (m *Monitor) GetStatus() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"is_monitoring": m.isMonitoring,
		"interval":      m.interval.String(),
		"last_indexes":  copyLastIndexes(m.lastIndexes),
		"callback_count": len(m.callbacks),
	}
}

func copyLastIndexes(src map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (m *Monitor) SetInterval(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interval = interval
}

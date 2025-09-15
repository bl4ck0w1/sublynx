package orchestration

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
)

type ResourceOptimizer struct {
	logger       *logrus.Logger
	mu           sync.RWMutex
	resourceUsage ResourceUsage
	rateLimit    int
	minRateLimit int
	maxRateLimit int
	adaptiveMode   bool
	metricsHistory []ResourceMetrics
	maxHistorySize int
	optimizationStrategies map[string]OptimizationStrategy
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type ResourceUsage struct {
	CPUPercent    float64
	MemoryMB      float64
	MemoryPercent float64 
	Goroutines    int
	ActiveTasks   int
	NetworkUsage  float64 
	DiskUsage     float64 
}

type ResourceMetrics struct {
	Timestamp time.Time
	ResourceUsage
}

type OptimizationStrategy interface {
	Apply(usage ResourceUsage, currentLimit int) int
}

func NewResourceOptimizer(logger *logrus.Logger) *ResourceOptimizer {
	if logger == nil {
		logger = logrus.New()
	}

	ro := &ResourceOptimizer{
		logger:                 logger,
		resourceUsage:          ResourceUsage{},
		rateLimit:              10,   
		minRateLimit:           1,    
		maxRateLimit:           1000, 
		adaptiveMode:           true,
		metricsHistory:         make([]ResourceMetrics, 0, 256),
		maxHistorySize:         1000,
		optimizationStrategies: make(map[string]OptimizationStrategy),
		stopCh:                 make(chan struct{}),
	}

	ro.initializeStrategies()

	ro.wg.Add(1)
	go ro.monitorResources()

	return ro
}

func (ro *ResourceOptimizer) Close() {
	ro.mu.Lock()
	select {
	case <-ro.stopCh:
	
	default:
		close(ro.stopCh)
	}
	ro.mu.Unlock()
	ro.wg.Wait()
}

func (ro *ResourceOptimizer) initializeStrategies() {
	ro.optimizationStrategies["cpu_based"] = &CPUBasedStrategy{}
	ro.optimizationStrategies["memory_based"] = &MemoryBasedStrategy{}
	ro.optimizationStrategies["network_based"] = &NetworkBasedStrategy{}
	ro.optimizationStrategies["balanced"] = &BalancedStrategy{}
}

func (ro *ResourceOptimizer) monitorResources() {
	defer ro.wg.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			usage, err := ro.collectResourceUsage()
			if err != nil {
				ro.logger.Warnf("Failed to collect resource usage: %v", err)
				continue
			}

			ro.mu.Lock()
			ro.resourceUsage = usage

			metrics := ResourceMetrics{
				Timestamp:     time.Now(),
				ResourceUsage: usage,
			}
			ro.metricsHistory = append(ro.metricsHistory, metrics)
			if len(ro.metricsHistory) > ro.maxHistorySize {
				ro.metricsHistory = ro.metricsHistory[len(ro.metricsHistory)-ro.maxHistorySize:]
			}

			if ro.adaptiveMode {
				ro.applyOptimizationLocked()
			}
			ro.mu.Unlock()

		case <-ro.stopCh:
			return
		}
	}
}

func (ro *ResourceOptimizer) collectResourceUsage() (ResourceUsage, error) {
	var usage ResourceUsage

	usage.CPUPercent = 0.0

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	usage.MemoryMB = float64(m.Alloc) / 1024.0 / 1024.0

	if m.HeapSys > 0 {
		usage.MemoryPercent = (float64(m.HeapAlloc) / float64(m.HeapSys)) * 100.0
	} else {
		usage.MemoryPercent = 0
	}

	usage.Goroutines = runtime.NumGoroutine()

	usage.NetworkUsage = usage.NetworkUsage
	usage.DiskUsage = usage.DiskUsage

	ro.mu.RLock()
	usage.ActiveTasks = ro.resourceUsage.ActiveTasks
	ro.mu.RUnlock()

	return usage, nil
}

func (ro *ResourceOptimizer) applyOptimizationLocked() {
	newLimit := ro.rateLimit

	for name, strategy := range ro.optimizationStrategies {
		suggested := strategy.Apply(ro.resourceUsage, ro.rateLimit)
		if suggested < newLimit {
			newLimit = suggested
			ro.logger.Debugf("Strategy %s suggests limit: %d", name, suggested)
		}
	}

	if newLimit < ro.minRateLimit {
		newLimit = ro.minRateLimit
	}
	if newLimit > ro.maxRateLimit {
		newLimit = ro.maxRateLimit
	}

	if newLimit != ro.rateLimit {
		old := ro.rateLimit
		ro.rateLimit = newLimit
		ro.logger.Infof("Rate limit adjusted from %d to %d based on resource usage", old, newLimit)
	}
}

func (ro *ResourceOptimizer) GetRateLimit() int {
	ro.mu.RLock()
	defer ro.mu.RUnlock()
	return ro.rateLimit
}

func (ro *ResourceOptimizer) SetRateLimit(limit int) {
	ro.mu.Lock()
	defer ro.mu.Unlock()

	if limit < 1 {
		limit = 1
	}
	ro.rateLimit = limit
	ro.adaptiveMode = false
	ro.logger.Infof("Rate limit set to %d (adaptive mode disabled)", limit)
}

func (ro *ResourceOptimizer) SetRateBounds(min, max int) error {
	if min <= 0 || max < min {
		return fmt.Errorf("invalid bounds: min=%d max=%d", min, max)
	}
	ro.mu.Lock()
	ro.minRateLimit = min
	ro.maxRateLimit = max
	if ro.rateLimit < min {
		ro.rateLimit = min
	}
	if ro.rateLimit > max {
		ro.rateLimit = max
	}
	ro.mu.Unlock()
	return nil
}

func (ro *ResourceOptimizer) SetAdaptiveMode(enabled bool) {
	ro.mu.Lock()
	defer ro.mu.Unlock()

	ro.adaptiveMode = enabled
	if enabled {
		ro.logger.Info("Adaptive rate limiting enabled")
	} else {
		ro.logger.Info("Adaptive rate limiting disabled")
	}
}

func (ro *ResourceOptimizer) UpdateActiveTasks(n int) {
	ro.mu.Lock()
	ro.resourceUsage.ActiveTasks = n
	if ro.adaptiveMode {
		ro.applyOptimizationLocked()
	}
	ro.mu.Unlock()
}

func (ro *ResourceOptimizer) GetResourceUsage() ResourceUsage {
	ro.mu.RLock()
	defer ro.mu.RUnlock()
	return ro.resourceUsage
}

func (ro *ResourceOptimizer) GetMetricsHistory() []ResourceMetrics {
	ro.mu.RLock()
	defer ro.mu.RUnlock()

	history := make([]ResourceMetrics, len(ro.metricsHistory))
	copy(history, ro.metricsHistory)
	return history
}

func (ro *ResourceOptimizer) SetMaxHistorySize(n int) {
	if n < 10 {
		n = 10
	}
	ro.mu.Lock()
	ro.maxHistorySize = n
	if len(ro.metricsHistory) > ro.maxHistorySize {
		ro.metricsHistory = ro.metricsHistory[len(ro.metricsHistory)-ro.maxHistorySize:]
	}
	ro.mu.Unlock()
}

func (ro *ResourceOptimizer) RegisterStrategy(name string, strategy OptimizationStrategy) error {
	ro.mu.Lock()
	defer ro.mu.Unlock()

	if _, exists := ro.optimizationStrategies[name]; exists {
		return fmt.Errorf("strategy already exists: %s", name)
	}
	ro.optimizationStrategies[name] = strategy
	return nil
}

func (ro *ResourceOptimizer) GetStats() map[string]interface{} {
	ro.mu.RLock()
	defer ro.mu.RUnlock()

	return map[string]interface{}{
		"rate_limit":          ro.rateLimit,
		"adaptive_mode":       ro.adaptiveMode,
		"min_rate_limit":      ro.minRateLimit,
		"max_rate_limit":      ro.maxRateLimit,
		"cpu_usage":           ro.resourceUsage.CPUPercent,
		"memory_usage_mb":     ro.resourceUsage.MemoryMB,
		"memory_usage_percent": ro.resourceUsage.MemoryPercent,
		"goroutines":          ro.resourceUsage.Goroutines,
		"active_tasks":        ro.resourceUsage.ActiveTasks,
		"network_usage":       ro.resourceUsage.NetworkUsage,
		"disk_usage":          ro.resourceUsage.DiskUsage,
		"history_size":        len(ro.metricsHistory),
		"strategies":          len(ro.optimizationStrategies),
	}
}

type CPUBasedStrategy struct{}

func (s *CPUBasedStrategy) Apply(usage ResourceUsage, currentLimit int) int {
	if usage.CPUPercent <= 0 {
		return currentLimit
	}
	if usage.CPUPercent > 80.0 {
		return maxInt(1, currentLimit/2)
	} else if usage.CPUPercent > 60.0 {
		return maxInt(1, (currentLimit*3)/4)
	} else if usage.CPUPercent < 20.0 {
		return currentLimit * 2
	}
	return currentLimit
}

type MemoryBasedStrategy struct{}

func (s *MemoryBasedStrategy) Apply(usage ResourceUsage, currentLimit int) int {
	if usage.MemoryPercent <= 0 {
		return currentLimit
	}
	if usage.MemoryPercent > 80.0 {
		return maxInt(1, currentLimit/2)
	} else if usage.MemoryPercent > 60.0 {
		return maxInt(1, (currentLimit*3)/4)
	} else if usage.MemoryPercent < 20.0 {
		return currentLimit * 2
	}
	return currentLimit
}

type NetworkBasedStrategy struct{}

func (s *NetworkBasedStrategy) Apply(usage ResourceUsage, currentLimit int) int {
	if usage.NetworkUsage <= 0 {
		return currentLimit
	}
	if usage.NetworkUsage > 10.0 { // 10 MB/s
		return maxInt(1, currentLimit/2)
	} else if usage.NetworkUsage > 5.0 { // 5 MB/s
		return maxInt(1, (currentLimit*3)/4)
	} else if usage.NetworkUsage < 1.0 {
		return currentLimit * 2
	}
	return currentLimit
}


type BalancedStrategy struct{}

func (s *BalancedStrategy) Apply(usage ResourceUsage, currentLimit int) int {
	cpuScore := 1.0
	switch {
	case usage.CPUPercent <= 0:
		cpuScore = 1.0
	case usage.CPUPercent > 80.0:
		cpuScore = 0.3
	case usage.CPUPercent > 60.0:
		cpuScore = 0.6
	case usage.CPUPercent > 40.0:
		cpuScore = 0.8
	}

	memScore := 1.0
	switch {
	case usage.MemoryPercent <= 0: 
		memScore = 1.0
	case usage.MemoryPercent > 80.0:
		memScore = 0.3
	case usage.MemoryPercent > 60.0:
		memScore = 0.6
	case usage.MemoryPercent > 40.0:
		memScore = 0.8
	}

	netScore := 1.0
	switch {
	case usage.NetworkUsage <= 0:
		netScore = 1.0
	case usage.NetworkUsage > 10.0:
		netScore = 0.3
	case usage.NetworkUsage > 5.0:
		netScore = 0.6
	case usage.NetworkUsage > 2.0:
		netScore = 0.8
	}


	if nCPU := runtime.NumCPU(); nCPU > 0 && usage.ActiveTasks > nCPU*2 {
		netScore = minFloat(netScore, 0.7)
		cpuScore = minFloat(cpuScore, 0.7)
	}

	minScore := minFloat(cpuScore, memScore, netScore)
	newLimit := int(float64(currentLimit) * minScore)
	return maxInt(1, newLimit)
}


func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minFloat(a, b float64, rest ...float64) float64 {
	min := a
	if b < min {
		min = b
	}
	for _, v := range rest {
		if v < min {
			min = v
		}
	}
	return min
}

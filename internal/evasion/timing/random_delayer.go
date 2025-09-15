package timing

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type RandomDelayer struct {
	minDelay    time.Duration
	maxDelay    time.Duration
	jitter      float64 
	logger      *logrus.Logger

	mu          sync.RWMutex
	delayCount  int64
	totalDelay  time.Duration
	lastDelays  []time.Duration
	statsWindow int
}

func NewRandomDelayer(minDelay, maxDelay time.Duration, jitter float64, logger *logrus.Logger) *RandomDelayer {
	if logger == nil {
		logger = logrus.New()
	}
	if jitter < 0 {
		jitter = 0
	} else if jitter > 1 {
		jitter = 1
	}
	if maxDelay < minDelay {
		maxDelay = minDelay
	}
	return &RandomDelayer{
		minDelay:    minDelay,
		maxDelay:    maxDelay,
		jitter:      jitter,
		logger:      logger,
		lastDelays:  make([]time.Duration, 0, 100),
		statsWindow: 100,
	}
}

func (rd *RandomDelayer) Delay() {
	d := rd.calculateDelay()
	rd.recordDelay(d)
	time.Sleep(d)
}

func (rd *RandomDelayer) DelayCtx(ctx context.Context) error {
	d := rd.calculateDelay()
	rd.recordDelay(d)

	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rd *RandomDelayer) calculateDelay() time.Duration {
	rd.mu.RLock()
	min := rd.minDelay
	max := rd.maxDelay
	jitter := rd.jitter
	rd.mu.RUnlock()
	base := min
	if max > min {
		rangeNs := int64(max - min)
		if rangeNs > 0 {
			if r, err := rand.Int(rand.Reader, big.NewInt(rangeNs)); err == nil {
				base += time.Duration(r.Int64())
			}
		}
	}

	if jitter > 0 && base > 0 {
		jRange := float64(base) * jitter
		if jRange >= 1 {
			if r, err := rand.Int(rand.Reader, big.NewInt(int64(jRange*2))); err == nil {
				adj := time.Duration(r.Int64()) - time.Duration(jRange)
				base += adj
			}
		}
	}

	if base < 0 {
		base = 0
	}
	return base
}

func (rd *RandomDelayer) recordDelay(d time.Duration) {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	rd.delayCount++
	rd.totalDelay += d

	if rd.statsWindow <= 0 {
		rd.statsWindow = 100
	}
	if len(rd.lastDelays) >= rd.statsWindow {
		rd.lastDelays = rd.lastDelays[1:]
	}
	rd.lastDelays = append(rd.lastDelays, d)
}

func (rd *RandomDelayer) SetDelayRange(min, max time.Duration) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if max < min {
		max = min
	}
	rd.minDelay = min
	rd.maxDelay = max
}

func (rd *RandomDelayer) SetJitter(j float64) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if j < 0 {
		j = 0
	} else if j > 1 {
		j = 1
	}
	rd.jitter = j
}

func (rd *RandomDelayer) SetStatsWindow(n int) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if n <= 0 {
		n = 100
	}
	rd.statsWindow = n
	rd.lastDelays = make([]time.Duration, 0, n)
}

func (rd *RandomDelayer) ResetStats() {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.delayCount = 0
	rd.totalDelay = 0
	rd.lastDelays = rd.lastDelays[:0]
}

func (rd *RandomDelayer) GetStats() map[string]interface{} {
	rd.mu.RLock()
	defer rd.mu.RUnlock()

	var recentAvg time.Duration
	if n := len(rd.lastDelays); n > 0 {
		var recentTotal time.Duration
		for _, d := range rd.lastDelays {
			recentTotal += d
		}
		recentAvg = recentTotal / time.Duration(n)
	}

	avg := time.Duration(0)
	if rd.delayCount > 0 {
		avg = rd.totalDelay / time.Duration(rd.delayCount)
	}

	return map[string]interface{}{
		"total_delays":       rd.delayCount,
		"total_delay_time":   rd.totalDelay,
		"average_delay":      avg,
		"recent_avg_delay":   recentAvg,
		"min_delay":          rd.minDelay,
		"max_delay":          rd.maxDelay,
		"jitter":             rd.jitter,
		"recent_delay_count": len(rd.lastDelays),
		"stats_window":       rd.statsWindow,
	}
}

func (rd *RandomDelayer) AdaptiveDelay(successRate float64, minDelay, maxDelay time.Duration) {
	if successRate < 0 {
		successRate = 0
	} else if successRate > 1 {
		successRate = 1
	}
	if maxDelay < minDelay {
		maxDelay = minDelay
	}

	spanMs := float64(maxDelay-minDelay) / float64(time.Millisecond)
	adjustment := 1.0 - successRate 
	target := minDelay + time.Duration(adjustment*spanMs)*time.Millisecond

	if target < minDelay {
		target = minDelay
	}
	if target > maxDelay {
		target = maxDelay
	}
	rd.SetDelayRange(minDelay, target)
}

func (rd *RandomDelayer) ExponentialBackoff(attempt int, baseDelay, maxDelay time.Duration) {
	_ = rd.ExponentialBackoffCtx(context.Background(), attempt, baseDelay, maxDelay)
}

func (rd *RandomDelayer) ExponentialBackoffCtx(ctx context.Context, attempt int, baseDelay, maxDelay time.Duration) error {
	if attempt < 0 {
		attempt = 0
	}
	if baseDelay <= 0 {
		return ctx.Err()
	}

	delay := baseDelay * time.Duration(1<<uint(attempt))
	if delay > maxDelay {
		delay = maxDelay
	}
	if delay <= 0 {
		return ctx.Err()
	}

	var sleep time.Duration
	if r, err := rand.Int(rand.Reader, big.NewInt(int64(delay))); err == nil {
		sleep = time.Duration(r.Int64())
	}

	t := time.NewTimer(sleep)
	defer t.Stop()

	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rd *RandomDelayer) DecorrelatedJitterBackoff(prevDelay, baseDelay, maxDelay time.Duration) time.Duration {
	if baseDelay <= 0 {
		return 0
	}
	if prevDelay <= 0 {
		prevDelay = baseDelay
	}
	high := prevDelay * 3
	if high < baseDelay {
		high = baseDelay
	}
	if high > maxDelay {
		high = maxDelay
	}
	span := high - baseDelay
	if span <= 0 {
		return baseDelay
	}
	if r, err := rand.Int(rand.Reader, big.NewInt(int64(span))); err == nil {
		return baseDelay + time.Duration(r.Int64())
	}
	return baseDelay
}

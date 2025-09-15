package timing

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limiter *rate.Limiter
	mu      sync.RWMutex
	logger  *logrus.Logger
	baseRate rate.Limit
	burst    int
	adaptive bool
	successRate  float64
	requestCount int64
	successCount int64
	blockedCount int64
	lastReset   time.Time
	statsWindow time.Duration
	adjustmentStep float64
	minRate        rate.Limit
	maxRate        rate.Limit
	increaseThreshold float64 
	decreaseThreshold float64 
	successEMA     float64
	successEMAInit bool
	emaAlpha       float64 
	adjustStop   chan struct{}
	adjustDone   chan struct{}
	adjustTicker *time.Ticker
	lastBlocked time.Time
}

func NewRateLimiter(baseRate rate.Limit, burst int, adaptive bool, logger *logrus.Logger) *RateLimiter {
	if logger == nil {
		logger = logrus.New()
	}

	rl := &RateLimiter{
		limiter:           rate.NewLimiter(baseRate, burst),
		logger:            logger,
		baseRate:          baseRate,
		burst:             burst,
		adaptive:          adaptive,
		successRate:       1.0,
		lastReset:         time.Now(),
		statsWindow:       5 * time.Minute,
		adjustmentStep:    0.10,
		minRate:           rate.Limit(0.1), 
		maxRate:           rate.Limit(100), 
		increaseThreshold: 0.90,
		decreaseThreshold: 0.50,
		emaAlpha:          0.2, 
	}

	if adaptive {
		rl.startAdjustLoop()
	}
	return rl
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	rl.mu.Lock()
	rl.requestCount++
	rl.mu.Unlock()

	if err := rl.limiter.Wait(ctx); err != nil {
		rl.mu.Lock()
		rl.blockedCount++
		rl.lastBlocked = time.Now()
		rl.mu.Unlock()
		return err
	}
	return nil
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	rl.requestCount++
	allowed := rl.limiter.Allow()
	if !allowed {
		rl.blockedCount++
		rl.lastBlocked = time.Now()
	}
	rl.mu.Unlock()
	return allowed
}

func (rl *RateLimiter) RecordSuccess() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.successCount++
	rl.updateSuccessRateLocked()
}

func (rl *RateLimiter) RecordFailure() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.updateSuccessRateLocked()
}

func (rl *RateLimiter) updateSuccessRateLocked() {
	total := rl.requestCount
	if total <= 0 {
		return
	}
	raw := float64(rl.successCount) / float64(total)
	rl.successRate = raw
	if !rl.successEMAInit {
		rl.successEMA = raw
		rl.successEMAInit = true
	} else {
		rl.successEMA = rl.emaAlpha*raw + (1-rl.emaAlpha)*rl.successEMA
	}
}

func (rl *RateLimiter) startAdjustLoop() {
	rl.stopAdjustLoop() 

	rl.adjustStop = make(chan struct{})
	rl.adjustDone = make(chan struct{})
	interval := rl.statsWindow / 2
	if interval <= 0 {
		interval = time.Minute
	}
	rl.adjustTicker = time.NewTicker(interval)

	go func() {
		defer close(rl.adjustDone)
		for {
			select {
			case <-rl.adjustTicker.C:
				rl.adjustRate()
				rl.resetStats()
				rl.mu.RLock()
				newInterval := rl.statsWindow / 2
				rl.mu.RUnlock()
				if newInterval <= 0 {
					newInterval = time.Minute
				}
				rl.adjustTicker.Stop()
				rl.adjustTicker = time.NewTicker(newInterval)

			case <-rl.adjustStop:
				rl.adjustTicker.Stop()
				return
			}
		}
	}()
}

func (rl *RateLimiter) stopAdjustLoop() {
	if rl.adjustStop != nil {
		close(rl.adjustStop)
		<-rl.adjustDone
		rl.adjustStop = nil
		rl.adjustDone = nil
	}
}

func (rl *RateLimiter) adjustRate() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if !rl.adaptive {
		return
	}

	current := rl.limiter.Limit()
	newRate := current
	success := rl.successEMA
	if !rl.successEMAInit {
		success = rl.successRate
	}

	switch {
	case success > rl.increaseThreshold:
		newRate = current * rate.Limit(1+rl.adjustmentStep)
	case success < rl.decreaseThreshold:
		newRate = current * rate.Limit(1-rl.adjustmentStep)
	default:
		// hold steady
	}

	if newRate < rl.minRate {
		newRate = rl.minRate
	}
	if newRate > rl.maxRate {
		newRate = rl.maxRate
	}

	if newRate != current {
		rl.limiter.SetLimit(newRate)
		rl.logger.Infof("Adjusted rate limit from %.2f to %.2f (successEMA=%.2f, raw=%.2f)",
			current, newRate, success, rl.successRate)
	}
}

func (rl *RateLimiter) resetStats() {
	rl.requestCount = 0
	rl.successCount = 0
	rl.blockedCount = 0
	rl.lastReset = time.Now()
}

func (rl *RateLimiter) SetRate(newRate rate.Limit) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if newRate < rl.minRate {
		newRate = rl.minRate
	}
	if newRate > rl.maxRate {
		newRate = rl.maxRate
	}
	rl.baseRate = newRate
	rl.limiter.SetLimit(newRate)
}

func (rl *RateLimiter) SetBurst(newBurst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if newBurst < 0 {
		newBurst = 0
	}
	rl.burst = newBurst
	rl.limiter.SetBurst(newBurst)
}

func (rl *RateLimiter) SetAdaptive(adaptive bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.adaptive == adaptive {
		return
	}
	rl.adaptive = adaptive
	go func(enable bool) {
		if enable {
			rl.startAdjustLoop()
		} else {
			rl.stopAdjustLoop()
		}
	}(adaptive)
}

func (rl *RateLimiter) SetAdjustmentStep(step float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if step > 0 && step <= 1 {
		rl.adjustmentStep = step
	}
}

func (rl *RateLimiter) SetStatsWindow(window time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if window > 0 {
		rl.statsWindow = window
	}
}

func (rl *RateLimiter) SetRateBounds(min, max rate.Limit) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if min <= 0 {
		min = rl.minRate
	}
	if max < min {
		max = min
	}
	rl.minRate = min
	rl.maxRate = max
	cur := rl.limiter.Limit()
	if cur < rl.minRate {
		rl.limiter.SetLimit(rl.minRate)
	} else if cur > rl.maxRate {
		rl.limiter.SetLimit(rl.maxRate)
	}
}

func (rl *RateLimiter) SetHysteresis(increaseAbove, decreaseBelow float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if increaseAbove < 0 {
		increaseAbove = 0
	}
	if increaseAbove > 1 {
		increaseAbove = 1
	}
	if decreaseBelow < 0 {
		decreaseBelow = 0
	}
	if decreaseBelow > 1 {
		decreaseBelow = 1
	}
	rl.increaseThreshold = increaseAbove
	rl.decreaseThreshold = decreaseBelow
}

func (rl *RateLimiter) SetEMASmoothing(alpha float64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if alpha < 0 {
		alpha = 0
	}
	if alpha > 1 {
		alpha = 1
	}
	rl.emaAlpha = alpha
}

func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return map[string]interface{}{
		"current_rate":       rl.limiter.Limit(),
		"base_rate":          rl.baseRate,
		"burst":              rl.burst,
		"adaptive":           rl.adaptive,
		"success_rate_raw":   rl.successRate,
		"success_rate_ema":   rl.successEMA,
		"request_count":      rl.requestCount,
		"success_count":      rl.successCount,
		"blocked_count":      rl.blockedCount,
		"last_reset":         rl.lastReset,
		"last_blocked":       rl.lastBlocked,
		"stats_window":       rl.statsWindow,
		"adjustment_step":    rl.adjustmentStep,
		"min_rate":           rl.minRate,
		"max_rate":           rl.maxRate,
		"increase_threshold": rl.increaseThreshold,
		"decrease_threshold": rl.decreaseThreshold,
		"ema_alpha":          rl.emaAlpha,
	}
}

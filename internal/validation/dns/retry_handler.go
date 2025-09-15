package dns

import (
	"context"
	"math/rand"
	"strings"
	"time"
	"github.com/sirupsen/logrus"
)

type RetryHandler struct {
	maxRetries   int          
	baseTimeout  time.Duration 
	maxTimeout   time.Duration 
	jitterFactor float64      
	logger       *logrus.Logger
}

func NewRetryHandler(maxRetries int, baseTimeout time.Duration, logger *logrus.Logger) *RetryHandler {
	if logger == nil {
		logger = logrus.New()
	}
	if baseTimeout <= 0 {
		baseTimeout = 500 * time.Millisecond
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	return &RetryHandler{
		maxRetries:   maxRetries,
		baseTimeout:  baseTimeout,
		maxTimeout:   baseTimeout * 10, 
		jitterFactor: 0.3,            
		logger:       logger,
	}
}

func (r *RetryHandler) DoWithRetry(ctx context.Context, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}

		if IsPermanentDNSError(lastErr) {
			r.logger.Debugf("Stopping retries due to permanent error: %v", lastErr)
			break
		}
		if attempt == r.maxRetries {
			r.logger.Debugf("Stopping retries after %d attempts", attempt+1)
			break
		}
		backoff := r.calculateBackoff(attempt + 1)
		r.logger.Debugf("DNS operation failed (attempt %d/%d), retrying in %v: %v",
			attempt+1, r.maxRetries+1, backoff, lastErr)

		select {
		case <-time.After(backoff):
			// continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return lastErr
}

func (r *RetryHandler) calculateBackoff(attemptNumber int) time.Duration {
	backoff := r.baseTimeout * time.Duration(1<<(attemptNumber-1))

	if backoff > r.maxTimeout {
		backoff = r.maxTimeout
	}

	j := r.jitterFactor
	if j < 0 {
		j = 0
	} else if j > 1 {
		j = 1
	}
	scale := 1 + j*(2*rand.Float64()-1)
	return time.Duration(float64(backoff) * scale)
}

func IsPermanentDNSError(err error) bool {
	if err == nil {
		return false
	}
	permanentTokens := []string{
		"NXDOMAIN",
		"REFUSED",
		"NOTZONE",
		"NOTAUTH",
		"FORMERR",
	}
	msg := err.Error()
	for _, tok := range permanentTokens {
		if strings.Contains(msg, tok) {
			return true
		}
	}
	return false
}

func (r *RetryHandler) SetMaxRetries(maxRetries int) {
	if maxRetries < 0 {
		maxRetries = 0
	}
	r.maxRetries = maxRetries
}

func (r *RetryHandler) SetBaseTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	r.baseTimeout = timeout
}

func (r *RetryHandler) SetMaxTimeout(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	r.maxTimeout = timeout
}

func (r *RetryHandler) SetJitterFactor(factor float64) {
	if factor < 0 {
		factor = 0
	}
	if factor > 1 {
		factor = 1
	}
	r.jitterFactor = factor
}

func (r *RetryHandler) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"max_retries":   r.maxRetries,
		"base_timeout":  r.baseTimeout,
		"max_timeout":   r.maxTimeout,
		"jitter_factor": r.jitterFactor,
	}
}

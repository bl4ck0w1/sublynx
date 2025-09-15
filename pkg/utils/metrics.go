package utils

import (
	"context"
	"expvar"
	"fmt"
	"net/http"
	"sync"
	"time"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type MetricsCollector struct {
	registry   *prometheus.Registry
	counters   map[string]*prometheus.CounterVec
	gauges     map[string]*prometheus.GaugeVec
	histograms map[string]*prometheus.HistogramVec
	summaries  map[string]*prometheus.SummaryVec
	mu         sync.RWMutex
}

func NewMetricsCollector(enableRuntimeMetrics bool) *MetricsCollector {
	reg := prometheus.NewRegistry()

	if enableRuntimeMetrics {
		_ = reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		_ = reg.Register(collectors.NewGoCollector())
	}

	return &MetricsCollector{
		registry:   reg,
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		summaries:  make(map[string]*prometheus.SummaryVec),
	}
}

func (m *MetricsCollector) RegisterCounter(name, help string, labelNames ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.counters[name]; ok {
		return nil
	}
	cv := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labelNames)
	if err := m.registry.Register(cv); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			m.counters[name] = are.ExistingCollector.(*prometheus.CounterVec)
			return nil
		}
		return err
	}
	m.counters[name] = cv
	return nil
}

func (m *MetricsCollector) RegisterGauge(name, help string, labelNames ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.gauges[name]; ok {
		return nil
	}
	gv := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labelNames)
	if err := m.registry.Register(gv); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			m.gauges[name] = are.ExistingCollector.(*prometheus.GaugeVec)
			return nil
		}
		return err
	}
	m.gauges[name] = gv
	return nil
}

func (m *MetricsCollector) RegisterHistogram(name, help string, buckets []float64, labelNames ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.histograms[name]; ok {
		return nil
	}
	if buckets == nil {
		buckets = prometheus.DefBuckets
	}
	hv := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: help, Buckets: buckets}, labelNames)
	if err := m.registry.Register(hv); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			m.histograms[name] = are.ExistingCollector.(*prometheus.HistogramVec)
			return nil
		}
		return err
	}
	m.histograms[name] = hv
	return nil
}

func (m *MetricsCollector) RegisterSummary(name, help string, objectives map[float64]float64, labelNames ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.summaries[name]; ok {
		return nil
	}
	sv := prometheus.NewSummaryVec(prometheus.SummaryOpts{Name: name, Help: help, Objectives: objectives}, labelNames)
	if err := m.registry.Register(sv); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			m.summaries[name] = are.ExistingCollector.(*prometheus.SummaryVec)
			return nil
		}
		return err
	}
	m.summaries[name] = sv
	return nil
}

func (m *MetricsCollector) IncCounter(name string, delta float64, labels prometheus.Labels) {
	m.mu.RLock()
	cv := m.counters[name]
	m.mu.RUnlock()
	if cv != nil {
		cv.With(labels).Add(delta)
	}
}

func (m *MetricsCollector) SetGauge(name string, value float64, labels prometheus.Labels) {
	m.mu.RLock()
	gv := m.gauges[name]
	m.mu.RUnlock()
	if gv != nil {
		gv.With(labels).Set(value)
	}
}

func (m *MetricsCollector) AddGauge(name string, delta float64, labels prometheus.Labels) {
	m.mu.RLock()
	gv := m.gauges[name]
	m.mu.RUnlock()
	if gv != nil {
		gv.With(labels).Add(delta)
	}
}

func (m *MetricsCollector) ObserveHistogram(name string, value float64, labels prometheus.Labels) {
	m.mu.RLock()
	hv := m.histograms[name]
	m.mu.RUnlock()
	if hv != nil {
		hv.With(labels).Observe(value)
	}
}

func (m *MetricsCollector) ObserveSummary(name string, value float64, labels prometheus.Labels) {
	m.mu.RLock()
	sv := m.summaries[name]
	m.mu.RUnlock()
	if sv != nil {
		sv.With(labels).Observe(value)
	}
}

func (m *MetricsCollector) TimeFunc(histogramName string, labels prometheus.Labels, fn func()) {
	start := time.Now()
	fn()
	m.ObserveHistogram(histogramName, time.Since(start).Seconds(), labels)
}

func (m *MetricsCollector) StartServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	server := &http.Server{Addr: addr, Handler: mux}
	return server.ListenAndServe()
}

func (m *MetricsCollector) StartServerWithContext(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	server := &http.Server{Addr: addr, Handler: mux}

	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("metrics server error: %w", err)
	}
}

func (m *MetricsCollector) ExpVarHandler() http.Handler {
	return expvar.Handler()
}

func (m *MetricsCollector) GetRegistry() *prometheus.Registry {
	return m.registry
}

func DefaultMetricsCollector() *MetricsCollector {
	return NewMetricsCollector(true)
}

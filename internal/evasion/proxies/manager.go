package proxies

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	xproxy "golang.org/x/net/proxy"
)

type ProxyManager struct {
	proxies             []*Proxy
	activeProxies       []*Proxy
	failedProxies       map[string]time.Time
	proxySources        []ProxySource
	healthCheckInterval time.Duration
	maxFailures         int
	logger              *logrus.Logger

	mu            sync.RWMutex
	rotationIndex int
	rng           *rand.Rand

	healthCheckStop chan struct{}
	healthRunning   bool
}

type Proxy struct {
	URL          *url.URL
	Type         string 
	Latency      time.Duration
	SuccessRate  float64
	LastUsed     time.Time
	LastChecked  time.Time
	FailureCount int
	Country      string
	ASN          string
	Source       string
	Credentials  *ProxyAuth
}

type ProxyAuth struct {
	Username string
	Password string
}

type ProxySource interface {
	Name() string
	GetProxies() ([]*Proxy, error)
	RateLimit() time.Duration
}

type RotationStrategy int

const (
	RoundRobin RotationStrategy = iota
	Random
	LatencyBased
	SuccessRateBased
)

func NewProxyManager(healthCheckInterval time.Duration, maxFailures int, logger *logrus.Logger) *ProxyManager {
	if logger == nil {
		logger = logrus.New()
	}

	pm := &ProxyManager{
		proxies:             make([]*Proxy, 0),
		activeProxies:       make([]*Proxy, 0),
		failedProxies:       make(map[string]time.Time),
		healthCheckInterval: healthCheckInterval,
		maxFailures:         maxFailures,
		logger:              logger,
		healthCheckStop:     make(chan struct{}),
		rng:                 rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	pm.initializeSources()
	return pm
}

func (pm *ProxyManager) AddProxy(proxy *Proxy) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if proxy == nil || proxy.URL == nil {
		return fmt.Errorf("proxy or proxy URL is nil")
	}

	for _, p := range pm.proxies {
		if p.URL.String() == proxy.URL.String() {
			return fmt.Errorf("proxy already exists")
		}
	}

	pm.proxies = append(pm.proxies, proxy)
	pm.activeProxies = append(pm.activeProxies, proxy)
	pm.logger.Debugf("Added proxy: %s", proxy.URL.String())
	return nil
}

func (pm *ProxyManager) RemoveProxy(proxyURL string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i, proxy := range pm.proxies {
		if proxy.URL.String() == proxyURL {
			pm.proxies = append(pm.proxies[:i], pm.proxies[i+1:]...)
			break
		}
	}

	for i, proxy := range pm.activeProxies {
		if proxy.URL.String() == proxyURL {
			pm.activeProxies = append(pm.activeProxies[:i], pm.activeProxies[i+1:]...)
			break
		}
	}

	delete(pm.failedProxies, proxyURL)
}

func (pm *ProxyManager) GetProxy(strategy RotationStrategy) (*Proxy, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.activeProxies) == 0 {
		return nil, fmt.Errorf("no active proxies available")
	}

	var p *Proxy
	switch strategy {
	case RoundRobin:
		p = pm.roundRobinProxy()
	case Random:
		p = pm.randomProxy()
	case LatencyBased:
		p = pm.latencyBasedProxy()
	case SuccessRateBased:
		p = pm.successRateBasedProxy()
	default:
		p = pm.roundRobinProxy()
	}
	if p != nil {
		p.LastUsed = time.Now()
	}
	return p, nil
}

func (pm *ProxyManager) roundRobinProxy() *Proxy {
	proxy := pm.activeProxies[pm.rotationIndex]
	pm.rotationIndex = (pm.rotationIndex + 1) % len(pm.activeProxies)
	return proxy
}

func (pm *ProxyManager) randomProxy() *Proxy {
	index := pm.rng.Intn(len(pm.activeProxies))
	return pm.activeProxies[index]
}

func (pm *ProxyManager) latencyBasedProxy() *Proxy {
	var best *Proxy
	for _, proxy := range pm.activeProxies {
		if best == nil || proxy.Latency < best.Latency {
			best = proxy
		}
	}
	return best
}

func (pm *ProxyManager) successRateBasedProxy() *Proxy {
	var best *Proxy
	for _, proxy := range pm.activeProxies {
		if best == nil || proxy.SuccessRate > best.SuccessRate {
			best = proxy
		}
	}
	return best
}

func (pm *ProxyManager) MarkSuccess(proxyURL string, latency time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, proxy := range pm.proxies {
		if proxy.URL.String() == proxyURL {
			if proxy.Latency == 0 {
				proxy.Latency = latency
			} else {
				proxy.Latency = time.Duration(0.7*float64(proxy.Latency) + 0.3*float64(latency))
			}
			proxy.SuccessRate = 0.95*proxy.SuccessRate + 0.05
			proxy.FailureCount = 0
			delete(pm.failedProxies, proxyURL)
			break
		}
	}
}

func (pm *ProxyManager) MarkFailure(proxyURL string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, proxy := range pm.proxies {
		if proxy.URL.String() == proxyURL {
			proxy.FailureCount++
			proxy.SuccessRate = 0.9 * proxy.SuccessRate

			if proxy.FailureCount >= pm.maxFailures {
				pm.failedProxies[proxyURL] = time.Now()
				for i, p := range pm.activeProxies {
					if p.URL.String() == proxyURL {
						pm.activeProxies = append(pm.activeProxies[:i], pm.activeProxies[i+1:]...)
						break
					}
				}
			}
			break
		}
	}
}

func (pm *ProxyManager) HealthCheck() {
	pm.mu.RLock()
	all := make([]*Proxy, len(pm.proxies))
	copy(all, pm.proxies)
	pm.mu.RUnlock()

	for _, proxy := range all {
		healthy := pm.isProxyHealthy(proxy)
		pm.mu.Lock()
		inActive := false
		for _, ap := range pm.activeProxies {
			if ap.URL.String() == proxy.URL.String() {
				inActive = true
				break
			}
		}
		if healthy && !inActive {
			pm.activeProxies = append(pm.activeProxies, proxy)
			delete(pm.failedProxies, proxy.URL.String())
			proxy.FailureCount = 0
		}
		if !healthy && inActive {
			for i, ap := range pm.activeProxies {
				if ap.URL.String() == proxy.URL.String() {
					pm.activeProxies = append(pm.activeProxies[:i], pm.activeProxies[i+1:]...)
					break
				}
			}
			pm.failedProxies[proxy.URL.String()] = time.Now()
		}
		proxy.LastChecked = time.Now()
		pm.mu.Unlock()
	}
}

func (pm *ProxyManager) isProxyHealthy(proxy *Proxy) bool {
	pm.mu.RLock()
	lastFail, inFailed := pm.failedProxies[proxy.URL.String()]
	pm.mu.RUnlock()
	if inFailed && time.Since(lastFail) < time.Hour {
		return false
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	transport := &http.Transport{}
	switch strings.ToLower(proxy.Type) {
	case "http", "https":
		transport.Proxy = http.ProxyURL(proxy.URL)
	case "socks5", "socks", "socks5h":
		dialer, err := xproxy.SOCKS5("tcp", proxy.URL.Host, nil, xproxy.Direct)
		if err != nil {
			pm.logger.Debugf("SOCKS dialer error for %s: %v", proxy.URL.String(), err)
			return false
		}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}
	default:
		transport.Proxy = http.ProxyURL(proxy.URL)
	}
	client.Transport = transport
	req, _ := http.NewRequest("GET", "https://www.gstatic.com/generate_204", nil)
	req.Header.Set("User-Agent", "SubLynx-ProxyHealth/1.0")
	resp, err := client.Do(req)
	if err != nil {
		pm.logger.Debugf("Health check failed for %s: %v", proxy.URL.String(), err)
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func (pm *ProxyManager) StartHealthChecks() {
	pm.mu.Lock()
	if pm.healthRunning {
		pm.mu.Unlock()
		return
	}
	pm.healthRunning = true
	interval := pm.healthCheckInterval
	stop := pm.healthCheckStop
	pm.mu.Unlock()

	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				pm.HealthCheck()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
}

func (pm *ProxyManager) StopHealthChecks() {
	pm.mu.Lock()
	if !pm.healthRunning {
		pm.mu.Unlock()
		return
	}
	pm.healthRunning = false
	close(pm.healthCheckStop)
	pm.healthCheckStop = make(chan struct{}) 
	pm.mu.Unlock()
}

func (pm *ProxyManager) RefreshProxies() error {
	var newProxies []*Proxy
	pm.mu.RLock()
	sources := make([]ProxySource, len(pm.proxySources))
	copy(sources, pm.proxySources)
	pm.mu.RUnlock()

	for _, source := range sources {
		proxies, err := source.GetProxies()
		if err != nil {
			pm.logger.Warnf("Failed to get proxies from %s: %v", source.Name(), err)
			continue
		}
		newProxies = append(newProxies, proxies...)
		time.Sleep(source.RateLimit())
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, p := range newProxies {
		exists := false
		for _, existing := range pm.proxies {
			if existing.URL.String() == p.URL.String() {
				exists = true
				break
			}
		}
		if !exists {
			pm.proxies = append(pm.proxies, p)
			pm.activeProxies = append(pm.activeProxies, p)
		}
	}

	pm.logger.Infof("Refreshed proxies. Total: %d, Active: %d", len(pm.proxies), len(pm.activeProxies))
	return nil
}


func (pm *ProxyManager) initializeSources() {
	pm.proxySources = []ProxySource{
		&PublicProxySource{},
		&PaidProxySource{},
		&InternalProxySource{},
	}
}

func (pm *ProxyManager) GetStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := map[string]interface{}{
		"total_proxies":  len(pm.proxies),
		"active_proxies": len(pm.activeProxies),
		"failed_proxies": len(pm.failedProxies),
		"proxy_sources":  len(pm.proxySources),
	}

	var totalSuccessRate float64
	var totalLatency time.Duration
	for _, proxy := range pm.proxies {
		totalSuccessRate += proxy.SuccessRate
		totalLatency += proxy.Latency
	}
	if n := len(pm.proxies); n > 0 {
		stats["avg_success_rate"] = totalSuccessRate / float64(n)
		stats["avg_latency"] = (totalLatency / time.Duration(n)).String()
	}

	return stats
}

type PublicProxySource struct{}

func (p *PublicProxySource) Name() string                 { return "public" }
func (p *PublicProxySource) GetProxies() ([]*Proxy, error) { return []*Proxy{}, nil }
func (p *PublicProxySource) RateLimit() time.Duration     { return 5 * time.Second }


type PaidProxySource struct{}

func (p *PaidProxySource) Name() string                 { return "paid" }
func (p *PaidProxySource) GetProxies() ([]*Proxy, error) { return []*Proxy{}, nil }
func (p *PaidProxySource) RateLimit() time.Duration     { return 1 * time.Second }


type InternalProxySource struct{}

func (p *InternalProxySource) Name() string                 { return "internal" }
func (p *InternalProxySource) GetProxies() ([]*Proxy, error) { return []*Proxy{}, nil }
func (p *InternalProxySource) RateLimit() time.Duration     { return 100 * time.Millisecond }

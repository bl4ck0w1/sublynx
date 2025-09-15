package proxies

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	xproxy "golang.org/x/net/proxy"
)


type ProxyRotator struct {
	manager        *ProxyManager
	strategy       RotationStrategy
	logger         *logrus.Logger
	mu             sync.RWMutex
	requestCount   map[string]int
	sessionProxies map[string]*Proxy 
}

func NewProxyRotator(manager *ProxyManager, strategy RotationStrategy, logger *logrus.Logger) *ProxyRotator {
	if logger == nil {
		logger = logrus.New()
	}

	return &ProxyRotator{
		manager:        manager,
		strategy:       strategy,
		logger:         logger,
		requestCount:   make(map[string]int),
		sessionProxies: make(map[string]*Proxy),
	}
}

func (pr *ProxyRotator) GetTransport(sessionID string) (*http.Transport, *Proxy, error) {
	proxy, err := pr.GetProxy(sessionID)
	if err != nil {
		return nil, nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, 
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	switch strings.ToLower(proxy.Type) {
	case "socks", "socks5", "socks5h":
		dialer, err := xproxy.SOCKS5("tcp", proxy.URL.Host, nil, xproxy.Direct)
		if err != nil {
			return nil, nil, err
		}
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}
	default:
		tr.Proxy = http.ProxyURL(proxy.URL)
	}

	if proxy.Credentials != nil {
		if tr.ProxyConnectHeader == nil {
			tr.ProxyConnectHeader = http.Header{}
		}
		tr.ProxyConnectHeader.Set("Proxy-Authorization",
			"Basic "+basicAuth(proxy.Credentials.Username, proxy.Credentials.Password))
	}

	return tr, proxy, nil
}

func (pr *ProxyRotator) GetProxy(sessionID string) (*Proxy, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if proxy, exists := pr.sessionProxies[sessionID]; exists {
		pr.requestCount[proxy.URL.String()]++
		return proxy, nil
	}

	proxy, err := pr.manager.GetProxy(pr.strategy)
	if err != nil {
		return nil, err
	}

	pr.sessionProxies[sessionID] = proxy
	pr.requestCount[proxy.URL.String()]++
	return proxy, nil
}

func (pr *ProxyRotator) RotateProxy(sessionID string) error {
	newProxy, err := pr.manager.GetProxy(pr.strategy)
	if err != nil {
		return err
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	if oldProxy, exists := pr.sessionProxies[sessionID]; exists {
		if cnt := pr.requestCount[oldProxy.URL.String()]; cnt > 0 {
			pr.requestCount[oldProxy.URL.String()] = cnt - 1
		}
	}
	pr.sessionProxies[sessionID] = newProxy
	pr.requestCount[newProxy.URL.String()]++

	pr.logger.Debugf("Rotated proxy for session %s to %s", sessionID, newProxy.URL.String())
	return nil
}

func (pr *ProxyRotator) MarkSuccess(sessionID string, latency time.Duration) {
	pr.mu.RLock()
	proxy, exists := pr.sessionProxies[sessionID]
	pr.mu.RUnlock()
	if exists {
		pr.manager.MarkSuccess(proxy.URL.String(), latency)
	}
}

func (pr *ProxyRotator) MarkFailure(sessionID string) {
	pr.mu.RLock()
	proxy, exists := pr.sessionProxies[sessionID]
	pr.mu.RUnlock()
	if exists {
		pr.manager.MarkFailure(proxy.URL.String())
		go func() { _ = pr.RotateProxy(sessionID) }()
	}
}

func (pr *ProxyRotator) SetStrategy(strategy RotationStrategy) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.strategy = strategy
}

func (pr *ProxyRotator) GetStrategy() RotationStrategy {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.strategy
}


func (pr *ProxyRotator) CleanupSessions(maxAge time.Duration) {
	// Implement if/when session timestamps are added
}

func (pr *ProxyRotator) GetStats() map[string]interface{} {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	return map[string]interface{}{
		"strategy":       pr.strategy.String(),
		"session_count":  len(pr.sessionProxies),
		"unique_proxies": len(pr.requestCount),
		"total_requests": pr.totalRequests(),
	}
}

func (pr *ProxyRotator) totalRequests() int {
	total := 0
	for _, count := range pr.requestCount {
		total += count
	}
	return total
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (rs RotationStrategy) String() string {
	switch rs {
	case RoundRobin:
		return "round_robin"
	case Random:
		return "random"
	case LatencyBased:
		return "latency_based"
	case SuccessRateBased:
		return "success_rate_based"
	default:
		return "unknown"
	}
}

package http

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type Prober struct {
	client            *http.Client
	timeout           time.Duration
	maxRedirects      int
	concurrency       int
	logger            *logrus.Logger
	mu                sync.RWMutex
	userAgents        []string
	evasionTechniques []EvasionTechnique
	proxyManager      ProxyManager
}

type EvasionTechnique struct {
	Name        string
	Description string
	Apply       func(*http.Request) error
}

type ProxyManager interface {
	GetProxy() (string, error)      
	RotateProxy() error
	GetStats() map[string]interface{}
}

func NewProber(timeout time.Duration, maxRedirects, concurrency int, proxyManager ProxyManager, logger *logrus.Logger) *Prober {
	if logger == nil {
		logger = logrus.New()
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		Proxy: func(req *http.Request) (*url.URL, error) {
			if proxyManager == nil {
				return http.ProxyFromEnvironment(req)
			}
			addr, err := proxyManager.GetProxy()
			if err != nil || addr == "" {
				return http.ProxyFromEnvironment(req)
			}
			u, err := url.Parse(addr)
			if err != nil {
				return nil, err
			}
			return u, nil
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}

	return &Prober{
		client:            client,
		timeout:           timeout,
		maxRedirects:      maxRedirects,
		concurrency:       concurrency,
		logger:            logger,
		userAgents:        loadUserAgents(),
		evasionTechniques: initializeEvasionTechniques(),
		proxyManager:      proxyManager,
	}
}

func (p *Prober) Probe(ctx context.Context, host string, protocols []string) (*models.HTTPResponse, error) {
	var results []*models.HTTPResponse
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	for _, protocol := range protocols {
		protocol := protocol
		g.Go(func() error {
			fullURL := fmt.Sprintf("%s://%s", protocol, host)
			resp, err := p.probeSingle(ctx, fullURL)
			if err != nil {
				p.logger.Debugf("Probe failed for %s: %v", fullURL, err)
				return nil 
			}
			mu.Lock()
			results = append(results, resp)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	for _, r := range results {
		if r != nil && r.StatusCode > 0 {
			return r, nil
		}
	}
	return nil, fmt.Errorf("all probe attempts failed for %s", host)
}

func (p *Prober) probeSingle(ctx context.Context, urlStr string) (*models.HTTPResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	p.applyEvasionTechniques(req)

	if p.proxyManager != nil {
		if err := p.rotateProxy(); err != nil {
			p.logger.Debugf("Failed to rotate proxy: %v", err)
		}
	}

	start := time.Now()
	resp, err := p.client.Do(req)
	rt := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	cl := resp.ContentLength
	if cl < 0 {
		cl = int64(len(body))
	}

	return &models.HTTPResponse{
		URL:           urlStr,
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Headers:       headers,
		Body:          string(body),
		ResponseTime:  rt,
		Protocol:      resp.Proto,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: cl,
		Timestamp:     time.Now(),
	}, nil
}

func (p *Prober) applyEvasionTechniques(req *http.Request) {
	req.Header.Set("User-Agent", p.getRandomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Cache-Control", "max-age=0")

	for _, t := range p.evasionTechniques {
		if err := t.Apply(req); err != nil {
			p.logger.Debugf("Failed to apply evasion technique %s: %v", t.Name, err)
		}
	}
}

func (p *Prober) getRandomUserAgent() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.userAgents) == 0 {
		return "SubNexus/1.0"
	}
	n, _ := crand.Int(crand.Reader, big.NewInt(int64(len(p.userAgents))))
	return p.userAgents[n.Int64()]
}

func (p *Prober) rotateProxy() error {
	if p.proxyManager == nil {
		return fmt.Errorf("proxy manager not configured")
	}
	return p.proxyManager.RotateProxy()
}

func (p *Prober) BatchProbe(ctx context.Context, hosts []string, protocols []string) ([]*models.HTTPResponse, error) {
	var results []*models.HTTPResponse
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(p.concurrency)

	for _, host := range hosts {
		host := host
		g.Go(func() error {
			resp, err := p.Probe(ctx, host, protocols)
			if err != nil {
				p.logger.Debugf("Batch probe failed for %s: %v", host, err)
				return nil 
			}
			mu.Lock()
			results = append(results, resp)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

func (p *Prober) SetTimeout(timeout time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timeout = timeout
	p.client.Timeout = timeout
}

func (p *Prober) SetMaxRedirects(maxRedirects int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxRedirects = maxRedirects
	p.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return nil
	}
}

func (p *Prober) GetStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := map[string]interface{}{
		"timeout":                   p.timeout.String(),
		"max_redirects":             p.maxRedirects,
		"concurrency":               p.concurrency,
		"user_agent_count":          len(p.userAgents),
		"evasion_techniques_count":  len(p.evasionTechniques),
	}
	if p.proxyManager != nil {
		out["proxy_stats"] = p.proxyManager.GetStats()
	}
	return out
}

func loadUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:124.0) Gecko/20100101 Firefox/124.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/124.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	}
}

func initializeEvasionTechniques() []EvasionTechnique {
	return []EvasionTechnique{
		{
			Name:        "Header Order Randomization",
			Description: "Randomizes the order of HTTP headers (limited effect in Go).",
			Apply: func(req *http.Request) error {
				return nil
			},
		},
		{
			Name:        "Case Variation",
			Description: "Varies the case of header names (Go may re-canonicalize).",
			Apply: func(req *http.Request) error {
				h := req.Header
				newH := make(http.Header, len(h))
				for k, v := range h {
					if time.Now().UnixNano()%2 == 0 {
						newH[strings.ToUpper(k)] = v
					} else {
						newH[strings.ToLower(k)] = v
					}
				}
				req.Header = newH
				return nil
			},
		},
		{
			Name:        "Fake Headers",
			Description: "Adds fake headers to confuse WAFs",
			Apply: func(req *http.Request) error {
				req.Header.Set("X-Forwarded-For", generateRandomIP())
				req.Header.Set("X-Real-IP", generateRandomIP())
				req.Header.Set("X-Request-ID", generateRandomString(16))
				req.Header.Set("X-Correlation-ID", generateRandomString(16))
				return nil
			},
		},
		{
			Name:        "HTTP Version Mixing",
			Description: "Uses different HTTP versions (transport negotiates h2/1.1).",
			Apply: func(req *http.Request) error {
				return nil
			},
		},
	}
}

func generateRandomIP() string {
	octet := func() int64 {
		n, _ := crand.Int(crand.Reader, big.NewInt(256))
		return n.Int64()
	}
	return fmt.Sprintf("%d.%d.%d.%d", octet(), octet(), octet(), octet())
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		n, _ := crand.Int(crand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

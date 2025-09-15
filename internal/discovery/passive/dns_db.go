package passive

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type PassiveDNSClient struct {
	clients      map[string]PDNSProvider
	rateLimiters map[string]*rate.Limiter
	httpClient   *http.Client
	logger       *logrus.Logger
	mu           sync.RWMutex
	apiKeys      map[string]string
	userAgent    string
}

type PDNSProvider interface {
	Name() string
	Query(ctx context.Context, httpClient *http.Client, domain string) ([]string, error)
	RateLimit() time.Duration
	RequiresAPIKey() bool
}

type DNSDBConfig struct {
	APIKey     string
	BaseURL    string
	RateLimit  time.Duration
	MaxResults int
}

type VirusTotalConfig struct {
	APIKey    string
	BaseURL   string
	RateLimit time.Duration
}

type SecurityTrailsConfig struct {
	APIKey    string
	BaseURL   string
	RateLimit time.Duration
}

type CIRCLConfig struct {
	Username  string
	Password  string
	BaseURL   string
	RateLimit time.Duration
}

func NewPassiveDNSClient(logger *logrus.Logger) *PassiveDNSClient {
	if logger == nil {
		logger = logrus.New()
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
	}

	return &PassiveDNSClient{
		clients:      make(map[string]PDNSProvider),
		rateLimiters: make(map[string]*rate.Limiter),
		httpClient:   httpClient,
		logger:       logger,
		apiKeys:      make(map[string]string),
		userAgent:    "SubLynx/1.0 PassiveDNS",
	}
}

func (p *PassiveDNSClient) AddProvider(provider PDNSProvider, apiKey string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	name := provider.Name()
	if _, exists := p.clients[name]; exists {
		return fmt.Errorf("provider %s already added", name)
	}

	if provider.RequiresAPIKey() && apiKey == "" {
		return fmt.Errorf("API key required for %s", name)
	}

	p.clients[name] = provider
	rlEvery := provider.RateLimit()
	if rlEvery <= 0 {
		rlEvery = 250 * time.Millisecond
	}
	p.rateLimiters[name] = rate.NewLimiter(rate.Every(rlEvery), 1)

	if provider.RequiresAPIKey() {
		p.apiKeys[name] = apiKey
	}

	p.logger.Infof("Added passive DNS provider: %s", name)
	return nil
}

func (p *PassiveDNSClient) QueryAll(ctx context.Context, domain string) ([]models.Subdomain, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var (
		mu      sync.Mutex
		results = make([]models.Subdomain, 0, 256)
		seen    = make(map[string]bool)
	)

	g, ctx := errgroup.WithContext(ctx)

	for name, provider := range p.clients {
		name := name
		provider := provider

		g.Go(func() error {
			if err := p.rateLimiters[name].Wait(ctx); err != nil {
				return err
			}

			subs, err := provider.Query(ctx, p.httpClient, domain)
			if err != nil {
				p.logger.Warnf("Passive DNS query failed for %s: %v", name, err)
				return nil 
			}

			now := time.Now()
			mu.Lock()
			for _, fqdn := range subs {
				fqdn = strings.TrimSuffix(strings.ToLower(fqdn), ".")
				if fqdn == "" || seen[fqdn] {
					continue
				}
				seen[fqdn] = true
				results = append(results, models.Subdomain{
					Name:         fqdn,
					Source:       name,
					DiscoveredAt: now,
					Confidence:   0.8,
				})
			}
			mu.Unlock()

			p.logger.Debugf("Provider %s returned %d unique subdomains", name, len(subs))
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

type DNSDBProvider struct {
	config *DNSDBConfig
}

func NewDNSDBProvider(config *DNSDBConfig) *DNSDBProvider {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.dnsdb.info" 
	}
	if config.RateLimit == 0 {
		config.RateLimit = 100 * time.Millisecond
	}
	if config.MaxResults == 0 {
		config.MaxResults = 1000
	}
	return &DNSDBProvider{config: config}
}

func (d *DNSDBProvider) Name() string { return "dnsdb" }
func (d *DNSDBProvider) RateLimit() time.Duration { return d.config.RateLimit }
func (d *DNSDBProvider) RequiresAPIKey() bool { return true }
func (d *DNSDBProvider) Query(ctx context.Context, httpClient *http.Client, domain string) ([]string, error) {
	escaped := url.PathEscape("*." + domain)
	u := fmt.Sprintf("%s/lookup/rrset/name/%s?limit=%d", strings.TrimRight(d.config.BaseURL, "/"), escaped, d.config.MaxResults)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("dnsdb: new request: %w", err)
	}
	req.Header.Set("Accept", "application/x-ndjson")
	req.Header.Set("X-API-Key", d.config.APIKey)
	req.Header.Set("User-Agent", "SubLynxs/1.0 PassiveDNS (dnsdb)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dnsdb: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("dnsdb: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	subdomains := make([]string, 0, 256)
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			RRName string `json:"rrname"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		rr := strings.TrimSuffix(strings.ToLower(row.RRName), ".")
		if rr == "" {
			continue
		}
		if rr == domain || !strings.HasSuffix(rr, "."+strings.ToLower(domain)) {
			continue
		}
		subdomains = append(subdomains, rr)
	}
	return subdomains, nil
}

type VirusTotalProvider struct {
	config *VirusTotalConfig
}

func NewVirusTotalProvider(config *VirusTotalConfig) *VirusTotalProvider {
	if config.BaseURL == "" {
		config.BaseURL = "https://www.virustotal.com/api/v3"
	}
	if config.RateLimit == 0 {
		config.RateLimit = 15 * time.Second
	}
	return &VirusTotalProvider{config: config}
}

func (v *VirusTotalProvider) Name() string                 { return "virustotal" }
func (v *VirusTotalProvider) RateLimit() time.Duration     { return v.config.RateLimit }
func (v *VirusTotalProvider) RequiresAPIKey() bool         { return true }
func (v *VirusTotalProvider) Query(ctx context.Context, httpClient *http.Client, domain string) ([]string, error) {
	base := strings.TrimRight(v.config.BaseURL, "/")
	u := fmt.Sprintf("%s/domains/%s/subdomains?limit=40", base, url.PathEscape(domain))

	collected := make([]string, 0, 128)
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("vt: new request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Apikey", v.config.APIKey)
		req.Header.Set("User-Agent", "SubLynx/1.0 PassiveDNS (virustotal)")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("vt: do request: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("vt: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var vt struct {
			Data []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if err := json.Unmarshal(body, &vt); err != nil {
			return nil, fmt.Errorf("vt: parse response: %w", err)
		}

		for _, d := range vt.Data {
			if d.Type == "domain" && strings.HasSuffix(strings.ToLower(d.ID), strings.ToLower(domain)) {
				collected = append(collected, strings.ToLower(strings.TrimSuffix(d.ID, ".")))
			}
		}

		if vt.Links.Next == "" {
			break
		}
		u = vt.Links.Next
	}
	return collected, nil
}

type SecurityTrailsProvider struct {
	config *SecurityTrailsConfig
}

func NewSecurityTrailsProvider(config *SecurityTrailsConfig) *SecurityTrailsProvider {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.securitytrails.com/v1"
	}
	if config.RateLimit == 0 {
		config.RateLimit = 1 * time.Second
	}
	return &SecurityTrailsProvider{config: config}
}

func (s *SecurityTrailsProvider) Name() string             { return "securitytrails" }
func (s *SecurityTrailsProvider) RateLimit() time.Duration { return s.config.RateLimit }
func (s *SecurityTrailsProvider) RequiresAPIKey() bool     { return true }

func (s *SecurityTrailsProvider) Query(ctx context.Context, httpClient *http.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("%s/domain/%s/subdomains", strings.TrimRight(s.config.BaseURL, "/"), url.PathEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("securitytrails: new request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("APIKEY", s.config.APIKey)
	req.Header.Set("User-Agent", "SubLynx/1.0 PassiveDNS (securitytrails)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("securitytrails: do request: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("securitytrails: parse: %w", err)
	}

	res := make([]string, 0, len(out.Subdomains))
	for _, label := range out.Subdomains {
		label = strings.ToLower(strings.Trim(label, "."))
		if label == "" {
			continue
		}
		res = append(res, label+"."+strings.ToLower(domain))
	}
	return res, nil
}

type CIRCLProvider struct {
	config *CIRCLConfig
}

func NewCIRCLProvider(config *CIRCLConfig) *CIRCLProvider {
	if config.BaseURL == "" {
		config.BaseURL = "https://www.circl.lu/pdns/query"
	}
	if config.RateLimit == 0 {
		config.RateLimit = 100 * time.Millisecond
	}
	return &CIRCLProvider{config: config}
}

func (c *CIRCLProvider) Name() string                 { return "circl" }
func (c *CIRCLProvider) RateLimit() time.Duration     { return c.config.RateLimit }
func (c *CIRCLProvider) RequiresAPIKey() bool         { return false }

func (c *CIRCLProvider) Query(ctx context.Context, httpClient *http.Client, domain string) ([]string, error) {
	u := fmt.Sprintf("%s/%s", strings.TrimRight(c.config.BaseURL, "/"), url.PathEscape(domain))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("circl: new request: %w", err)
	}
	req.SetBasicAuth(c.config.Username, c.config.Password)
	req.Header.Set("Accept", "application/x-ndjson, application/json")
	req.Header.Set("User-Agent", "SubLynx/1.0 PassiveDNS (circl)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("circl: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("circl: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	subdomains := make([]string, 0, 256)

	sc := bufio.NewScanner(resp.Body)
	var gotAny bool
	for sc.Scan() {
		gotAny = true
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row struct {
			RRName string `json:"rrname"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		rr := strings.TrimSuffix(strings.ToLower(row.RRName), ".")
		if rr == "" || rr == strings.ToLower(domain) {
			continue
		}
		if strings.HasSuffix(rr, "."+strings.ToLower(domain)) {
			subdomains = append(subdomains, rr)
		}
	}
	if err := sc.Err(); err == nil && gotAny {
		return subdomains, nil
	}
	return subdomains, nil
}

func (p *PassiveDNSClient) GetProviders() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	providers := make([]string, 0, len(p.clients))
	for name := range p.clients {
		providers = append(providers, name)
	}
	return providers
}

func (p *PassiveDNSClient) GetStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"providers":      len(p.clients),
		"provider_names": p.GetProviders(),
	}
}

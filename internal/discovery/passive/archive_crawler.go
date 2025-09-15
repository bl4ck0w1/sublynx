package passive

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type ArchiveCrawler struct {
	providers    map[string]ArchiveProvider
	rateLimiters map[string]*rate.Limiter
	httpClient   *http.Client
	logger       *logrus.Logger
	mu           sync.RWMutex
	userAgent    string
}

type ArchiveProvider interface {
	Name() string
	Query(ctx context.Context, httpClient *http.Client, domain string) ([]string, error)
	RateLimit() time.Duration
	RequiresAPIKey() bool
}

func NewArchiveCrawler(logger *logrus.Logger) *ArchiveCrawler {
	if logger == nil {
		logger = logrus.New()
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: true,
		MaxIdleConns:      200,
		IdleConnTimeout:   90 * time.Second,
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
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
	}

	return &ArchiveCrawler{
		providers:    make(map[string]ArchiveProvider),
		rateLimiters: make(map[string]*rate.Limiter),
		httpClient:   httpClient,
		logger:       logger,
		userAgent:    "SubNexus/1.0 ArchiveCrawler",
	}
}

func (c *ArchiveCrawler) AddProvider(p ArchiveProvider) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	name := p.Name()
	if _, ok := c.providers[name]; ok {
		return fmt.Errorf("archive provider %q already added", name)
	}

	c.providers[name] = p
	every := p.RateLimit()
	if every <= 0 {
		every = 250 * time.Millisecond
	}
	c.rateLimiters[name] = rate.NewLimiter(rate.Every(every), 1)

	c.logger.Infof("Added archive provider: %s", name)
	return nil
}

func (c *ArchiveCrawler) QueryAll(ctx context.Context, domain string) ([]models.Subdomain, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.providers) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var mu sync.Mutex
	out := make([]models.Subdomain, 0, 256)

	g, ctx := errgroup.WithContext(ctx)
	for name, provider := range c.providers {
		name := name
		provider := provider

		g.Go(func() error {
			if err := c.rateLimiters[name].Wait(ctx); err != nil {
				return err
			}

			subs, err := provider.Query(ctx, c.httpClient, domain)
			if err != nil {
				c.logger.Warnf("Archive provider %s query failed: %v", name, err)
				return nil // continue others
			}

			now := time.Now()
			mu.Lock()
			for _, fqdn := range subs {
				fqdn = strings.TrimSuffix(strings.ToLower(fqdn), ".")
				if fqdn == "" || !isSubdomainOf(fqdn, domain) || seen[fqdn] {
					continue
				}
				seen[fqdn] = true
				out = append(out, models.Subdomain{
					Name:         fqdn,
					Source:       name,
					DiscoveredAt: now,
					Confidence:   0.65,
				})
			}
			mu.Unlock()

			c.logger.Debugf("Archive provider %s returned %d unique", name, len(subs))
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *ArchiveCrawler) Providers() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.providers))
	for k := range c.providers {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

type WaybackConfig struct {
	BaseURL   string       
	RateLimit time.Duration 
	StatusFilter []string 
	BatchSize    int    
	MaxBatches   int     
}

type WaybackProvider struct {
	cfg WaybackConfig
}

func NewWaybackProvider(cfg WaybackConfig) *WaybackProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://web.archive.org/cdx/search/cdx"
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 500 * time.Millisecond
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 5000
	}
	return &WaybackProvider{cfg: cfg}
}

func (w *WaybackProvider) Name() string                 { return "wayback_cdx" }
func (w *WaybackProvider) RateLimit() time.Duration     { return w.cfg.RateLimit }
func (w *WaybackProvider) RequiresAPIKey() bool         { return false }
func (w *WaybackProvider) Query(ctx context.Context, httpClient *http.Client, domain string) ([]string, error) {

	params := url.Values{}
	params.Set("url", "*."+domain)
	params.Set("fl", "original")
	params.Set("collapse", "urlkey")
	params.Set("output", "json")

	if len(w.cfg.StatusFilter) > 0 {
		for _, s := range w.cfg.StatusFilter {
			params.Add("filter", "statuscode:"+s)
		}
	}

	subdomains := make([]string, 0, 256)
	offset := 0
	batches := 0

	for {
		params.Set("limit", fmt.Sprintf("%d", w.cfg.BatchSize))
		params.Set("offset", fmt.Sprintf("%d", offset))

		endpoint := w.cfg.BaseURL + "?" + params.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("wayback: new request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "SubNexus/1.0 ArchiveCrawler (wayback)")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("wayback: do: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("wayback: read: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			if len(subdomains) > 0 {
				return subdomains, nil
			}
			return nil, fmt.Errorf("wayback: status %d", resp.StatusCode)
		}

		var rows [][]string
		if err := json.Unmarshal(body, &rows); err != nil {
			return subdomains, nil
		}
		if len(rows) == 0 {
			break
		}

		added := 0
		for _, r := range rows {
			if len(r) == 0 {
				continue
			}
			orig := r[0]
			host := hostFromURL(orig)
			if host == "" {
				continue
			}
			if isSubdomainOf(host, domain) {
				subdomains = append(subdomains, strings.ToLower(host))
				added++
			}
		}

		if added == 0 || len(rows) < w.cfg.BatchSize {
			// No more pages
			break
		}

		offset += w.cfg.BatchSize
		batches++
		if w.cfg.MaxBatches > 0 && batches >= w.cfg.MaxBatches {
			break
		}
	}

	return subdomains, nil
}


type CCIndexConfig struct {
	BaseURL    string      
	Indexes    []string      
	LatestN    int           
	RateLimit  time.Duration 
	MaxPages   int           
	PageSize   int           
	StatusOnly string       
}

type CCIndexProvider struct {
	cfg CCIndexConfig
}

func NewCCIndexProvider(cfg CCIndexConfig) *CCIndexProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://index.commoncrawl.org"
	}
	if cfg.LatestN <= 0 {
		cfg.LatestN = 3
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 750 * time.Millisecond
	}
	return &CCIndexProvider{cfg: cfg}
}

func (p *CCIndexProvider) Name() string             { return "commoncrawl_cdx" }
func (p *CCIndexProvider) RateLimit() time.Duration { return p.cfg.RateLimit }
func (p *CCIndexProvider) RequiresAPIKey() bool     { return false }

func (p *CCIndexProvider) Query(ctx context.Context, httpClient *http.Client, domain string) ([]string, error) {
	indexes := p.cfg.Indexes
	if len(indexes) == 0 {
		var err error
		indexes, err = p.fetchLatestIndexes(ctx, httpClient, p.cfg.LatestN)
		if err != nil || len(indexes) == 0 {
			return nil, fmt.Errorf("cc: failed to get collinfo: %w", err)
		}
	}

	collected := make([]string, 0, 256)
	seen := make(map[string]bool)

	for _, idx := range indexes {
		for page := 0; ; page++ {
			if p.cfg.MaxPages > 0 && page >= p.cfg.MaxPages {
				break
			}

			params := url.Values{}
			params.Set("url", "*."+domain)
			params.Set("output", "json")
			params.Set("page", fmt.Sprintf("%d", page))
			if p.cfg.StatusOnly != "" {
				params.Add("filter", "status:"+p.cfg.StatusOnly)
			}

			u := fmt.Sprintf("%s/%s-index?%s", strings.TrimRight(p.cfg.BaseURL, "/"), idx, params.Encode())

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return collected, fmt.Errorf("cc: new request: %w", err)
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("User-Agent", "SubNexus/1.0 ArchiveCrawler (cc-index)")

			resp, err := httpClient.Do(req)
			if err != nil {
				return collected, fmt.Errorf("cc: do: %w", err)
			}
			if resp.StatusCode == http.StatusNotFound {
				resp.Body.Close()
				break
			}
			if resp.StatusCode != http.StatusOK {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				break
			}

			sc := bufio.NewScanner(resp.Body)
			lines := 0
			for sc.Scan() {
				lines++
				var row struct {
					URL string `json:"url"`
				}
				if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
					continue
				}
				host := hostFromURL(row.URL)
				if host == "" || !isSubdomainOf(host, domain) {
					continue
				}
				host = strings.ToLower(strings.TrimSuffix(host, "."))
				if !seen[host] {
					seen[host] = true
					collected = append(collected, host)
				}
			}
			resp.Body.Close()

			if lines == 0 {
				break
			}
		}
	}

	return collected, nil
}

func (p *CCIndexProvider) fetchLatestIndexes(ctx context.Context, httpClient *http.Client, n int) ([]string, error) {
	u := strings.TrimRight(p.cfg.BaseURL, "/") + "/collinfo.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SubNexus/1.0 ArchiveCrawler (cc-index)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no indexes")
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].ID > rows[j].ID })

	out := make([]string, 0, minInt(n, len(rows)))
	for i := 0; i < minInt(n, len(rows)); i++ {
		out = append(out, rows[i].ID)
	}
	return out, nil
}

func hostFromURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u == nil {
		if !strings.Contains(s, "://") {
			u2, err2 := url.Parse("http://" + s)
			if err2 == nil && u2 != nil {
				return u2.Host
			}
		}
		return ""
	}
	return u.Host
}

func isSubdomainOf(fqdn, targetDomain string) bool {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	targetDomain = strings.ToLower(strings.TrimSuffix(targetDomain, "."))

	if fqdn == "" || targetDomain == "" || fqdn == targetDomain {
		return false
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(targetDomain)
	if err == nil && etld1 != targetDomain {
		targetDomain = etld1
	}

	if !strings.HasSuffix(fqdn, "."+targetDomain) {
		return false
	}

	rest := strings.TrimSuffix(fqdn, "."+targetDomain)
	return rest != "" && !strings.HasPrefix(rest, ".") && !strings.HasSuffix(rest, ".")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

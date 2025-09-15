package passive

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type PassiveDiscoverer struct {
	dnsClient      *PassiveDNSClient
	archiveCrawler *ArchiveCrawler
	logger         *logrus.Logger
	mu             sync.RWMutex
}

func NewPassiveDiscoverer(logger *logrus.Logger) (*PassiveDiscoverer, error) {
	if logger == nil {
		logger = logrus.New()
	}
	dnsClient := NewPassiveDNSClient(logger)
	archiveCrawler := NewArchiveCrawler(logger)

	return &PassiveDiscoverer{
		dnsClient:      dnsClient,
		archiveCrawler: archiveCrawler,
		logger:         logger,
	}, nil
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
func getString(m map[string]any, key, def string) string {
	if m == nil {
		return def
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}
func getBool(m map[string]any, key string, def bool) bool {
	if m == nil {
		return def
	}
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}
func getInt(m map[string]any, key string, def int) int {
	if m == nil {
		return def
	}
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		}
	}
	return def
}
func getDuration(m map[string]any, key string, def time.Duration) time.Duration {
	if m == nil {
		return def
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(s); err == nil {
				return d
			}
		}
	}
	return def
}

func (p *PassiveDiscoverer) ConfigureDNSProviders(config map[string]any) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	if cfg := asMap(config["dnsdb"]); getBool(cfg, "enabled", false) {
		d := &DNSDBConfig{
			APIKey:     getString(cfg, "api_key", ""),
			BaseURL:    getString(cfg, "base_url", ""),
			RateLimit:  getDuration(cfg, "rate_limit", 100*time.Millisecond),
			MaxResults: getInt(cfg, "max_results", 1000),
		}
		if d.APIKey == "" {
			errs = append(errs, errors.New("dnsdb enabled but api_key missing"))
		} else {
			if err := p.dnsClient.AddProvider(NewDNSDBProvider(d), d.APIKey); err != nil {
				errs = append(errs, fmt.Errorf("dnsdb: %w", err))
			}
		}
	}

	if cfg := asMap(config["virustotal"]); getBool(cfg, "enabled", false) {
		v := &VirusTotalConfig{
			APIKey:    getString(cfg, "api_key", ""),
			BaseURL:   getString(cfg, "base_url", ""),
			RateLimit: getDuration(cfg, "rate_limit", 15*time.Second),
		}
		if v.APIKey == "" {
			errs = append(errs, errors.New("virustotal enabled but api_key missing"))
		} else {
			if err := p.dnsClient.AddProvider(NewVirusTotalProvider(v), v.APIKey); err != nil {
				errs = append(errs, fmt.Errorf("virustotal: %w", err))
			}
		}
	}

	if cfg := asMap(config["securitytrails"]); getBool(cfg, "enabled", false) {
		s := &SecurityTrailsConfig{
			APIKey:    getString(cfg, "api_key", ""),
			BaseURL:   getString(cfg, "base_url", ""),
			RateLimit: getDuration(cfg, "rate_limit", time.Second),
		}
		if s.APIKey == "" {
			errs = append(errs, errors.New("securitytrails enabled but api_key missing"))
		} else {
			if err := p.dnsClient.AddProvider(NewSecurityTrailsProvider(s), s.APIKey); err != nil {
				errs = append(errs, fmt.Errorf("securitytrails: %w", err))
			}
		}
	}

	if cfg := asMap(config["circl"]); getBool(cfg, "enabled", false) {
		c := &CIRCLConfig{
			Username:  getString(cfg, "username", ""),
			Password:  getString(cfg, "password", ""),
			BaseURL:   getString(cfg, "base_url", ""),
			RateLimit: getDuration(cfg, "rate_limit", 100*time.Millisecond),
		}
		if c.Username == "" || c.Password == "" {
			errs = append(errs, errors.New("circl enabled but username/password missing"))
		} else {
			if err := p.dnsClient.AddProvider(NewCIRCLProvider(c), ""); err != nil {
				errs = append(errs, fmt.Errorf("circl: %w", err))
			}
		}
	}

	if len(errs) > 0 {
		return joinErrors(errs)
	}
	return nil
}

func (p *PassiveDiscoverer) ConfigureArchiveServices(config map[string]any) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	if cfg := asMap(config["wayback"]); getBool(cfg, "enabled", false) {
		w := WaybackConfig{
			BaseURL:      getString(cfg, "base_url", ""),
			RateLimit:    getDuration(cfg, "rate_limit", 500*time.Millisecond),
			BatchSize:    getInt(cfg, "batch_size", 5000),
			MaxBatches:   getInt(cfg, "max_batches", 0),
			StatusFilter: nil,
		}
		if v, ok := cfg["status_filter"].([]any); ok {
			w.StatusFilter = make([]string, 0, len(v))
			for _, it := range v {
				if s, ok := it.(string); ok && s != "" {
					w.StatusFilter = append(w.StatusFilter, s)
				}
			}
		}
		if err := p.archiveCrawler.AddProvider(NewWaybackProvider(w)); err != nil {
			errs = append(errs, fmt.Errorf("wayback: %w", err))
		}
	}

	if cfg := asMap(config["commoncrawl"]); getBool(cfg, "enabled", false) {
		cc := CCIndexConfig{
			BaseURL:    getString(cfg, "base_url", ""),
			LatestN:    getInt(cfg, "latest_n", 3),
			RateLimit:  getDuration(cfg, "rate_limit", 750*time.Millisecond),
			MaxPages:   getInt(cfg, "max_pages", 0),
			PageSize:   getInt(cfg, "page_size", 0),
			StatusOnly: getString(cfg, "status_only", ""),
		}
		if v, ok := cfg["indexes"].([]any); ok {
			cc.Indexes = make([]string, 0, len(v))
			for _, it := range v {
				if s, ok := it.(string); ok && s != "" {
					cc.Indexes = append(cc.Indexes, s)
				}
			}
			sort.Strings(cc.Indexes)
		}
		if err := p.archiveCrawler.AddProvider(NewCCIndexProvider(cc)); err != nil {
			errs = append(errs, fmt.Errorf("commoncrawl: %w", err))
		}
	}

	if len(errs) > 0 {
		return joinErrors(errs)
	}
	return nil
}

func (p *PassiveDiscoverer) Discover(ctx context.Context, domain string) ([]models.Subdomain, error) {
	var (
		results []models.Subdomain
		mu      sync.Mutex
		wg      sync.WaitGroup
		errs    []error
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		dnsResults, err := p.dnsClient.QueryAll(ctx, domain)
		if err != nil {
			p.logger.Warnf("Passive DNS discovery failed: %v", err)
			errs = append(errs, err)
			return
		}
		mu.Lock()
		results = append(results, dnsResults...)
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		archiveResults, err := p.archiveCrawler.QueryAll(ctx, domain)
		if err != nil {
			p.logger.Warnf("Archive discovery failed: %v", err)
			errs = append(errs, err)
			return
		}
		mu.Lock()
		results = append(results, archiveResults...)
		mu.Unlock()
	}()

	wg.Wait()
	results = mergeAndDedupe(results)

	if len(errs) > 0 && len(results) == 0 {
		return nil, joinErrors(errs)
	}
	return results, nil
}

func (p *PassiveDiscoverer) GetStats() map[string]interface{} {
	dnsStats := p.dnsClient.GetStats()
	serviceNames := p.archiveCrawler.Providers()

	return map[string]interface{}{
		"dns_providers":    dnsStats,
		"archive_services": map[string]any{"services": len(serviceNames), "service_names": serviceNames},
		"total_sources":    dnsStats["providers"].(int) + len(serviceNames),
	}
}

func mergeAndDedupe(in []models.Subdomain) []models.Subdomain {
	if len(in) == 0 {
		return in
	}
	byName := make(map[string]models.Subdomain, len(in))
	for _, s := range in {
		key := strings.ToLower(strings.TrimSuffix(s.Name, "."))
		if key == "" {
			continue
		}
		if existing, ok := byName[key]; ok {
			if s.Confidence > existing.Confidence {
				byName[key] = s
			}
		} else {
			byName[key] = s
		}
	}
	out := make([]models.Subdomain, 0, len(byName))
	for _, v := range byName {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	msg := "multiple errors:"
	for _, e := range errs {
		msg += " " + e.Error() + ";"
	}
	return errors.New(msg)
}

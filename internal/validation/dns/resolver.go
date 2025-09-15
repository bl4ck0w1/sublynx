package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	mdns "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/idna"
	"golang.org/x/sync/errgroup"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type Resolver struct {
	servers     []string
	timeout     time.Duration
	maxRetries  int
	concurrency int
	udpClient *mdns.Client
	tcpClient *mdns.Client
	logger      *logrus.Logger
	mu          sync.RWMutex
	cache       *DNSCache
	rotateIndex int
}

type DNSCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
	defaultTTL time.Duration
}

type CacheEntry struct {
	Records    []models.DNSRecord
	Expiration time.Time
}

func NewResolver(servers []string, timeout time.Duration, maxRetries, concurrency int, logger *logrus.Logger) *Resolver {
	if logger == nil {
		logger = logrus.New()
	}
	if len(servers) == 0 {
		servers = getSystemResolvers()
	}

	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	if concurrency <= 0 {
		concurrency = 10
	}

	udp := &mdns.Client{
		Net:          "udp",
		Timeout:      timeout,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		UDPSize:      1232, 
	}
	tcp := &mdns.Client{
		Net:          "tcp",
		Timeout:      timeout,
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	return &Resolver{
		servers:     servers,
		timeout:     timeout,
		maxRetries:  maxRetries,
		concurrency: concurrency,
		udpClient:   udp,
		tcpClient:   tcp,
		logger:      logger,
		cache: &DNSCache{
			entries:    make(map[string]*CacheEntry),
			defaultTTL: 5 * time.Minute,
		},
	}
}

func (r *Resolver) Resolve(ctx context.Context, domain string, recordTypes []uint16) ([]models.DNSRecord, error) {
	asciiDomain, err := idna.ToASCII(strings.TrimSpace(domain))
	if err != nil || asciiDomain == "" {
		return nil, fmt.Errorf("invalid domain %q: %w", domain, err)
	}

	if cached := r.cache.Get(asciiDomain, recordTypes); cached != nil {
		return cached, nil
	}

	var results []models.DNSRecord
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(r.concurrency)

	for _, rt := range recordTypes {
		rt := rt
		g.Go(func() error {
			recs, err := r.resolveWithRetry(ctx, asciiDomain, rt)
			if err != nil {
				r.logger.Debugf("Failed to resolve %s type %d: %v", asciiDomain, rt, err)
				return nil 
			}
			mu.Lock()
			results = append(results, recs...)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	results = dedupeRecords(results)
	r.cache.Set(asciiDomain, recordTypes, results)

	return results, nil
}

func (r *Resolver) resolveWithRetry(ctx context.Context, domain string, recordType uint16) ([]models.DNSRecord, error) {
	retryHandler := NewRetryHandler(r.maxRetries, r.timeout, r.logger)

	var records []models.DNSRecord
	var lastErr error

	err := retryHandler.DoWithRetry(ctx, func() error {
		recs, err := r.resolveSingle(ctx, domain, recordType)
		if err != nil {
			lastErr = err
			return err
		}
		records = recs
		return nil
	})

	if err != nil {
		return nil, lastErr
	}
	return records, nil
}

func (r *Resolver) resolveSingle(ctx context.Context, domain string, recordType uint16) ([]models.DNSRecord, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(domain), recordType)
	msg.RecursionDesired = true
	msg.SetEdns0(1232, true)

	server := r.selectServer() 
	resp, _, err := r.udpClient.ExchangeContext(ctx, msg, server)
	if err != nil {
		return r.exchangeTCP(ctx, msg, server)
	}
	if resp == nil {
		return nil, fmt.Errorf("nil DNS response")
	}
	if resp.Truncated {
		return r.exchangeTCP(ctx, msg, server)
	}

	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: %s", mdns.RcodeToString[resp.Rcode])
	}

	return r.parseAnswers(resp.Answer, domain, recordType), nil
}

func (r *Resolver) exchangeTCP(ctx context.Context, msg *mdns.Msg, server string) ([]models.DNSRecord, error) {
	resp, _, err := r.tcpClient.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, fmt.Errorf("DNS TCP query failed: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("nil DNS TCP response")
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: %s", mdns.RcodeToString[resp.Rcode])
	}
	q := msg.Question[0]
	return r.parseAnswers(resp.Answer, strings.TrimSuffix(q.Name, "."), q.Qtype), nil
}

func (r *Resolver) parseAnswers(rrs []mdns.RR, domain string, recordType uint16) []models.DNSRecord {
	out := make([]models.DNSRecord, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		rec := r.parseDNSRecord(rr, domain, recordType)
		if rec != nil {
			out = append(out, *rec)
		}
	}
	return out
}

func (r *Resolver) parseDNSRecord(rr mdns.RR, domain string, recordType uint16) *models.DNSRecord {
	record := &models.DNSRecord{
		Domain: domain,
		Type:   mdns.TypeToString[recordType],
		TTL:    rr.Header().Ttl,
	}

	trimDot := func(s string) string { return strings.TrimSuffix(s, ".") }

	switch rr := rr.(type) {
	case *mdns.A:
		record.Value = rr.A.String()
	case *mdns.AAAA:
		record.Value = rr.AAAA.String()
	case *mdns.CNAME:
		record.Value = trimDot(rr.Target)
	case *mdns.MX:
		record.Value = fmt.Sprintf("%d %s", rr.Preference, trimDot(rr.Mx))
	case *mdns.TXT:
		record.Value = strings.Join(rr.Txt, " ")
	case *mdns.NS:
		record.Value = trimDot(rr.Ns)
	case *mdns.PTR:
		record.Value = trimDot(rr.Ptr)
	case *mdns.SRV:
		record.Value = fmt.Sprintf("%d %d %d %s", rr.Priority, rr.Weight, rr.Port, trimDot(rr.Target))
	case *mdns.SOA:
		record.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
			trimDot(rr.Ns), trimDot(rr.Mbox), rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
	default:
		r.logger.Debugf("Unhandled DNS record type: %T", rr)
		return nil
	}

	return record
}

func (r *Resolver) selectServer() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.servers) == 0 {
		r.servers = getSystemResolvers()
	}
	server := r.servers[r.rotateIndex%len(r.servers)]
	r.rotateIndex = (r.rotateIndex + 1) % len(r.servers)

	if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	}
	return server
}

func (r *Resolver) SetServers(servers []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.servers = servers
	r.rotateIndex = 0
}

func (r *Resolver) GetServers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cp := make([]string, len(r.servers))
	copy(cp, r.servers)
	return cp
}

func (r *Resolver) GetCache() *DNSCache { return r.cache }
func (r *Resolver) ClearCache() { r.cache.Clear() }
func getSystemResolvers() []string {
	cfg, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || cfg == nil || len(cfg.Servers) == 0 {
		return []string{
			"1.1.1.1:53",       
			"8.8.8.8:53",        
			"9.9.9.9:53",       
			"208.67.222.222:53", 
		}
	}
	servers := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		servers = append(servers, net.JoinHostPort(s, "53"))
	}
	return servers
}

func (c *DNSCache) Get(domain string, recordTypes []uint16) []models.DNSRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := generateCacheKey(domain, recordTypes)
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.Expiration) {
		return nil
	}
	out := make([]models.DNSRecord, len(entry.Records))
	copy(out, entry.Records)
	return out
}

func (c *DNSCache) Set(domain string, recordTypes []uint16, records []models.DNSRecord) {
	if len(records) == 0 {
		return
	}
	minTTL := c.defaultTTL
	for _, r := range records {
		if r.TTL > 0 {
			rt := time.Duration(r.TTL) * time.Second
			if rt < minTTL {
				minTTL = rt
			}
		}
	}
	if minTTL <= 0 {
		minTTL = c.defaultTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]*CacheEntry)
	}
	key := generateCacheKey(domain, recordTypes)
	c.entries[key] = &CacheEntry{
		Records:    append([]models.DNSRecord(nil), records...),
		Expiration: time.Now().Add(minTTL),
	}
}

func (c *DNSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

func (c *DNSCache) SetDefaultTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.defaultTTL = ttl
	c.mu.Unlock()
}

func (c *DNSCache) GetDefaultTTL() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.defaultTTL
}

func generateCacheKey(domain string, recordTypes []uint16) string {
	types := make([]string, 0, len(recordTypes))
	for _, rt := range recordTypes {
		types = append(types, mdns.TypeToString[rt])
	}
	sort.Strings(types) 
	return fmt.Sprintf("%s|%s", strings.ToLower(domain), strings.Join(types, ","))
}

func dedupeRecords(in []models.DNSRecord) []models.DNSRecord {
	if len(in) == 0 {
		return in
	}
	type key struct{ t, v string }
	seen := make(map[key]bool, len(in))
	out := make([]models.DNSRecord, 0, len(in))
	for _, r := range in {
		k := key{t: strings.ToUpper(r.Type), v: strings.ToLower(strings.TrimSpace(r.Value))}
		if !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}

package ctlogs

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"github.com/bl4ck0w1/sublynx/pkg/models" 
)


type Fetcher struct {
	clients    map[string]*client.LogClient
	logs       []models.CTLog
	rateLimit  *rate.Limiter
	logger     *logrus.Logger
	httpClient *http.Client
	mu         sync.RWMutex
}

func NewFetcher(logs []models.CTLog, logger *logrus.Logger) (*Fetcher, error) {
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
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	f := &Fetcher{
		clients:    make(map[string]*client.LogClient),
		rateLimit:  rate.NewLimiter(rate.Every(100*time.Millisecond), 10), 
		logger:     logger,
		httpClient: httpClient,
	}

	for _, lg := range logs {
		if err := f.AddLog(lg); err != nil {
			f.logger.Warnf("Failed to initialize CT log client for %s: %v", lg.URL, err)
		}
	}

	return f, nil
}

func (f *Fetcher) AddLog(lg models.CTLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	opts := jsonclient.Options{
		UserAgent: "SubLynx/1.0 CT Log Fetcher",
	}

	lc, err := client.New(lg.URL, f.httpClient, opts)
	if err != nil {
		return fmt.Errorf("failed to create CT log client: %w", err)
	}

	f.clients[lg.ID] = lc
	f.logs = append(f.logs, lg)
	return nil
}

func (f *Fetcher) GetEntries(ctx context.Context, domain string, startIndex, batchSize int64) ([]models.CTLogEntry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var results []models.CTLogEntry
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	for logID, lc := range f.clients {
		logID := logID
		lc := lc

		g.Go(func() error {
			if err := f.rateLimit.Wait(ctx); err != nil {
				return err
			}

			entries, err := f.getEntriesFromLog(ctx, lc, logID, domain, startIndex, batchSize)
			if err != nil {
				f.logger.Warnf("Failed to get entries from log %s: %v", logID, err)
				return nil
			}

			mu.Lock()
			results = append(results, entries...)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

func (f *Fetcher) getEntriesFromLog(ctx context.Context, lc *client.LogClient, logID, domain string, startIndex, batchSize int64) ([]models.CTLogEntry, error) {

	sth, err := lc.GetSTH(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get STH from log %s: %w", logID, err)
	}

	endIndex := startIndex + batchSize - 1
	maxIndex := int64(sth.TreeSize) - 1
	if endIndex > maxIndex {
		endIndex = maxIndex
	}
	if startIndex > endIndex {
		return nil, nil 
	}

	logEntries, err := lc.GetEntries(ctx, startIndex, endIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries from log %s: %w", logID, err)
	}

	var out []models.CTLogEntry
	for _, le := range logEntries {
		ctEntry, err := f.processEntry(ctx, le, logID, domain)
		if err != nil {
			f.logger.Debugf("Failed to process entry from log %s: %v", logID, err)
			continue
		}
		if ctEntry != nil {
			out = append(out, *ctEntry)
		}
	}

	return out, nil
}

func (f *Fetcher) processEntry(_ context.Context, entry ct.LogEntry, logID, targetDomain string) (*models.CTLogEntry, error) {
	var domains []string
	switch {
	case entry.X509Cert != nil:
		ds, err := extractDomainsFromX509(entry.X509Cert)
		if err != nil {
			return nil, fmt.Errorf("failed to extract from X509: %w", err)
		}
		domains = ds

	case entry.Precert != nil:
		pre, err := entry.Leaf.Precertificate()
		if err != nil {
			return nil, fmt.Errorf("failed to parse precertificate: %w", err)
		}
		ds, err := extractDomainsFromX509(pre)
		if err != nil {
			return nil, fmt.Errorf("failed to extract from precert: %w", err)
		}
		domains = ds

	default:
		return nil, nil
	}

	matching := filterDomains(domains, targetDomain)
	if len(matching) == 0 {
		return nil, nil
	}

	leafHash, err := ct.LeafHashForLeaf(&entry.Leaf)
	if err != nil {
		return nil, fmt.Errorf("failed to compute leaf hash: %w", err)
	}

	ts := ct.TimestampToTime(entry.Leaf.TimestampedEntry.Timestamp)

	return &models.CTLogEntry{
		LogID:            logID,
		Timestamp:        ts,
		Domain:           targetDomain,
		Subdomains:       matching,
		CertificateHash:  hex.EncodeToString(leafHash[:]),
		ValidationStatus: "pending",
	}, nil
}

func extractDomainsFromX509(cert *ctX509.Certificate) ([]string, error) {
	if cert == nil {
		return nil, fmt.Errorf("nil certificate")
	}

	var out []string
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		out = append(out, cn)
	}
	for _, dns := range cert.DNSNames {
		if dns = strings.TrimSpace(dns); dns != "" {
			out = append(out, dns)
		}
	}
	return out, nil
}

func filterDomains(domains []string, targetDomain string) []string {
	var result []string
	for _, d := range domains {
		if isSubdomainOf(d, targetDomain) {
			result = append(result, d)
		}
	}
	return result
}

func isSubdomainOf(domain, targetDomain string) bool {
	normalize := func(s string) (string, error) {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, ".")
		if strings.HasPrefix(s, "*.") {
			s = strings.TrimPrefix(s, "*.")
		}
		p := idna.New(idna.MapForLookup(), idna.RemoveLeadingDots(true))
		ascii, err := p.ToASCII(s)
		if err != nil {
			return "", err
		}
		return strings.ToLower(ascii), nil
	}

	d, err1 := normalize(domain)
	t, err2 := normalize(targetDomain)
	if err1 != nil || err2 != nil || d == "" || t == "" {
		return false
	}

	if ps, _ := publicsuffix.PublicSuffix(t); ps == t {
		return false
	}

	if d == t {
		return false
	}

	if !strings.HasSuffix(d, "."+t) {
		return false
	}

	return true
}

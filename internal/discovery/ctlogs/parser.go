package ctlogs

import (
	"context"
	"crypto/sha256"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	ct "github.com/google/certificate-transparency-go"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type Parser struct {
	logger        *logrus.Logger
	knownLogs     map[string]models.CTLog
	domainFilters []string
}

func NewParser(knownLogs []models.CTLog, logger *logrus.Logger) *Parser {
	logsMap := make(map[string]models.CTLog, len(knownLogs))
	for _, lg := range knownLogs {
		logsMap[lg.ID] = lg
	}
	if logger == nil {
		logger = logrus.New()
	}
	return &Parser{
		logger:    logger,
		knownLogs: logsMap,
	}
}

func (p *Parser) ParseAndValidate(ctx context.Context, rawData []byte) (*models.CTLogEntry, error) { 
	var leafEntry ct.LeafEntry
	if err := json.Unmarshal(rawData, &leafEntry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal leaf entry: %w", err)
	}

	ci, err := ct.LeafEntryToCertInfo(leafEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf entry: %w", err)
	}

	ctEntry := &models.CTLogEntry{
		Timestamp: ct.TimestampToTime(ci.Leaf.TimestampedEntry.Timestamp),
		RawEntry:  rawData,
	}

	var (
		domains []string
		cert    *ctx509.Certificate
	)
	switch ci.Type {
	case ct.X509LogEntryType:
		cert, err = ci.X509Cert.ToX509()
		if err != nil {
			return nil, fmt.Errorf("failed to convert X509 cert: %w", err)
		}
		domains = p.extractDomainsFromCert(cert)

	case ct.PrecertLogEntryType:
		cert, err = ci.Precert.ToX509()
		if err != nil {
			return nil, fmt.Errorf("failed to convert precert: %w", err)
		}
		domains = p.extractDomainsFromCert(cert)

	default:
		return nil, fmt.Errorf("unknown log entry type: %v", ci.Type)
	}

	certHash := sha256.Sum256(cert.Raw)
	ctEntry.CertificateHash = hex.EncodeToString(certHash[:])

	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		ctEntry.Issuer = cert.Issuer.Organization[0]
	} else if cert.Issuer.CommonName != "" {
		ctEntry.Issuer = cert.Issuer.CommonName
	}

	ctEntry.Subdomains = p.filterRelevantDomains(domains)
	if len(ctEntry.Subdomains) > 0 {
		ctEntry.Domain = p.extractRootDomain(ctEntry.Subdomains[0])
	}

	ctEntry.ValidationStatus = p.validateCertificate(cert)

	return ctEntry, nil
}

func (p *Parser) extractDomainsFromCert(cert *ctx509.Certificate) []string {
	set := make(map[string]struct{}, 1+len(cert.DNSNames))

	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		set[strings.ToLower(cn)] = struct{}{}
	}

	for _, d := range cert.DNSNames {
		if d = strings.TrimSpace(d); d != "" {
			set[strings.ToLower(d)] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	return out
}

func (p *Parser) filterRelevantDomains(domains []string) []string {
	if len(p.domainFilters) == 0 {
		out := make([]string, len(domains))
		copy(out, domains)
		return out
	}

	var result []string
	for _, d := range domains {
		for _, f := range p.domainFilters {
			if strings.EqualFold(d, f) || isSubdomainOf(d, f) {
				result = append(result, d)
				break
			}
		}
	}
	return result
}

func (p *Parser) extractRootDomain(domain string) string {
	etld1, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), "."))
	if err != nil || etld1 == "" {
		return domain
	}
	return etld1
}

func (p *Parser) validateCertificate(cert *ctx509.Certificate) string {
	now := time.Now().UTC()

	if now.After(cert.NotAfter) {
		return "expired"
	}
	if now.Before(cert.NotBefore) {
		return "not_yet_valid"
	}

	if cert.PublicKeyAlgorithm == ctx509.RSA {
		if pk, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if pk.N.BitLen() < 2048 {
				return "weak_key"
			}
		} else {
			return "unknown_rsa_key"
		}
	}

	switch cert.SignatureAlgorithm {
	case ctx509.MD2WithRSA, ctx509.MD5WithRSA, ctx509.SHA1WithRSA,
		ctx509.DSAWithSHA1, ctx509.ECDSAWithSHA1, ctx509.SHA1WithRSA, ctx509.SHA1WithRSA: 
		return "weak_signature"
	}

	return "valid"
}

func (p *Parser) SetDomainFilters(filters []string) {
	p.domainFilters = filters
}

func (p *Parser) BatchParse(ctx context.Context, rawEntries [][]byte) ([]models.CTLogEntry, error) {
	results := make([]models.CTLogEntry, 0, len(rawEntries))
	errCount := 0

	for _, raw := range rawEntries {
		entry, err := p.ParseAndValidate(ctx, raw)
		if err != nil {
			errCount++
			continue
		}
		if entry != nil && len(entry.Subdomains) > 0 {
			results = append(results, *entry)
		}
	}

	if errCount > 0 {
		p.logger.Warnf("Encountered %d errors during batch parsing", errCount)
	}
	return results, nil
}

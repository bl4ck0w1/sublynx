package dns

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type RecordAnalyzer struct {
	logger       *logrus.Logger
	ipReputation IPReputationChecker
	spfRegex     *regexp.Regexp
	dkimRegex    *regexp.Regexp
	dmarcRegex   *regexp.Regexp
}

type IPReputationChecker interface {
	CheckIP(ip string) (float64, error)
}
func NewRecordAnalyzer(ipReputation IPReputationChecker, logger *logrus.Logger) *RecordAnalyzer {
	if logger == nil {
		logger = logrus.New()
	}
	spfRegex := regexp.MustCompile(`(?i)\bv=spf1\b`)
	dkimRegex := regexp.MustCompile(`(?i)\bv=DKIM1\b`)
	dmarcRegex := regexp.MustCompile(`(?i)\bv=DMARC1\b`)

	return &RecordAnalyzer{
		logger:       logger,
		ipReputation: ipReputation,
		spfRegex:     spfRegex,
		dkimRegex:    dkimRegex,
		dmarcRegex:   dmarcRegex,
	}
}

func (r *RecordAnalyzer) AnalyzeRecords(records []models.DNSRecord) *models.DNSAnalysis {
	analysis := &models.DNSAnalysis{
		Records:         records,
		AnalyzedAt:      time.Now(),
		Findings:        make([]models.DNSFinding, 0),
		RecordTypes:     make(map[string]int),
		ConfidenceScore: 0,
	}

	for _, record := range records {
		analysis.RecordTypes[record.Type]++
	}
	r.analyzeRecordConsistency(analysis)
	r.analyzeIPAddresses(analysis)
	r.analyzeEmailSecurity(analysis)
	r.analyzeDNSSEC(analysis)
	r.analyzeSubdomainTakeover(analysis)

	analysis.ConfidenceScore = r.calculateConfidenceScore(analysis)

	return analysis
}

func (r *RecordAnalyzer) analyzeRecordConsistency(analysis *models.DNSAnalysis) {
	aRecords := make(map[string]int)
	aaaaRecords := make(map[string]int)

	for _, record := range analysis.Records {
		switch record.Type {
		case "A":
			aRecords[record.Value]++
		case "AAAA":
			aaaaRecords[record.Value]++
		}
	}

	for value, count := range aRecords {
		if count > 1 {
			analysis.Findings = append(analysis.Findings, models.DNSFinding{
				Type:        "duplicate_a_record",
				Severity:    models.SeverityLow,
				Description: fmt.Sprintf("Multiple A records point to %s", value),
				Confidence:  0.9,
			})
		}
	}

	for value, count := range aaaaRecords {
		if count > 1 {
			analysis.Findings = append(analysis.Findings, models.DNSFinding{
				Type:        "duplicate_aaaa_record",
				Severity:    models.SeverityLow,
				Description: fmt.Sprintf("Multiple AAAA records point to %s", value),
				Confidence:  0.9,
			})
		}
	}

	cnameDomains := make(map[string]bool)
	otherRecords := make(map[string]bool)

	for _, record := range analysis.Records {
		if record.Type == "CNAME" {
			cnameDomains[record.Domain] = true
		} else {
			otherRecords[record.Domain] = true
		}
	}

	for domain := range cnameDomains {
		if otherRecords[domain] {
			analysis.Findings = append(analysis.Findings, models.DNSFinding{
				Type:        "cname_conflict",
				Severity:    models.SeverityMedium,
				Description: fmt.Sprintf("Domain %s has CNAME and other record types", domain),
				Confidence:  0.95,
			})
		}
	}
}

func (r *RecordAnalyzer) analyzeIPAddresses(analysis *models.DNSAnalysis) {
	for _, record := range analysis.Records {
		if record.Type != "A" && record.Type != "AAAA" {
			continue
		}
		ipStr := strings.TrimSpace(record.Value)
		if ipStr == "" {
			continue
		}
		ipAddr := net.ParseIP(ipStr)
		if ipAddr == nil {
			continue
		}

		if ipAddr.IsPrivate() {
			analysis.Findings = append(analysis.Findings, models.DNSFinding{
				Type:        "private_ip",
				Severity:    models.SeverityLow,
				Description: fmt.Sprintf("Record points to private IP: %s", ipStr),
				Confidence:  1.0,
			})
		}
		if ipAddr.IsLoopback() {
			analysis.Findings = append(analysis.Findings, models.DNSFinding{
				Type:        "loopback_ip",
				Severity:    models.SeverityLow,
				Description: fmt.Sprintf("Record points to loopback IP: %s", ipStr),
				Confidence:  1.0,
			})
		}
		if ip := ipAddr.To4(); ip == nil && ipAddr.IsLinkLocalUnicast() {
			analysis.Findings = append(analysis.Findings, models.DNSFinding{
				Type:        "link_local_ipv6",
				Severity:    models.SeverityLow,
				Description: fmt.Sprintf("Record points to link-local address: %s", ipStr),
				Confidence:  0.9,
			})
		}

		if r.ipReputation != nil {
			score, err := r.ipReputation.CheckIP(ipStr)
			if err != nil {
				r.logger.Debugf("Failed to check IP reputation for %s: %v", ipStr, err)
			} else if score < 0.3 {
				analysis.Findings = append(analysis.Findings, models.DNSFinding{
					Type:        "low_reputation_ip",
					Severity:    models.SeverityHigh,
					Description: fmt.Sprintf("IP %s has low reputation score: %.2f", ipStr, score),
					Confidence:  0.8,
				})
			}
		}
	}
}

func (r *RecordAnalyzer) analyzeEmailSecurity(analysis *models.DNSAnalysis) {
	hasSPF := false
	hasDKIM := false
	hasDMARC := false

	for _, record := range analysis.Records {
		if record.Type == "TXT" {
			if r.spfRegex.MatchString(record.Value) {
				hasSPF = true
				r.analyzeSPFRecord(record.Value, analysis)
			}
			if r.dkimRegex.MatchString(record.Value) {
				hasDKIM = true
			}

			if r.dmarcRegex.MatchString(record.Value) {
				hasDMARC = true
				r.analyzeDMARCRecord(record.Value, analysis)
			}
		}

		if record.Type == "MX" {
			r.analyzeMXRecord(record.Value, analysis)
		}
	}

	if !hasSPF {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "missing_spf",
			Severity:    models.SeverityMedium,
			Description: "No SPF record found for domain",
			Confidence:  0.9,
		})
	}

	if !hasDKIM {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "missing_dkim",
			Severity:    models.SeverityMedium,
			Description: "No DKIM record found for domain",
			Confidence:  0.9,
		})
	}

	if !hasDMARC {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "missing_dmarc",
			Severity:    models.SeverityMedium,
			Description: "No DMARC record found for domain",
			Confidence:  0.9,
		})
	}
}

func (r *RecordAnalyzer) analyzeSPFRecord(spf string, analysis *models.DNSAnalysis) {
	s := strings.ToLower(spf)

	if strings.Contains(s, "+all") {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "spf_too_permissive",
			Severity:    models.SeverityMedium,
			Description: "SPF record uses +all (too permissive)",
			Confidence:  0.9,
		})
	}

	if strings.Contains(s, "?all") {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "spf_neutral",
			Severity:    models.SeverityLow,
			Description: "SPF record uses ?all (neutral)",
			Confidence:  0.9,
		})
	}

	if !strings.Contains(s, "-all") && !strings.Contains(s, "~all") {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "spf_missing_fail",
			Severity:    models.SeverityMedium,
			Description: "SPF record missing -all or ~all (fail mechanism)",
			Confidence:  0.8,
		})
	}
}

func (r *RecordAnalyzer) analyzeDMARCRecord(dmarc string, analysis *models.DNSAnalysis) {
	s := strings.ToLower(dmarc)

	if !strings.Contains(s, "p=reject") && !strings.Contains(s, "p=quarantine") {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "dmarc_too_weak",
			Severity:    models.SeverityMedium,
			Description: "DMARC policy is too weak (should be reject or quarantine)",
			Confidence:  0.8,
		})
	}

	if !strings.Contains(s, "rua=") {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "dmarc_no_aggregate_reports",
			Severity:    models.SeverityLow,
			Description: "DMARC record missing aggregate reports (rua)",
			Confidence:  0.7,
		})
	}

	if !strings.Contains(s, "ruf=") {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "dmarc_no_forensic_reports",
			Severity:    models.SeverityLow,
			Description: "DMARC record missing forensic reports (ruf)",
			Confidence:  0.7,
		})
	}
}

func (r *RecordAnalyzer) analyzeMXRecord(mx string, analysis *models.DNSAnalysis) {
	if strings.HasPrefix(mx, "0 ") {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "mx_priority_zero",
			Severity:    models.SeverityLow,
			Description: "MX record with priority 0: " + mx,
			Confidence:  0.8,
		})
	}

	parts := strings.Split(mx, " ")
	if len(parts) >= 2 {
		mxDomain := parts[1]
		for _, record := range analysis.Records {
			if record.Type == "A" && strings.HasSuffix(mxDomain, record.Domain) {
				analysis.Findings = append(analysis.Findings, models.DNSFinding{
					Type:        "mx_self_reference",
					Severity:    models.SeverityLow,
					Description: "MX record points to same domain: " + mx,
					Confidence:  0.7,
				})
				break
			}
		}
	}
}

func (r *RecordAnalyzer) analyzeDNSSEC(analysis *models.DNSAnalysis) {
	hasDNSKEY := false
	hasRRSIG := false
	hasDS := false

	for _, record := range analysis.Records {
		switch record.Type {
		case "DNSKEY":
			hasDNSKEY = true
		case "RRSIG":
			hasRRSIG = true
		case "DS":
			hasDS = true
		}
	}

	if hasDNSKEY && hasRRSIG {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "dnssec_configured",
			Severity:    models.SeverityInfo,
			Description: "DNSSEC is properly configured",
			Confidence:  0.9,
		})
	} else if hasDS && !hasDNSKEY {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "dnssec_misconfigured",
			Severity:    models.SeverityMedium,
			Description: "DS record found but no DNSKEY (DNSSEC misconfiguration)",
			Confidence:  0.8,
		})
	} else {
		analysis.Findings = append(analysis.Findings, models.DNSFinding{
			Type:        "dnssec_not_configured",
			Severity:    models.SeverityLow,
			Description: "DNSSEC is not configured",
			Confidence:  0.9,
		})
	}
}

func (r *RecordAnalyzer) analyzeSubdomainTakeover(analysis *models.DNSAnalysis) {
	vulnerableServices := map[string]string{
		".github.io":             "GitHub Pages",
		".herokuapp.com":         "Heroku",
		".azurewebsites.net":     "Azure App Services",
		".cloudapp.net":          "Azure Cloud Services",
		".elasticbeanstalk.com":  "AWS Elastic Beanstalk",
		".s3.amazonaws.com":      "AWS S3",
		".cloudfront.net":        "AWS CloudFront",
		".readthedocs.io":        "ReadTheDocs",
		".wordpress.com":         "WordPress",
		".pantheonsite.io":       "Pantheon",
		".zendesk.com":           "Zendesk",
		".surge.sh":              "Surge",
		".fastly.net":            "Fastly",
	}

	for _, record := range analysis.Records {
		if record.Type != "CNAME" {
			continue
		}
		for pattern, service := range vulnerableServices {
			if strings.HasSuffix(strings.ToLower(record.Value), pattern) {
				analysis.Findings = append(analysis.Findings, models.DNSFinding{
					Type:        "potential_subdomain_takeover",
					Severity:    models.SeverityHigh,
					Description: fmt.Sprintf("Potential %s subdomain takeover: %s", service, record.Value),
					Confidence:  0.7,
				})
			}
		}
	}
}

func (r *RecordAnalyzer) calculateConfidenceScore(analysis *models.DNSAnalysis) float64 {
	score := 1.0

	for _, finding := range analysis.Findings {
		switch finding.Severity {
		case models.SeverityCritical:
			score -= 0.2
		case models.SeverityHigh:
			score -= 0.1
		case models.SeverityMedium:
			score -= 0.05
		case models.SeverityLow:
			score -= 0.02
		case models.SeverityInfo:
			// Informational
		}
		score -= (1 - finding.Confidence) * 0.05
	}

	if score < 0 {
		score = 0
	} else if score > 1 {
		score = 1
	}
	return score
}

func (r *RecordAnalyzer) SortFindingsBySeverity(analysis *models.DNSAnalysis) {
	sort.Slice(analysis.Findings, func(i, j int) bool {
		return analysis.Findings[i].Severity > analysis.Findings[j].Severity
	})
}

func (r *RecordAnalyzer) FilterFindingsBySeverity(analysis *models.DNSAnalysis, minSeverity models.SeverityLevel) []models.DNSFinding {
	var filtered []models.DNSFinding
	for _, finding := range analysis.Findings {
		if finding.Severity >= minSeverity {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func (r *RecordAnalyzer) GetSummary(analysis *models.DNSAnalysis) string {
	critical, high, medium, low, info := 0, 0, 0, 0, 0
	for _, f := range analysis.Findings {
		switch f.Severity {
		case models.SeverityCritical:
			critical++
		case models.SeverityHigh:
			high++
		case models.SeverityMedium:
			medium++
		case models.SeverityLow:
			low++
		case models.SeverityInfo:
			info++
		}
	}
	return fmt.Sprintf(
		"DNS Analysis: %d critical, %d high, %d medium, %d low, %d info findings. Confidence: %.2f",
		critical, high, medium, low, info, analysis.ConfidenceScore,
	)
}

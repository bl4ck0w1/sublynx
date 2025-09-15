package reporting

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"github.com/bl4ck0w1/sublynx/pkg/models"
	"github.com/bl4ck0w1/sublynx/internal/reporting/formatters"
)

type ReportGenerator struct {
	formatters  map[string]Formatter
	logger      *logrus.Logger
	mu          sync.RWMutex
	config      ReportConfig
	templateMgr *TemplateManager
	riskScorer  *RiskScorer
}

type Formatter interface {
	Format(report *ComprehensiveReport) ([]byte, error)
	FileExtension() string
}

type ReportConfig struct {
	OutputDir          string                 `yaml:"output_dir" json:"output_dir"`
	DefaultFormat      string                 `yaml:"default_format" json:"default_format"`
	IncludeRawData     bool                   `yaml:"include_raw_data" json:"include_raw_data"`
	RiskScoreThreshold float64                `yaml:"risk_score_threshold" json:"risk_score_threshold"`
	MaxReportAge       time.Duration          `yaml:"max_report_age" json:"max_report_age"`
	AutoCleanup        bool                   `yaml:"auto_cleanup" json:"auto_cleanup"`
	CompressReports    bool                   `yaml:"compress_reports" json:"compress_reports"`
	RiskWeights        map[string]float64     `yaml:"risk_weights" json:"risk_weights"`
}

type ComprehensiveReport struct {
	Metadata        ReportMetadata           `json:"metadata" yaml:"metadata"`
	Summary         ReportSummary            `json:"summary" yaml:"summary"`
	Subdomains      []models.Subdomain       `json:"subdomains" yaml:"subdomains"`
	Findings        []models.Finding         `json:"findings" yaml:"findings"`
	Recommendations []SecurityRecommendation `json:"recommendations" yaml:"recommendations"`
	RawData         interface{}              `json:"raw_data,omitempty" yaml:"raw_data,omitempty"`
	GeneratedAt     time.Time                `json:"generated_at" yaml:"generated_at"`
}

type ReportMetadata struct {
	ReportID     string    `json:"report_id" yaml:"report_id"`
	ScanID       string    `json:"scan_id" yaml:"scan_id"`
	TargetDomain string    `json:"target_domain" yaml:"target_domain"`
	GeneratedBy  string    `json:"generated_by" yaml:"generated_by"`
	ToolVersion  string    `json:"tool_version" yaml:"tool_version"`
	Duration     string    `json:"duration" yaml:"duration"`
	Timestamp    time.Time `json:"timestamp" yaml:"timestamp"`
}

type ReportSummary struct {
	TotalSubdomains    int     `json:"total_subdomains" yaml:"total_subdomains"`
	ActiveSubdomains   int     `json:"active_subdomains" yaml:"active_subdomains"`
	TotalFindings      int     `json:"total_findings" yaml:"total_findings"`
	CriticalFindings   int     `json:"critical_findings" yaml:"critical_findings"`
	HighRiskFindings   int     `json:"high_risk_findings" yaml:"high_risk_findings"`
	MediumRiskFindings int     `json:"medium_risk_findings" yaml:"medium_risk_findings"`
	LowRiskFindings    int     `json:"low_risk_findings" yaml:"low_risk_findings"`
	RiskScore          float64 `json:"risk_score" yaml:"risk_score"`
}

type SecurityRecommendation struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Description string   `json:"description" yaml:"description"`
	Severity    string   `json:"severity" yaml:"severity"`
	Affected    []string `json:"affected" yaml:"affected"`
	Remediation string   `json:"remediation" yaml:"remediation"`
	References  []string `json:"references" yaml:"references"`
	Priority    int      `json:"priority" yaml:"priority"`
}

func NewReportGenerator(config ReportConfig, logger *logrus.Logger) (*ReportGenerator, error) {
	if logger == nil {
		logger = logrus.New()
	}

	if err := os.MkdirAll(config.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	rg := &ReportGenerator{
		formatters:  make(map[string]Formatter),
		logger:      logger,
		config:      config,
		templateMgr: NewTemplateManager(),
		riskScorer: NewRiskScorerWithWeights(config.RiskWeights),
	}

	rg.RegisterFormatter("txt", &formatters.TXTFormatter{})
	rg.RegisterFormatter("csv", &formatters.CSVFormatter{})
	rg.RegisterFormatter("json", &formatters.JSONFormatter{})
	rg.RegisterFormatter("yaml", &formatters.YAMLFormatter{})

	if config.AutoCleanup {
		go rg.cleanupOldReports()
	}

	return rg, nil
}

func (rg *ReportGenerator) RegisterFormatter(name string, formatter Formatter) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.formatters[name] = formatter
}

func (rg *ReportGenerator) SupportedFormats() []string {
	rg.mu.RLock()
	defer rg.mu.RUnlock()
	names := make([]string, 0, len(rg.formatters))
	for k := range rg.formatters {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (rg *ReportGenerator) GenerateReport(
	metadata ReportMetadata,
	subdomains []models.Subdomain,
	findings []models.Finding,
) (*ComprehensiveReport, error) {
	startTime := time.Now()
	scoredFindings := rg.riskScorer.ScoreFindings(findings)
	summary := rg.generateSummary(subdomains, scoredFindings)
	recommendations := rg.generateRecommendations(scoredFindings, subdomains)
	report := &ComprehensiveReport{
		Metadata:        metadata,
		Summary:         summary,
		Subdomains:      subdomains,
		Findings:        scoredFindings,
		Recommendations: recommendations,
		GeneratedAt:     time.Now(),
	}

	if rg.config.IncludeRawData {
		report.RawData = rg.collectRawData(subdomains, findings)
	}

	rg.logger.Infof("Report generated in %v", time.Since(startTime))
	return report, nil
}

func (rg *ReportGenerator) generateSummary(subdomains []models.Subdomain, findings []models.Finding) ReportSummary {
	summary := ReportSummary{
		TotalSubdomains: len(subdomains),
	}

	for _, sd := range subdomains {
		if sd.Status == "active" {
			summary.ActiveSubdomains++
		}
	}

	summary.TotalFindings = len(findings)
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			summary.CriticalFindings++
		case "high":
			summary.HighRiskFindings++
		case "medium":
			summary.MediumRiskFindings++
		case "low":
			summary.LowRiskFindings++
		}
	}

	summary.RiskScore = rg.riskScorer.CalculateOverallRiskScore(findings)
	return summary
}

func (rg *ReportGenerator) generateRecommendations(findings []models.Finding, _ []models.Subdomain) []SecurityRecommendation {
	var recs []SecurityRecommendation

	groups := make(map[string][]models.Finding)
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			groups[f.Type] = append(groups[f.Type], f)
		}
	}

	for ftype, gf := range groups {
		rec := SecurityRecommendation{
			ID:          fmt.Sprintf("rec_%s_%d", ftype, time.Now().Unix()),
			Title:       rg.getRecommendationTitle(ftype),
			Description: rg.getRecommendationDescription(ftype),
			Severity:    gf[0].Severity,
			Remediation: rg.getRemediationSteps(ftype),
			Priority:    rg.getPriority(ftype),
			References:  rg.getReferences(ftype),
		}
		seen := make(map[string]struct{})
		for _, f := range gf {
			if _, ok := seen[f.Target]; ok {
				continue
			}
			seen[f.Target] = struct{}{}
			rec.Affected = append(rec.Affected, f.Target)
		}

		recs = append(recs, rec)
	}

	sort.Slice(recs, func(i, j int) bool { return recs[i].Priority > recs[j].Priority })
	return recs
}

func (rg *ReportGenerator) getRecommendationTitle(findingType string) string {
	titles := map[string]string{
		"ssl_issue":             "SSL/TLS Configuration Issues",
		"cve_vulnerability":     "Critical Vulnerability Detected",
		"misconfiguration":      "Security Misconfiguration",
		"information_disclosure":"Information Disclosure Vulnerability",
		"default_credentials":   "Default Credentials in Use",
		"outdated_software":     "Outdated Software Detected",
	}
	if t, ok := titles[findingType]; ok {
		return t
	}
	return "Security Issue Requires Attention"
}

func (rg *ReportGenerator) getRecommendationDescription(findingType string) string {
	descriptions := map[string]string{
		"ssl_issue":             "SSL/TLS configuration issues were detected that could allow attackers to intercept or decrypt sensitive information.",
		"cve_vulnerability":     "Critical vulnerabilities were detected that could allow remote code execution or system compromise.",
		"misconfiguration":      "Security misconfigurations were found that could expose sensitive data or system functionality.",
		"information_disclosure":"Information disclosure vulnerabilities were found that could expose sensitive system information.",
		"default_credentials":   "Systems were found using default credentials that could be easily compromised.",
		"outdated_software":     "Outdated software versions were detected that contain known vulnerabilities.",
	}
	if d, ok := descriptions[findingType]; ok {
		return d
	}
	return "A security issue was detected that requires attention to prevent potential compromise."
}

func (rg *ReportGenerator) getRemediationSteps(findingType string) string {
	rem := map[string]string{
		"ssl_issue":             "Update SSL/TLS configuration to use strong ciphers, disable outdated protocols, and ensure certificates are valid and properly configured.",
		"cve_vulnerability":     "Apply security patches immediately. If no patch is available, implement compensating controls and monitor for exploitation attempts.",
		"misconfiguration":      "Review and harden system configuration according to security best practices and industry standards.",
		"information_disclosure":"Limit information disclosure through proper configuration of servers and applications.",
		"default_credentials":   "Change default credentials to strong, unique passwords and implement multi-factor authentication where possible.",
		"outdated_software":     "Update to the latest supported version of the software and apply all security patches.",
	}
	if r, ok := rem[findingType]; ok {
		return r
	}
	return "Investigate the specific finding and implement appropriate security controls based on the nature of the issue."
}

func (rg *ReportGenerator) getPriority(findingType string) int {
	p := map[string]int{
		"ssl_issue":             2,
		"cve_vulnerability":     1,
		"misconfiguration":      2,
		"information_disclosure":3,
		"default_credentials":   1,
		"outdated_software":     2,
	}
	if v, ok := p[findingType]; ok {
		return v
	}
	return 3
}

func (rg *ReportGenerator) getReferences(findingType string) []string {
	refs := map[string][]string{
		"ssl_issue": {
			"https://ssl-config.mozilla.org/",
			"https://www.ssllabs.com/ssltest/",
		},
		"cve_vulnerability": {
			"https://nvd.nist.gov/vuln/detail/",
			"https://cve.mitre.org/",
		},
		"misconfiguration": {
			"https://owasp.org/www-project-top-ten/",
			"https://www.cisecurity.org/benchmarks/",
		},
	}
	if r, ok := refs[findingType]; ok {
		return r
	}
	return []string{"https://owasp.org/www-project-top-ten/"}
}

func (rg *ReportGenerator) collectRawData(subdomains []models.Subdomain, findings []models.Finding) interface{} {
	return map[string]interface{}{
		"subdomains":   subdomains,
		"findings":     findings,
		"collected_at": time.Now(),
	}
}

func (rg *ReportGenerator) ExportReport(report *ComprehensiveReport, format string) (string, error) {
	rg.mu.RLock()
	formatter, exists := rg.formatters[format]
	rg.mu.RUnlock()
	if !exists {
		return "", fmt.Errorf("unsupported report format: %s", format)
	}

	data, err := formatter.Format(report)
	if err != nil {
		return "", fmt.Errorf("failed to format report: %w", err)
	}

	filename := rg.generateFilename(report.Metadata, format)

	if err := os.MkdirAll(rg.config.OutputDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to ensure output dir: %w", err)
	}
	outPath := filepath.Join(rg.config.OutputDir, filename)

	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	if rg.config.CompressReports {
		compressedPath, cerr := rg.compressReport(outPath)
		if cerr != nil {
			rg.logger.Warnf("Failed to compress report: %v", cerr)
		} else {
			_ = os.Remove(outPath)
			outPath = compressedPath
		}
	}

	rg.logger.Infof("Report exported to %s", outPath)
	return outPath, nil
}

func (rg *ReportGenerator) GenerateAndExport(
	metadata ReportMetadata,
	subs []models.Subdomain,
	finds []models.Finding,
	format string,
) (string, error) {
	rep, err := rg.GenerateReport(metadata, subs, finds)
	if err != nil {
		return "", err
	}
	if format == "" {
		format = rg.config.DefaultFormat
	}
	return rg.ExportReport(rep, format)
}

func (rg *ReportGenerator) generateFilename(metadata ReportMetadata, format string) string {
	tstamp := metadata.Timestamp.Format("20060102_150405")
	domain := sanitizeFilename(metadata.TargetDomain)
	return fmt.Sprintf("sublynx_%s_%s.%s", domain, tstamp, format)
}

func (rg *ReportGenerator) compressReport(path string) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()

	dstPath := path + ".gz"
	dst, err := os.Create(dstPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = dst.Close() }()

	gw := gzip.NewWriter(dst)
	gw.Name = filepath.Base(path)
	gw.ModTime = time.Now()

	_, copyErr := io.Copy(gw, src)
	closeErr := gw.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return dstPath, nil
}

func (rg *ReportGenerator) cleanupOldReports() {
	ticker := time.NewTicker(24 * time.Hour) 
	defer ticker.Stop()

	for range ticker.C {
		rg.mu.RLock()
		maxAge := rg.config.MaxReportAge
		outputDir := rg.config.OutputDir
		rg.mu.RUnlock()

		if maxAge == 0 {
			return
		}

		files, err := os.ReadDir(outputDir)
		if err != nil {
			rg.logger.Warnf("Failed to read output directory: %v", err)
			continue
		}

		cutoff := time.Now().Add(-maxAge)
		for _, f := range files {
			info, err := f.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				p := filepath.Join(outputDir, f.Name())
				if err := os.Remove(p); err != nil {
					rg.logger.Warnf("Failed to remove old report %s: %v", f.Name(), err)
				} else {
					rg.logger.Infof("Removed old report: %s", f.Name())
				}
			}
		}
	}
}

func (rg *ReportGenerator) GetReportStats() (map[string]interface{}, error) {
	rg.mu.RLock()
	defer rg.mu.RUnlock()

	files, err := os.ReadDir(rg.config.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read output directory: %w", err)
	}

	stats := map[string]interface{}{
		"total_reports": len(files),
		"output_dir":    rg.config.OutputDir,
	}

	formatCounts := make(map[string]int)
	for _, f := range files {
		ext := filepath.Ext(f.Name())
		if ext != "" {
			format := ext[1:] 
			formatCounts[format]++
		}
	}
	stats["formats"] = formatCounts
	return stats, nil
}

func (rg *ReportGenerator) LoadConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg ReportConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	rg.mu.Lock()
	rg.config = cfg
	rg.riskScorer = NewRiskScorerWithWeights(cfg.RiskWeights)
	rg.mu.Unlock()
	return nil
}

func (rg *ReportGenerator) SaveConfig(configPath string) error {
	rg.mu.RLock()
	cfg := rg.config
	rg.mu.RUnlock()

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

func sanitizeFilename(s string) string {
	var out []rune
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

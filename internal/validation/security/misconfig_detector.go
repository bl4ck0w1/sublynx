package security

import (
	"strings"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type MisconfigDetector struct {
	rules        []MisconfigRule
	logger       *logrus.Logger
	mu           sync.RWMutex
	ruleSeverity map[string]models.SeverityLevel
}

type MisconfigRule struct {
	ID          string
	Category    string
	Description string
	Check       func(*models.SystemConfig) bool
	Severity    models.SeverityLevel
}

func NewMisconfigDetector(logger *logrus.Logger) *MisconfigDetector {
	if logger == nil {
		logger = logrus.New()
	}

	md := &MisconfigDetector{
		logger: logger,
		ruleSeverity: map[string]models.SeverityLevel{
			"default-credentials": models.SeverityCritical,
			"weak-crypto":         models.SeverityHigh,
			"exposed-services":    models.SeverityMedium,
			"info-disclosure":     models.SeverityLow,
		},
	}

	md.initializeRules()

	return md
}

func (m *MisconfigDetector) initializeRules() {
	m.rules = []MisconfigRule{
		{
			ID:          "default-credentials",
			Category:    "Authentication",
			Description: "Default credentials are in use",
			Check:       m.checkDefaultCredentials,
			Severity:    models.SeverityCritical,
		},
		{
			ID:          "weak-ciphers",
			Category:    "Cryptography",
			Description: "Weak cryptographic ciphers are enabled",
			Check:       m.checkWeakCiphers,
			Severity:    models.SeverityHigh,
		},
		{
			ID:          "weak-protocols",
			Category:    "Protocols",
			Description: "Weak protocols are enabled",
			Check:       m.checkWeakProtocols,
			Severity:    models.SeverityHigh,
		},
		{
			ID:          "no-encryption",
			Category:    "Data Protection",
			Description: "Data is transmitted without encryption",
			Check:       m.checkNoEncryption,
			Severity:    models.SeverityHigh,
		},
		{
			ID:          "exposed-admin",
			Category:    "Access Control",
			Description: "Administrative interfaces are exposed",
			Check:       m.checkExposedAdminInterfaces,
			Severity:    models.SeverityHigh,
		},
		{
			ID:          "info-disclosure",
			Category:    "Information Disclosure",
			Description: "Sensitive information is exposed",
			Check:       m.checkInformationDisclosure,
			Severity:    models.SeverityMedium,
		},
		{
			ID:          "no-auth",
			Category:    "Authentication",
			Description: "No authentication required",
			Check:       m.checkNoAuthentication,
			Severity:    models.SeverityHigh,
		},
		{
			ID:          "debug-enabled",
			Category:    "Development",
			Description: "Debug features are enabled",
			Check:       m.checkDebugEnabled,
			Severity:    models.SeverityMedium,
		},
		{
			ID:          "directory-listing",
			Category:    "Web Security",
			Description: "Directory listing is enabled",
			Check:       m.checkDirectoryListing,
			Severity:    models.SeverityLow,
		},
		{
			ID:          "missing-headers",
			Category:    "Web Security",
			Description: "Security headers are missing",
			Check:       m.checkMissingSecurityHeaders,
			Severity:    models.SeverityLow,
		},
	}
}

func (m *MisconfigDetector) DetectMisconfigurations(config *models.SystemConfig) *models.MisconfigReport {
	if config == nil {
		return &models.MisconfigReport{
			AnalyzedAt: time.Now(),
			Findings:   make([]models.MisconfigFinding, 0),
		}
	}
	m.mu.RLock()
	rules := make([]MisconfigRule, len(m.rules))
	copy(rules, m.rules)
	m.mu.RUnlock()

	report := &models.MisconfigReport{
		SystemConfig: *config,
		AnalyzedAt:   time.Now(),
		Findings:     make([]models.MisconfigFinding, 0),
	}

	for _, rule := range rules {
		if rule.Check(config) {
			finding := models.MisconfigFinding{
				RuleID:      rule.ID,
				Category:    rule.Category,
				Description: rule.Description,
				Severity:    rule.Severity,
				Confidence:  0.9, 
			}
			report.Findings = append(report.Findings, finding)
		}
	}

	report.RiskScore = m.calculateRiskScore(report)

	return report
}

func (m *MisconfigDetector) checkDefaultCredentials(config *models.SystemConfig) bool {
	defaultCredentials := map[string][]string{
		"admin": {"admin", "password", "123456", "admin123"},
		"root":  {"root", "toor", "password", "123456"},
		"user":  {"user", "password", "123456"},
		"guest": {"guest", "guest", "password"},
	}

	for _, account := range config.Accounts {
		for user, passwords := range defaultCredentials {
			if strings.EqualFold(account.Username, user) {
				for _, password := range passwords {
					if account.Password == password {
						return true
					}
				}
			}
		}
	}

	return false
}

func (m *MisconfigDetector) checkWeakCiphers(config *models.SystemConfig) bool {
	weakCiphers := []string{
		"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "SHA1",
	}

	for _, service := range config.Services {
		for _, cipher := range service.Ciphers {
			up := strings.ToUpper(cipher)
			for _, weakCipher := range weakCiphers {
				if strings.Contains(up, weakCipher) {
					return true
				}
			}
		}
	}

	return false
}

func (m *MisconfigDetector) checkWeakProtocols(config *models.SystemConfig) bool {
	weakProtocols := []string{
		"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1",
	}

	for _, service := range config.Services {
		for _, protocol := range service.Protocols {
			for _, weakProtocol := range weakProtocols {
				if strings.EqualFold(protocol, weakProtocol) {
					return true
				}
			}
		}
	}

	return false
}

func (m *MisconfigDetector) checkNoEncryption(config *models.SystemConfig) bool {
	for _, service := range config.Services {
		if service.UnencryptedData {
			return true
		}
	}
	return false
}

func (m *MisconfigDetector) checkExposedAdminInterfaces(config *models.SystemConfig) bool {
	adminInterfaces := []string{
		"admin", "administrator", "manager", "console", "dashboard",
		"control", "config", "configuration", "settings", "login",
	}

	for _, service := range config.Services {
		name := strings.ToLower(service.Name)
		for _, adminInterface := range adminInterfaces {
			if strings.Contains(name, adminInterface) && service.ExposedPublicly {
				return true
			}
		}
	}

	return false
}

func (m *MisconfigDetector) checkInformationDisclosure(config *models.SystemConfig) bool {
	for _, service := range config.Services {
		if service.Headers != nil {
			if v, ok := headerValue(service.Headers, "Server"); ok {
				if strings.Contains(v, "/") {
					return true
				}
			}
			if v, ok := headerValue(service.Headers, "X-Powered-By"); ok && v != "" {
				return true
			}
		}
		if service.VerboseErrors {
			return true
		}
	}

	return false
}

func (m *MisconfigDetector) checkNoAuthentication(config *models.SystemConfig) bool {
	for _, service := range config.Services {
		if service.AllowAnonymousAccess && service.SensitiveData {
			return true
		}
	}
	return false
}

func (m *MisconfigDetector) checkDebugEnabled(config *models.SystemConfig) bool {
	for _, service := range config.Services {
		if service.DebugEnabled {
			return true
		}
	}
	return false
}

func (m *MisconfigDetector) checkDirectoryListing(config *models.SystemConfig) bool {
	for _, service := range config.Services {
		if service.DirectoryListingEnabled {
			return true
		}
	}
	return false
}

func (m *MisconfigDetector) checkMissingSecurityHeaders(config *models.SystemConfig) bool {
	securityHeaders := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",     
		"Content-Security-Policy",
	}

	for _, service := range config.Services {
		if service.Headers == nil {
			return true
		}
		for _, h := range securityHeaders {
			if !headerExists(service.Headers, h) {
				return true
			}
		}
	}

	return false
}

func (m *MisconfigDetector) calculateRiskScore(report *models.MisconfigReport) float64 {
	score := 0.0
	totalWeight := 0.0

	for _, finding := range report.Findings {
		weight := 0.0
		switch finding.Severity {
		case models.SeverityCritical:
			weight = 1.0
		case models.SeverityHigh:
			weight = 0.8
		case models.SeverityMedium:
			weight = 0.5
		case models.SeverityLow:
			weight = 0.2
		default:
			weight = 0.1
		}

		score += weight * finding.Confidence
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0.0
	}

	return score / totalWeight
}

func (m *MisconfigDetector) AddRule(rule MisconfigRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = append(m.rules, rule)
}

func (m *MisconfigDetector) RemoveRule(ruleID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, rule := range m.rules {
		if rule.ID == ruleID {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			break
		}
	}
}

func (m *MisconfigDetector) GetRules() []MisconfigRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]MisconfigRule, len(m.rules))
	copy(out, m.rules)
	return out
}

func (m *MisconfigDetector) SetRuleSeverity(ruleID string, severity models.SeverityLevel) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ruleSeverity[ruleID] = severity
	for i, rule := range m.rules {
		if rule.ID == ruleID {
			m.rules[i].Severity = severity
		}
	}
}

func (m *MisconfigDetector) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"rule_count": len(m.rules),
		"categories": m.getRuleCategories(),
	}
}

func (m *MisconfigDetector) getRuleCategories() []string {
	categories := make(map[string]bool)
	for _, rule := range m.rules {
		categories[rule.Category] = true
	}

	result := make([]string, 0, len(categories))
	for category := range categories {
		result = append(result, category)
	}
	return result
}

func (m *MisconfigDetector) BatchDetect(configs []*models.SystemConfig) ([]*models.MisconfigReport, error) {
	var reports []*models.MisconfigReport
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, cfg := range configs {
		wg.Add(1)
		go func(config *models.SystemConfig) {
			defer wg.Done()
			report := m.DetectMisconfigurations(config)
			mu.Lock()
			reports = append(reports, report)
			mu.Unlock()
		}(cfg)
	}

	wg.Wait()
	return reports, nil
}

func headerExists(headers map[string]string, name string) bool {
	_, ok := headerValue(headers, name)
	return ok
}

func headerValue(headers map[string]string, name string) (string, bool) {
	lname := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == lname {
			return v, true
		}
	}
	return "", false
}

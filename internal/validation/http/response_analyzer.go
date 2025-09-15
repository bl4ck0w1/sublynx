package http

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type ResponseAnalyzer struct {
	logger               *logrus.Logger
	mu                   sync.RWMutex
	deadPagePatterns     []*regexp.Regexp
	errorPagePatterns    []*regexp.Regexp
	hashDB               *HashDatabase
	similarityThreshold  float64
}

type HashDatabase struct {
	hashes map[string]string
	mu     sync.RWMutex
}

var (
	reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

func NewResponseAnalyzer(similarityThreshold float64, logger *logrus.Logger) *ResponseAnalyzer {
	if logger == nil {
		logger = logrus.New()
	}
	if similarityThreshold <= 0 {
		similarityThreshold = 0.9
	}
	deadPagePatterns := compileDeadPagePatterns()
	errorPagePatterns := compileErrorPagePatterns()

	return &ResponseAnalyzer{
		logger:            logger,
		deadPagePatterns:  deadPagePatterns,
		errorPagePatterns: errorPagePatterns,
		hashDB: &HashDatabase{
			hashes: make(map[string]string),
		},
		similarityThreshold: similarityThreshold,
	}
}

func (r *ResponseAnalyzer) AnalyzeResponse(response *models.HTTPResponse) *models.HTTPAnalysis {
	analysis := &models.HTTPAnalysis{
		Response:   response,
		AnalyzedAt: time.Now(),
		Findings:   make([]models.HTTPFinding, 0),
	}

	r.analyzeStatusCode(analysis)
	r.analyzeHeaders(analysis)
	r.analyzeContent(analysis)
	r.analyzeDeadPage(analysis)
	r.analyzeSimilarity(analysis)
	r.analyzeSecurityHeaders(analysis)
	r.analyzeServerTechnology(analysis)
	analysis.ConfidenceScore = r.calculateConfidenceScore(analysis)

	return analysis
}

func (r *ResponseAnalyzer) analyzeStatusCode(analysis *models.HTTPAnalysis) {
	statusCode := analysis.Response.StatusCode

	switch {
	case statusCode >= 200 && statusCode < 300:
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "success_status",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Success status code: %d", statusCode),
			Confidence:  1.0,
		})
	case statusCode >= 300 && statusCode < 400:
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "redirect_status",
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("Redirect status code: %d", statusCode),
			Confidence:  1.0,
		})
	case statusCode >= 400 && statusCode < 500:
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "client_error",
			Severity:    models.SeverityMedium,
			Description: fmt.Sprintf("Client error status code: %d", statusCode),
			Confidence:  1.0,
		})
	case statusCode >= 500:
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "server_error",
			Severity:    models.SeverityMedium,
			Description: fmt.Sprintf("Server error status code: %d", statusCode),
			Confidence:  1.0,
		})
	}
}

func (r *ResponseAnalyzer) analyzeHeaders(analysis *models.HTTPAnalysis) {
	headers := analysis.Response.Headers

	if server, exists := headers["Server"]; exists && server != "" {
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "server_header",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Server: %s", server),
			Confidence:  0.9,
		})
		analysis.Server = server
	}
	if poweredBy, exists := headers["X-Powered-By"]; exists && poweredBy != "" {
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "powered_by_header",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Powered by: %s", poweredBy),
			Confidence:  0.9,
		})
	}

	if contentType, exists := headers["Content-Type"]; exists && contentType != "" {
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "content_type",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Content type: %s", contentType),
			Confidence:  1.0,
		})
		analysis.ContentType = contentType
	}
}

func (r *ResponseAnalyzer) analyzeContent(analysis *models.HTTPAnalysis) {
	content := analysis.Response.Body
	hash := r.calculateContentHash(content)
	analysis.ContentHash = hash
	for _, pattern := range r.errorPagePatterns {
		if pattern.MatchString(content) {
			analysis.Findings = append(analysis.Findings, models.HTTPFinding{
				Type:        "error_page_content",
				Severity:    models.SeverityMedium,
				Description: fmt.Sprintf("Error page content detected: %s", pattern.String()),
				Confidence:  0.8,
			})
			break
		}
	}

	if titleMatch := reTitle.FindStringSubmatch(content); len(titleMatch) > 1 {
		title := strings.TrimSpace(titleMatch[1])
		analysis.Title = title
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "page_title",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Page title: %s", title),
			Confidence:  1.0,
		})
	}

	if strings.Contains(content, "<form") {
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "form_detected",
			Severity:    models.SeverityLow,
			Description: "HTML form detected",
			Confidence:  0.9,
		})
	}
	if strings.Contains(content, "<script") {
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "javascript_detected",
			Severity:    models.SeverityLow,
			Description: "JavaScript detected",
			Confidence:  0.9,
		})
	}
}

func (r *ResponseAnalyzer) analyzeDeadPage(analysis *models.HTTPAnalysis) {
	content := analysis.Response.Body

	for _, pattern := range r.deadPagePatterns {
		if pattern.MatchString(content) {
			analysis.IsDeadPage = true
			analysis.Findings = append(analysis.Findings, models.HTTPFinding{
				Type:        "dead_page",
				Severity:    models.SeverityMedium,
				Description: fmt.Sprintf("Dead page detected: %s", pattern.String()),
				Confidence:  0.9,
			})
			break
		}
	}
}

func (r *ResponseAnalyzer) analyzeSimilarity(analysis *models.HTTPAnalysis) {
	hash := analysis.ContentHash
	if hash == "" {
		return
	}

	var matchedDomain string
	var matchedSimilarity float64

	r.hashDB.mu.RLock()
	for storedHash, domain := range r.hashDB.hashes {
		similarity := r.calculateHashSimilarity(hash, storedHash)
		if similarity >= r.similarityThreshold {
			matchedDomain = domain
			matchedSimilarity = similarity
			break
		}
	}
	r.hashDB.mu.RUnlock()

	if matchedDomain != "" {
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "similar_content",
			Severity:    models.SeverityLow,
			Description: fmt.Sprintf("Content similar to %s (similarity: %.2f)", matchedDomain, matchedSimilarity),
			Confidence:  0.8,
		})
		analysis.SimilarityScore = matchedSimilarity
	}
	r.hashDB.mu.Lock()
	r.hashDB.hashes[hash] = analysis.Response.URL
	r.hashDB.mu.Unlock()
}

func (r *ResponseAnalyzer) analyzeSecurityHeaders(analysis *models.HTTPAnalysis) {
	headers := analysis.Response.Headers
	missingHeaders := []string{}
	securityHeaders := map[string]string{
		"Strict-Transport-Security": "HSTS header missing",
		"X-Frame-Options":           "Clickjacking protection missing",
		"X-Content-Type-Options":    "MIME type sniffing protection missing",
		"X-XSS-Protection":          "XSS protection header missing",
		"Content-Security-Policy":   "Content Security Policy missing",
		"Referrer-Policy":           "Referrer policy missing",
	}

	for header, description := range securityHeaders {
		if _, exists := headers[header]; !exists {
			missingHeaders = append(missingHeaders, description)
		}
	}

	if len(missingHeaders) > 0 {
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "missing_security_headers",
			Severity:    models.SeverityMedium,
			Description: fmt.Sprintf("Missing security headers: %s", strings.Join(missingHeaders, ", ")),
			Confidence:  0.9,
		})
	}
}

func (r *ResponseAnalyzer) analyzeServerTechnology(analysis *models.HTTPAnalysis) {
	headers := analysis.Response.Headers
	content := analysis.Response.Body
	lc := strings.ToLower(content)
	technologies := make(map[string]bool)
	if server, exists := headers["Server"]; exists && server != "" {
		technologies[fmt.Sprintf("Server: %s", server)] = true
	}
	if poweredBy, exists := headers["X-Powered-By"]; exists && poweredBy != "" {
		technologies[fmt.Sprintf("Powered by: %s", poweredBy)] = true
	}

	if strings.Contains(lc, "wp-content") {
		technologies["WordPress"] = true
	}
	if strings.Contains(lc, "joomla") {
		technologies["Joomla"] = true
	}
	if strings.Contains(lc, "drupal") {
		technologies["Drupal"] = true
	}
	if strings.Contains(lc, ".aspx") {
		technologies["ASP.NET"] = true
	}
	if strings.Contains(lc, "laravel") {
		technologies["Laravel"] = true
	}

	for tech := range technologies {
		analysis.Technologies = append(analysis.Technologies, tech)
		analysis.Findings = append(analysis.Findings, models.HTTPFinding{
			Type:        "technology_detected",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Technology detected: %s", tech),
			Confidence:  0.7,
		})
	}
}

func (r *ResponseAnalyzer) calculateContentHash(content string) string {
	normalized := strings.Join(strings.Fields(content), " ")
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

func (r *ResponseAnalyzer) calculateHashSimilarity(hash1, hash2 string) float64 {
	if hash1 == "" || hash2 == "" {
		return 0
	}
	minLen := min(len(hash1), len(hash2))
	if minLen == 0 {
		return 0
	}
	matchingChars := 0
	for i := 0; i < minLen; i++ {
		if hash1[i] == hash2[i] {
			matchingChars++
		}
	}
	return float64(matchingChars) / float64(minLen)
}

func (r *ResponseAnalyzer) calculateConfidenceScore(analysis *models.HTTPAnalysis) float64 {
	score := 1.0

	for _, finding := range analysis.Findings {
		switch finding.Type {
		case "dead_page", "error_page_content":
			score -= 0.3
		case "client_error", "server_error":
			score -= 0.2
		case "missing_security_headers":
			score -= 0.1
		case "similar_content":
			score -= 0.05 * (1 - finding.Confidence)
		}
	}

	if analysis.Response.StatusCode >= 400 {
		score -= 0.2
	}

	if score < 0 {
		score = 0
	} else if score > 1 {
		score = 1
	}

	return score
}

func compileDeadPagePatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)page not found`,
		`(?i)404 error`,
		`(?i)not found`,
		`(?i)does not exist`,
		`(?i)invalid domain`,
		`(?i)domain parking`,
		`(?i)this domain is for sale`,
		`(?i)under construction`,
		`(?i)coming soon`,
		`(?i)default page`,
		`(?i)apache.*test page`,
		`(?i)nginx.*welcome`,
		`(?i)index of /`,
		`(?i)placeholder page`,
	}

	var regexPatterns []*regexp.Regexp
	for _, pattern := range patterns {
		regexPatterns = append(regexPatterns, regexp.MustCompile(pattern))
	}

	return regexPatterns
}

func compileErrorPagePatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)error`,
		`(?i)exception`,
		`(?i)stack trace`,
		`(?i)internal server error`,
		`(?i)application error`,
		`(?i)database error`,
		`(?i)syntax error`,
		`(?i)permission denied`,
		`(?i)access denied`,
		`(?i)forbidden`,
		`(?i)unauthorized`,
	}

	var regexPatterns []*regexp.Regexp
	for _, pattern := range patterns {
		regexPatterns = append(regexPatterns, regexp.MustCompile(pattern))
	}

	return regexPatterns
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *ResponseAnalyzer) AddDeadPagePattern(pattern string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.deadPagePatterns = append(r.deadPagePatterns, compiled)

	return nil
}

func (r *ResponseAnalyzer) AddErrorPagePattern(pattern string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.errorPagePatterns = append(r.errorPagePatterns, compiled)

	return nil
}

func (r *ResponseAnalyzer) SetSimilarityThreshold(threshold float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.similarityThreshold = threshold
}

func (r *ResponseAnalyzer) ClearHashDB() {
	r.hashDB.mu.Lock()
	defer r.hashDB.mu.Unlock()
	r.hashDB.hashes = make(map[string]string)
}

func (r *ResponseAnalyzer) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.hashDB.mu.RLock()
	defer r.hashDB.mu.RUnlock()

	return map[string]interface{}{
		"dead_page_patterns":   len(r.deadPagePatterns),
		"error_page_patterns":  len(r.errorPagePatterns),
		"stored_hashes":        len(r.hashDB.hashes),
		"similarity_threshold": r.similarityThreshold,
	}
}

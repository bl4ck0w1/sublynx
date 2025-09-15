package stealth

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

type RequestMasquerade struct {
	techniques      map[string]MasqueradeTechnique
	activeTechnique string
	logger          *logrus.Logger
	mu              sync.RWMutex
	referrers       []string
	userAgents      []string
}

type MasqueradeTechnique struct {
	Name        string
	Description string
	Complexity  int
	SuccessRate float64
}

func NewRequestMasquerade(logger *logrus.Logger) *RequestMasquerade {
	if logger == nil {
		logger = logrus.New()
	}

	rm := &RequestMasquerade{
		techniques: make(map[string]MasqueradeTechnique),
		logger:     logger,
		referrers:  make([]string, 0),
		userAgents: make([]string, 0),
	}
	rm.initializeTechniques()
	rm.loadReferrers()
	rm.loadUserAgents()

	return rm
}

func (rm *RequestMasquerade) initializeTechniques() {
	rm.techniques["google_referrer"] = MasqueradeTechnique{
		Name:        "google_referrer",
		Description: "Use Google referrer to appear as organic traffic",
		Complexity:  1,
		SuccessRate: 0.8,
	}

	rm.techniques["social_media_referrer"] = MasqueradeTechnique{
		Name:        "social_media_referrer",
		Description: "Use social media referrers to appear as social traffic",
		Complexity:  1,
		SuccessRate: 0.7,
	}

	rm.techniques["direct_traffic"] = MasqueradeTechnique{
		Name:        "direct_traffic",
		Description: "Appear as direct traffic with no referrer",
		Complexity:  0,
		SuccessRate: 0.9,
	}

	rm.techniques["ajax_request"] = MasqueradeTechnique{
		Name:        "ajax_request",
		Description: "Masquerade as AJAX request with X-Requested-With header",
		Complexity:  2,
		SuccessRate: 0.6,
	}

	rm.techniques["api_request"] = MasqueradeTechnique{
		Name:        "api_request",
		Description: "Masquerade as API request with JSON accept headers",
		Complexity:  2,
		SuccessRate: 0.7,
	}

	rm.activeTechnique = "google_referrer"
}

func (rm *RequestMasquerade) loadReferrers() {
	rm.referrers = []string{
		"https://www.google.com/",
		"https://www.google.com/search?q=sublynx",
		"https://www.bing.com/",
		"https://search.yahoo.com/",
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.linkedin.com/",
		"https://www.reddit.com/",
		"https://www.instagram.com/",
		"",
	}
}

func (rm *RequestMasquerade) loadUserAgents() {
	rm.userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	}
}

func (rm *RequestMasquerade) ApplyActive(req *http.Request) error {
	rm.mu.RLock()
	tech := rm.activeTechnique
	rm.mu.RUnlock()
	return rm.MasqueradeRequest(req, tech)
}

func (rm *RequestMasquerade) MasqueradeRequest(req *http.Request, technique string) error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	switch technique {
	case "google_referrer":
		return rm.applyGoogleReferrer(req)
	case "social_media_referrer":
		return rm.applySocialMediaReferrer(req)
	case "direct_traffic":
		return rm.applyDirectTraffic(req)
	case "ajax_request":
		return rm.applyAjaxRequest(req)
	case "api_request":
		return rm.applyApiRequest(req)
	default:
		return fmt.Errorf("unknown masquerade technique: %s", technique)
	}
}

func (rm *RequestMasquerade) applyGoogleReferrer(req *http.Request) error {
	ref := "https://www.google.com/"
	if req != nil && req.URL != nil && req.URL.Host != "" {
		q := url.Values{}
		q.Set("q", req.URL.Host)
		ref = "https://www.google.com/search?" + q.Encode()
	}
	req.Header.Set("Referer", ref)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-User", "?1")

	if ua := rm.randomUserAgent(); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	return nil
}

func (rm *RequestMasquerade) applySocialMediaReferrer(req *http.Request) error {
	social := []string{
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.linkedin.com/",
		"https://www.reddit.com/",
		"https://www.instagram.com/",
	}
	req.Header.Set("Referer", social[rm.randIndex(len(social))])

	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")

	if ua := rm.randomUserAgent(); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	return nil
}

func (rm *RequestMasquerade) applyDirectTraffic(req *http.Request) error {
	req.Header.Del("Referer")
	if ua := rm.randomUserAgent(); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	return nil
}

func (rm *RequestMasquerade) applyAjaxRequest(req *http.Request) error {
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")

	switch strings.ToUpper(req.Method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}

	if len(rm.referrers) > 0 {
		req.Header.Set("Referer", rm.referrers[rm.randIndex(len(rm.referrers))])
	}
	if ua := rm.randomUserAgent(); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	return nil
}

func (rm *RequestMasquerade) applyApiRequest(req *http.Request) error {
	req.Header.Set("Accept", "application/json")
	switch strings.ToUpper(req.Method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		req.Header.Set("Content-Type", "application/json")
	}
	if ua := rm.randomUserAgent(); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	return nil
}

func (rm *RequestMasquerade) SetActiveTechnique(technique string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.techniques[technique]; !exists {
		return fmt.Errorf("technique not found: %s", technique)
	}
	rm.activeTechnique = technique
	return nil
}

func (rm *RequestMasquerade) GetActiveTechnique() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.activeTechnique
}

func (rm *RequestMasquerade) AddCustomReferrer(referrer string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.referrers = append(rm.referrers, referrer)
}

func (rm *RequestMasquerade) AddCustomUserAgent(userAgent string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.userAgents = append(rm.userAgents, userAgent)
}

func (rm *RequestMasquerade) GenerateRandomURL(baseURL string) (string, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()

	trackingParams := []string{"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"}
	for _, param := range trackingParams {
		query.Set(param, fmt.Sprintf("%d", rm.randUint(1_000_000)))
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

func (rm *RequestMasquerade) ObfuscateURL(originalURL string) (string, error) {
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return "", err
	}

	path := parsedURL.EscapedPath()
	if path == "" {
		path = parsedURL.Path 
	}

	var b []byte
	if path == "" {
		b = []byte{}
	} else {
		unescaped, err := url.PathUnescape(path)
		if err != nil {
			unescaped = path
		}
		b = []byte(unescaped)
	}

	var ob strings.Builder
	for _, by := range b {
		if by == '/' {
			ob.WriteByte('/')
			continue
		}
		if rm.randUint(100) < 30 {
			ob.WriteString(fmt.Sprintf("%%%02X", by))
		} else {
			ob.WriteByte(by)
		}
	}

	parsedURL.Path = ob.String()
	return parsedURL.String(), nil
}

func (rm *RequestMasquerade) AddFakeParameters(req *http.Request) {
	if req.Method != http.MethodGet {
		return
	}
	query := req.URL.Query()
	fakeParams := []string{"cache", "timestamp", "random", "version", "cb"}
	for _, param := range fakeParams {
		query.Set(param, fmt.Sprintf("%d", rm.randUint(1_000_000)))
	}
	req.URL.RawQuery = query.Encode()
}

func (rm *RequestMasquerade) RotateUserAgent(req *http.Request) {
	if ua := rm.randomUserAgent(); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
}

func (rm *RequestMasquerade) GetTechniques() map[string]MasqueradeTechnique {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	techniques := make(map[string]MasqueradeTechnique, len(rm.techniques))
	for k, v := range rm.techniques {
		techniques[k] = v
	}
	return techniques
}

func (rm *RequestMasquerade) UpdateTechniqueStats(technique string, success bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if tech, exists := rm.techniques[technique]; exists {
		if success {
			tech.SuccessRate = (tech.SuccessRate*9 + 1) / 10
		} else {
			tech.SuccessRate = (tech.SuccessRate * 9) / 10
		}
		rm.techniques[technique] = tech
	}
}

func (rm *RequestMasquerade) GetStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	stats := map[string]interface{}{
		"active_technique": rm.activeTechnique,
		"user_agents":      len(rm.userAgents),
		"referrers":        len(rm.referrers),
	}
	perTech := make(map[string]float64, len(rm.techniques))
	for k, v := range rm.techniques {
		perTech[k] = v.SuccessRate
	}
	stats["success_rates"] = perTech
	return stats
}

func (rm *RequestMasquerade) randIndex(n int) int {
	if n <= 0 {
		return 0
	}
	i, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(i.Int64())
}

func (rm *RequestMasquerade) randUint(n int64) int64 {
	if n <= 0 {
		return 0
	}
	i, _ := rand.Int(rand.Reader, big.NewInt(n))
	return i.Int64()
}

func (rm *RequestMasquerade) randomUserAgent() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	if len(rm.userAgents) == 0 {
		return ""
	}
	return rm.userAgents[rm.randIndex(len(rm.userAgents))]
}

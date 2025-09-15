package fingerprinting

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type HTTPFingerprinter struct {
	profiles      map[string]*HTTPProfile
	userAgents    []string
	logger        *logrus.Logger
	mu            sync.RWMutex
	customHeaders map[string][]string
}

type HTTPProfile struct {
	Name            string
	UserAgent       string
	Headers         map[string]string
	HeaderOrder     []string
	HTTPVersion     string 
	Accept          string
	AcceptLanguage  string
	AcceptEncoding  string
	AcceptCharset   string
	Connection      string
	CacheControl    string
	TE              string
	UpgradeInsecure string
	SecFetch        map[string]string
	Priority        int
	SuccessRate     float64
	LastUsed        time.Time
}

func NewHTTPFingerprinter(logger *logrus.Logger) *HTTPFingerprinter {
	if logger == nil {
		logger = logrus.New()
	}

	hf := &HTTPFingerprinter{
		profiles:      make(map[string]*HTTPProfile),
		userAgents:    make([]string, 0),
		logger:        logger,
		customHeaders: make(map[string][]string),
	}

	hf.initializeProfiles()
	hf.loadUserAgents()

	return hf
}

func (hf *HTTPFingerprinter) initializeProfiles() {
	hf.profiles["chrome_win"] = &HTTPProfile{
		Name:           "chrome_win",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		HTTPVersion:    "HTTP/1.1",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		AcceptCharset:  "utf-8, iso-8859-1;q=0.5",
		Connection:     "keep-alive",
		CacheControl:   "max-age=0",
		TE:             "Trailers",
		Headers: map[string]string{
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
		},
		HeaderOrder: []string{
			"Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
			"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
			"Accept-Encoding", "Accept-Language", "Cache-Control", "TE",
		},
		Priority: 10,
	}

	hf.profiles["firefox_win"] = &HTTPProfile{
		Name:           "firefox_win",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		HTTPVersion:    "HTTP/1.1",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.5",
		AcceptEncoding: "gzip, deflate, br",
		AcceptCharset:  "utf-8, iso-8859-1;q=0.5",
		Connection:     "keep-alive",
		CacheControl:   "max-age=0",
		TE:             "Trailers",
		Headers: map[string]string{
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
		},
		HeaderOrder: []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
			"Connection", "Upgrade-Insecure-Requests", "Cache-Control", "TE",
		},
		Priority: 9,
	}

	hf.profiles["safari_mac"] = &HTTPProfile{
		Name:           "safari_mac",
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		HTTPVersion:    "HTTP/1.1",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-us",
		AcceptEncoding: "gzip, deflate, br",
		AcceptCharset:  "utf-8, iso-8859-1;q=0.5",
		Connection:     "keep-alive",
		CacheControl:   "max-age=0",
		Headers: map[string]string{
			"Upgrade-Insecure-Requests": "1",
		},
		HeaderOrder: []string{
			"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
			"Connection", "Upgrade-Insecure-Requests", "Cache-Control",
		},
		Priority: 8,
	}

	hf.profiles["chrome_android"] = &HTTPProfile{
		Name:           "chrome_android",
		UserAgent:      "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36",
		HTTPVersion:    "HTTP/1.1",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		AcceptCharset:  "utf-8, iso-8859-1;q=0.5",
		Connection:     "keep-alive",
		CacheControl:   "max-age=0",
		Headers: map[string]string{
			"Upgrade-Insecure-Requests": "1",
		},
		HeaderOrder: []string{
			"Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
			"Accept-Encoding", "Accept-Language", "Cache-Control",
		},
		Priority: 7,
	}
}

func (hf *HTTPFingerprinter) loadUserAgents() {
	hf.userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	}
}

func (hf *HTTPFingerprinter) GetProfile(name string) (*HTTPProfile, error) {
	hf.mu.RLock()
	defer hf.mu.RUnlock()

	if profile, exists := hf.profiles[name]; exists {
		return profile, nil
	}
	return nil, fmt.Errorf("HTTP profile not found: %s", name)
}

func (hf *HTTPFingerprinter) AddProfile(profile *HTTPProfile) error {
	hf.mu.Lock()
	defer hf.mu.Unlock()

	if _, exists := hf.profiles[profile.Name]; exists {
		return fmt.Errorf("HTTP profile already exists: %s", profile.Name)
	}
	hf.profiles[profile.Name] = profile
	return nil
}

func (hf *HTTPFingerprinter) RemoveProfile(name string) {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	delete(hf.profiles, name)
}

func (hf *HTTPFingerprinter) GetRandomProfile() *HTTPProfile {
	hf.mu.RLock()
	defer hf.mu.RUnlock()

	if len(hf.profiles) == 0 {
		return nil
	}

	profiles := make([]*HTTPProfile, 0, len(hf.profiles))
	for _, profile := range hf.profiles {
		profiles = append(profiles, profile)
	}

	totalPriority := 0
	for _, profile := range profiles {
		totalPriority += profile.Priority
	}

	randNum, _ := rand.Int(rand.Reader, big.NewInt(int64(totalPriority)))
	randomValue := int(randNum.Int64())

	current := 0
	for _, profile := range profiles {
		current += profile.Priority
		if randomValue < current {
			return profile
		}
	}
	return profiles[len(profiles)-1]
}

func (hf *HTTPFingerprinter) ApplyProfile(req *http.Request, profileName string) error {
	profile, err := hf.GetProfile(profileName)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("Accept", profile.Accept)
	req.Header.Set("Accept-Language", profile.AcceptLanguage)
	req.Header.Set("Accept-Encoding", profile.AcceptEncoding)
	req.Header.Set("Connection", profile.Connection)
	req.Header.Set("Cache-Control", profile.CacheControl)

	if profile.AcceptCharset != "" {
		req.Header.Set("Accept-Charset", profile.AcceptCharset)
	}
	if profile.TE != "" {
		req.Header.Set("TE", profile.TE)
	}

	for key, value := range profile.Headers {
		req.Header.Set(key, value)
	}

	for key, values := range hf.customHeaders {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	hf.reorderHeaders(req, profile.HeaderOrder)
	hf.updateProfileStats(profileName, true)
	return nil
}

func (hf *HTTPFingerprinter) BuildTransportForProfile(profileName string) (*http.Transport, error) {
	profile, err := hf.GetProfile(profileName)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression: !strings.Contains(strings.ToLower(profile.AcceptEncoding), "gzip"),
	}

	if strings.EqualFold(profile.HTTPVersion, "HTTP/1.1") {
		tr.TLSNextProto = map[string.func(authority string, c *http.Transport) http.RoundTripper{} 
	
	}

	return tr, nil
}

func (hf *HTTPFingerprinter) BuildClientForProfile(profileName string, timeout time.Duration) (*http.Client, error) {
	tr, err := hf.BuildTransportForProfile(profileName)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}, nil
}

func (hf *HTTPFingerprinter) reorderHeaders(req *http.Request, order []string) {
	newHeader := http.Header{}

	for _, key := range order {
		if values, exists := req.Header[key]; exists {
			for _, value := range values {
				newHeader.Add(key, value)
			}
			req.Header.Del(key)
		}
	}
	for key, values := range req.Header {
		for _, value := range values {
			newHeader.Add(key, value)
		}
	}
	req.Header = newHeader
}


func (hf *HTTPFingerprinter) updateProfileStats(profileName string, success bool) {
	hf.mu.Lock()
	defer hf.mu.Unlock()

	if profile, exists := hf.profiles[profileName]; exists {
		profile.LastUsed = time.Now()
		if success {
			profile.SuccessRate = (profile.SuccessRate*9 + 1) / 10
		} else {
			profile.SuccessRate = (profile.SuccessRate * 9) / 10
		}
	}
}

func (hf *HTTPFingerprinter) AddCustomHeader(key, value string) {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	hf.customHeaders[key] = append(hf.customHeaders[key], value)
}

func (hf *HTTPFingerprinter) RemoveCustomHeader(key string) {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	delete(hf.customHeaders, key)
}

func (hf *HTTPFingerprinter) GenerateRandomUserAgent() string {
	hf.mu.RLock()
	defer hf.mu.RUnlock()

	if len(hf.userAgents) == 0 {
		return "SubLynx/1.0"
	}
	randIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(hf.userAgents))))
	return hf.userAgents[randIndex.Int64()]
}

func (hf *HTTPFingerprinter) GetProfileNames() []string {
	hf.mu.RLock()
	defer hf.mu.RUnlock()

	names := make([]string, 0, len(hf.profiles))
	for name := range hf.profiles {
		names = append(names, name)
	}
	return names
}

func (hf *HTTPFingerprinter) GetProfileStats() map[string]interface{} {
	hf.mu.RLock()
	defer hf.mu.RUnlock()

	stats := make(map[string]interface{})
	for name, profile := range hf.profiles {
		stats[name] = map[string]interface{}{
			"success_rate": profile.SuccessRate,
			"last_used":    profile.LastUsed,
			"priority":     profile.Priority,
		}
	}
	return stats
}

func (hf *HTTPFingerprinter) CloneProfile(name string, modifications func(*HTTPProfile)) (*HTTPProfile, error) {
	profile, err := hf.GetProfile(name)
	if err != nil {
		return nil, err
	}

	newProfile := &HTTPProfile{
		Name:           profile.Name + "_clone",
		UserAgent:      profile.UserAgent,
		HTTPVersion:    profile.HTTPVersion,
		Accept:         profile.Accept,
		AcceptLanguage: profile.AcceptLanguage,
		AcceptEncoding: profile.AcceptEncoding,
		AcceptCharset:  profile.AcceptCharset,
		Connection:     profile.Connection,
		CacheControl:   profile.CacheControl,
		TE:             profile.TE,
		Priority:       profile.Priority,
		SuccessRate:    profile.SuccessRate,
		LastUsed:       profile.LastUsed,
	}

	newProfile.Headers = make(map[string]string, len(profile.Headers))
	for k, v := range profile.Headers {
		newProfile.Headers[k] = v
	}
	newProfile.HeaderOrder = make([]string, len(profile.HeaderOrder))
	copy(newProfile.HeaderOrder, profile.HeaderOrder)

	if modifications != nil {
		modifications(newProfile)
	}
	return newProfile, nil
}

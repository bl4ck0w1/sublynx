package proxies

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
)

type ProxyProviderAPI interface {
	GetProxies() ([]*Proxy, error)
	GetStats() map[string]interface{}
	GetQuota() (used, total int, err error)
}

type ProxyAPIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Message string      `json:"message"`
}

type LuminatiProvider struct {
	host       string 
	zone       string
	username   string
	password   string
	httpClient *http.Client
	logger     *logrus.Logger
}

func NewLuminatiProvider(zone, username, password string, logger *logrus.Logger) *LuminatiProvider {
	if logger == nil {
		logger = logrus.New()
	}
	return &LuminatiProvider{
		host:       "zproxy.lum-superproxy.io",
		zone:       zone,
		username:   username,
		password:   password,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

func (l *LuminatiProvider) GetProxies() ([]*Proxy, error) {
	user := fmt.Sprintf("%s-zone-%s", l.username, l.zone)
	raw := fmt.Sprintf("http://%s:%s@%s:%d", url.QueryEscape(user), url.QueryEscape(l.password), l.host, 22225)

	parsedURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %w", err)
	}

	proxy := &Proxy{
		URL:   parsedURL,
		Type:  "http",
		Source:"luminati",
		Country: "us", 
		Credentials: &ProxyAuth{
			Username: user,
			Password: l.password,
		},
	}

	return []*Proxy{proxy}, nil
}

func (l *LuminatiProvider) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"provider": "luminati",
		"zone":     l.zone,
		"username": l.username,
	}
}

func (l *LuminatiProvider) GetQuota() (used, total int, err error) {
	return 0, 1000, nil
}

type SmartproxyProvider struct {
	host       string
	username   string
	password   string
	httpClient *http.Client
	logger     *logrus.Logger
}

func NewSmartproxyProvider(username, password string, logger *logrus.Logger) *SmartproxyProvider {
	if logger == nil {
		logger = logrus.New()
	}
	return &SmartproxyProvider{
		host:       "gate.smartproxy.com",
		username:   username,
		password:   password,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

func (s *SmartproxyProvider) GetProxies() ([]*Proxy, error) {
	raw := fmt.Sprintf("http://%s:%s@%s:%d", url.QueryEscape(s.username), url.QueryEscape(s.password), s.host, 10000)

	parsedURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %w", err)
	}

	proxy := &Proxy{
		URL:   parsedURL,
		Type:  "http",
		Source:"smartproxy",
		Country: "us",
		Credentials: &ProxyAuth{
			Username: s.username,
			Password: s.password,
		},
	}

	return []*Proxy{proxy}, nil
}

func (s *SmartproxyProvider) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"provider": "smartproxy",
		"username": s.username,
	}
}

func (s *SmartproxyProvider) GetQuota() (used, total int, err error) {
	return 0, 1000, nil
}

type OxylabsProvider struct {
	host       string 
	username   string
	password   string
	httpClient *http.Client
	logger     *logrus.Logger
}

func NewOxylabsProvider(username, password string, logger *logrus.Logger) *OxylabsProvider {
	if logger == nil {
		logger = logrus.New()
	}
	return &OxylabsProvider{
		host:       "proxy.oxylabs.io",
		username:   username,
		password:   password,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

func (o *OxylabsProvider) GetProxies() ([]*Proxy, error) {
	raw := fmt.Sprintf("http://%s:%s@%s:%d", url.QueryEscape(o.username), url.QueryEscape(o.password), o.host, 60000)

	parsedURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy URL: %w", err)
	}

	proxy := &Proxy{
		URL:   parsedURL,
		Type:  "http",
		Source:"oxylabs",
		Country: "us",
		Credentials: &ProxyAuth{
			Username: o.username,
			Password: o.password,
		},
	}

	return []*Proxy{proxy}, nil
}

func (o *OxylabsProvider) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"provider": "oxylabs",
		"username": o.username,
	}
}

func (o *OxylabsProvider) GetQuota() (used, total int, err error) {
	return 0, 1000, nil
}

type FreeProxyProvider struct {
	baseURL    string
	httpClient *http.Client
	logger     *logrus.Logger
}

func NewFreeProxyProvider(logger *logrus.Logger) *FreeProxyProvider {
	if logger == nil {
		logger = logrus.New()
	}
	return &FreeProxyProvider{
		baseURL:    "https://free-proxy-list.net",
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

func (f *FreeProxyProvider) GetProxies() ([]*Proxy, error) {
	resp, err := f.httpClient.Get(f.baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch free proxies: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return f.parseFreeProxyList(resp.Body)
}

func (f *FreeProxyProvider) parseFreeProxyList(body io.Reader) ([]*Proxy, error) {
	example := []struct {
		ip        string
		port      int
		proxyType string
		country   string
	}{
		{"203.0.113.10", 8080, "http", "us"},
		{"198.51.100.22", 3128, "http", "gb"},
		{"192.0.2.33", 8080, "https", "de"},
	}

	var proxies []*Proxy
	for _, e := range example {
		raw := fmt.Sprintf("http://%s:%d", e.ip, e.port)
		u, err := url.Parse(raw)
		if err != nil {
			f.logger.Warnf("Failed to parse proxy URL %s: %v", raw, err)
			continue
		}
		proxies = append(proxies, &Proxy{
			URL:     u,
			Type:    e.proxyType,
			Source:  "free",
			Country: e.country,
		})
	}
	return proxies, nil
}

func (f *FreeProxyProvider) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"provider": "free",
		"source":   f.baseURL,
	}
}

func (f *FreeProxyProvider) GetQuota() (used, total int, err error) {
	return 0, 0, nil
}

func ProviderFactory(providerType, username, password, zone string, logger *logrus.Logger) (ProxyProviderAPI, error) {
	switch providerType {
	case "luminati":
		return NewLuminatiProvider(zone, username, password, logger), nil
	case "smartproxy":
		return NewSmartproxyProvider(username, password, logger), nil
	case "oxylabs":
		return NewOxylabsProvider(username, password, logger), nil
	case "free":
		return NewFreeProxyProvider(logger), nil
	default:
		return nil, fmt.Errorf("unknown provider type: %s", providerType)
	}
}

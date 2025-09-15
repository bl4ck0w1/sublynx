package models

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Global     GlobalConfig     `yaml:"global" json:"global"`
	Discovery  DiscoveryConfig  `yaml:"discovery" json:"discovery"`
	Validation ValidationConfig `yaml:"validation" json:"validation"`
	Evasion    EvasionConfig    `yaml:"evasion" json:"evasion"`
	Reporting  ReportingConfig  `yaml:"reporting" json:"reporting"`
	Storage    StorageConfig    `yaml:"storage" json:"storage"`
	API        APIConfig        `yaml:"api" json:"api"`
}

type GlobalConfig struct {
	LogLevel      string        `yaml:"log_level" json:"log_level"`
	MaxConcurrent int           `yaml:"max_concurrent" json:"max_concurrent"`
	Timeout       time.Duration `yaml:"timeout" json:"timeout"`
	RetryAttempts int           `yaml:"retry_attempts" json:"retry_attempts"`
	UserAgent     string        `yaml:"user_agent" json:"user_agent"`
	Debug         bool          `yaml:"debug" json:"debug"`
	DataDir       string        `yaml:"data_dir" json:"data_dir"`
	TempDir       string        `yaml:"temp_dir" json:"temp_dir"`
}

type DiscoveryConfig struct {
	CTLogs         CTLogsConfig   `yaml:"ct_logs" json:"ct_logs"`
	Permutations   PermutationsConfig `yaml:"permutations" json:"permutations"`
	Passive        PassiveConfig  `yaml:"passive" json:"passive"`
	AI             AIConfig       `yaml:"ai" json:"ai"`
	EnabledMethods []string       `yaml:"enabled_methods" json:"enabled_methods"`
	RateLimit      int            `yaml:"rate_limit" json:"rate_limit"`
	Timeout        time.Duration  `yaml:"timeout" json:"timeout"`
	Concurrency    int            `yaml:"concurrency" json:"concurrency"`
}

type CTLogsConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	LogURLs         []string      `yaml:"log_urls" json:"log_urls"`
	BatchSize       int           `yaml:"batch_size" json:"batch_size"`
	MaxEntries      int           `yaml:"max_entries" json:"max_entries"`
	MonitorInterval time.Duration `yaml:"monitor_interval" json:"monitor_interval"`
	DomainFilter    []string      `yaml:"domain_filter" json:"domain_filter"`
}

type PermutationsConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	WordlistDir      string   `yaml:"wordlist_dir" json:"wordlist_dir"`
	MaxDepth         int      `yaml:"max_depth" json:"max_depth"`
	MaxPermutations  int      `yaml:"max_permutations" json:"max_permutations"`
	IndustrySpecific []string `yaml:"industry_specific" json:"industry_specific"`
	UseCommon        bool     `yaml:"use_common" json:"use_common"`
	UseCombinatorics bool     `yaml:"use_combinatorics" json:"use_combinatorics"`
	UseFuzzing       bool     `yaml:"use_fuzzing" json:"use_fuzzing"`
}

type PassiveConfig struct {
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	DNSDatabases []string     `yaml:"dns_databases" json:"dns_databases"`
	WebArchives []string      `yaml:"web_archives" json:"web_archives"`
	MaxResults  int           `yaml:"max_results" json:"max_results"`
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
}

type AIConfig struct {
	Enabled            bool    `yaml:"enabled" json:"enabled"`
	ModelPath          string  `yaml:"model_path" json:"model_path"`
	ConfidenceThreshold float64 `yaml:"confidence_threshold" json:"confidence_threshold"`
	MaxPredictions     int     `yaml:"max_predictions" json:"max_predictions"`
	TrainingDataSize   int     `yaml:"training_data_size" json:"training_data_size"`
}

type ValidationConfig struct {
	DNS             DNSConfig             `yaml:"dns" json:"dns"`
	HTTP            HTTPConfig            `yaml:"http" json:"http"`
	ContentAnalysis ContentAnalysisConfig `yaml:"content_analysis" json:"content_analysis"`
	Security        SecurityConfig        `yaml:"security" json:"security"`
	EnabledMethods  []string              `yaml:"enabled_methods" json:"enabled_methods"`
	Timeout         time.Duration         `yaml:"timeout" json:"timeout"`
	Concurrency     int                   `yaml:"concurrency" json:"concurrency"`
}


type DNSConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	Nameservers   []string      `yaml:"nameservers" json:"nameservers"`
	RecordTypes   []string      `yaml:"record_types" json:"record_types"`
	RetryAttempts int           `yaml:"retry_attempts" json:"retry_attempts"`
	Timeout       time.Duration `yaml:"timeout" json:"timeout"`
}

type HTTPConfig struct {
	Enabled           bool              `yaml:"enabled" json:"enabled"`
	Timeout           time.Duration     `yaml:"timeout" json:"timeout"`
	FollowRedirects   bool              `yaml:"follow_redirects" json:"follow_redirects"`
	MaxRedirects      int               `yaml:"max_redirects" json:"max_redirects"`
	UserAgent         string            `yaml:"user_agent" json:"user_agent"`
	Headers           map[string]string `yaml:"headers" json:"headers"`
	ProbeSSL          bool              `yaml:"probe_ssl" json:"probe_ssl"`
	ProbeHeaders      bool              `yaml:"probe_headers" json:"probe_headers"`
	ProbeTechnologies bool              `yaml:"probe_technologies" json:"probe_technologies"`
}

type ContentAnalysisConfig struct {
	Enabled             bool    `yaml:"enabled" json:"enabled"`
	SimilarityThreshold float64 `yaml:"similarity_threshold" json:"similarity_threshold"`
	HashAnalysis        bool    `yaml:"hash_analysis" json:"hash_analysis"`
	PatternMatching     bool    `yaml:"pattern_matching" json:"pattern_matching"`
	NLPProcessing       bool    `yaml:"nlp_processing" json:"nlp_processing"`
	DeadPageDetection   bool    `yaml:"dead_page_detection" json:"dead_page_detection"`
}

type SecurityConfig struct {
	Enabled                 bool `yaml:"enabled" json:"enabled"`
	SSLAnalysis             bool `yaml:"ssl_analysis" json:"ssl_analysis"`
	VulnerabilityMatching   bool `yaml:"vulnerability_matching" json:"vulnerability_matching"`
	MisconfigurationDetection bool `yaml:"misconfiguration_detection" json:"misconfiguration_detection"`
	CVEChecking             bool `yaml:"cve_checking" json:"cve_checking"`
}

type EvasionConfig struct {
	Proxies        ProxiesConfig        `yaml:"proxies" json:"proxies"`
	Fingerprinting FingerprintingConfig `yaml:"fingerprinting" json:"fingerprinting"`
	Timing         TimingConfig         `yaml:"timing" json:"timing"`
	Stealth        StealthConfig        `yaml:"stealth" json:"stealth"`
	Enabled        bool                 `yaml:"enabled" json:"enabled"`
}

type ProxiesConfig struct {
	Enabled          bool          `yaml:"enabled" json:"enabled"`
	ProxyList        []string      `yaml:"proxy_list" json:"proxy_list"`
	RotationInterval time.Duration `yaml:"rotation_interval" json:"rotation_interval"`
	MaxRetries       int           `yaml:"max_retries" json:"max_retries"`
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	AuthRequired     bool          `yaml:"auth_required" json:"auth_required"`
	Username         string        `yaml:"username" json:"username"`
	Password         string        `yaml:"password" json:"password"`
}

type FingerprintingConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	TLSFingerprints   []string `yaml:"tls_fingerprints" json:"tls_fingerprints"`
	HTTPProfiles      []string `yaml:"http_profiles" json:"http_profiles"`
	BrowserSimulation bool     `yaml:"browser_simulation" json:"browser_simulation"`
	Randomize         bool     `yaml:"randomize" json:"randomize"`
}

type TimingConfig struct {
	Enabled   bool          `yaml:"enabled" json:"enabled"`
	MinDelay  time.Duration `yaml:"min_delay" json:"min_delay"`
	MaxDelay  time.Duration `yaml:"max_delay" json:"max_delay"`
	Jitter    float64       `yaml:"jitter" json:"jitter"`
	RateLimit int           `yaml:"rate_limit" json:"rate_limit"`
	Adaptive  bool          `yaml:"adaptive" json:"adaptive"`
}

type StealthConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	IPObfuscation     bool     `yaml:"ip_obfuscation" json:"ip_obfuscation"`
	RequestMasquerade bool     `yaml:"request_masquerade" json:"request_masquerade"`
	Techniques        []string `yaml:"techniques" json:"techniques"`
}

type ReportingConfig struct {
	Formats        []string      `yaml:"formats" json:"formats"`
	OutputDir      string        `yaml:"output_dir" json:"output_dir"`
	TemplateDir    string        `yaml:"template_dir" json:"template_dir"`
	RiskThreshold  float64       `yaml:"risk_threshold" json:"risk_threshold"`
	IncludeRawData bool          `yaml:"include_raw_data" json:"include_raw_data"`
	AutoOpen       bool          `yaml:"auto_open" json:"auto_open"`
	Compression    bool          `yaml:"compression" json:"compression"`
	Retention      time.Duration `yaml:"retention" json:"retention"`
}

type StorageConfig struct {
	Type           string        `yaml:"type" json:"type"` 
	Path           string        `yaml:"path" json:"path"`
	Compression    bool          `yaml:"compression" json:"compression"`
	Encryption     bool          `yaml:"encryption" json:"encryption"`
	EncryptionKey  string        `yaml:"encryption_key" json:"encryption_key"`
	Retention      time.Duration `yaml:"retention" json:"retention"`
	MaxSize        int64         `yaml:"max_size" json:"max_size"` 
	BackupInterval time.Duration `yaml:"backup_interval" json:"backup_interval"`
}

type APIConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	Host           string        `yaml:"host" json:"host"`
	Port           int           `yaml:"port" json:"port"`
	Authentication bool          `yaml:"authentication" json:"authentication"`
	APIKey         string        `yaml:"api_key" json:"api_key"`
	RateLimit      int           `yaml:"rate_limit" json:"rate_limit"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	SSL            bool          `yaml:"ssl" json:"ssl"`
	SSLCert        string        `yaml:"ssl_cert" json:"ssl_cert"`
	SSLKey         string        `yaml:"ssl_key" json:"ssl_key"`
}


func DefaultConfig() *Config {
	return &Config{
		Global: GlobalConfig{
			LogLevel:      "info",
			MaxConcurrent: 100,
			Timeout:       30 * time.Minute,
			RetryAttempts: 3,
			UserAgent:     "SubLynx/1.0",
			Debug:         false,
			DataDir:       "./data",
			TempDir:       "/tmp",
		},
		Discovery: DiscoveryConfig{
			EnabledMethods: []string{"ct_logs", "permutations", "passive"},
			RateLimit:      10,
			Timeout:        10 * time.Minute,
			Concurrency:    50,
			CTLogs: CTLogsConfig{
				Enabled:         true,
				LogURLs:         []string{"https://ct.googleapis.com/logs"},
				BatchSize:       1000,
				MaxEntries:      10000,
				MonitorInterval: 5 * time.Minute,
			},
			Permutations: PermutationsConfig{
				Enabled:          true,
				WordlistDir:      "./configs/wordlists",
				MaxDepth:         3,
				MaxPermutations:  100000,
				UseCommon:        true,
				UseCombinatorics: true,
				UseFuzzing:       true,
			},
			Passive: PassiveConfig{
				Enabled:      true,
				DNSDatabases: []string{"https://api.sublist3r.com"},
				WebArchives:  []string{"https://web.archive.org"},
				MaxResults:   1000,
				Timeout:      5 * time.Minute,
			},
			AI: AIConfig{
				Enabled:            false,
				ModelPath:          "./data/models",
				ConfidenceThreshold: 0.8,
				MaxPredictions:     1000,
			},
		},
		Validation: ValidationConfig{
			EnabledMethods: []string{"dns", "http", "content_analysis", "security"},
			Timeout:        15 * time.Minute,
			Concurrency:    100,
			DNS: DNSConfig{
				Enabled:       true,
				Nameservers:   []string{"8.8.8.8", "1.1.1.1"},
				RecordTypes:   []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"},
				RetryAttempts: 2,
				Timeout:       5 * time.Second,
			},
			HTTP: HTTPConfig{
				Enabled:           true,
				Timeout:           10 * time.Second,
				FollowRedirects:   true,
				MaxRedirects:      5,
				UserAgent:         "Mozilla/5.0 (compatible; SubLynx/1.0; +https://github.com/bl4ck0w1/sublynx)",
				ProbeSSL:          true,
				ProbeHeaders:      true,
				ProbeTechnologies: true,
			},
			ContentAnalysis: ContentAnalysisConfig{
				Enabled:             true,
				SimilarityThreshold: 0.9,
				HashAnalysis:        true,
				PatternMatching:     true,
				NLPProcessing:       false,
				DeadPageDetection:   true,
			},
			Security: SecurityConfig{
				Enabled:                 true,
				SSLAnalysis:             true,
				VulnerabilityMatching:   true,
				MisconfigurationDetection: true,
				CVEChecking:             true,
			},
		},
		Evasion: EvasionConfig{
			Enabled: true,
			Proxies: ProxiesConfig{
				Enabled:          false,
				ProxyList:        []string{},
				RotationInterval: 1 * time.Minute,
				MaxRetries:       3,
				Timeout:          10 * time.Second,
			},
			Fingerprinting: FingerprintingConfig{
				Enabled:           true,
				TLSFingerprints:   []string{"chrome", "firefox", "safari"},
				HTTPProfiles:      []string{"chrome_win", "firefox_win", "safari_mac"},
				BrowserSimulation: true,
				Randomize:         true,
			},
			Timing: TimingConfig{
				Enabled:   true,
				MinDelay:  100 * time.Millisecond,
				MaxDelay:  5 * time.Second,
				Jitter:    0.3,
				RateLimit: 10,
				Adaptive:  true,
			},
			Stealth: StealthConfig{
				Enabled:           true,
				IPObfuscation:     false,
				RequestMasquerade: true,
				Techniques:        []string{"google_referrer", "direct_traffic"},
			},
		},
		Reporting: ReportingConfig{
			Formats:        []string{"txt", "csv", "json"},
			OutputDir:      "./reports",
			TemplateDir:    "./configs/templates",
			RiskThreshold:  3.0,
			IncludeRawData: false,
			AutoOpen:       false,
			Compression:    true,
			Retention:      30 * 24 * time.Hour, 
		},
		Storage: StorageConfig{
			Type:           "local",
			Path:           "./data/storage",
			Compression:    true,
			Encryption:     false,
			Retention:      90 * 24 * time.Hour,        
			MaxSize:        10 * 1024 * 1024 * 1024,    
			BackupInterval: 24 * time.Hour,
		},
		API: APIConfig{
			Enabled:        false,
			Host:           "127.0.0.1",
			Port:           8080,
			Authentication: true,
			RateLimit:      1000,
			Timeout:        30 * time.Second,
			SSL:            false,
		},
	}
}

func (c *Config) Validate() error {
	var errs []string

	switch strings.ToLower(c.Global.LogLevel) {
	case "trace", "debug", "info", "warn", "warning", "error", "fatal", "panic":
	default:
		errs = append(errs, "global.log_level must be one of trace|debug|info|warn|error|fatal|panic")
	}
	if c.Global.MaxConcurrent <= 0 {
		errs = append(errs, "global.max_concurrent must be > 0")
	}
	if c.Global.Timeout <= 0 {
		errs = append(errs, "global.timeout must be > 0")
	}
	if c.Global.RetryAttempts < 0 {
		errs = append(errs, "global.retry_attempts must be >= 0")
	}
	if c.Global.DataDir == "" {
		errs = append(errs, "global.data_dir must not be empty")
	}
	if c.Global.TempDir == "" {
		errs = append(errs, "global.temp_dir must not be empty")
	}

	if c.Discovery.RateLimit < 0 {
		errs = append(errs, "discovery.rate_limit must be >= 0")
	}
	if c.Discovery.Timeout <= 0 {
		errs = append(errs, "discovery.timeout must be > 0")
	}
	if c.Discovery.Concurrency <= 0 {
		errs = append(errs, "discovery.concurrency must be > 0")
	}
	if c.Discovery.CTLogs.Enabled {
		if c.Discovery.CTLogs.BatchSize <= 0 {
			errs = append(errs, "discovery.ct_logs.batch_size must be > 0 when CT logs are enabled")
		}
		if c.Discovery.CTLogs.MonitorInterval <= 0 {
			errs = append(errs, "discovery.ct_logs.monitor_interval must be > 0 when CT logs are enabled")
		}
	}

	if c.Validation.Timeout <= 0 {
		errs = append(errs, "validation.timeout must be > 0")
	}
	if c.Validation.Concurrency <= 0 {
		errs = append(errs, "validation.concurrency must be > 0")
	}
	if c.Validation.DNS.Enabled {
		if c.Validation.DNS.Timeout <= 0 {
			errs = append(errs, "validation.dns.timeout must be > 0 when DNS validation is enabled")
		}
		if c.Validation.DNS.RetryAttempts < 0 {
			errs = append(errs, "validation.dns.retry_attempts must be >= 0")
		}
	}
	if c.Validation.HTTP.Enabled {
		if c.Validation.HTTP.Timeout <= 0 {
			errs = append(errs, "validation.http.timeout must be > 0 when HTTP validation is enabled")
		}
		if c.Validation.HTTP.FollowRedirects && c.Validation.HTTP.MaxRedirects < 0 {
			errs = append(errs, "validation.http.max_redirects must be >= 0 when follow_redirects is true")
		}
		if c.Validation.HTTP.UserAgent == "" {
			errs = append(errs, "validation.http.user_agent must not be empty when HTTP validation is enabled")
		}
	}
	if c.Validation.ContentAnalysis.Enabled {
		if c.Validation.ContentAnalysis.SimilarityThreshold < 0 || c.Validation.ContentAnalysis.SimilarityThreshold > 1 {
			errs = append(errs, "validation.content_analysis.similarity_threshold must be in [0,1]")
		}
	}


	if c.Evasion.Enabled {
		if c.Evasion.Timing.Enabled {
			if c.Evasion.Timing.MinDelay < 0 || c.Evasion.Timing.MaxDelay < 0 {
				errs = append(errs, "evasion.timing.{min_delay,max_delay} must be >= 0")
			}
			if c.Evasion.Timing.MaxDelay > 0 && c.Evasion.Timing.MinDelay > c.Evasion.Timing.MaxDelay {
				errs = append(errs, "evasion.timing.min_delay must be <= max_delay")
			}
			if c.Evasion.Timing.Jitter < 0 || c.Evasion.Timing.Jitter > 1 {
				errs = append(errs, "evasion.timing.jitter must be in [0,1]")
			}
			if c.Evasion.Timing.RateLimit < 0 {
				errs = append(errs, "evasion.timing.rate_limit must be >= 0")
			}
		}
		if c.Evasion.Proxies.Enabled && len(c.Evasion.Proxies.ProxyList) == 0 {
			errs = append(errs, "evasion.proxies.proxy_list must not be empty when proxies are enabled")
		}
		if c.Evasion.Proxies.AuthRequired {
			if c.Evasion.Proxies.Username == "" || c.Evasion.Proxies.Password == "" {
				errs = append(errs, "evasion.proxies.username/password must be set when auth_required is true")
			}
		}
	}


	if c.Reporting.RiskThreshold < 0 || c.Reporting.RiskThreshold > 10 {
		errs = append(errs, "reporting.risk_threshold must be in [0,10]")
	}
	if c.Reporting.OutputDir == "" {
		errs = append(errs, "reporting.output_dir must not be empty")
	}
	if len(c.Reporting.Formats) == 0 {
		errs = append(errs, "reporting.formats must include at least one format")
	}
	for _, f := range c.Reporting.Formats {
		switch f {
		case "txt", "csv", "json", "yaml": 
		default:
			errs = append(errs, fmt.Sprintf("reporting.format %q is not supported", f))
		}
	}

	if c.Storage.Type == "" {
		errs = append(errs, "storage.type must not be empty")
	}
	if c.Storage.Path == "" {
		errs = append(errs, "storage.path must not be empty")
	}
	if c.Storage.Encryption && c.Storage.EncryptionKey == "" {
		errs = append(errs, "storage.encryption_key must be set when storage.encryption is true")
	}
	if c.Storage.MaxSize < 0 {
		errs = append(errs, "storage.max_size must be >= 0")
	}
	if c.Storage.BackupInterval < 0 {
		errs = append(errs, "storage.backup_interval must be >= 0")
	}

	if c.API.Enabled {
		if c.API.Port <= 0 || c.API.Port > 65535 {
			errs = append(errs, "api.port must be in 1..65535 when API is enabled")
		}
		if c.API.Authentication && c.API.APIKey == "" {
			errs = append(errs, "api.api_key must be set when authentication is enabled")
		}
		if c.API.Timeout <= 0 {
			errs = append(errs, "api.timeout must be > 0 when API is enabled")
		}
		if c.API.SSL {
			if c.API.SSLCert == "" || c.API.SSLKey == "" {
				errs = append(errs, "api.ssl_cert and api.ssl_key must be set when api.ssl is true")
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	var (
		data []byte
		err  error
	)
	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(c)
	case ".json":
		data, err = json.MarshalIndent(c, "", "  ")
	default:
		data, err = yaml.Marshal(c)
	}
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("atomically write config: %w", err)
	}
	return nil
}

func (c *Config) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml", "":
		if err := yaml.Unmarshal(data, c); err != nil {
			return fmt.Errorf("parse yaml: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, c); err != nil {
			return fmt.Errorf("parse json: %w", err)
		}
	default:
		if err := yaml.Unmarshal(data, c); err != nil {
			if err2 := json.Unmarshal(data, c); err2 != nil {
				return fmt.Errorf("parse config (yaml/json): %v | %v", err, err2)
			}
		}
	}

	return c.Validate()
}


func (c *Config) GetEnabledDiscoveryMethods() []string {
	return c.Discovery.EnabledMethods
}

func (c *Config) GetEnabledValidationMethods() []string {
	return c.Validation.EnabledMethods
}

func (c *Config) IsMethodEnabled(module, method string) bool {
	switch module {
	case "discovery":
		for _, m := range c.Discovery.EnabledMethods {
			if m == method {
				return true
			}
		}
	case "validation":
		for _, m := range c.Validation.EnabledMethods {
			if m == method {
				return true
			}
		}
	}
	return false
}

package models

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var domainLabelRE = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)

type Subdomain struct {
	ID              string    `json:"id" bson:"_id"`
	Name            string    `json:"name" bson:"name"`
	RootDomain      string    `json:"root_domain" bson:"root_domain"`
	IPAddresses     []string  `json:"ip_addresses" bson:"ip_addresses"`
	Status          string    `json:"status" bson:"status"` 
	DiscoveryMethod string    `json:"discovery_method" bson:"discovery_method"`
	Technologies    []string  `json:"technologies" bson:"technologies"`
	Ports           []Port    `json:"ports" bson:"ports"`
	HTTPStatus      int       `json:"http_status" bson:"http_status"`
	Title           string    `json:"title" bson:"title"`
	Banner          string    `json:"banner" bson:"banner"`
	FirstSeen       time.Time `json:"first_seen" bson:"first_seen"`
	LastSeen        time.Time `json:"last_seen" bson:"last_seen"`
	LastScanned     time.Time `json:"last_scanned" bson:"last_scanned"`
	RiskScore       float64   `json:"risk_score" bson:"risk_score"`
	Tags            []string  `json:"tags" bson:"tags"`
	Metadata        Metadata  `json:"metadata" bson:"metadata"`
}

type Port struct {
	Number   int    `json:"number" bson:"number"`
	Protocol string `json:"protocol" bson:"protocol"`
	Service  string `json:"service" bson:"service"`
	Version  string `json:"version" bson:"version"`
	Banner   string `json:"banner" bson:"banner"`
	Status   string `json:"status" bson:"status"` 
}

type Metadata struct {
	SSL           SSLInfo     `json:"ssl" bson:"ssl"`
	Headers       []Header    `json:"headers" bson:"headers"`
	Cookies       []Cookie    `json:"cookies" bson:"cookies"`
	DNSRecords    []DNSRecord `json:"dns_records" bson:"dns_records"`
	ResponseTime  int64       `json:"response_time" bson:"response_time"` 
	ContentLength int         `json:"content_length" bson:"content_length"`
	ContentType   string      `json:"content_type" bson:"content_type"`
}

type SSLInfo struct {
	Enabled     bool      `json:"enabled" bson:"enabled"`
	Version     string    `json:"version" bson:"version"`
	Cipher      string    `json:"cipher" bson:"cipher"`
	Issuer      string    `json:"issuer" bson:"issuer"`
	Subject     string    `json:"subject" bson:"subject"`
	Expires     time.Time `json:"expires" bson:"expires"`
	AltNames    []string  `json:"alt_names" bson:"alt_names"`
	Fingerprint string    `json:"fingerprint" bson:"fingerprint"`
}


type Header struct {
	Name  string `json:"name" bson:"name"`
	Value string `json:"value" bson:"value"`
}

type Cookie struct {
	Name     string    `json:"name" bson:"name"`
	Value    string    `json:"value" bson:"value"`
	Domain   string    `json:"domain" bson:"domain"`
	Path     string    `json:"path" bson:"path"`
	Expires  time.Time `json:"expires" bson:"expires"`
	Secure   bool      `json:"secure" bson:"secure"`
	HTTPOnly bool      `json:"http_only" bson:"http_only"`
}


type DNSRecord struct {
	Type  string `json:"type" bson:"type"`
	Name  string `json:"name" bson:"name"`
	Value string `json:"value" bson:"value"`
	TTL   int    `json:"ttl" bson:"ttl"`
}

type SubdomainDiscoveryResult struct {
	ScanID       string         `json:"scan_id" bson:"scan_id"`
	TargetDomain string         `json:"target_domain" bson:"target_domain"`
	StartTime    time.Time      `json:"start_time" bson:"start_time"`
	EndTime      time.Time      `json:"end_time" bson:"end_time"`
	Duration     int64          `json:"duration" bson:"duration"` 
	Subdomains   []Subdomain    `json:"subdomains" bson:"subdomains"`
	Stats        DiscoveryStats `json:"stats" bson:"stats"`
}

type DiscoveryStats struct {
	TotalFound    int `json:"total_found" bson:"total_found"`
	ActiveCount   int `json:"active_count" bson:"active_count"`
	InactiveCount int `json:"inactive_count" bson:"inactive_count"`
	NewCount      int `json:"new_count" bson:"new_count"`
}


type SubdomainUpdate struct {
	SubdomainID string                 `json:"subdomain_id" bson:"subdomain_id"`
	Field       string                 `json:"field" bson:"field"`
	OldValue    interface{}            `json:"old_value" bson:"old_value"`
	NewValue    interface{}            `json:"new_value" bson:"new_value"`
	Timestamp   time.Time              `json:"timestamp" bson:"timestamp"`
	Source      string                 `json:"source" bson:"source"`
	Metadata    map[string]interface{} `json:"metadata" bson:"metadata"`
}

type SubdomainListOptions struct {
	Domain        string   `json:"domain" bson:"domain"`
	Status        string   `json:"status" bson:"status"`
	Tags          []string `json:"tags" bson:"tags"`
	Technologies  []string `json:"technologies" bson:"technologies"`
	MinRiskScore  float64  `json:"min_risk_score" bson:"min_risk_score"`
	MaxRiskScore  float64  `json:"max_risk_score" bson:"max_risk_score"`
	Limit         int      `json:"limit" bson:"limit"`
	Offset        int      `json:"offset" bson:"offset"`
	SortBy        string   `json:"sort_by" bson:"sort_by"`
	SortOrder     string   `json:"sort_order" bson:"sort_order"`
}


type SubdomainAnalysis struct {
	SubdomainID  string                 `json:"subdomain_id" bson:"subdomain_id"`
	AnalysisType string                 `json:"analysis_type" bson:"analysis_type"`
	Results      map[string]interface{} `json:"results" bson:"results"`
	RiskLevel    string                 `json:"risk_level" bson:"risk_level"` 
	Confidence   float64                `json:"confidence" bson:"confidence"` 
	Timestamp    time.Time              `json:"timestamp" bson:"timestamp"`
}

func (s *Subdomain) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("subdomain name is required")
	}
	if s.RootDomain == "" {
		return fmt.Errorf("root domain is required")
	}
	if !isValidDomain(s.Name) {
		return fmt.Errorf("invalid subdomain name: %s", s.Name)
	}
	if !isValidDomain(s.RootDomain) {
		return fmt.Errorf("invalid root domain: %s", s.RootDomain)
	}
	if s.Status != "active" && s.Status != "inactive" && s.Status != "unknown" {
		return fmt.Errorf("invalid status: %s", s.Status)
	}
	if s.RiskScore < 0 || s.RiskScore > 10 {
		return fmt.Errorf("risk score must be between 0 and 10")
	}
	return nil
}


func (s *Subdomain) IsActive() bool {
	return s.Status == "active"
}

func (s *Subdomain) HasTechnology(tech string) bool {
	for _, t := range s.Technologies {
		if strings.EqualFold(t, tech) {
			return true
		}
	}
	return false
}

func (s *Subdomain) HasTag(tag string) bool {
	for _, t := range s.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

func (s *Subdomain) HasPort(port int) bool {
	for _, p := range s.Ports {
		if p.Number == port && p.Status == "open" {
			return true
		}
	}
	return false
}

func (s *Subdomain) GetOpenPorts() []Port {
	var openPorts []Port
	for _, port := range s.Ports {
		if port.Status == "open" {
			openPorts = append(openPorts, port)
		}
	}
	return openPorts
}

func (s *Subdomain) GetPort(portNumber int) *Port {
	for i := range s.Ports {
		if s.Ports[i].Number == portNumber {
			return &s.Ports[i]
		}
	}
	return nil
}

func (s *Subdomain) AddTag(tag string) {
	if !s.HasTag(tag) {
		s.Tags = append(s.Tags, tag)
	}
}

func (s *Subdomain) RemoveTag(tag string) {
	for i, t := range s.Tags {
		if strings.EqualFold(t, tag) {
			s.Tags = append(s.Tags[:i], s.Tags[i+1:]...)
			break
		}
	}
}

func (s *Subdomain) AddTechnology(tech string) {
	if !s.HasTechnology(tech) {
		s.Technologies = append(s.Technologies, tech)
	}
}

func (s *Subdomain) RemoveTechnology(tech string) {
	for i, t := range s.Technologies {
		if strings.EqualFold(t, tech) {
			s.Technologies = append(s.Technologies[:i], s.Technologies[i+1:]...)
			break
		}
	}
}

func (s *Subdomain) UpdateStatus(status string) error {
	if status != "active" && status != "inactive" && status != "unknown" {
		return fmt.Errorf("invalid status: %s", status)
	}
	s.Status = status
	s.LastScanned = time.Now()
	return nil
}

func (s *Subdomain) UpdateRiskScore(score float64) error {
	if score < 0 || score > 10 {
		return fmt.Errorf("risk score must be between 0 and 10")
	}
	s.RiskScore = score
	return nil
}

func (s *Subdomain) CalculateRiskScore() float64 {
	score := 0.0
	switch s.Status {
	case "active":
		score += 3.0
	case "inactive":
		score += 1.0
	case "unknown":
		score += 2.0
	}
	risky := map[int]float64{
		21: 0.5, 22: 0.5, 23: 0.5, 25: 0.5, 53: 0.5, 80: 0.5, 110: 0.5, 143: 0.5, 443: 0.5,
		445: 0.5, 993: 0.5, 995: 0.5, 1433: 0.5, 3306: 0.5, 3389: 0.5, 5432: 0.5, 5900: 0.5, 6379: 0.5,
	}
	for _, p := range s.Ports {
		if p.Status == "open" {
			if w, ok := risky[p.Number]; ok {
				score += w
			} else {
				score += 0.2
			}
		}
	}

	for _, tech := range s.Technologies {
		lt := strings.ToLower(tech)
		if strings.Contains(lt, "wordpress") ||
			strings.Contains(lt, "joomla") ||
			strings.Contains(lt, "drupal") ||
			strings.Contains(lt, "php") {
			score += 0.3
		}
	}

	if score > 10 {
		score = 10
	}
	return score
}

func isValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if !domainLabelRE.MatchString(part) {
			return false
		}
		// No leading/trailing hyphen
		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
	}
	return true
}

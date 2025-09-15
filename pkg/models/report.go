package models

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)


const (
	ReportTypeSummary   = "summary"
	ReportTypeDetailed  = "detailed"
	ReportTypeExecutive = "executive"
	ReportTypeTechnical = "technical"
	ReportFormatTXT  = "txt"
	ReportFormatCSV  = "csv"
	ReportFormatJSON = "json"
	ReportFormatHTML = "html"
	ReportFormatPDF  = "pdf"
	ReportStatusPending    = "pending"
	ReportStatusGenerating = "generating"
	ReportStatusCompleted  = "completed"
	ReportStatusFailed     = "failed"
	RiskLevelLow      = "low"
	RiskLevelMedium   = "medium"
	RiskLevelHigh     = "high"
	RiskLevelCritical = "critical"
	DefaultRiskThresholdCritical = 9.0
	DefaultRiskThresholdHigh     = 7.0
	DefaultRiskThresholdMedium   = 4.0
)

var (
	allowedTypes   = map[string]bool{ReportTypeSummary: true, ReportTypeDetailed: true, ReportTypeExecutive: true, ReportTypeTechnical: true}
	allowedFormats = map[string]bool{ReportFormatTXT: true, ReportFormatCSV: true, ReportFormatJSON: true, ReportFormatHTML: true, ReportFormatPDF: true}
	allowedStatus  = map[string]bool{ReportStatusPending: true, ReportStatusGenerating: true, ReportStatusCompleted: true, ReportStatusFailed: true}
	allowedContent = map[string]bool{"text": true, "table": true, "chart": true, "list": true}

	filenameSanitizer = regexp.MustCompile(`[^\w\-.]+`)
)

type Report struct {
	ID          string         `json:"id" bson:"_id"`
	ScanID      string         `json:"scan_id" bson:"scan_id"`
	Title       string         `json:"title" bson:"title"`
	Description string         `json:"description" bson:"description"`
	Type        string         `json:"type" bson:"type"`  
	Format      string         `json:"format" bson:"format"` 
	Status      string         `json:"status" bson:"status"` 
	GeneratedAt time.Time      `json:"generated_at" bson:"generated_at"`
	Duration    int64          `json:"duration" bson:"duration"` 
	Size        int64          `json:"size" bson:"size"`       
	Path        string         `json:"path" bson:"path"`
	URL         string         `json:"url" bson:"url"`
	Metadata    ReportMetadata `json:"metadata" bson:"metadata"`
	Summary     ReportSummary  `json:"summary" bson:"summary"`
	Sections    []ReportSection `json:"sections" bson:"sections"`
	RawData     interface{}    `json:"raw_data,omitempty" bson:"raw_data,omitempty"`
}


type ReportMetadata struct {
	ToolName    string   `json:"tool_name" bson:"tool_name"`
	ToolVersion string   `json:"tool_version" bson:"tool_version"`
	GeneratedBy string   `json:"generated_by" bson:"generated_by"`
	Target      string   `json:"target" bson:"target"`
	Scope       string   `json:"scope" bson:"scope"`
	TimeRange   TimeRange `json:"time_range" bson:"time_range"`
	Tags        []string `json:"tags" bson:"tags"`
}

type TimeRange struct {
	Start time.Time `json:"start" bson:"start"`
	End   time.Time `json:"end" bson:"end"`
}

type ReportSummary struct {
	TotalSubdomains     int     `json:"total_subdomains" bson:"total_subdomains"`
	ActiveSubdomains    int     `json:"active_subdomains" bson:"active_subdomains"`
	NewSubdomains       int     `json:"new_subdomains" bson:"new_subdomains"`
	TotalFindings       int     `json:"total_findings" bson:"total_findings"`
	CriticalFindings    int     `json:"critical_findings" bson:"critical_findings"`
	HighRiskFindings    int     `json:"high_risk_findings" bson:"high_risk_findings"`
	MediumRiskFindings  int     `json:"medium_risk_findings" bson:"medium_risk_findings"`
	LowRiskFindings     int     `json:"low_risk_findings" bson:"low_risk_findings"`
	RiskScore           float64 `json:"risk_score" bson:"risk_score"`
	RiskLevel           string  `json:"risk_level" bson:"risk_level"` 
}


type ReportSection struct {
	ID          string      `json:"id" bson:"id"`
	Title       string      `json:"title" bson:"title"`
	Description string      `json:"description" bson:"description"`
	Order       int         `json:"order" bson:"order"`
	ContentType string      `json:"content_type" bson:"content_type"` 
	Content     interface{} `json:"content" bson:"content"`
	Collapsible bool        `json:"collapsible" bson:"collapsible"`
	Expanded    bool        `json:"expanded" bson:"expanded"`
}


type ReportTemplate struct {
	ID          string                 `json:"id" bson:"_id"`
	Name        string                 `json:"name" bson:"name"`
	Description string                 `json:"description" bson:"description"`
	Type        string                 `json:"type" bson:"type"`
	Format      string                 `json:"format" bson:"format"`
	Version     string                 `json:"version" bson:"version"`
	Author      string                 `json:"author" bson:"author"`
	Sections    []TemplateSection      `json:"sections" bson:"sections"`
	Styles      map[string]interface{} `json:"styles" bson:"styles"`
	Settings    map[string]interface{} `json:"settings" bson:"settings"`
}

type TemplateSection struct {
	ID          string `json:"id" bson:"id"`
	Title       string `json:"title" bson:"title"`
	Description string `json:"description" bson:"description"`
	Order       int    `json:"order" bson:"order"`
	ContentType string `json:"content_type" bson:"content_type"`
	Required    bool   `json:"required" bson:"required"`
	Default     bool   `json:"default" bson:"default"`
}

type ReportRequest struct {
	ScanID         string                 `json:"scan_id" bson:"scan_id"`
	TemplateID     string                 `json:"template_id" bson:"template_id"`
	Format         string                 `json:"format" bson:"format"`
	Sections       []string               `json:"sections" bson:"sections"`
	IncludeRawData bool                   `json:"include_raw_data" bson:"include_raw_data"`
	Parameters     map[string]interface{} `json:"parameters" bson:"parameters"`
}

type ReportExport struct {
	ID            string    `json:"id" bson:"_id"`
	ReportID      string    `json:"report_id" bson:"report_id"`
	Format        string    `json:"format" bson:"format"`
	ExportedAt    time.Time `json:"exported_at" bson:"exported_at"`
	Size          int64     `json:"size" bson:"size"`
	Path          string    `json:"path" bson:"path"`
	URL           string    `json:"url" bson:"url"`
	DownloadCount int       `json:"download_count" bson:"download_count"`
}

type ReportSchedule struct {
	ID          string    `json:"id" bson:"_id"`
	Name        string    `json:"name" bson:"name"`
	Description string    `json:"description" bson:"description"`
	Enabled     bool      `json:"enabled" bson:"enabled"`
	Schedule    string    `json:"schedule" bson:"schedule"` 
	TemplateID  string    `json:"template_id" bson:"template_id"`
	Format      string    `json:"format" bson:"format"`
	Recipients  []string  `json:"recipients" bson:"recipients"`
	LastRun     time.Time `json:"last_run" bson:"last_run"`
	NextRun     time.Time `json:"next_run" bson:"next_run"`
}


type ReportStatistics struct {
	TotalReports    int            `json:"total_reports" bson:"total_reports"`
	ReportsByType   map[string]int `json:"reports_by_type" bson:"reports_by_type"`
	ReportsByFormat map[string]int `json:"reports_by_format" bson:"reports_by_format"`
	ReportsByStatus map[string]int `json:"reports_by_status" bson:"reports_by_status"`
	AverageSize     int64          `json:"average_size" bson:"average_size"`
	TotalSize       int64          `json:"total_size" bson:"total_size"`
	GenerationTime  TimeStats      `json:"generation_time" bson:"generation_time"`
}


type TimeStats struct {
	Min    int64 `json:"min" bson:"min"`
	Max    int64 `json:"max" bson:"max"`
	Avg    int64 `json:"avg" bson:"avg"`
	Median int64 `json:"median" bson:"median"`
	P95    int64 `json:"p95" bson:"p95"`
	P99    int64 `json:"p99" bson:"p99"`
}

func (r *Report) Validate() error {
	var problems []string

	if r.ScanID == "" {
		problems = append(problems, "scan ID is required")
	}
	if r.Title == "" {
		problems = append(problems, "report title is required")
	}
	if !allowedTypes[r.Type] {
		problems = append(problems, fmt.Sprintf("invalid report type: %s", r.Type))
	}
	if !allowedFormats[r.Format] {
		problems = append(problems, fmt.Sprintf("invalid report format: %s", r.Format))
	}
	if r.Status == "" {
		problems = append(problems, "report status is required")
	} else if !allowedStatus[r.Status] {
		problems = append(problems, fmt.Sprintf("invalid report status: %s", r.Status))
	}
	if r.Duration < 0 {
		problems = append(problems, "duration cannot be negative")
	}
	if r.Size < 0 {
		problems = append(problems, "size cannot be negative")
	}
	if r.Summary.RiskScore < 0 || r.Summary.RiskScore > 10 {
		problems = append(problems, "summary.risk_score must be in [0,10]")
	}
	if r.Summary.RiskLevel != "" &&
		r.Summary.RiskLevel != RiskLevelLow &&
		r.Summary.RiskLevel != RiskLevelMedium &&
		r.Summary.RiskLevel != RiskLevelHigh &&
		r.Summary.RiskLevel != RiskLevelCritical {
		problems = append(problems, fmt.Sprintf("invalid summary.risk_level: %s", r.Summary.RiskLevel))
	}

	seen := make(map[string]struct{}, len(r.Sections))
	for i, s := range r.Sections {
		if s.ID == "" {
			problems = append(problems, fmt.Sprintf("section %d has empty id", i))
		} else {
			if _, ok := seen[s.ID]; ok {
				problems = append(problems, fmt.Sprintf("duplicate section id: %s", s.ID))
			}
			seen[s.ID] = struct{}{}
		}
		if s.Title == "" {
			problems = append(problems, fmt.Sprintf("section %q title is required", s.ID))
		}
		if !allowedContent[s.ContentType] {
			problems = append(problems, fmt.Sprintf("section %q invalid content_type: %s", s.ID, s.ContentType))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("report validation failed:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

func (r *Report) IsCompleted() bool { return r.Status == ReportStatusCompleted }

func (r *Report) IsFailed() bool { return r.Status == ReportStatusFailed }

func (r *Report) IsPending() bool { return r.Status == ReportStatusPending }

func (r *Report) AddSection(section ReportSection) {
	r.Sections = append(r.Sections, section)
}

func (r *Report) RemoveSection(sectionID string) {
	for i := range r.Sections {
		if r.Sections[i].ID == sectionID {
			r.Sections = append(r.Sections[:i], r.Sections[i+1:]...)
			return
		}
	}
}

func (r *Report) GetSection(sectionID string) *ReportSection {
	for i := range r.Sections {
		if r.Sections[i].ID == sectionID {
			return &r.Sections[i]
		}
	}
	return nil
}

func (r *Report) SortSections() {
	sort.SliceStable(r.Sections, func(i, j int) bool { return r.Sections[i].Order < r.Sections[j].Order })
}

func (r *Report) UpdateSummary(summary ReportSummary) { r.Summary = summary }

func (r *Report) CalculateRiskLevel() string {
	return riskLevelFromScore(r.Summary.RiskScore)
}

func (r *Report) GenerateFileName() string {
	tgt := r.Metadata.Target
	if tgt == "" {
		tgt = "unknown"
	}
	tgt = strings.ToLower(filenameSanitizer.ReplaceAllString(tgt, "_"))

	typ := r.Type
	if typ == "" {
		typ = ReportTypeDetailed
	}

	ext := r.Format
	if ext == "" {
		ext = ReportFormatJSON
	}

	ts := r.GeneratedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	timestamp := ts.Format("20060102_150405")

	return fmt.Sprintf("sublynx_%s_%s_%s.%s", tgt, typ, timestamp, ext)
}

func (r *Report) GetDurationString() string {
	d := time.Duration(r.Duration) * time.Millisecond
	return fmt.Sprintf("%.2f seconds", d.Seconds())
}

func (r *Report) GetSizeString() string {
	const unit = 1024
	if r.Size < unit {
		return fmt.Sprintf("%d B", r.Size)
	}
	div, exp := int64(unit), 0
	for n := r.Size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.2f %s", float64(r.Size)/float64(div), units[exp])
}

func DefaultReportTemplate() *ReportTemplate {
	return &ReportTemplate{
		ID:          "default",
		Name:        "Default Report Template",
		Description: "Default template for SubLynx reports",
		Type:        ReportTypeDetailed,
		Format:      ReportFormatJSON,
		Version:     "1.0",
		Author:      "SubLynx",
		Sections: []TemplateSection{
			{
				ID:          "executive_summary",
				Title:       "Executive Summary",
				Description: "High-level overview of the scan results",
				Order:       1,
				ContentType: "text",
				Required:    true,
				Default:     true,
			},
			{
				ID:          "subdomain_list",
				Title:       "Discovered Subdomains",
				Description: "List of all discovered subdomains",
				Order:       2,
				ContentType: "table",
				Required:    true,
				Default:     true,
			},
			{
				ID:          "findings",
				Title:       "Security Findings",
				Description: "Detailed security findings and vulnerabilities",
				Order:       3,
				ContentType: "table",
				Required:    true,
				Default:     true,
			},
			{
				ID:          "recommendations",
				Title:       "Recommendations",
				Description: "Security recommendations and remediation steps",
				Order:       4,
				ContentType: "list",
				Required:    true,
				Default:     true,
			},
			{
				ID:          "technical_details",
				Title:       "Technical Details",
				Description: "Technical details and evidence",
				Order:       5,
				ContentType: "text",
				Required:    false,
				Default:     false,
			},
		},
		Styles: map[string]interface{}{
			"font_family": "Arial, sans-serif",
			"font_size":   "12pt",
			"colors": map[string]string{
				"primary":   "#2c3e50",
				"secondary": "#3498db",
				"success":   "#27ae60",
				"warning":   "#f39c12",
				"danger":    "#e74c3c",
			},
		},
		Settings: map[string]interface{}{
			"include_raw_data": false,
			"compress_output":  true,
			"password_protect": false,
		},
	}
}


func riskLevelFromScore(score float64) string {
	switch {
	case score >= DefaultRiskThresholdCritical:
		return RiskLevelCritical
	case score >= DefaultRiskThresholdHigh:
		return RiskLevelHigh
	case score >= DefaultRiskThresholdMedium:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

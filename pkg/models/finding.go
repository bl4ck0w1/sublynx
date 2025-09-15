package models

import (
	"fmt"
	"strings"
	"time"
)

type Finding struct {
	ID            string                 `json:"id" bson:"_id"`
	Type          string                 `json:"type" bson:"type"`
	Title         string                 `json:"title" bson:"title"`
	Description   string                 `json:"description" bson:"description"`
	Severity      string                 `json:"severity" bson:"severity"`           
	Confidence    float64                `json:"confidence" bson:"confidence"`       
	Status        string                 `json:"status" bson:"status"`               
	Target        string                 `json:"target" bson:"target"`
	TargetType    string                 `json:"target_type" bson:"target_type"`     
	Evidence      map[string]interface{} `json:"evidence" bson:"evidence"`
	Impact        string                 `json:"impact" bson:"impact"`
	Remediation   string                 `json:"remediation" bson:"remediation"`
	References    []string               `json:"references" bson:"references"`
	CVE           string                 `json:"cve" bson:"cve"`
	CVSS          float64                `json:"cvss" bson:"cvss"`
	OWASP         string                 `json:"owasp" bson:"owasp"`
	WASC          string                 `json:"wasc" bson:"wasc"`
	Tags          []string               `json:"tags" bson:"tags"`
	Source        string                 `json:"source" bson:"source"`
	Scanner       string                 `json:"scanner" bson:"scanner"`
	ScanID        string                 `json:"scan_id" bson:"scan_id"`
	FirstSeen     time.Time              `json:"first_seen" bson:"first_seen"`
	LastSeen      time.Time              `json:"last_seen" bson:"last_seen"`
	ResolvedAt    time.Time              `json:"resolved_at" bson:"resolved_at"`
	ResolvedBy    string                 `json:"resolved_by" bson:"resolved_by"`
	RiskScore     float64                `json:"risk_score" bson:"risk_score"`
	FalsePositive bool                   `json:"false_positive" bson:"false_positive"`
	RiskAccepted  bool                   `json:"risk_accepted" bson:"risk_accepted"`
	Metadata      map[string]interface{} `json:"metadata" bson:"metadata"`
}


type FindingListOptions struct {
	Severity      string   `json:"severity" bson:"severity"`
	Status        string   `json:"status" bson:"status"`
	Target        string   `json:"target" bson:"target"`
	Type          string   `json:"type" bson:"type"`
	Tags          []string `json:"tags" bson:"tags"`
	Source        string   `json:"source" bson:"source"`
	Scanner       string   `json:"scanner" bson:"scanner"`
	MinConfidence float64  `json:"min_confidence" bson:"min_confidence"`
	MaxConfidence float64  `json:"max_confidence" bson:"max_confidence"`
	MinRiskScore  float64  `json:"min_risk_score" bson:"min_risk_score"`
	MaxRiskScore  float64  `json:"max_risk_score" bson:"max_risk_score"`
	Limit         int      `json:"limit" bson:"limit"`
	Offset        int      `json:"offset" bson:"offset"`
	SortBy        string   `json:"sort_by" bson:"sort_by"`
	SortOrder     string   `json:"sort_order" bson:"sort_order"` 
}


type FindingStats struct {
	Total         int            `json:"total" bson:"total"`
	BySeverity    map[string]int `json:"by_severity" bson:"by_severity"`
	ByStatus      map[string]int `json:"by_status" bson:"by_status"`
	ByType        map[string]int `json:"by_type" bson:"by_type"`
	ByTarget      map[string]int `json:"by_target" bson:"by_target"`
	OpenCount     int            `json:"open_count" bson:"open_count"`
	ResolvedCount int            `json:"resolved_count" bson:"resolved_count"`
	RiskScore     float64        `json:"risk_score" bson:"risk_score"`
}


type FindingUpdate struct {
	FindingID string                 `json:"finding_id" bson:"finding_id"`
	Field     string                 `json:"field" bson:"field"`
	OldValue  interface{}            `json:"old_value" bson:"old_value"`
	NewValue  interface{}            `json:"new_value" bson:"new_value"`
	Timestamp time.Time              `json:"timestamp" bson:"timestamp"`
	UpdatedBy string                 `json:"updated_by" bson:"updated_by"`
	Reason    string                 `json:"reason" bson:"reason"`
	Metadata  map[string]interface{} `json:"metadata" bson:"metadata"`
}


func (f *Finding) Validate() error {
	if f.Title == "" {
		return fmt.Errorf("finding title is required")
	}
	if f.Type == "" {
		return fmt.Errorf("finding type is required")
	}
	if f.Target == "" {
		return fmt.Errorf("finding target is required")
	}

	switch f.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("invalid severity: %s", f.Severity)
	}

	if f.Confidence < 0 || f.Confidence > 100 {
		return fmt.Errorf("confidence must be between 0 and 100")
	}

	switch f.Status {
	case "open", "in_progress", "resolved", "false_positive", "risk_accepted":
	default:
		return fmt.Errorf("invalid status: %s", f.Status)
	}

	if f.RiskScore < 0 || f.RiskScore > 10 {
		return fmt.Errorf("risk score must be between 0 and 10")
	}

	return nil
}


func (f *Finding) IsOpen() bool {
	return f.Status == "open" || f.Status == "in_progress"
}


func (f *Finding) IsResolved() bool {
	return f.Status == "resolved" || f.Status == "false_positive" || f.Status == "risk_accepted"
}


func (f *Finding) IsFalsePositive() bool {
	return f.Status == "false_positive" || f.FalsePositive
}

func (f *Finding) IsRiskAccepted() bool {
	return f.Status == "risk_accepted" || f.RiskAccepted
}

func (f *Finding) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

func (f *Finding) AddTag(tag string) {
	if !f.HasTag(tag) {
		f.Tags = append(f.Tags, tag)
	}
}

func (f *Finding) RemoveTag(tag string) {
	for i, t := range f.Tags {
		if strings.EqualFold(t, tag) {
			f.Tags = append(f.Tags[:i], f.Tags[i+1:]...)
			break
		}
	}
}

func (f *Finding) UpdateStatus(status, updatedBy, reason string) error {
	switch status {
	case "open", "in_progress", "resolved", "false_positive", "risk_accepted":
	default:
		return fmt.Errorf("invalid status: %s", status)
	}

	now := time.Now()
	f.Status = status
	f.LastSeen = now


	if f.Metadata == nil {
		f.Metadata = make(map[string]interface{})
	}
	if reason != "" {
		f.Metadata["status_reason"] = reason
		f.Metadata["status_updated_at"] = now
		f.Metadata["status_updated_by"] = updatedBy
	}

	switch status {
	case "resolved", "false_positive", "risk_accepted":
		f.ResolvedAt = now
		f.ResolvedBy = updatedBy
		f.FalsePositive = (status == "false_positive")
		f.RiskAccepted = (status == "risk_accepted")
	default:
		//do not flip resolution flags.
	}

	return nil
}

func (f *Finding) UpdateSeverity(severity string) error {
	switch severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("invalid severity: %s", severity)
	}
	f.Severity = severity
	return nil
}

func (f *Finding) UpdateConfidence(confidence float64) error {
	if confidence < 0 || confidence > 100 {
		return fmt.Errorf("confidence must be between 0 and 100")
	}
	f.Confidence = confidence
	return nil
}

func (f *Finding) UpdateRiskScore(score float64) error {
	if score < 0 || score > 10 {
		return fmt.Errorf("risk score must be between 0 and 10")
	}
	f.RiskScore = score
	return nil
}


func (f *Finding) CalculateRiskScore() float64 {
	severityScores := map[string]float64{
		"info":     1.0,
		"low":      3.0,
		"medium":   5.0,
		"high":     7.5,
		"critical": 10.0,
	}
	base, ok := severityScores[f.Severity]
	if !ok {
		base = 1.0
	}

	conf := f.Confidence
	if conf < 0 {
		conf = 0
	} else if conf > 100 {
		conf = 100
	}

	adjusted := base * (conf / 100.0)
	if adjusted > 10 {
		adjusted = 10
	}
	return adjusted
}

func (f *Finding) AddEvidence(key string, value interface{}) {
	if f.Evidence == nil {
		f.Evidence = make(map[string]interface{})
	}
	f.Evidence[key] = value
}

func (f *Finding) RemoveEvidence(key string) {
	if f.Evidence != nil {
		delete(f.Evidence, key)
	}
}

func (f *Finding) AddReference(reference string) {
	for _, ref := range f.References {
		if ref == reference {
			return
		}
	}
	f.References = append(f.References, reference)
}

func (f *Finding) RemoveReference(reference string) {
	for i, ref := range f.References {
		if ref == reference {
			f.References = append(f.References[:i], f.References[i+1:]...)
			break
		}
	}
}

func (f *Finding) GetCVELink() string {
	if f.CVE == "" {
		return ""
	}
	return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", f.CVE)
}


func (f *Finding) GetOWASPLink() string {
	if f.OWASP == "" {
		return ""
	}
	return fmt.Sprintf("https://owasp.org/www-project-top-ten/%s", f.OWASP)
}

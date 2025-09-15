package models

import "time"

type ScanStats struct {
	TotalSubdomains    int     `json:"total_subdomains" bson:"total_subdomains"`
	ActiveSubdomains   int     `json:"active_subdomains" bson:"active_subdomains"`
	TotalFindings      int     `json:"total_findings" bson:"total_findings"`
	CriticalFindings   int     `json:"critical_findings" bson:"critical_findings"`
	HighRiskFindings   int     `json:"high_risk_findings" bson:"high_risk_findings"`
	MediumRiskFindings int     `json:"medium_risk_findings" bson:"medium_risk_findings"`
	LowRiskFindings    int     `json:"low_risk_findings" bson:"low_risk_findings"`
	RiskScore          float64 `json:"risk_score" bson:"risk_score"`
}

type ScanResult struct {
	ScanID       string      `json:"scan_id" bson:"scan_id"`
	TargetDomain string      `json:"target_domain" bson:"target_domain"`
	StartTime    time.Time   `json:"start_time" bson:"start_time"`
	EndTime      time.Time   `json:"end_time" bson:"end_time"`
	Status       string      `json:"status" bson:"status"`
	Subdomains   []Subdomain `json:"subdomains" bson:"subdomains"`
	Findings     []Finding   `json:"findings" bson:"findings"`
	Stats        ScanStats   `json:"stats" bson:"stats"`
}

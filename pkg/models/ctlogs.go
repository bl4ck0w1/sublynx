package models

import (
	"time"
)

type CTLog struct {
	ID          string    `json:"id"           yaml:"id"`
	URL         string    `json:"url"          yaml:"url"`
	Name        string    `json:"name"         yaml:"name"`
	Operator    string    `json:"operator"     yaml:"operator"`
	Description string    `json:"description"  yaml:"description,omitempty"`
	State       LogState  `json:"state"        yaml:"state"`
	PublicKey   string    `json:"public_key"   yaml:"public_key,omitempty"` 
	MaxEntries  int       `json:"max_entries"  yaml:"max_entries,omitempty"`
	LastSync    time.Time `json:"last_sync"    yaml:"last_sync,omitempty"`
	Priority    int       `json:"priority"     yaml:"priority,omitempty"` 
}

type LogState string

const (
	LogStatePending   LogState = "pending"
	LogStateQualified LogState = "qualified"
	LogStateUsable    LogState = "usable"
	LogStateReadOnly  LogState = "readonly"
	LogStateRetired   LogState = "retired"
	LogStateRejected  LogState = "rejected"
)

func (s LogState) IsUsable() bool {
	return s == LogStateUsable || s == LogStateReadOnly
}

type CTLogEntry struct {
	ID               string    `json:"id"`                           
	LogID            string    `json:"log_id"`                      
	Timestamp        time.Time `json:"timestamp"`                    
	Domain           string    `json:"domain"`                      
	Subdomains       []string  `json:"subdomains"`                   
	CertificateHash  string    `json:"certificate_hash"`             
	Issuer           string    `json:"issuer,omitempty"`            
	ValidationStatus string    `json:"validation_status,omitempty"`  
	RawEntry         []byte    `json:"raw_entry,omitempty"`          
}

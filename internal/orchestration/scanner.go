package orchestration

import (
	"context"
	"fmt"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/internal/discovery"
	"github.com/bl4ck0w1/sublynx/internal/evasion"
	"github.com/bl4ck0w1/sublynx/internal/validation"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type Scanner struct {
	discoveryManager  *discovery.Manager
	validationManager *validation.Manager
	evasionManager    *evasion.Manager
	workflowManager   *WorkflowManager
	priorityScheduler *PriorityScheduler
	resourceOptimizer *ResourceOptimizer
	logger            *logrus.Logger
	mu                sync.RWMutex
	activeScans       map[string]*ScanContext
	scanConfig        ScanConfig
}

type ScanContext struct {
	ScanID       string
	TargetDomain string
	StartTime    time.Time
	Status       string
	Progress     float64
	Results      *models.ScanResult
	CancelFunc   context.CancelFunc
}

type ScanConfig struct {
	MaxConcurrentScans int           `yaml:"max_concurrent_scans" json:"max_concurrent_scans"`
	DefaultTimeout     time.Duration `yaml:"default_timeout" json:"default_timeout"`
	RetryAttempts      int           `yaml:"retry_attempts" json:"retry_attempts"`
	RateLimit          int           `yaml:"rate_limit" json:"rate_limit"`
	ValidationDepth    int           `yaml:"validation_depth" json:"validation_depth"`
}

func NewScanner(
	discoveryManager *discovery.Manager,
	validationManager *validation.Manager,
	evasionManager *evasion.Manager,
	config ScanConfig,
	logger *logrus.Logger,
) *Scanner {
	if logger == nil {
		logger = logrus.New()
	}

	scanner := &Scanner{
		discoveryManager:  discoveryManager,
		validationManager: validationManager,
		evasionManager:    evasionManager,
		workflowManager:   NewWorkflowManager(logger),
		priorityScheduler: NewPriorityScheduler(logger),
		resourceOptimizer: NewResourceOptimizer(logger),
		logger:            logger,
		activeScans:       make(map[string]*ScanContext),
		scanConfig:        config,
	}

	scanner.workflowManager.SetDiscoveryManager(discoveryManager)
	scanner.workflowManager.SetValidationManager(validationManager)
	scanner.workflowManager.initializeWorkflows() 

	scanner.priorityScheduler.SetMaxConcurrent(config.MaxConcurrentScans)
	scanner.resourceOptimizer.SetRateLimit(config.RateLimit)

	return scanner
}

func (s *Scanner) StartScan(ctx context.Context, targetDomain string, options ScanOptions) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	scanID := generateScanID(targetDomain)

	if _, exists := s.activeScans[scanID]; exists {
		return "", fmt.Errorf("scan already exists for domain: %s", targetDomain)
	}

	scanCtx, cancel := context.WithTimeout(ctx, s.scanConfig.DefaultTimeout)
	scanContext := &ScanContext{
		ScanID:       scanID,
		TargetDomain: targetDomain,
		StartTime:    time.Now(),
		Status:       "initializing",
		Progress:     0,
		CancelFunc:   cancel,
	}

	s.activeScans[scanID] = scanContext
	go s.executeScan(scanCtx, scanContext, options)

	return scanID, nil
}

func (s *Scanner) executeScan(ctx context.Context, scanContext *ScanContext, options ScanOptions) {
	defer func() {
		s.mu.Lock()
		delete(s.activeScans, scanContext.ScanID)
		s.mu.Unlock()
		scanContext.CancelFunc()
	}()

	s.updateScanProgress(scanContext, "discovery", 10)
	subdomains, err := s.discoveryPhase(ctx, scanContext.TargetDomain, options)
	if err != nil {
		s.logger.Errorf("Discovery phase failed for %s: %v", scanContext.TargetDomain, err)
		s.updateScanProgress(scanContext, "failed", 100)
		return
	}

	s.updateScanProgress(scanContext, "validation", 40)
	validatedSubdomains, findings, err := s.validationPhase(ctx, subdomains, options)
	if err != nil {
		s.logger.Errorf("Validation phase failed for %s: %v", scanContext.TargetDomain, err)
		s.updateScanProgress(scanContext, "failed", 100)
		return
	}

	s.updateScanProgress(scanContext, "analysis", 80)
	result, err := s.analysisPhase(ctx, scanContext, validatedSubdomains, findings, options)
	if err != nil {
		s.logger.Errorf("Analysis phase failed for %s: %v", scanContext.TargetDomain, err)
		s.updateScanProgress(scanContext, "failed", 100)
		return
	}

	s.mu.Lock()
	scanContext.Results = result
	scanContext.Status = "completed"
	scanContext.Progress = 100
	s.mu.Unlock()

	s.logger.Infof("Scan completed for %s: %d subdomains found, %d findings",
		scanContext.TargetDomain, len(validatedSubdomains), len(findings))
}

func (s *Scanner) discoveryPhase(ctx context.Context, targetDomain string, options ScanOptions) ([]models.Subdomain, error) {
	s.logger.Infof("Starting discovery phase for %s", targetDomain)

	workflow := s.workflowManager.GetDiscoveryWorkflow(options.DiscoveryMethods)
	subdomains, err := workflow.Execute(ctx, targetDomain)
	if err != nil {
		return nil, fmt.Errorf("discovery workflow failed: %w", err)
	}

	s.logger.Infof("Discovery phase completed for %s: %d subdomains found", targetDomain, len(subdomains))
	return subdomains, nil
}

func (s *Scanner) validationPhase(ctx context.Context, subdomains []models.Subdomain, options ScanOptions) ([]models.Subdomain, []models.Finding, error) {
	s.logger.Infof("Starting validation phase for %d subdomains", len(subdomains))

	workflow := s.workflowManager.GetValidationWorkflow(options.ValidationMethods, s.scanConfig.ValidationDepth)
	validatedSubdomains, findings, err := workflow.Execute(ctx, subdomains)
	if err != nil {
		return nil, nil, fmt.Errorf("validation workflow failed: %w", err)
	}

	s.logger.Infof("Validation phase completed: %d active subdomains, %d findings",
		len(validatedSubdomains), len(findings))
	return validatedSubdomains, findings, nil
}

func (s *Scanner) analysisPhase(ctx context.Context, scanContext *ScanContext, subdomains []models.Subdomain, findings []models.Finding, options ScanOptions) (*models.ScanResult, error) {
	s.logger.Infof("Starting analysis phase for %d subdomains and %d findings", len(subdomains), len(findings))

	targetDomain := scanContext.TargetDomain
	scanID := scanContext.ScanID

	result := &models.ScanResult{
		ScanID:       scanID,
		TargetDomain: targetDomain,
		StartTime:    scanContext.StartTime,
		EndTime:      time.Now(),
		Status:       "completed",
		Subdomains:   subdomains,
		Findings:     findings,
		Stats: models.ScanStats{
			TotalSubdomains:    len(subdomains),
			ActiveSubdomains:   countActiveSubdomains(subdomains),
			TotalFindings:      len(findings),
			CriticalFindings:   countFindingsBySeverity(findings, "critical"),
			HighRiskFindings:   countFindingsBySeverity(findings, "high"),
			MediumRiskFindings: countFindingsBySeverity(findings, "medium"),
			LowRiskFindings:    countFindingsBySeverity(findings, "low"),
		},
	}

	result.Stats.RiskScore = calculateRiskScore(findings)

	s.logger.Infof("Analysis phase completed for %s: risk score %.2f", targetDomain, result.Stats.RiskScore)
	return result, nil
}

func (s *Scanner) GetScanStatus(scanID string) (*ScanContext, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scanContext, exists := s.activeScans[scanID]
	if !exists {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}

	return scanContext, nil
}

func (s *Scanner) CancelScan(scanID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	scanContext, exists := s.activeScans[scanID]
	if !exists {
		return fmt.Errorf("scan not found: %s", scanID)
	}

	scanContext.CancelFunc()
	scanContext.Status = "cancelled"
	scanContext.Progress = 100

	delete(s.activeScans, scanID)

	s.logger.Infof("Scan cancelled: %s", scanID)
	return nil
}

func (s *Scanner) ListActiveScans() []*ScanContext {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scans := make([]*ScanContext, 0, len(s.activeScans))
	for _, scan := range s.activeScans {
		scans = append(scans, scan)
	}

	return scans
}

func (s *Scanner) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"active_scans":     len(s.activeScans),
		"max_concurrent":   s.scanConfig.MaxConcurrentScans,
		"default_timeout":  s.scanConfig.DefaultTimeout.String(),
		"retry_attempts":   s.scanConfig.RetryAttempts,
		"rate_limit":       s.scanConfig.RateLimit,
		"validation_depth": s.scanConfig.ValidationDepth,
	}

	activeScanDetails := make([]map[string]interface{}, 0)
	for _, scan := range s.activeScans {
		activeScanDetails = append(activeScanDetails, map[string]interface{}{
			"scan_id":    scan.ScanID,
			"domain":     scan.TargetDomain,
			"status":     scan.Status,
			"progress":   scan.Progress,
			"start_time": scan.StartTime,
		})
	}
	stats["active_scan_details"] = activeScanDetails

	return stats
}

func (s *Scanner) UpdateConfig(config ScanConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.scanConfig = config
	s.priorityScheduler.SetMaxConcurrent(config.MaxConcurrentScans)
	s.resourceOptimizer.SetRateLimit(config.RateLimit)
}

func (s *Scanner) updateScanProgress(scanContext *ScanContext, status string, progress float64) {
	s.mu.Lock()
	scanContext.Status = status
	scanContext.Progress = progress
	s.mu.Unlock()
}

func generateScanID(targetDomain string) string {
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("scan_%s_%s", targetDomain, timestamp)
}

func countActiveSubdomains(subdomains []models.Subdomain) int {
	count := 0
	for _, subdomain := range subdomains {
		if subdomain.Status == "active" {
			count++
		}
	}
	return count
}

func countFindingsBySeverity(findings []models.Finding, severity string) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
}

func calculateRiskScore(findings []models.Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	totalScore := 0.0
	severityWeights := map[string]float64{
		"critical": 10.0,
		"high":     7.5,
		"medium":   5.0,
		"low":      2.5,
		"info":     1.0,
	}

	for _, finding := range findings {
		if weight, ok := severityWeights[finding.Severity]; ok {
			totalScore += weight
		}
	}

	averageScore := totalScore / float64(len(findings))
	if averageScore > 10.0 {
		return 10.0
	}
	return averageScore
}

type ScanOptions struct {
	DiscoveryMethods  []string `json:"discovery_methods"`
	ValidationMethods []string `json:"validation_methods"`
	EvasionTechniques []string `json:"evasion_techniques"`
	Depth             int      `json:"depth"`
	Priority          int      `json:"priority"`
}

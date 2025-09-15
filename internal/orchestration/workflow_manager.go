package orchestration

import (
	"context"
	"fmt"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/internal/discovery"
	"github.com/bl4ck0w1/sublynx/internal/validation"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type WorkflowManager struct {
	logger              *logrus.Logger
	discoveryWorkflows  map[string]DiscoveryWorkflow
	validationWorkflows map[string]ValidationWorkflow
	mu                  sync.RWMutex

	discoveryMgr  *discovery.Manager
	validationMgr *validation.Manager
}

type DiscoveryWorkflow interface {
	Execute(ctx context.Context, targetDomain string) ([]models.Subdomain, error)
}

type ValidationWorkflow interface {
	Execute(ctx context.Context, subdomains []models.Subdomain) ([]models.Subdomain, []models.Finding, error)
}

func NewWorkflowManager(logger *logrus.Logger) *WorkflowManager {
	if logger == nil {
		logger = logrus.New()
	}

	wm := &WorkflowManager{
		logger:              logger,
		discoveryWorkflows:  make(map[string]DiscoveryWorkflow),
		validationWorkflows: make(map[string]ValidationWorkflow),
	}

	wm.initializeWorkflows()

	return wm
}

func (wm *WorkflowManager) SetDiscoveryManager(m *discovery.Manager) { wm.mu.Lock(); defer wm.mu.Unlock() wm.discoveryMgr = m }
func (wm *WorkflowManager) SetValidationManager(m *validation.Manager) { wm.mu.Lock(); defer wm.mu.Unlock() wm.validationMgr = m }

func (wm *WorkflowManager) initializeWorkflows() {
	wm.discoveryWorkflows["standard"] = &StandardDiscoveryWorkflow{
		logger:  wm.logger,
		timeout: 3 * time.Minute,
		mgr:     wm.discoveryMgr,
	}
	wm.discoveryWorkflows["comprehensive"] = &ComprehensiveDiscoveryWorkflow{
		logger:  wm.logger,
		timeout: 6 * time.Minute,
		mgr:     wm.discoveryMgr,
	}
	wm.discoveryWorkflows["stealth"] = &StealthDiscoveryWorkflow{
		logger:  wm.logger,
		timeout: 5 * time.Minute,
		mgr:     wm.discoveryMgr,
	}

	wm.validationWorkflows["standard"] = &StandardValidationWorkflow{
		logger:  wm.logger,
		timeout: 5 * time.Minute,
		mgr:     wm.validationMgr,
	}
	wm.validationWorkflows["comprehensive"] = &ComprehensiveValidationWorkflow{
		logger:  wm.logger,
		timeout: 10 * time.Minute,
		mgr:     wm.validationMgr,
	}
	wm.validationWorkflows["quick"] = &QuickValidationWorkflow{
		logger:  wm.logger,
		timeout: 2 * time.Minute,
		mgr:     wm.validationMgr,
	}
}

func (wm *WorkflowManager) GetDiscoveryWorkflow(methods []string) DiscoveryWorkflow {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if len(methods) == 0 {
		return wm.discoveryWorkflows["standard"]
	}

	if contains(methods, "comprehensive") {
		return wm.discoveryWorkflows["comprehensive"]
	}
	if contains(methods, "stealth") {
		return wm.discoveryWorkflows["stealth"]
	}

	parts := make([]DiscoveryWorkflow, 0, len(methods))
	for _, m := range methods {
		if wf, ok := wm.discoveryWorkflows[m]; ok {
			parts = append(parts, wf)
		}
	}
	if len(parts) == 0 {
		return wm.discoveryWorkflows["standard"]
	}

	return &CompositeDiscoveryWorkflow{
		logger: wm.logger,
		parts:  parts,
	}
}

func (wm *WorkflowManager) GetValidationWorkflow(methods []string, depth int) ValidationWorkflow {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	if len(methods) == 0 {
		if depth <= 1 {
			return wm.validationWorkflows["quick"]
		}
		if depth >= 3 {
			return wm.validationWorkflows["comprehensive"]
		}
		return wm.validationWorkflows["standard"]
	}

	if contains(methods, "comprehensive") || depth >= 3 {
		return wm.validationWorkflows["comprehensive"]
	}
	if contains(methods, "quick") || depth <= 1 {
		return wm.validationWorkflows["quick"]
	}

	parts := make([]ValidationWorkflow, 0, len(methods))
	for _, m := range methods {
		if wf, ok := wm.validationWorkflows[m]; ok {
			parts = append(parts, wf)
		}
	}
	if len(parts) == 0 {
		return wm.validationWorkflows["standard"]
	}
	return &CompositeValidationWorkflow{
		logger: wm.logger,
		parts:  parts,
	}
}

type StandardDiscoveryWorkflow struct {
	logger  *logrus.Logger
	timeout time.Duration
	mgr     *discovery.Manager 
}

func (w *StandardDiscoveryWorkflow) Execute(ctx context.Context, targetDomain string) ([]models.Subdomain, error) {
	w.logger.Infof("Discovery[standard] starting for %s", targetDomain)
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return []models.Subdomain{}, nil
}

type ComprehensiveDiscoveryWorkflow struct {
	logger  *logrus.Logger
	timeout time.Duration
	mgr     *discovery.Manager
}

func (w *ComprehensiveDiscoveryWorkflow) Execute(ctx context.Context, targetDomain string) ([]models.Subdomain, error) {
	w.logger.Infof("Discovery[comprehensive] starting for %s", targetDomain)
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	parts := []DiscoveryWorkflow{
		&StandardDiscoveryWorkflow{logger: w.logger, timeout: w.timeout / 2, mgr: w.mgr},
		&StealthDiscoveryWorkflow{logger: w.logger, timeout: w.timeout / 2, mgr: w.mgr},
	}

	var wg sync.WaitGroup
	type result struct {
		list []models.Subdomain
		err  error
	}
	results := make(chan result, len(parts))

	for _, p := range parts {
		wg.Add(1)
		go func(p DiscoveryWorkflow) {
			defer wg.Done()
			list, err := p.Execute(ctx, targetDomain)
			results <- result{list: list, err: err}
		}(p)
	}

	wg.Wait()
	close(results)

	var all []models.Subdomain
	for r := range results {
		if r.err != nil && ctx.Err() == nil {
			w.logger.Warnf("Discovery sub-step error: %v", r.err)
			continue
		}
		all = append(all, r.list...)
	}

	all = dedupeSubdomains(all)
	w.logger.Infof("Discovery[comprehensive] finished for %s: %d unique", targetDomain, len(all))
	return all, nil
}

type StealthDiscoveryWorkflow struct {
	logger  *logrus.Logger
	timeout time.Duration
	mgr     *discovery.Manager 
}

func (w *StealthDiscoveryWorkflow) Execute(ctx context.Context, targetDomain string) ([]models.Subdomain, error) {
	w.logger.Infof("Discovery[stealth] starting for %s", targetDomain)
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return []models.Subdomain{}, nil
}

type CompositeDiscoveryWorkflow struct {
	logger *logrus.Logger
	parts  []DiscoveryWorkflow
}

func (c *CompositeDiscoveryWorkflow) Execute(ctx context.Context, targetDomain string) ([]models.Subdomain, error) {
	if len(c.parts) == 0 {
		return []models.Subdomain{}, nil
	}

	var wg sync.WaitGroup
	type result struct {
		list []models.Subdomain
		err  error
	}
	results := make(chan result, len(c.parts))

	for _, p := range c.parts {
		wg.Add(1)
		go func(p DiscoveryWorkflow) {
			defer wg.Done()
			list, err := p.Execute(ctx, targetDomain)
			results <- result{list: list, err: err}
		}(p)
	}

	wg.Wait()
	close(results)

	var all []models.Subdomain
	var firstErr error
	for r := range results {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		all = append(all, r.list...)
	}

	all = dedupeSubdomains(all)
	return all, firstErr
}


type StandardValidationWorkflow struct {
	logger  *logrus.Logger
	timeout time.Duration
	mgr     *validation.Manager 
}

func (w *StandardValidationWorkflow) Execute(ctx context.Context, subdomains []models.Subdomain) ([]models.Subdomain, []models.Finding, error) {
	w.logger.Infof("Validation[standard] starting on %d subdomains", len(subdomains))
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}
	active := markActiveIfUnknown(subdomains)
	return active, []models.Finding{}, nil
}

type ComprehensiveValidationWorkflow struct {
	logger  *logrus.Logger
	timeout time.Duration
	mgr     *validation.Manager 
}

func (w *ComprehensiveValidationWorkflow) Execute(ctx context.Context, subdomains []models.Subdomain) ([]models.Subdomain, []models.Finding, error) {
	w.logger.Infof("Validation[comprehensive] starting on %d subdomains", len(subdomains))
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	parts := []ValidationWorkflow{
		&StandardValidationWorkflow{logger: w.logger, timeout: w.timeout / 2, mgr: w.mgr},
		&QuickValidationWorkflow{logger: w.logger, timeout: w.timeout / 2, mgr: w.mgr},
	}

	var wg sync.WaitGroup
	type result struct {
		val []models.Subdomain
		f   []models.Finding
		err error
	}
	results := make(chan result, len(parts))

	for _, p := range parts {
		wg.Add(1)
		go func(p ValidationWorkflow) {
			defer wg.Done()
			val, f, err := p.Execute(ctx, subdomains)
			results <- result{val: val, f: f, err: err}
		}(p)
	}

	wg.Wait()
	close(results)

	var allVal []models.Subdomain
	var allFind []models.Finding
	var firstErr error
	for r := range results {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		allVal = append(allVal, r.val...)
		allFind = append(allFind, r.f...)
	}

	allVal = dedupeSubdomains(allVal)
	allFind = dedupeFindings(allFind)
	w.logger.Infof("Validation[comprehensive] finished: %d active, %d findings", len(allVal), len(allFind))
	return allVal, allFind, firstErr
}

type QuickValidationWorkflow struct {
	logger  *logrus.Logger
	timeout time.Duration
	mgr     *validation.Manager 
}

func (w *QuickValidationWorkflow) Execute(ctx context.Context, subdomains []models.Subdomain) ([]models.Subdomain, []models.Finding, error) {
	w.logger.Infof("Validation[quick] starting on %d subdomains", len(subdomains))
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	active := markActiveIfUnknown(subdomains)
	return active, []models.Finding{}, nil
}

type CompositeValidationWorkflow struct {
	logger *logrus.Logger
	parts  []ValidationWorkflow
}

func (c *CompositeValidationWorkflow) Execute(ctx context.Context, subdomains []models.Subdomain) ([]models.Subdomain, []models.Finding, error) {
	if len(c.parts) == 0 {
		return subdomains, nil, nil
	}

	var wg sync.WaitGroup
	type result struct {
		val []models.Subdomain
		f   []models.Finding
		err error
	}
	results := make(chan result, len(c.parts))

	for _, p := range c.parts {
		wg.Add(1)
		go func(p ValidationWorkflow) {
			defer wg.Done()
			val, f, err := p.Execute(ctx, subdomains)
			results <- result{val: val, f: f, err: err}
		}(p)
	}

	wg.Wait()
	close(results)

	var allVal []models.Subdomain
	var allFind []models.Finding
	var firstErr error
	for r := range results {
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		allVal = append(allVal, r.val...)
		allFind = append(allFind, r.f...)
	}

	allVal = dedupeSubdomains(allVal)
	allFind = dedupeFindings(allFind)
	return allVal, allFind, firstErr
}

func contains(list []string, key string) bool {
	for _, v := range list {
		if v == key {
			return true
		}
	}
	return false
}

func dedupeSubdomains(in []models.Subdomain) []models.Subdomain {
	seen := make(map[string]bool)
	out := make([]models.Subdomain, 0, len(in))
	for _, s := range in {
		key := s.Name
		if key == "" {
			key = s.RootDomain + "|" + s.Name
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupeFindings(in []models.Finding) []models.Finding {
	seen := make(map[string]bool)
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {
		key := f.Target + "|" + f.Type + "|" + f.Title
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

func markActiveIfUnknown(in []models.Subdomain) []models.Subdomain {
	out := make([]models.Subdomain, 0, len(in))
	for _, s := range in {
		if s.Status == "" {
			s.Status = "active" 
		}
		out = append(out, s)
	}
	return out
}

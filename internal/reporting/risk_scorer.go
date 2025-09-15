package reporting

import (
	"math"
	"sort"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type RiskScorer struct {
	severityWeights map[string]float64
}

func NewRiskScorer() *RiskScorer {
	return NewRiskScorerWithWeights(nil)
}

func NewRiskScorerWithWeights(override map[string]float64) *RiskScorer {
	base := map[string]float64{
		"critical": 10.0,
		"high":     7.5,
		"medium":   5.0,
		"low":      2.5,
		"info":     1.0,
	}
	for k, v := range override {
		base[k] = v
	}
	return &RiskScorer{severityWeights: base}
}

func (rs *RiskScorer) ScoreFindings(findings []models.Finding) []models.Finding {
	scored := make([]models.Finding, len(findings))
	copy(scored, findings)
	for i := range scored {
		scored[i].RiskScore = rs.CalculateFindingRiskScore(scored[i])
	}
	sort.Slice(scored, func(i, j int) bool { return scored[i].RiskScore > scored[j].RiskScore })
	return scored
}

func (rs *RiskScorer) CalculateFindingRiskScore(finding models.Finding) float64 {
	base := rs.severityWeights[finding.Severity]
	if base == 0 {
		base = 1.0
	}
	conf := 1.0
	switch {
	case finding.Confidence < 80:
		conf = 0.7
	case finding.Confidence > 95:
		conf = 1.2
	}
	impact := 1.0
	switch finding.Impact {
	case "high":
		impact = 1.3
	case "low":
		impact = 0.7
	}
	return base * conf * impact
}

func (rs *RiskScorer) CalculateOverallRiskScore(findings []models.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	var total float64
	for _, f := range findings {
		total += f.RiskScore
	}
	avg := total / float64(len(findings))
	if avg > 10 {
		return 10
	}
	return math.Round(avg*100) / 100
}

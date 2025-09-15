package http

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type RedirectHandler struct {
	maxRedirects    int
	maxDepth        int
	followSameHost  bool
	followCrossHost bool
	timeout         time.Duration
	logger          *logrus.Logger
	mu              sync.RWMutex
}

func NewRedirectHandler(maxRedirects, maxDepth int, followSameHost, followCrossHost bool, timeout time.Duration, logger *logrus.Logger) *RedirectHandler {
	if logger == nil {
		logger = logrus.New()
	}

	return &RedirectHandler{
		maxRedirects:    maxRedirects,
		maxDepth:        maxDepth,
		followSameHost:  followSameHost,
		followCrossHost: followCrossHost,
		timeout:         timeout,
		logger:          logger,
	}
}

func (r *RedirectHandler) FollowRedirects(ctx context.Context, client *http.Client, initialURL string) (*models.RedirectChain, error) {
	if client == nil {
		return nil, fmt.Errorf("nil http client")
	}

	chain := &models.RedirectChain{
		URL:       initialURL,
		StartTime: time.Now(),
		Redirects: make([]*models.Redirect, 0),
	}
	localClient := *client
	localClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	currentURL := initialURL
	visited := map[string]bool{currentURL: true}

	for i := 0; i < r.maxRedirects; i++ {
		if len(chain.Redirects) >= r.maxDepth {
			chain.CompletionReason = "max_depth_reached"
			break
		}
		reqCtx := ctx
		var cancel context.CancelFunc
		if r.timeout > 0 {
			reqCtx, cancel = context.WithTimeout(ctx, r.timeout)
		}
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, currentURL, nil)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("User-Agent", "SubNexus/1.0 Redirect Analyzer")

		start := time.Now()
		resp, err := &localClient, error(nil)
		resp, err = localClient.Do(req)
		rt := time.Since(start)
		if cancel != nil {
			cancel()
		}

		if err != nil {
			chain.CompletionReason = "request_failed"
			break
		}

		func() {
			defer resp.Body.Close()

			if isRedirect(resp.StatusCode) {
				location := strings.TrimSpace(resp.Header.Get("Location"))
				if location == "" {
					chain.CompletionReason = "no_location_header"
					return
				}

				absoluteURL, err := resolveRelativeURL(currentURL, location)
				if err != nil {
					chain.CompletionReason = "invalid_location_url"
					return
				}
				if visited[absoluteURL] {
					chain.CompletionReason = "redirect_loop"
					return
				}
				visited[absoluteURL] = true
				currentHost := hostOnly(currentURL)
				nextHost := hostOnly(absoluteURL)
				sameHost := strings.EqualFold(currentHost, nextHost)

				if (sameHost && !r.followSameHost) || (!sameHost && !r.followCrossHost) {
					chain.CompletionReason = "redirect_policy_violation"
					return
				}

				chain.Redirects = append(chain.Redirects, &models.Redirect{
					From:         currentURL,
					To:           absoluteURL,
					StatusCode:   resp.StatusCode,
					Location:     location,
					ResponseTime: rt,
					Headers:      extractHeaders(resp.Header),
					Timestamp:    time.Now(),
				})

				currentURL = absoluteURL
			} else {
				chain.FinalURL = currentURL
				chain.FinalStatusCode = resp.StatusCode
				chain.CompletionReason = "non_redirect_response"
			}
		}()

		if chain.CompletionReason == "non_redirect_response" ||
			strings.HasPrefix(chain.CompletionReason, "redirect_") ||
			chain.CompletionReason == "no_location_header" ||
			chain.CompletionReason == "invalid_location_url" ||
			chain.CompletionReason == "redirect_policy_violation" {
			break
		}
	}

	chain.EndTime = time.Now()
	chain.Duration = chain.EndTime.Sub(chain.StartTime)
	return chain, nil
}

func (r *RedirectHandler) AnalyzeRedirectChain(chain *models.RedirectChain) *models.RedirectAnalysis {
	analysis := &models.RedirectAnalysis{
		Chain:      chain,
		Findings:   make([]models.RedirectFinding, 0),
		AnalyzedAt: time.Now(),
	}

	r.checkOpenRedirects(analysis)
	r.checkRedirectLoops(analysis)
	r.checkInsecureRedirects(analysis)
	r.checkSensitiveData(analysis)

	analysis.SecurityScore = r.calculateSecurityScore(analysis)
	return analysis
}

func (r *RedirectHandler) checkOpenRedirects(analysis *models.RedirectAnalysis) {
	paramKeys := []string{"url", "redirect", "next", "goto", "return", "rurl", "dest", "destination", "redir"}
	baseHost := hostOnly(analysis.Chain.URL)

	for i, hop := range analysis.Chain.Redirects {
		u, err := url.Parse(hop.To)
		if err != nil {
			continue
		}
		q := u.Query()
		for _, k := range paramKeys {
			if v := q.Get(k); v != "" {
				if target, err := url.Parse(v); err == nil && target.IsAbs() {
					if !sameOriginHost(baseHost, target.Host) {
						analysis.Findings = append(analysis.Findings, models.RedirectFinding{
							Type:          "open_redirect",
							Severity:      models.SeverityHigh,
							Description:   fmt.Sprintf("Potential open redirect via parameter '%s' -> %s", k, v),
							Confidence:    0.85,
							RedirectIndex: i,
						})
					}
				}
			}
		}
	}
}

func (r *RedirectHandler) checkRedirectLoops(analysis *models.RedirectAnalysis) {
	if analysis.Chain.CompletionReason == "redirect_loop" {
		analysis.Findings = append(analysis.Findings, models.RedirectFinding{
			Type:       "redirect_loop",
			Severity:   models.SeverityMedium,
			Description:"Redirect loop detected",
			Confidence: 1.0,
		})
		return
	}

	seen := make(map[string]bool)
	for _, hop := range analysis.Chain.Redirects {
		if seen[hop.To] {
			analysis.Findings = append(analysis.Findings, models.RedirectFinding{
				Type:       "redirect_loop",
				Severity:   models.SeverityMedium,
				Description:"Potential loop: URL repeats in chain",
				Confidence: 0.7,
			})
			return
		}
		seen[hop.To] = true
	}
}

func (r *RedirectHandler) checkInsecureRedirects(analysis *models.RedirectAnalysis) {
	for i, hop := range analysis.Chain.Redirects {
		if strings.HasPrefix(strings.ToLower(hop.From), "https://") &&
			strings.HasPrefix(strings.ToLower(hop.To), "http://") {
			analysis.Findings = append(analysis.Findings, models.RedirectFinding{
				Type:          "insecure_redirect",
				Severity:      models.SeverityMedium,
				Description:   "HTTPS to HTTP downgrade",
				Confidence:    1.0,
				RedirectIndex: i,
			})
		}
	}
}

func (r *RedirectHandler) checkSensitiveData(analysis *models.RedirectAnalysis) {
	keys := []string{"password", "passwd", "pwd", "secret", "key", "token", "auth", "credential", "session", "cookie", "jwt"}

	for i, hop := range analysis.Chain.Redirects {
		u, err := url.Parse(hop.To)
		if err != nil {
			continue
		}
		q := u.Query()
		for _, k := range keys {
			if v := q.Get(k); v != "" {
				analysis.Findings = append(analysis.Findings, models.RedirectFinding{
					Type:          "sensitive_data_exposure",
					Severity:      models.SeverityHigh,
					Description:   fmt.Sprintf("Sensitive query parameter in redirect: %s", k),
					Confidence:    0.9,
					RedirectIndex: i,
				})
			}
		}
		if frag := u.Fragment; frag != "" {
			for _, k := range keys {
				if strings.Contains(strings.ToLower(frag), strings.ToLower(k)+"=") {
					analysis.Findings = append(analysis.Findings, models.RedirectFinding{
						Type:          "sensitive_data_exposure",
						Severity:      models.SeverityHigh,
						Description:   fmt.Sprintf("Sensitive data in URL fragment: %s", k),
						Confidence:    0.8,
						RedirectIndex: i,
					})
				}
			}
		}
	}
}

func (r *RedirectHandler) calculateSecurityScore(analysis *models.RedirectAnalysis) float64 {
	score := 1.0
	for _, f := range analysis.Findings {
		switch f.Severity {
		case models.SeverityCritical:
			score -= 0.30
		case models.SeverityHigh:
			score -= 0.20
		case models.SeverityMedium:
			score -= 0.10
		case models.SeverityLow:
			score -= 0.05
		}
	}
	if score < 0 {
		score = 0
	} else if score > 1 {
		score = 1
	}
	return score
}

func isRedirect(code int) bool {
	return code >= 300 && code < 400 && code != http.StatusNotModified
}

func resolveRelativeURL(baseURL, relativeURL string) (string, error) {
	if strings.HasPrefix(relativeURL, "http://") || strings.HasPrefix(relativeURL, "https://") {
		return relativeURL, nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(relativeURL)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(rel).String(), nil
}

func hostOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func sameOriginHost(a, b string) bool {
	return strings.EqualFold(hostOnly(a), hostOnly(b))
}

func extractHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func (r *RedirectHandler) SetMaxRedirects(maxRedirects int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxRedirects = maxRedirects
}

func (r *RedirectHandler) SetMaxDepth(maxDepth int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxDepth = maxDepth
}

func (r *RedirectHandler) SetFollowPolicies(followSameHost, followCrossHost bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.followSameHost = followSameHost
	r.followCrossHost = followCrossHost
}

func (r *RedirectHandler) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return map[string]interface{}{
		"max_redirects":     r.maxRedirects,
		"max_depth":         r.maxDepth,
		"follow_same_host":  r.followSameHost,
		"follow_cross_host": r.followCrossHost,
		"timeout":           r.timeout.String(),
	}
}

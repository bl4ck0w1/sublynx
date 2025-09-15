package content_analysis

import (
	"regexp"
	"sync"
	"github.com/sirupsen/logrus"
)

type PatternMatcher struct {
	patterns       map[string]*regexp.Regexp
	customPatterns map[string]*regexp.Regexp
	mu             sync.RWMutex
	logger         *logrus.Logger
	matchCache   map[string]map[string][]string
	cacheEnabled bool
	cacheMutex   sync.RWMutex
}

func NewPatternMatcher(logger *logrus.Logger) *PatternMatcher {
	if logger == nil {
		logger = logrus.New()
	}

	pm := &PatternMatcher{
		patterns:       make(map[string]*regexp.Regexp),
		customPatterns: make(map[string]*regexp.Regexp),
		logger:         logger,
		matchCache:     make(map[string]map[string][]string),
		cacheEnabled:   true,
	}

	pm.initializeBuiltinPatterns()
	return pm
}

func (pm *PatternMatcher) initializeBuiltinPatterns() {
	builtinPatterns := map[string]string{
		"email":           `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		"url":             `https?://[^\s<>"{}|\\^\[\]` + "`" + `]+`,
		"ipv4":            `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
		"ipv6":            `(?:^|[\s\(\[])` + 
			`(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})`,
		"phone":           `(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`,
		"credit_card":     `\b(?:\d{4}[- ]?){3}\d{4}\b`,
		"ssn":             `\b\d{3}-\d{2}-\d{4}\b`,
		"jwt":             `eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`,
		"api_key":         `\b[a-zA-Z0-9]{32,}\b`,
		"private_key":     `-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`,
		"aws_access_key":  `\bAKIA[0-9A-Z]{16}\b`,
		"aws_secret_key":  `\b[0-9A-Za-z+/]{40}\b`,
		"google_api_key":  `\bAIza[0-9A-Za-z\-_]{35}\b`,
		"password":        `(?i)\bpassword\s*[=:]\s*['"]?[^'" \n\r]+['"]?`,
		"token":           `(?i)\btoken\s*[=:]\s*['"]?[^'" \n\r]+['"]?`,
		"auth":            `(?i)\bauth\s*[=:]\s*['"]?[^'" \n\r]+['"]?`,
		"secret":          `(?i)\bsecret\s*[=:]\s*['"]?[^'" \n\r]+['"]?`,
	}

	for name, pattern := range builtinPatterns {
		if err := pm.AddPattern(name, pattern); err != nil {
			pm.logger.Warnf("Failed to compile built-in pattern %s: %v", name, err)
		}
	}
}

func (pm *PatternMatcher) AddPattern(name, pattern string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	pm.patterns[name] = compiled
	return nil
}

func (pm *PatternMatcher) AddCustomPattern(name, pattern string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	pm.customPatterns[name] = compiled
	return nil
}

func (pm *PatternMatcher) Match(content string) map[string][]string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	results := make(map[string][]string)

	for name, pattern := range pm.patterns {
		if matches := pattern.FindAllString(content, -1); len(matches) > 0 {
			results[name] = matches
		}
	}
	for name, pattern := range pm.customPatterns {
		if matches := pattern.FindAllString(content, -1); len(matches) > 0 {
			results[name] = matches
		}
	}
	return results
}

func (pm *PatternMatcher) MatchSpecific(name, content string) ([]string, bool) {
	if pm.cacheEnabled {
		if matches, found := pm.getFromCache(name, content); found {
			return matches, len(matches) > 0
		}
	}

	pm.mu.RLock()
	pat, okBuilt := pm.patterns[name]
	cpat, okCustom := pm.customPatterns[name]
	pm.mu.RUnlock()

	var matches []string
	if okBuilt {
		matches = pat.FindAllString(content, -1)
	} else if okCustom {
		matches = cpat.FindAllString(content, -1)
	} else {
		return nil, false
	}

	if pm.cacheEnabled {
		pm.addToCache(name, content, matches)
	}
	return matches, len(matches) > 0
}

func (pm *PatternMatcher) MatchWithProbability(content string) map[string]float64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	results := make(map[string]float64)

	for name, pattern := range pm.patterns {
		if matches := pattern.FindAllString(content, -1); len(matches) > 0 {
			results[name] = pm.calculateConfidence(name, matches, content)
		}
	}
	for name, pattern := range pm.customPatterns {
		if matches := pattern.FindAllString(content, -1); len(matches) > 0 {
			results[name] = pm.calculateConfidence(name, matches, content)
		}
	}
	return results
}

func (pm *PatternMatcher) calculateConfidence(name string, matches []string, _ string) float64 {
	// Base confidence
	conf := 0.7
	if n := len(matches); n > 1 {
		conf += 0.1 * float64(n)
		if conf > 0.95 {
			conf = 0.95
		}
	}
	switch name {
	case "email", "ipv4", "ipv6", "credit_card", "ssn":
		conf += 0.2
	case "api_key", "private_key", "aws_access_key", "aws_secret_key", "google_api_key":
		conf += 0.25
	case "password", "token", "auth", "secret":
		conf += 0.1
	}

	if conf > 1.0 {
		conf = 1.0
	}
	if conf < 0.0 {
		conf = 0.0
	}
	return conf
}

func (pm *PatternMatcher) getFromCache(name, content string) ([]string, bool) {
	pm.cacheMutex.RLock()
	defer pm.cacheMutex.RUnlock()

	if byContent, ok := pm.matchCache[name]; ok {
		if matches, ok2 := byContent[content]; ok2 {
			cp := make([]string, len(matches))
			copy(cp, matches)
			return cp, true
		}
	}
	return nil, false
}

func (pm *PatternMatcher) addToCache(name, content string, matches []string) {
	pm.cacheMutex.Lock()
	defer pm.cacheMutex.Unlock()

	if _, ok := pm.matchCache[name]; !ok {
		pm.matchCache[name] = make(map[string][]string)
	}
	cp := make([]string, len(matches))
	copy(cp, matches)
	pm.matchCache[name][content] = cp
}

func (pm *PatternMatcher) ClearCache() {
	pm.cacheMutex.Lock()
	defer pm.cacheMutex.Unlock()
	pm.matchCache = make(map[string]map[string][]string)
}

func (pm *PatternMatcher) SetCacheEnabled(enabled bool) {
	pm.cacheMutex.Lock()
	pm.cacheEnabled = enabled
	pm.cacheMutex.Unlock()
	if !enabled {
		pm.ClearCache()
	}
}

func (pm *PatternMatcher) GetPatterns() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	out := make([]string, 0, len(pm.patterns)+len(pm.customPatterns))
	for name := range pm.patterns {
		out = append(out, name)
	}
	for name := range pm.customPatterns {
		out = append(out, name)
	}
	return out
}

func (pm *PatternMatcher) RemovePattern(name string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.patterns, name)
	delete(pm.customPatterns, name)

	pm.cacheMutex.Lock()
	delete(pm.matchCache, name)
	pm.cacheMutex.Unlock()
}

func (pm *PatternMatcher) RemoveAllPatterns() {
	pm.mu.Lock()
	pm.patterns = make(map[string]*regexp.Regexp)
	pm.customPatterns = make(map[string]*regexp.Regexp)
	pm.mu.Unlock()
	pm.ClearCache()
}

func (pm *PatternMatcher) MatchCount(content string) map[string]int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	results := make(map[string]int)
	for name, pattern := range pm.patterns {
		results[name] = len(pattern.FindAllString(content, -1))
	}
	for name, pattern := range pm.customPatterns {
		results[name] = len(pattern.FindAllString(content, -1))
	}
	return results
}

func (pm *PatternMatcher) MatchPosition(content string) map[string][][2]int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	results := make(map[string][][2]int)
	for name, pattern := range pm.patterns {
		results[name] = pattern.FindAllStringIndex(content, -1)
	}
	for name, pattern := range pm.customPatterns {
		results[name] = pattern.FindAllStringIndex(content, -1)
	}
	return results
}

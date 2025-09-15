package permutations

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type Generator struct {
	wordlistManager *WordlistManager
	combinatorics   *Combinatorics
	logger          *logrus.Logger

	rateLimiter chan struct{} 
	stopWatch   func()       
}

func NewGenerator(wordlistDir string, logger *logrus.Logger, maxConcurrent int) (*Generator, error) {
	if logger == nil {
		logger = logrus.New()
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}

	wm, err := NewWordlistManager(wordlistDir, logger)
	if err != nil {
		return nil, err
	}

	stop := wm.WatchForChanges(5 * time.Minute)

	rateLimiter := make(chan struct{}, maxConcurrent)
	for i := 0; i < maxConcurrent; i++ {
		rateLimiter <- struct{}{}
	}

	return &Generator{
		wordlistManager: wm,
		combinatorics:   NewCombinatorics(),
		logger:          logger,
		rateLimiter:     rateLimiter,
		stopWatch:       stop,
	}, nil
}

type GenerationOptions struct {
	UseCommonWordlists bool
	UseCombinatorics   bool
	UseFuzzing         bool
	Industry           string
	UseMarkov      bool
	MarkovModel    *MarkovModel 
	MarkovK        int         
	MarkovMinLen   int     
	MarkovMaxLen   int     
	InterleaveMark int         
	MarkovSeed     *int64       
	MaxDepth        int
	MaxPermutations int
}

func (g *Generator) GenerateSubdomains(ctx context.Context, domain string, opts GenerationOptions) <-chan string {
	out := make(chan string, 10000)

	go func() {
		defer close(out)

		base := normalizeDomain(domain)
		if base == "" {
			return
		}

		mid := make(chan string, 20000)

		var forwardWG sync.WaitGroup
		forwardWG.Add(1)
		go func() {
			defer forwardWG.Done()
			seen := make(map[string]struct{}, 1<<16)
			for {
				select {
				case <-ctx.Done():
					return
				case s, ok := <-mid:
					if !ok {
						return
					}
					s = strings.TrimSpace(strings.ToLower(s))
					if s == "" {
						continue
					}
					if _, dup := seen[s]; dup {
						continue
					}
					seen[s] = struct{}{}
					select {
					case <-ctx.Done():
						return
					case out <- s:
					}
				}
			}
		}()

		var prodWG sync.WaitGroup
		withPermit := func(fn func()) {
			select {
			case <-ctx.Done():
				return
			case <-g.rateLimiter:
				// got a token
			}
			prodWG.Add(1)
			go func() {
				defer func() {
					g.rateLimiter <- struct{}{} 
					prodWG.Done()
				}()
				fn()
			}()
		}

		if opts.UseCommonWordlists {
			withPermit(func() { g.generateFromWordlists(ctx, base, mid) })
		}

		if opts.UseCombinatorics {
			withPermit(func() { g.generateCombinatorial(ctx, base, mid) })
		}

		if opts.Industry != "" {
			industry := opts.Industry
			withPermit(func() { g.generateIndustrySpecific(ctx, base, industry, mid) })
		}

		if opts.UseFuzzing {
			withPermit(func() { g.generateFuzzingPatterns(ctx, base, mid) })
		}

		if opts.UseCombinatorics && opts.UseMarkov && opts.MarkovModel != nil && opts.MarkovK > 0 {
			minLen := opts.MarkovMinLen
			maxLen := opts.MarkovMaxLen
			if minLen <= 0 {
				minLen = 3
			}
			if maxLen <= 0 {
				maxLen = 16
			}
			withPermit(func() {
				common, _ := g.wordlistManager.GetWordlist("common_subdomains") 
				wordlists := map[string][]string{"common_subdomains": common}
				patterns := []string{"-", "_", ".", "0", "1", "2", "test", "dev", "stage"}

				ch := g.combinatorics.GenerateSmartPermutationsWithMarkov(
					base, wordlists, patterns, opts.MarkovModel, opts.MarkovK, opts.InterleaveMark, opts.MarkovSeed,
				)
				for {
					select {
					case <-ctx.Done():
						return
					case s, ok := <-ch:
						if !ok {
							return
						}
						select {
						case <-ctx.Done():
							return
						case mid <- s:
						}
					}
				}
			})
		} else if opts.UseMarkov && opts.MarkovModel != nil && opts.MarkovK > 0 {
			withPermit(func() {
				ch := g.combinatorics.GenerateMarkovLabels(opts.MarkovModel, base, opts.MarkovK,
					maxInt(opts.MarkovMinLen, 3), maxInt(opts.MarkovMaxLen, 16), opts.MarkovSeed)
				for {
					select {
					case <-ctx.Done():
						return
					case s, ok := <-ch:
						if !ok {
							return
						}
						select {
						case <-ctx.Done():
							return
						case mid <- s:
						}
					}
				}
			})
		}

		prodWG.Wait()
		close(mid)
		forwardWG.Wait()
	}()

	return out
}

func (g *Generator) generateFromWordlists(ctx context.Context, domain string, out chan<- string) {
	commonWords, err := g.wordlistManager.GetWordlist("common_subdomains")
	if err != nil {
		g.logger.Warnf("Failed to get common_subdomains wordlist: %v", err)
		return
	}
	permutationWords, err := g.wordlistManager.GetWordlist("permutations")
	if err != nil {
		g.logger.Warnf("Failed to get permutations wordlist: %v", err)
		return
	}

	for word := range g.combinatorics.GenerateCombinations(commonWords, 1, "") {
		select {
		case <-ctx.Done():
			return
		case out <- strings.ToLower(strings.TrimSpace(word)) + "." + domain:
		}
	}

	for word := range g.combinatorics.GenerateCombinations(commonWords, 1, "") {
		w := strings.ToLower(strings.TrimSpace(word))
		for _, pattern := range permutationWords {
			p := strings.ToLower(strings.TrimSpace(pattern))
			if p == "" && w == "" {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case out <- w + p + "." + domain:
			}
			select {
			case <-ctx.Done():
				return
			case out <- p + w + "." + domain:
			}
			select {
			case <-ctx.Done():
				return
			case out <- w + "-" + p + "." + domain:
			}
			select {
			case <-ctx.Done():
				return
			case out <- p + "-" + w + "." + domain:
			}
		}
	}
}

func (g *Generator) generateCombinatorial(ctx context.Context, domain string, out chan<- string) {
	commonWords, err := g.wordlistManager.GetWordlist("common_subdomains")
	if err != nil {
		g.logger.Warnf("Failed to get common_subdomains wordlist: %v", err)
		return
	}
	wordlists := map[string][]string{"common_subdomains": commonWords}
	patterns := []string{"-", "_", ".", "0", "1", "2", "test", "dev", "stage"}

	for sub := range g.combinatorics.GenerateSmartPermutations(domain, wordlists, patterns) {
		select {
		case <-ctx.Done():
			return
		case out <- sub:
		}
	}
}

func (g *Generator) generateIndustrySpecific(ctx context.Context, domain, industry string, out chan<- string) {
	commonWords, err := g.wordlistManager.GetWordlist("common_subdomains")
	if err != nil {
		g.logger.Warnf("Failed to get common_subdomains wordlist: %v", err)
		return
	}
	industryWords, err := g.wordlistManager.GetIndustryWordlist(industry)
	if err != nil {
		g.logger.Warnf("Failed to get industry wordlist %s: %v", industry, err)
		return
	}

	allWords := append([]string{}, commonWords...)
	allWords = append(allWords, industryWords...)

	for word := range g.combinatorics.GenerateCombinations(allWords, 2, "-") {
		select {
		case <-ctx.Done():
			return
		case out <- word + "." + domain:
		}
	}


	for _, iw := range industryWords {
		iw = strings.ToLower(strings.TrimSpace(iw))
		for _, cw := range commonWords {
			cw = strings.ToLower(strings.TrimSpace(cw))

			select {
			case <-ctx.Done():
				return
			case out <- iw + "-" + cw + "." + domain:
			}
			select {
			case <-ctx.Done():
				return
			case out <- cw + "-" + iw + "." + domain:
			}
			select {
			case <-ctx.Done():
				return
			case out <- iw + "." + cw + "." + domain:
			}
		}
	}
}

func (g *Generator) generateFuzzingPatterns(ctx context.Context, domain string, out chan<- string) {
	for pattern := range g.combinatorics.GenerateFuzzingPatterns(domain) {
		select {
		case <-ctx.Done():
			return
		case out <- pattern:
		}
	}
}

func (g *Generator) GenerateFromCTLogs(ctx context.Context, domain string, ctEntries []string) <-chan string {
	out := make(chan string, 1000)
	go func() {
		defer close(out)

		base := normalizeDomain(domain)
		if base == "" {
			return
		}

		patterns := g.extractPatternsFromCT(ctEntries)
		commonWords, err := g.wordlistManager.GetWordlist("common_subdomains")
		if err != nil {
			g.logger.Warnf("Failed to get common_subdomains wordlist: %v", err)
			return
		}

		for _, p := range patterns {
			p = strings.ToLower(strings.TrimSpace(p))
			for _, w := range commonWords {
				w = strings.ToLower(strings.TrimSpace(w))

				select {
				case <-ctx.Done():
					return
				case out <- w + p + "." + base:
				}
				select {
				case <-ctx.Done():
					return
				case out <- p + w + "." + base:
				}
			}
		}
	}()
	return out
}

func (g *Generator) extractPatternsFromCT(ctEntries []string) []string {
	patterns := make(map[string]struct{})

	for _, entry := range ctEntries {
		parts := strings.Split(strings.ToLower(strings.TrimSpace(entry)), ".")
		if len(parts) < 2 {
			continue
		}
		sub := parts[0]

		if len(sub) > 1 && sub[len(sub)-1] >= '0' && sub[len(sub)-1] <= '9' {
			i := len(sub) - 1
			for i >= 0 && sub[i] >= '0' && sub[i] <= '9' {
				i--
			}
			if i+1 < len(sub) {
				patterns[sub[i+1:]] = struct{}{}
			}
		}

		for _, prefix := range []string{"dev", "test", "stage", "prod", "uat", "qa"} {
			if strings.HasPrefix(sub, prefix) && len(sub) > len(prefix) {
				patterns[prefix] = struct{}{}
			}
		}

		if strings.Contains(sub, "-") {
			patterns["-"] = struct{}{}
		}
		if strings.Contains(sub, "_") {
			patterns["_"] = struct{}{}
		}
	}

	out := make([]string, 0, len(patterns))
	for p := range patterns {
		out = append(out, p)
	}
	return out
}

func (g *Generator) GenerateWithMarkov(ctx context.Context, domain string, trainingData []string, count int) <-chan string {
	out := make(chan string, 1000)
	go func() {
		defer close(out)

		base := normalizeDomain(domain)
		if base == "" || count <= 0 {
			return
		}
		mm := NewMarkovModel(3)
		_ = mm.FitFrom(trainingData, nil)
		mm.Prune(3, 2)
		mm.Compile()

		labels := mm.Generate(count, 3, 16, nil)
		for _, lbl := range labels {
			fqdn := strings.ToLower(strings.TrimSpace(lbl + "." + base))
			select {
			case <-ctx.Done():
				return
			case out <- fqdn:
			}
		}
	}()
	return out
}

func (g *Generator) Stats() map[string]interface{} {
	wordlists := g.wordlistManager.GetAllWordlists()
	industryWordlists := g.wordlistManager.GetIndustryWordlists()

	return map[string]interface{}{
		"wordlist_count":          len(wordlists),
		"industry_wordlist_count": len(industryWordlists),
		"wordlists":               wordlists,
		"industry_wordlists":      industryWordlists,
	}
}

func (g *Generator) Close() error {
	if g.stopWatch != nil {
		g.stopWatch()
	}
	if g.rateLimiter != nil {
		close(g.rateLimiter)
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

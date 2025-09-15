package permutations

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Combinatorics struct {
	mu sync.Mutex
}

func NewCombinatorics() *Combinatorics {
	return &Combinatorics{}
}

func (c *Combinatorics) GeneratePermutations(words []string, depth int) <-chan []string {
	out := make(chan []string, 1024)

	go func() {
		defer close(out)
		if depth <= 0 || len(words) == 0 {
			return
		}

		uniq := dedupeStrings(words)
		cur := make([]string, 0, depth)
		c.permuteRec(uniq, cur, depth, out)
	}()

	return out
}

func (c *Combinatorics) permuteRec(words, current []string, depth int, out chan<- []string) {
	if depth == 0 {
		if len(current) > 0 {
			leaf := make([]string, len(current))
			copy(leaf, current)
			out <- leaf
		}
		return
	}
	for _, w := range words {
		current = append(current, w)
		c.permuteRec(words, current, depth-1, out)
		current = current[:len(current)-1]
	}
}

func (c *Combinatorics) GenerateCombinations(words []string, depth int, separator string) <-chan string {
	out := make(chan string, 1024)

	go func() {
		defer close(out)
		if depth <= 0 || len(words) == 0 {
			return
		}

		uniq := dedupeStrings(words)
		cur := make([]string, 0, depth)
		c.combineRec(uniq, cur, depth, separator, out)
	}()

	return out
}

func (c *Combinatorics) combineRec(words, current []string, depth int, sep string, out chan<- string) {
	if depth == 0 {
		if len(current) > 0 {
			out <- strings.Join(current, sep)
		}
		return
	}
	for _, w := range words {
		current = append(current, w)
		c.combineRec(words, current, depth-1, sep, out)
		current = current[:len(current)-1]
	}
}

func (c *Combinatorics) GenerateSmartPermutations(baseDomain string, wordlists map[string][]string, patterns []string) <-chan string {
	return c.GenerateSmartPermutationsWithMarkov(baseDomain, wordlists, patterns, nil, 0, 0, nil)
}

func (c *Combinatorics) GenerateSmartPermutationsWithMarkov(
	baseDomain string,
	wordlists map[string][]string,
	patterns []string,
	mm *MarkovModel,
	markovK int,
	interleaveEvery int,
	seed *int64,
) <-chan string {
	out := make(chan string, 8192)

	go func() {
		defer close(out)

		base := normalizeDomain(baseDomain)
		if base == "" {
			return
		}

		common := wordlists["common_subdomains"]
		if len(common) == 0 {
			return
		}
		common = dedupeStrings(common)

		primaryCh := make(chan string, 8192)
		var wg sync.WaitGroup

		emitPrimary := func(s string) {
			if s == "" {
				return
			}
			primaryCh <- strings.ToLower(strings.TrimSpace(s))
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			for combo := range c.GenerateCombinations(common, 2, "-") {
				emitPrimary(combo + "." + base)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, p := range patterns {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				for _, w := range common {
					emitPrimary(w + p + "." + base)
					emitPrimary(p + w + "." + base)
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, w := range common {
				for i := 0; i < 10; i++ {
					emitPrimary(fmt.Sprintf("%s-%d.%s", w, i, base))
					emitPrimary(fmt.Sprintf("%s%d.%s", w, i, base))
				}
				for i := 0; i < 100; i += 5 {
					emitPrimary(fmt.Sprintf("%s-%02d.%s", w, i, base))
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			envs := []string{"dev", "test", "stage", "prod", "uat", "qa", "preprod"}
			for _, env := range envs {
				for _, w := range common {
					emitPrimary(env + "-" + w + "." + base)
					emitPrimary(w + "-" + env + "." + base)
					emitPrimary(env + "." + w + "." + base)
				}
			}
		}()

		go func() {
			wg.Wait()
			close(primaryCh)
		}()

		var markovCh <-chan string
		if mm != nil && markovK > 0 {
			markovCh = c.GenerateMarkovLabels(mm, base, markovK, 3, 16, seed)
		} else {
			ch := make(chan string)
			close(ch)
			markovCh = ch
		}

		seen := make(map[string]struct{}, 1<<16)
		push := func(s string) {
			s = strings.TrimSpace(strings.ToLower(s))
			if s == "" {
				return
			}
			if _, ok := seen[s]; ok {
				return
			}
			seen[s] = struct{}{}
			out <- s
		}

		var (
			countSinceMarkov int
			pendingMarkov    string
			ok               bool
		)

		select {
		case pendingMarkov, ok = <-markovCh:
			if !ok {
				pendingMarkov = ""
			}
		default:
			// none ready
		}

		for s := range primaryCh {
			push(s)
			if interleaveEvery > 0 {
				countSinceMarkov++
				if countSinceMarkov >= interleaveEvery && pendingMarkov != "" {
					push(pendingMarkov)
					countSinceMarkov = 0
					select {
					case pendingMarkov, ok = <-markovCh:
						if !ok {
							pendingMarkov = ""
						}
					default:
						pendingMarkov = ""
					}
				}
			}
		}

		if pendingMarkov != "" {
			push(pendingMarkov)
		}
		for s := range markovCh {
			push(s)
		}
	}()

	return out
}

func (c *Combinatorics) GenerateMarkovLabels(
	mm *MarkovModel,
	baseDomain string,
	k, minLen, maxLen int,
	seed *int64,
) <-chan string {
	out := make(chan string, 2048)
	go func() {
		defer close(out)
		if mm == nil {
			return
		}
		base := normalizeDomain(baseDomain)
		if base == "" {
			return
		}

		labels := mm.Generate(k, minLen, maxLen, seed)
		seen := make(map[string]struct{}, len(labels))
		for _, lbl := range labels {
			fqdn := strings.ToLower(strings.TrimSpace(lbl + "." + base))
			if fqdn == "."+base || fqdn == base {
				continue
			}
			if _, ok := seen[fqdn]; ok {
				continue
			}
			seen[fqdn] = struct{}{}
			out <- fqdn
		}
	}()
	return out
}

func (c *Combinatorics) GenerateFuzzingPatterns(baseDomain string) <-chan string {
	out := make(chan string, 2048)

	go func() {
		defer close(out)
		base := normalizeDomain(baseDomain)
		if base == "" {
			return
		}

		patterns := []string{
			"", "-", "_", ".", "0", "1", "2", "00", "01", "02",
			"test", "dev", "stage", "prod",
			"api", "web", "app", "admin", "login", "secure", "internal", "external",
		}

		seen := make(map[string]struct{}, 1<<12)
		emit := func(s string) {
			if s == "" {
				return
			}
			s = strings.ToLower(strings.TrimSpace(s))
			if _, ok := seen[s]; ok {
				return
			}
			seen[s] = struct{}{}
			out <- s
		}

		for _, p := range patterns {
			// avoid emitting ".base" when p == ""
			if p != "" {
				emit(p + "." + base)
			}
			emit("www" + p + "." + base)
			emit("api" + p + "." + base)
			if p != "" {
				emit(p + "www." + base)
				emit(p + "api." + base)
			}
		}

		for i := 0; i < 100; i++ {
			emit(fmt.Sprintf("%02d.%s", i, base))
			emit(fmt.Sprintf("www-%02d.%s", i, base))
			emit(fmt.Sprintf("api-%02d.%s", i, base))
		}
	}()

	return out
}


func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	m := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	return d
}

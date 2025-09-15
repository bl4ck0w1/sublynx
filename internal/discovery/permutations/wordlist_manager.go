package permutations

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type WordlistManager struct {
	wordlists     map[string][]string 
	cache         map[string]string   
	mu            sync.RWMutex
	logger        *logrus.Logger
	wordlistDir   string
	industryLists map[string][]string 
}

func NewWordlistManager(wordlistDir string, logger *logrus.Logger) (*WordlistManager, error) {
	if logger == nil {
		logger = logrus.New()
	}
	wm := &WordlistManager{
		wordlists:     make(map[string][]string),
		cache:         make(map[string]string),
		logger:        logger,
		wordlistDir:   wordlistDir,
		industryLists: make(map[string][]string),
	}
	if err := wm.LoadAllWordlists(); err != nil {
		return nil, fmt.Errorf("failed to load wordlists: %w", err)
	}
	return wm, nil
}

func (wm *WordlistManager) LoadAllWordlists() error {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.wordlists = make(map[string][]string)
	wm.cache = make(map[string]string)
	err := filepath.WalkDir(wm.wordlistDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err 
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".txt" {
			return nil
		}

		listName := strings.TrimSuffix(filepath.Base(path), ".txt")
		words, fileHash, err := wm.loadWordlist(path)
		if err != nil {
			wm.logger.Warnf("Failed to load wordlist %s: %v", listName, err)
			return nil 
		}
		wm.wordlists[listName] = words
		wm.cache[listName] = fileHash
		wm.logger.Infof("Loaded wordlist %s with %d words", listName, len(words))
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk wordlist directory: %w", err)
	}

	if err := wm.loadIndustryWordlists(); err != nil {
		wm.logger.Warnf("Failed to load industry wordlists: %v", err)
	}
	return nil
}

func (wm *WordlistManager) loadWordlist(path string) ([]string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open wordlist file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	tee := io.TeeReader(f, hasher)

	sc := bufio.NewScanner(tee)
	const maxLine = 1024 * 1024 
	buf := make([]byte, 64*1024)
	sc.Buffer(buf, maxLine)

	var words []string
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		words = append(words, w)
	}
	if err := sc.Err(); err != nil {
		return nil, "", fmt.Errorf("failed to scan wordlist %s: %w", path, err)
	}

	words = wm.deduplicateAndSort(words)
	fileHash := hex.EncodeToString(hasher.Sum(nil))
	return words, fileHash, nil
}

func (wm *WordlistManager) loadIndustryWordlists() error {
	industryDir := filepath.Join(wm.wordlistDir, "industry_specific")
	info, err := os.Stat(industryDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil 
		}
		return fmt.Errorf("failed to stat industry directory: %w", err)
	}
	if !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(industryDir)
	if err != nil {
		return fmt.Errorf("failed to read industry directory: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".txt" {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".txt")
		path := filepath.Join(industryDir, e.Name())

		words, _, err := wm.loadWordlist(path)
		if err != nil {
			wm.logger.Warnf("Failed to load industry wordlist %s: %v", name, err)
			continue
		}
		wm.industryLists[name] = words
		wm.logger.Infof("Loaded industry wordlist %s with %d words", name, len(words))
	}
	return nil
}

func (wm *WordlistManager) GetWordlist(name string) ([]string, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	words, ok := wm.wordlists[name]
	if !ok {
		return nil, fmt.Errorf("wordlist %q not found", name)
	}
	cp := make([]string, len(words))
	copy(cp, words)
	return cp, nil
}

func (wm *WordlistManager) GetIndustryWordlist(industry string) ([]string, error) {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	words, ok := wm.industryLists[industry]
	if !ok {
		return nil, fmt.Errorf("industry wordlist %q not found", industry)
	}
	cp := make([]string, len(words))
	copy(cp, words)
	return cp, nil
}

func (wm *WordlistManager) GetAllWordlists() []string {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	names := make([]string, 0, len(wm.wordlists))
	for name := range wm.wordlists {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (wm *WordlistManager) GetIndustryWordlists() []string {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	names := make([]string, 0, len(wm.industryLists))
	for name := range wm.industryLists {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (wm *WordlistManager) ReloadWordlist(name string) error {
	path := filepath.Join(wm.wordlistDir, name+".txt")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("wordlist file %s does not exist", path)
		}
		return fmt.Errorf("failed to stat %s: %w", path, err)
	}

	words, hash, err := wm.loadWordlist(path)
	if err != nil {
		return fmt.Errorf("failed to reload wordlist %q: %w", name, err)
	}

	wm.mu.Lock()
	wm.wordlists[name] = words
	wm.cache[name] = hash
	wm.mu.Unlock()

	wm.logger.Infof("Reloaded wordlist %s with %d words", name, len(words))
	return nil
}

func (wm *WordlistManager) WatchForChanges(interval time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := wm.checkForChanges(); err != nil {
					wm.logger.Warnf("Error checking for wordlist changes: %v", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return cancel
}

func (wm *WordlistManager) checkForChanges() error {
	wm.mu.RLock()
	names := make([]string, 0, len(wm.wordlists))
	for name := range wm.wordlists {
		names = append(names, name)
	}
	wm.mu.RUnlock()

	var g errgroup.Group
	for _, name := range names {
		name := name
		g.Go(func() error {
			path := filepath.Join(wm.wordlistDir, name+".txt")
			f, err := os.Open(path)
			if err != nil {
				wm.logger.Warnf("Failed to open wordlist %s: %v", name, err)
				return nil
			}
			defer f.Close()

			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				return fmt.Errorf("failed hashing %s: %w", name, err)
			}
			currentHash := hex.EncodeToString(h.Sum(nil))
			wm.mu.RLock()
			oldHash := wm.cache[name]
			wm.mu.RUnlock()

			if oldHash != currentHash {
				wm.logger.Infof("Wordlist %s has changed, reloading", name)
				if err := wm.ReloadWordlist(name); err != nil {
					return fmt.Errorf("failed to reload %s: %w", name, err)
				}
			}
			return nil
		})
	}
	return g.Wait()
}

func (wm *WordlistManager) deduplicateAndSort(words []string) []string {
	seen := make(map[string]struct{}, len(words))
	unique := make([]string, 0, len(words))
	for _, w := range words {
		if w == "" {
			continue
		}
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		unique = append(unique, w)
	}
	sort.Strings(unique)
	return unique
}

func (wm *WordlistManager) GenerateCustomWordlist(baseWords []string, patterns []string) []string {
	custom := make(map[string]struct{}, len(baseWords)*(1+6*len(patterns)))

	for _, w := range baseWords {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		custom[w] = struct{}{}
	}

	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		for _, w := range baseWords {
			w = strings.TrimSpace(w)
			if w == "" {
				continue
			}
			transforms := []string{
				w + p,
				p + w,
				w + "-" + p,
				p + "-" + w,
				w + "_" + p,
				p + "_" + w,
			}
			for _, t := range transforms {
				custom[t] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(custom))
	for w := range custom {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

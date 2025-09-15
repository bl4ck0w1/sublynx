package ai

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/net/idna"
)

type Preprocessor struct {
	charVocab      map[string]int
	wordVocab      map[string]int
	config         *PreprocessorConfig
	logger         *logrus.Logger
	mu             sync.RWMutex
	commonWords    map[string]bool
	separatorRegex *regexp.Regexp
}

type PreprocessorConfig struct {
	SeqLength           int  `json:"seq_length"`
	CharEmbeddingDim    int  `json:"char_embedding_dim"`
	WordEmbeddingDim    int  `json:"word_embedding_dim"`
	MaxWordLen          int  `json:"max_word_len"`
	MaxWords            int  `json:"max_words"`
	TopK                int  `json:"top_k"`
	MinSubdomainLen     int  `json:"min_subdomain_len"`
	MaxSubdomainLen     int  `json:"max_subdomain_len"`
	StripCommonPrefixes bool `json:"strip_common_prefixes"`
	VocabDir string `json:"vocab_dir"`
}

type appConfig struct {
	Paths struct {
		VocabDir string `json:"vocab_dir"`
	} `json:"paths"`
	Training struct {
		SeqLength               int `json:"seq_length"`
		MaxWordsPerSubdomain    int `json:"max_words_per_subdomain"`
	} `json:"training"`
	Model struct {
		CharEmbeddingDim int `json:"char_embedding_dim"`
		WordEmbeddingDim int `json:"word_embedding_dim"`
	} `json:"model"`
	Preprocessing struct {
		MinLength           int  `json:"min_length"`
		MaxLength           int  `json:"max_length"`
		StripCommonPrefixes bool `json:"strip_common_prefixes"`
	} `json:"preprocessing"`
	Prediction struct {
		TopK int `json:"top_k"`
	} `json:"prediction"`
}

func NewPreprocessor(configPath string, logger *logrus.Logger) (*Preprocessor, error) {
	if logger == nil {
		logger = logrus.New()
	}

	p := &Preprocessor{
		logger: logger,
		commonWords: map[string]bool{
			"www": true, "api": true, "app": true, "web": true, "admin": true,
			"test": true, "dev": true, "stage": true, "prod": true, "uat": true,
			"qa": true, "preprod": true, "internal": true, "external": true,
			"secure": true, "login": true, "auth": true, "console": true,
		},
		separatorRegex: regexp.MustCompile(`[\.\-_]`),
		charVocab:      make(map[string]int),
		wordVocab:      make(map[string]int),
	}

	if err := p.loadConfig(configPath); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if err := p.loadVocabularies(); err != nil {
		return nil, fmt.Errorf("failed to load vocabularies: %w", err)
	}

	return p, nil
}

func (p *Preprocessor) loadConfig(configPath string) error {
	cfg := &PreprocessorConfig{
		SeqLength:           50,
		CharEmbeddingDim:    64,
		WordEmbeddingDim:    64,
		MaxWordLen:          32,
		MaxWords:            10,
		TopK:                5,
		MinSubdomainLen:     3,
		MaxSubdomainLen:     253,
		StripCommonPrefixes: false,
		VocabDir:            "data/vocab",
	}

	raw, err := os.ReadFile(configPath)
	if err == nil {
		var ac appConfig
		if err := json.Unmarshal(raw, &ac); err == nil {
			if ac.Paths.VocabDir != "" {
				cfg.VocabDir = ac.Paths.VocabDir
			}
			if ac.Training.SeqLength > 0 {
				cfg.SeqLength = ac.Training.SeqLength
			}
			if ac.Training.MaxWordsPerSubdomain > 0 {
				cfg.MaxWords = ac.Training.MaxWordsPerSubdomain
			}
			if ac.Model.CharEmbeddingDim > 0 {
				cfg.CharEmbeddingDim = ac.Model.CharEmbeddingDim
			}
			if ac.Model.WordEmbeddingDim > 0 {
				cfg.WordEmbeddingDim = ac.Model.WordEmbeddingDim
			}
			if ac.Preprocessing.MinLength > 0 {
				cfg.MinSubdomainLen = ac.Preprocessing.MinLength
			}
			if ac.Preprocessing.MaxLength > 0 {
				cfg.MaxSubdomainLen = ac.Preprocessing.MaxLength
			}
			cfg.StripCommonPrefixes = ac.Preprocessing.StripCommonPrefixes
			if ac.Prediction.TopK > 0 {
				cfg.TopK = ac.Prediction.TopK
			}
		}
	}

	p.config = cfg
	p.logger.Infof("Preprocessor config: seq=%d maxWords=%d stripCommon=%v vocabDir=%s",
		cfg.SeqLength, cfg.MaxWords, cfg.StripCommonPrefixes, cfg.VocabDir)
	return nil
}

func (p *Preprocessor) loadVocabularies() error {
	charVocabPath := strings.TrimRight(p.config.VocabDir, "/") + "/char_vocab.json"
	wordVocabPath := strings.TrimRight(p.config.VocabDir, "/") + "/word_vocab.json"

	charVocabData, err := os.ReadFile(charVocabPath)
	if err != nil {
		return fmt.Errorf("load char vocabulary: %w", err)
	}
	if err := json.Unmarshal(charVocabData, &p.charVocab); err != nil {
		return fmt.Errorf("parse char vocabulary: %w", err)
	}

	wordVocabData, err := os.ReadFile(wordVocabPath)
	if err != nil {
		return fmt.Errorf("load word vocabulary: %w", err)
	}
	if err := json.Unmarshal(wordVocabData, &p.wordVocab); err != nil {
		return fmt.Errorf("parse word vocabulary: %w", err)
	}

	p.logger.Infof("Loaded vocabularies: %d chars, %d words", len(p.charVocab), len(p.wordVocab))
	return nil
}

func (p *Preprocessor) PreprocessSubdomain(subdomain string) (map[string]interface{}, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	normalized := p.normalizeSubdomain(subdomain)

	if l := len(normalized); l < p.config.MinSubdomainLen || l > p.config.MaxSubdomainLen {
		return nil, fmt.Errorf("subdomain length out of range (%d)", l)
	}

	features := map[string]interface{}{
		"subdomain":       normalized,
		"char_features":   p.extractCharFeatures(normalized),
		"word_features":   p.extractWordFeatures(normalized),
		"stat_features":   p.extractStatisticalFeatures(normalized),
		"domain_features": p.extractDomainFeatures(normalized),
	}
	return features, nil
}

func (p *Preprocessor) normalizeSubdomain(subdomain string) string {
	s := strings.TrimSpace(subdomain)
	s = strings.ToLower(s)

	reProto := regexp.MustCompile(`^https?://`)
	rePath := regexp.MustCompile(`/.*$`)
	s = reProto.ReplaceAllString(s, "")
	s = rePath.ReplaceAllString(s, "")

	s = norm.NFC.String(s)

	if a, err := idna.ToASCII(s); err == nil && a != "" {
		s = a
	}

	if p.config.StripCommonPrefixes {
		s = regexp.MustCompile(`^www\.`).ReplaceAllString(s, "")
		s = regexp.MustCompile(`^api\.`).ReplaceAllString(s, "")
	}

	s = strings.TrimSuffix(s, ".")
	return s
}

func (p *Preprocessor) extractCharFeatures(subdomain string) map[string]interface{} {
	features := map[string]interface{}{}

	ngrams := make([]string, 0, max(0, len(subdomain)-2))
	for i := 0; i <= len(subdomain)-3; i++ {
		ngrams = append(ngrams, subdomain[i:i+3])
	}
	features["char_ngrams"] = ngrams

	charFreq := make(map[string]int, len(subdomain))
	for _, ch := range subdomain {
		charFreq[string(ch)]++
	}
	features["char_freq"] = charFreq

	charPos := make(map[string][]int)
	for i, ch := range subdomain {
		cs := string(ch)
		charPos[cs] = append(charPos[cs], i)
	}
	features["char_positions"] = charPos

	return features
}

func (p *Preprocessor) extractWordFeatures(subdomain string) map[string]interface{} {
	features := map[string]interface{}{}

	parts := p.separatorRegex.Split(subdomain, -1)
	valid := make([]string, 0, len(parts))
	for _, w := range parts {
		if w != "" {
			valid = append(valid, w)
		}
	}

	features["words"] = valid
	features["word_count"] = len(valid)

	lengths := make([]int, len(valid))
	flags := make([]bool, len(valid))
	for i, w := range valid {
		lengths[i] = len(w)
		flags[i] = p.commonWords[w]
	}
	features["word_lengths"] = lengths
	features["common_words"] = flags
	return features
}

func (p *Preprocessor) extractStatisticalFeatures(subdomain string) map[string]interface{} {
	length := len(subdomain)
	digits := p.countDigits(subdomain)
	letters := p.countLetters(subdomain)
	hyphens := strings.Count(subdomain, "-")
	underscores := strings.Count(subdomain, "_")
	dots := strings.Count(subdomain, ".")

	entropy := p.calculateEntropy(subdomain)

	return map[string]interface{}{
		"length":           length,
		"digit_count":      digits,
		"letter_count":     letters,
		"hyphen_count":     hyphens,
		"underscore_count": underscores,
		"dot_count":        dots,
		"entropy":          entropy,
	}
}

func (p *Preprocessor) extractDomainFeatures(subdomain string) map[string]interface{} {
	etld1, _ := publicsuffix.EffectiveTLDPlusOne(subdomain)
	suffix, _ := publicsuffix.PublicSuffix(subdomain)

	domain := ""
	subPart := ""
	if etld1 != "" {
		domain = etld1
		if strings.HasSuffix(subdomain, "."+etld1) {
			subPart = strings.TrimSuffix(subdomain, "."+etld1)
		}
	}

	labels := strings.Split(subdomain, ".")

	return map[string]interface{}{
		"domain":          domain,   
		"suffix":          suffix,   
		"subdomain_part":  subPart,   
		"is_www":          len(labels) > 0 && labels[0] == "www",
		"is_api":          contains(labels, "api"),
		"is_admin":        contains(labels, "admin"),
		"is_test":         containsAny(labels, []string{"test", "dev", "stage", "qa"}),
	}
}

func (p *Preprocessor) countDigits(s string) int {
	count := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			count++
		}
	}
	return count
}

func (p *Preprocessor) countLetters(s string) int {
	count := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			count++
		}
	}
	return count
}

func (p *Preprocessor) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	charCounts := make(map[rune]int)
	for _, r := range s {
		charCounts[r]++
	}
	ent := 0.0
	for _, c := range charCounts {
		f := float64(c) / float64(len(s))
		ent -= f * math.Log2(f)
	}
	return ent
}

func (p *Preprocessor) containsTestWords(subdomain string) bool {
	testWords := []string{"test", "dev", "stage", "qa", "preprod", "uat"}
	for _, w := range testWords {
		if strings.Contains(subdomain, w) {
			return true
		}
	}
	return false
}


func (p *Preprocessor) ConvertToModelInput(features map[string]interface{}) ([]int32, []int32, []float32, error) {
	subdomain, ok := features["subdomain"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("subdomain not found in features")
	}

	seqLen := p.config.SeqLength
	maxWords := p.config.MaxWords
	charSeq := make([]int32, seqLen)
	padID := int32(p.charVocab["<PAD>"])
	unkID := int32(p.charVocab["<UNK>"])

	for i := range charSeq {
		charSeq[i] = padID
	}

	end := seqLen
	start := seqLen - len(subdomain)
	if start < 0 {
		start = 0
	}
	for i := start; i < end && i-start < len(subdomain); i++ {
		ch := string(subdomain[i-start])
		if idx, exists := p.charVocab[ch]; exists {
			charSeq[i] = int32(idx)
		} else {
			charSeq[i] = unkID
		}
	}

	wordFeatures, ok := features["word_features"].(map[string]interface{})
	if !ok {
		return nil, nil, nil, fmt.Errorf("word_features not found")
	}
	wordsIfc, ok := wordFeatures["words"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("words not found in word_features")
	}
	words := toStringSlice(wordsIfc)

	wordSeq := make([]int32, maxWords)
	wPadID := int32(p.wordVocab["<PAD>"])
	wUnkID := int32(p.wordVocab["<UNK>"])
	for i := range wordSeq {
		wordSeq[i] = wPadID
	}
	for i := 0; i < maxWords && i < len(words); i++ {
		if idx, exists := p.wordVocab[words[i]]; exists {
			wordSeq[i] = int32(idx)
		} else {
			wordSeq[i] = wUnkID
		}
	}

	statFeatures, ok := features["stat_features"].(map[string]interface{})
	if !ok {
		return nil, nil, nil, fmt.Errorf("stat_features not found")
	}
	statSeq := make([]float32, 7)
	statSeq[0] = float32(asInt(statFeatures["length"]))
	statSeq[1] = float32(asInt(statFeatures["digit_count"]))
	statSeq[2] = float32(asInt(statFeatures["letter_count"]))
	statSeq[3] = float32(asInt(statFeatures["hyphen_count"]))
	statSeq[4] = float32(asInt(statFeatures["underscore_count"]))
	statSeq[5] = float32(asInt(statFeatures["dot_count"]))
	statSeq[6] = float32(asFloat(statFeatures["entropy"]))

	return charSeq, wordSeq, statSeq, nil
}

func asInt(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float32:
		return int(t)
	case float64:
		return int(t)
	default:
		return 0
	}
}

func asFloat(v interface{}) float64 {
	switch t := v.(type) {
	case float32:
		return float64(t)
	case float64:
		return t
	case int:
		return float64(t)
	case int32:
		return float64(t)
	case int64:
		return float64(t)
	default:
		return 0
	}
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	if s, ok := v.([]string); ok {
		return s
	}
	if arr, ok := v.([]interface{}); ok {
		out := make([]string, 0, len(arr))
		for _, x := range arr {
			if xs, ok := x.(string); ok {
				out = append(out, xs)
			}
		}
		return out
	}
	return nil
}

func contains(list []string, needle string) bool {
	for _, s := range list {
		if s == needle {
			return true
		}
	}
	return false
}

func containsAny(list []string, needles []string) bool {
	for _, n := range needles {
		if contains(list, n) {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

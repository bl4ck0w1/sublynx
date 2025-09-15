package ai

import (
	"fmt"
	"math"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	ort "github.com/yalue/onnxruntime_go"
)

type InferenceEngine struct {
	modelSession  *ort.AdvancedSession
	preprocessor  *Preprocessor
	logger        *logrus.Logger
	mu            sync.Mutex
	isInitialized bool

	idxToChar   map[int]string
	topK        int
	temperature float64
}

func NewInferenceEngine(modelPath, configPath string, logger *logrus.Logger) (*InferenceEngine, error) {
	if logger == nil {
		logger = logrus.New()
	}

	if !ort.IsInitialized() {
		if err := ort.InitializeEnvironment(); err != nil {
			return nil, fmt.Errorf("failed to initialize ONNX runtime: %w", err)
		}
	}

	preprocessor, err := NewPreprocessor(configPath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create preprocessor: %w", err)
	}

	idxToChar := make(map[int]string, len(preprocessor.charVocab))
	for ch, idx := range preprocessor.charVocab {
		idxToChar[idx] = ch
	}

	engine := &InferenceEngine{
		preprocessor: preprocessor,
		logger:       logger,
		idxToChar:    idxToChar,
		topK:         max(1, preprocessor.config.TopK),
		temperature:  1.0, 
	}

	if err := engine.LoadModel(modelPath); err != nil {
		return nil, fmt.Errorf("failed to load model: %w", err)
	}

	rand.Seed(time.Now().UnixNano())

	return engine, nil
}

func (e *InferenceEngine) SetSampling(topK int, temperature float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if topK > 0 {
		e.topK = topK
	}
	if temperature > 0 {
		e.temperature = temperature
	}
}

func (e *InferenceEngine) LoadModel(modelPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	options, err := ort.NewSessionOptions()
	if err != nil {
		return fmt.Errorf("failed to create session options: %w", err)
	}
	defer options.Destroy()
	options.SetGraphOptimizationLevel(ort.GraphOptimizationLevel(3))
	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{"char_input", "word_input", "stat_input"},
		[]string{"output"},
		options,
	)
	if err != nil {
		return fmt.Errorf("failed to create ONNX session: %w", err)
	}

	e.modelSession = session
	e.isInitialized = true
	e.logger.Infof("Loaded ONNX model from %s", modelPath)
	return nil
}

func (e *InferenceEngine) PredictNextChar(subdomain string) ([]CharProbability, error) {
	if !e.isInitialized {
		return nil, fmt.Errorf("inference engine not initialized")
	}
	features, err := e.preprocessor.PreprocessSubdomain(subdomain)
	if err != nil {
		return nil, fmt.Errorf("failed to preprocess subdomain: %w", err)
	}

	charSeq, wordSeq, statSeq, err := e.preprocessor.ConvertToModelInput(features)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to model input: %w", err)
	}

	batchedChar := [][]int32{charSeq}
	batchedWord := [][]int32{wordSeq}
	batchedStat := [][]float32{statSeq}

	inputTensors := map[string]interface{}{
		"char_input": batchedChar,
		"word_input": batchedWord,
		"stat_input": batchedStat,
	}

	e.mu.Lock()
	outputs, err := e.modelSession.Run(inputTensors)
	e.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to run inference: %w", err)
	}

	var probs []float32
	switch t := outputs["output"].(type) {
	case []float32:
		probs = t
	case [][]float32:
		if len(t) == 0 {
			return nil, fmt.Errorf("empty output batch")
		}
		probs = t[0]
	default:
		return nil, fmt.Errorf("invalid output type %T", outputs["output"])
	}

	k := e.topK
	if k <= 0 {
		k = 1
	}
	topIdxs := getTopKIndices(probs, k)

	result := make([]CharProbability, 0, len(topIdxs))
	for _, idx := range topIdxs {
		result = append(result, CharProbability{
			Char:        e.getCharFromIndex(idx),
			Probability: probs[idx],
		})
	}
	return result, nil
}

func (e *InferenceEngine) GenerateSubdomains(baseDomain, seed string, count, maxLength int) ([]string, error) {
	if count <= 0 {
		count = 1
	}
	if maxLength <= 0 {
		maxLength = 30
	}

	generated := make([]string, 0, count)
	seen := make(map[string]bool)

	for i := 0; i < count; i++ {
		current := seed
		for j := 0; j < maxLength; j++ {
			topCandidates, err := e.PredictNextChar(current)
			if err != nil || len(topCandidates) == 0 {
				break
			}

			nextChar, err := e.chooseNextChar(topCandidates)
			if err != nil {
				break
			}
			if nextChar == "<END>" {
				break
			}
			current += nextChar
		}

		label := strings.ToLower(strings.Trim(current, ".-"))
		fullDomain := label + "." + strings.Trim(baseDomain, ".")
		if e.preprocessor.isValidSubdomain(label) && !seen[fullDomain] {
			generated = append(generated, fullDomain)
			seen[fullDomain] = true
		}
	}

	return generated, nil
}

func (e *InferenceEngine) chooseNextChar(candidates []CharProbability) (string, error) {
	if len(candidates) == 0 {
		return "", fmt.Errorf("no predictions available")
	}

	temperature := e.temperature
	if temperature <= 0 {
		return candidates[0].Char, nil
	}

	logits := make([]float64, len(candidates))
	for i, c := range candidates {
		p := float64(c.Probability)
		if p < 1e-12 {
			p = 1e-12
		}
		logits[i] = math.Log(p) / math.Max(temperature, 1e-6)
	}

	maxLogit := logits[0]
	for _, v := range logits[1:] {
		if v > maxLogit {
			maxLogit = v
		}
	}
	sum := 0.0
	for i := range logits {
		logits[i] = math.Exp(logits[i] - maxLogit)
		sum += logits[i]
	}
	if sum == 0 {
		return candidates[0].Char, nil
	}
	for i := range logits {
		logits[i] /= sum
	}

	r := rand.Float64()
	cum := 0.0
	for i, p := range logits {
		cum += p
		if r <= cum {
			return candidates[i].Char, nil
		}
	}
	return candidates[len(candidates)-1].Char, nil
}

func (e *InferenceEngine) getCharFromIndex(idx int) string {
	if ch, ok := e.idxToChar[idx]; ok {
		return ch
	}
	return "<UNK>"
}

func getTopKIndices(values []float32, k int) []int {
	if k <= 0 {
		k = 1
	}
	indices := make([]int, len(values))
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(i, j int) bool {
		return values[indices[i]] > values[indices[j]]
	})
	if k > len(indices) {
		k = len(indices)
	}
	return indices[:k]
}

type CharProbability struct {
	Char        string  `json:"char"`
	Probability float32 `json:"probability"`
}

func (e *InferenceEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.modelSession != nil {
		e.modelSession.Destroy()
		e.modelSession = nil
	}
	e.isInitialized = false
	return nil
}

func (p *Preprocessor) isValidSubdomain(subdomain string) bool {
	if len(subdomain) < 1 || len(subdomain) > 63 {
		return false
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9\-\._]+$`).MatchString(subdomain) {
		return false
	}
	if strings.Contains(subdomain, "..") || strings.Contains(subdomain, "--") {
		return false
	}
	if strings.HasPrefix(subdomain, "-") || strings.HasPrefix(subdomain, ".") ||
		strings.HasSuffix(subdomain, "-") || strings.HasSuffix(subdomain, ".") {
		return false
	}
	return true
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

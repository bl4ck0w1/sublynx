package permutations

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	mrand "math/rand"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)


type MarkovModel struct {
	N int `json:"n"`

	states map[string]*distCounts
	alias map[string]*aliasTable
	TotalTransitions int `json:"total_transitions"`

	mu sync.RWMutex
}

func NewMarkovModel(n int) *MarkovModel {
	if n < 1 {
		n = 2
	}
	return &MarkovModel{
		N:                 n,
		states:            make(map[string]*distCounts),
		alias:             make(map[string]*aliasTable),
		TotalTransitions:  0,
	}
}

func (m *MarkovModel) AddSample(s string) {
	s = normalizeLabel(s)
	if len([]rune(s)) < m.N+1 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rs := []rune(s)
	for i := 0; i+m.N < len(rs); i++ {
		state := string(rs[i : i+m.N])
		next := int32(rs[i+m.N])

		dc := m.states[state]
		if dc == nil {
			dc = &distCounts{counts: make(map[int32]int)}
			m.states[state] = dc
		}
		dc.counts[next]++
		m.TotalTransitions++
	}
}

func (m *MarkovModel) FitFrom(samples []string, r io.Reader) error {
	for _, s := range samples {
		m.AddSample(s)
	}
	if r != nil {
		sc := bufio.NewScanner(r)
		const maxLine = 1 << 20
		buf := make([]byte, 64*1024)
		sc.Buffer(buf, maxLine)
		for sc.Scan() {
			m.AddSample(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return err
		}
	}
	return nil
}

func (m *MarkovModel) Prune(minStateTotal, minEdgeCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for state, dc := range m.states {
		total := 0
		for sym, c := range dc.counts {
			if c < minEdgeCount {
				delete(dc.counts, sym)
				continue
			}
			total += c
		}
		if total < minStateTotal || len(dc.counts) == 0 {
			delete(m.states, state)
		} else {
			dc.total = total
		}
	}
}

func (m *MarkovModel) Compile() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.alias = make(map[string]*aliasTable, len(m.states))
	for state, dc := range m.states {
		at := buildAliasTable(dc)
		if at != nil {
			m.alias[state] = at
		}
	}
}

func (m *MarkovModel) Generate(k, minLen, maxLen int, seed *int64) []string {
	if k <= 0 || maxLen <= 0 || minLen > maxLen {
		return nil
	}

	var rnd *mrand.Rand
	if seed != nil {
		rnd = mrand.New(mrand.NewSource(*seed))
	} else {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			rnd = mrand.New(mrand.NewSource(time.Now().UnixNano()))
		} else {
			seedv := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
				int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
			rnd = mrand.New(mrand.NewSource(seedv))
		}
	}

	m.mu.RLock()
	states := make([]string, 0, len(m.alias))
	for s := range m.alias {
		states = append(states, s)
	}
	muAlias := m.alias
	n := m.N
	m.mu.RUnlock()

	if len(states) == 0 {
		return nil
	}

	rnd.Shuffle(len(states), func(i, j int) { states[i], states[j] = states[j], states[i] })

	out := make([]string, 0, k)
	tryLimit := k * 5 

	for tries := 0; tries < tryLimit && len(out) < k; tries++ {
		start := states[rnd.Intn(len(states))]
		seq := []rune(start)

		for len(seq) < maxLen {
			state := string(seq[len(seq)-n:])
			at := muAlias[state]
			if at == nil || at.len == 0 {
				break
			}
			next := at.sample(rnd)
			seq = append(seq, next)
		}

		token := string(seq)
		if !isValidLabel(token) {
			continue
		}
		if l := len([]rune(token)); l < minLen || l > maxLen {
			continue
		}
		out = append(out, token)
	}

	return out
}

func (m *MarkovModel) Save(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	ser := serialModel{
		N:                 m.N,
		TotalTransitions:  m.TotalTransitions,
		States:            make([]serialState, 0, len(m.states)),
	}

	for state, dc := range m.states {
		ss := serialState{
			State:   state,
			Symbols: make([]int32, 0, len(dc.counts)),
			Counts:  make([]int, 0, len(dc.counts)),
		}
		var syms []int32
		for sym := range dc.counts {
			syms = append(syms, sym)
		}
		sort.Slice(syms, func(i, j int) bool { return syms[i] < syms[j] })
		for _, sym := range syms {
			ss.Symbols = append(ss.Symbols, sym)
			ss.Counts = append(ss.Counts, dc.counts[sym])
		}
		ser.States = append(ser.States, ss)
	}

	enc := json.NewEncoder(gz)
	enc.SetEscapeHTML(false)
	return enc.Encode(&ser)
}

func (m *MarkovModel) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	var ser serialModel
	dec := json.NewDecoder(gz)
	if err := dec.Decode(&ser); err != nil {
		return err
	}

	if ser.N < 1 {
		return errors.New("invalid n in model")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.N = ser.N
	m.TotalTransitions = ser.TotalTransitions
	m.states = make(map[string]*distCounts, len(ser.States))
	m.alias = make(map[string]*aliasTable, len(ser.States))

	for _, st := range ser.States {
		if len(st.Symbols) != len(st.Counts) || st.State == "" {
			continue
		}
		dc := &distCounts{counts: make(map[int32]int), total: 0}
		for i, sym := range st.Symbols {
			c := st.Counts[i]
			if c <= 0 {
				continue
			}
			dc.counts[sym] = c
			dc.total += c
		}
		if dc.total > 0 {
			m.states[st.State] = dc
			m.alias[st.State] = buildAliasTable(dc)
		}
	}
	return nil
}

type distCounts struct {
	counts map[int32]int
	total  int
}

type aliasTable struct {
	symbols []int32
	prob    []float64
	alias   []int
	len     int
}

func buildAliasTable(dc *distCounts) *aliasTable {
	if dc == nil || len(dc.counts) == 0 || dc.total == 0 {
		return nil
	}

	syms := make([]int32, 0, len(dc.counts))
	for s := range dc.counts {
		syms = append(syms, s)
	}
	sort.Slice(syms, func(i, j int) bool { return syms[i] < syms[j] })

	K := len(syms)
	prob := make([]float64, K)
	alias := make([]int, K)

	avg := float64(dc.total) / float64(K)
	small := make([]int, 0, K)
	large := make([]int, 0, K)

	for i, s := range syms {
		p := float64(dc.counts[s]) / avg
		prob[i] = p
		if p < 1.0 {
			small = append(small, i)
		} else {
			large = append(large, i)
		}
	}

	for len(small) > 0 && len(large) > 0 {
		s := small[len(small)-1]
		small = small[:len(small)-1]
		l := large[len(large)-1]
		large = large[:len(large)-1]

		alias[s] = l
		prob[l] = (prob[l] + prob[s]) - 1.0

		if prob[l] < 1.0 {
			small = append(small, l)
		} else {
			large = append(large, l)
		}
	}

	for _, i := range append(small, large...) {
		prob[i] = 1.0
	}

	return &aliasTable{
		symbols: syms,
		prob:    prob,
		alias:   alias,
		len:     K,
	}
}

func (a *aliasTable) sample(rng *mrand.Rand) int32 {
	if a == nil || a.len == 0 {
		return 0
	}
	i := rng.Intn(a.len)
	if rng.Float64() < a.prob[i] {
		return a.symbols[i]
	}
	return a.symbols[a.alias[i]]
}

var (
	labelAllowed = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`)
)

func normalizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	replacer := strings.NewReplacer("_", "-", ".", "-", " ", "-", "/", "-", "\\", "-")
	s = replacer.Replace(s)

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			b.WriteByte(ch)
		}
	}
	res := strings.Trim(b.String(), "-")

	if len(res) > 63 {
		res = res[:63]
	}
	return res
}

func isValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	return labelAllowed.MatchString(s)
}

type serialModel struct {
	N                int            `json:"n"`
	TotalTransitions int            `json:"total_transitions"`
	States           []serialState  `json:"states"`
}

type serialState struct {
	State   string  `json:"state"`
	Symbols []int32 `json:"symbols"`
	Counts  []int   `json:"counts"`
}

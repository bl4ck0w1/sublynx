package content_analysis

import (
	"crypto/md5"  
	"crypto/sha1" 
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/fnv"
	"strings"
	"sync"
	"github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
)

type HashAnalyzer struct {
	hashes              map[string]map[string]string 
	similarityDB        map[string]map[string]float64 
	mu                  sync.RWMutex
	logger              *logrus.Logger
	similarityThreshold float64
}

func NewHashAnalyzer(logger *logrus.Logger) *HashAnalyzer {
	if logger == nil {
		logger = logrus.New()
	}
	return &HashAnalyzer{
		hashes:              make(map[string]map[string]string),
		similarityDB:        make(map[string]map[string]float64),
		logger:              logger,
		similarityThreshold: 0.95, 
	}
}

func (ha *HashAnalyzer) HashContent(domain, content string) map[string]string {
	hashes := make(map[string]string, 11)
	hashes["md5"] = ha.calculateHash(md5.New(), content)
	hashes["sha1"] = ha.calculateHash(sha1.New(), content)
	hashes["sha256"] = ha.calculateHash(sha256.New(), content)
	hashes["sha512"] = ha.calculateHash(sha512.New(), content)
	hashes["crc32"] = ha.calculateHash(crc32.NewIEEE(), content)
	hashes["adler32"] = fmt.Sprintf("%x", adler32.Checksum([]byte(content)))
	hashes["fnv32a"] = ha.calculateFnv32a(content)
	hashes["fnv64a"] = ha.calculateFnv64a(content)
	hashes["fnv128a"] = ha.calculateFnv128a(content)
	hashes["xxh3"] = ha.calculateXXH3(content)
	hashes["simhash"] = ha.calculateSimHash(content)

	ha.mu.Lock()
	if ha.hashes[domain] == nil {
		ha.hashes[domain] = make(map[string]string, len(hashes))
	}
	for hashType, hashValue := range hashes {
		ha.hashes[domain][hashType] = hashValue
	}
	ha.mu.Unlock()

	return hashes
}

func (ha *HashAnalyzer) calculateHash(h hash.Hash, content string) string {
	_, _ = h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

func (ha *HashAnalyzer) calculateFnv32a(content string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(content))
	return fmt.Sprintf("%x", h.Sum32())
}

func (ha *HashAnalyzer) calculateFnv64a(content string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(content))
	return fmt.Sprintf("%x", h.Sum64())
}

func (ha *HashAnalyzer) calculateFnv128a(content string) string {
	h := fnv.New128a()
	_, _ = h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

func (ha *HashAnalyzer) calculateXXH3(content string) string {
	return fmt.Sprintf("%x", xxh3.HashString(content))
}

func (ha *HashAnalyzer) calculateSimHash(content string) string {
	words := strings.Fields(strings.ToLower(content))
	vector := make([]int, 64)

	for _, w := range words {
		sum := md5.Sum([]byte(w))
		for i := 0; i < 64; i++ {
			byteIndex := i / 8
			bitIndex := uint(i % 8)
			bit := (sum[byteIndex] >> bitIndex) & 1
			if bit == 1 {
				vector[i]++
			} else {
				vector[i]--
			}
		}
	}

	var simhash uint64
	for i := 0; i < 64; i++ {
		if vector[i] > 0 {
			simhash |= (1 << uint(i))
		}
	}
	return fmt.Sprintf("%016x", simhash)
}

func (ha *HashAnalyzer) FindSimilarContent(domain, hashType string) map[string]float64 {
	ha.mu.RLock()
	defer ha.mu.RUnlock()

	similar := make(map[string]float64)
	targetHash, exists := ha.hashes[domain][hashType]
	if !exists {
		return similar
	}

	for otherDomain, hashes := range ha.hashes {
		if otherDomain == domain {
			continue
		}
		otherHash, ok := hashes[hashType]
		if !ok {
			continue
		}

		sim := ha.calculateHashSimilarity(targetHash, otherHash, hashType)
		if sim >= ha.similarityThreshold {
			similar[otherDomain] = sim
		}
	}
	return similar
}

func (ha *HashAnalyzer) calculateHashSimilarity(hash1, hash2, hashType string) float64 {
	switch hashType {
	case "simhash":
		return ha.simhashSimilarity(hash1, hash2)
	case "md5", "sha1", "sha256", "sha512", "crc32", "adler32", "fnv32a", "fnv64a", "fnv128a", "xxh3":
		if hash1 == hash2 {
			return 1.0
		}
		return 0.0
	default:
		if hash1 == hash2 {
			return 1.0
		}
		return 0.0
	}
}

func (ha *HashAnalyzer) simhashSimilarity(hex1, hex2 string) float64 {
	var h1, h2 uint64
	if _, err := fmt.Sscanf(hex1, "%x", &h1); err != nil {
		return 0.0
	}
	if _, err := fmt.Sscanf(hex2, "%x", &h2); err != nil {
		return 0.0
	}
	distance := ha.hammingDistance(h1, h2)
	return 1.0 - (float64(distance) / 64.0)
}

func (ha *HashAnalyzer) hammingDistance(a, b uint64) int {
	x := a ^ b
	count := 0
	for x != 0 {
		x &= x - 1
		count++
	}
	return count
}

func (ha *HashAnalyzer) FindDuplicateContent(hashType string) map[string][]string {
	ha.mu.RLock()
	defer ha.mu.RUnlock()

	hashToDomains := make(map[string][]string)

	for domain, hashes := range ha.hashes {
		h, ok := hashes[hashType]
		if !ok {
			continue
		}
		hashToDomains[h] = append(hashToDomains[h], domain)
	}

	duplicates := make(map[string][]string)
	for h, domains := range hashToDomains {
		if len(domains) > 1 {
			cp := make([]string, len(domains))
			copy(cp, domains)
			duplicates[h] = cp
		}
	}
	return duplicates
}

func (ha *HashAnalyzer) GetHash(domain, hashType string) (string, bool) {
	ha.mu.RLock()
	defer ha.mu.RUnlock()

	if hashes, exists := ha.hashes[domain]; exists {
		h, ok := hashes[hashType]
		return h, ok
	}
	return "", false
}

func (ha *HashAnalyzer) GetAllHashes(domain string) (map[string]string, bool) {
	ha.mu.RLock()
	defer ha.mu.RUnlock()

	src, exists := ha.hashes[domain]
	if !exists {
		return nil, false
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst, true
}

func (ha *HashAnalyzer) SetSimilarityThreshold(threshold float64) {
	ha.mu.Lock()
	ha.similarityThreshold = threshold
	ha.mu.Unlock()
}

func (ha *HashAnalyzer) GetSimilarityThreshold() float64 {
	ha.mu.RLock()
	defer ha.mu.RUnlock()
	return ha.similarityThreshold
}

func (ha *HashAnalyzer) Clear() {
	ha.mu.Lock()
	defer ha.mu.Unlock()
	ha.hashes = make(map[string]map[string]string)
	ha.similarityDB = make(map[string]map[string]float64)
}

func (ha *HashAnalyzer) RemoveDomain(domain string) {
	ha.mu.Lock()
	defer ha.mu.Unlock()
	delete(ha.hashes, domain)
	delete(ha.similarityDB, domain)
	for d, neighbors := range ha.similarityDB {
		delete(neighbors, domain)
		if len(neighbors) == 0 {
			delete(ha.similarityDB, d)
		}
	}
}

func (ha *HashAnalyzer) GetStats() map[string]interface{} {
	ha.mu.RLock()
	defer ha.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["domain_count"] = len(ha.hashes)
	stats["similarity_threshold"] = ha.similarityThreshold

	hashCounts := make(map[string]int)
	for _, hashes := range ha.hashes {
		for hashType := range hashes {
			hashCounts[hashType]++
		}
	}
	stats["hash_counts"] = hashCounts
	return stats
}

func (ha *HashAnalyzer) BuildSimilarityIndex() {
	ha.mu.Lock()
	defer ha.mu.Unlock()

	ha.similarityDB = make(map[string]map[string]float64)

	for domain1, hashes1 := range ha.hashes {
		sim1, ok := hashes1["simhash"]
		if !ok {
			continue
		}
		for domain2, hashes2 := range ha.hashes {
			if domain1 == domain2 {
				continue
			}
			sim2, ok2 := hashes2["simhash"]
			if !ok2 {
				continue
			}
			sim := ha.simhashSimilarity(sim1, sim2)
			if sim >= ha.similarityThreshold {
				if ha.similarityDB[domain1] == nil {
					ha.similarityDB[domain1] = make(map[string]float64)
				}
				ha.similarityDB[domain1][domain2] = sim
			}
		}
	}
}

func (ha *HashAnalyzer) GetSimilarDomains(domain string) map[string]float64 {
	ha.mu.RLock()
	defer ha.mu.RUnlock()

	if m, ok := ha.similarityDB[domain]; ok {
		cp := make(map[string]float64, len(m))
		for k, v := range m {
			cp[k] = v
		}
		return cp
	}
	return map[string]float64{}
}

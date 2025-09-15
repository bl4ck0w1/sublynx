package stealth

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
)

type IPObfuscator struct {
	proxies         []*Proxy
	proxyRotator    *ProxyRotator
	logger          *logrus.Logger
	mu              sync.RWMutex
	techniques      map[string]IPTechnique
	activeTechnique string
	spoofedIPs      []net.IP
}

type IPTechnique struct {
	Name        string
	Description string
	SuccessRate float64
	Latency     time.Duration
	Complexity  int
}

type Proxy struct {
	Address     string
	Port        int
	Type        string 
	Username    string
	Password    string
	Latency     time.Duration
	SuccessRate float64
	LastUsed    time.Time
	Country     string
	Anonymous   bool
}

type ProxyRotator struct {
	proxies          []*Proxy
	current          int
	mu               sync.RWMutex
	logger           *logrus.Logger
	rotationStrategy string
}

func NewIPObfuscator(logger *logrus.Logger) *IPObfuscator {
	if logger == nil {
		logger = logrus.New()
	}

	obfuscator := &IPObfuscator{
		logger:     logger,
		techniques: make(map[string]IPTechnique),
		spoofedIPs: make([]net.IP, 0),
	}

	obfuscator.initializeTechniques()

	return obfuscator
}

func (io *IPObfuscator) initializeTechniques() {
	io.techniques["proxy_rotation"] = IPTechnique{
		Name:        "proxy_rotation",
		Description: "Rotate through multiple proxy servers",
		SuccessRate: 0.9,
		Latency:     200 * time.Millisecond,
		Complexity:  2,
	}

	io.techniques["tor_network"] = IPTechnique{
		Name:        "tor_network",
		Description: "Use Tor network for anonymity",
		SuccessRate: 0.8,
		Latency:     1000 * time.Millisecond,
		Complexity:  3,
	}

	io.techniques["cloud_proxy"] = IPTechnique{
		Name:        "cloud_proxy",
		Description: "Use cloud-based proxy services",
		SuccessRate: 0.95,
		Latency:     150 * time.Millisecond,
		Complexity:  2,
	}

	io.techniques["direct"] = IPTechnique{
		Name:        "direct",
		Description: "Direct connection (no obfuscation)",
		SuccessRate: 1.0,
		Latency:     0,
		Complexity:  0,
	}

	io.activeTechnique = "proxy_rotation"
}

func (io *IPObfuscator) AddProxy(proxy *Proxy) {
	io.mu.Lock()
	defer io.mu.Unlock()

	io.proxies = append(io.proxies, proxy)
	if io.proxyRotator != nil {
		io.proxyRotator.AddProxy(proxy)
	}
}

func (io *IPObfuscator) RemoveProxy(address string, port int) {
	io.mu.Lock()
	defer io.mu.Unlock()

	for i, proxy := range io.proxies {
		if proxy.Address == address && proxy.Port == port {
			io.proxies = append(io.proxies[:i], io.proxies[i+1:]...)
			break
		}
	}
	if io.proxyRotator != nil {
		io.proxyRotator.RemoveProxy(address, port)
	}
}

func (io *IPObfuscator) SetProxies(proxies []*Proxy) {
	io.mu.Lock()
	defer io.mu.Unlock()
	io.proxies = make([]*Proxy, len(proxies))
	copy(io.proxies, proxies)
	if io.proxyRotator != nil {
		io.proxyRotator.mu.Lock()
		io.proxyRotator.proxies = make([]*Proxy, len(proxies))
		copy(io.proxyRotator.proxies, proxies)
		io.proxyRotator.current = 0
		io.proxyRotator.mu.Unlock()
	}
}

func (io *IPObfuscator) GetRandomProxy() (*Proxy, error) {
	io.mu.RLock()
	defer io.mu.RUnlock()

	if len(io.proxies) == 0 {
		return nil, fmt.Errorf("no proxies available")
	}

	randIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(io.proxies))))
	return io.proxies[randIndex.Int64()], nil
}

func (io *IPObfuscator) GetBestProxy() (*Proxy, error) {
	io.mu.RLock()
	defer io.mu.RUnlock()

	if len(io.proxies) == 0 {
		return nil, fmt.Errorf("no proxies available")
	}

	bestProxy := io.proxies[0]
	bestScore := io.calculateProxyScore(bestProxy)

	for _, proxy := range io.proxies[1:] {
		score := io.calculateProxyScore(proxy)
		if score > bestScore {
			bestProxy = proxy
			bestScore = score
		}
	}

	return bestProxy, nil
}

func (io *IPObfuscator) calculateProxyScore(proxy *Proxy) float64 {
	successWeight := 0.7
	latencyWeight := 0.3
	const maxLatency = 5_000.0 // ms
	latMs := float64(proxy.Latency.Milliseconds())
	latencyScore := 1.0 - (latMs / maxLatency)
	if latencyScore < 0 {
		latencyScore = 0
	}

	return successWeight*proxy.SuccessRate + latencyWeight*latencyScore
}

func (io *IPObfuscator) MarkProxySuccess(p *Proxy, latency time.Duration) {
	io.mu.Lock()
	defer io.mu.Unlock()
	if p.Latency == 0 {
		p.Latency = latency
	} else {
		p.Latency = time.Duration(0.7*float64(p.Latency) + 0.3*float64(latency))
	}
	p.SuccessRate = 0.95*p.SuccessRate + 0.05
	p.LastUsed = time.Now()
}

func (io *IPObfuscator) MarkProxyFailure(p *Proxy) {
	io.mu.Lock()
	defer io.mu.Unlock()

	p.SuccessRate = 0.90 * p.SuccessRate
	p.LastUsed = time.Now()
}

func (io *IPObfuscator) SetActiveTechnique(technique string) error {
	io.mu.Lock()
	defer io.mu.Unlock()

	if _, exists := io.techniques[technique]; !exists {
		return fmt.Errorf("technique not found: %s", technique)
	}

	io.activeTechnique = technique
	return nil
}

func (io *IPObfuscator) GetActiveTechnique() string {
	io.mu.RLock()
	defer io.mu.RUnlock()
	return io.activeTechnique
}

func (io *IPObfuscator) UpdateTechniqueStats(technique string, success bool, latency time.Duration) {
	io.mu.Lock()
	defer io.mu.Unlock()

	if tech, exists := io.techniques[technique]; exists {
		if success {
			tech.SuccessRate = (tech.SuccessRate*9 + 1) / 10
		} else {
			tech.SuccessRate = (tech.SuccessRate * 9) / 10
		}
		tech.Latency = (tech.Latency*9 + latency) / 10
		io.techniques[technique] = tech
	}
}


func (io *IPObfuscator) GetTechniques() map[string]IPTechnique {
	io.mu.RLock()
	defer io.mu.RUnlock()

	techniques := make(map[string]IPTechnique, len(io.techniques))
	for k, v := range io.techniques {
		techniques[k] = v
	}
	return techniques
}

func (io *IPObfuscator) AcquireProxy(overrideTechnique ...string) (*Proxy, error) {
	tech := io.GetActiveTechnique()
	if len(overrideTechnique) > 0 && overrideTechnique[0] != "" {
		tech = overrideTechnique[0]
	}

	switch tech {
	case "direct":
		return nil, nil
	case "proxy_rotation", "cloud_proxy":
		if io.proxyRotator != nil {
			return io.proxyRotator.NextProxy()
		}
		return io.GetBestProxy()
	case "tor_network":
		io.mu.RLock()
		for _, p := range io.proxies {
			if p.Type == "socks5" {
				io.mu.RUnlock()
				return p, nil
			}
		}
		io.mu.RUnlock()
		return io.GetBestProxy()
	default:
		return io.GetBestProxy()
	}
}

func (io *IPObfuscator) GenerateSpoofedIP() net.IP {
	for attempts := 0; attempts < 20; attempts++ {
		ip := make(net.IP, 4)
		_, _ = rand.Read(ip)
		if !isBogonIPv4(ip) {
			return ip
		}
	}
	return net.IPv4(8, 8, 8, 8)
}

func (io *IPObfuscator) AddSpoofedIP(ip net.IP) {
	io.mu.Lock()
	defer io.mu.Unlock()
	io.spoofedIPs = append(io.spoofedIPs, ip.To4())
}

func (io *IPObfuscator) GetSpoofedIP() net.IP {
	io.mu.RLock()
	n := len(io.spoofedIPs)
	io.mu.RUnlock()

	if n == 0 {
		return io.GenerateSpoofedIP()
	}

	randIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	io.mu.RLock()
	ip := make(net.IP, len(io.spoofedIPs[randIndex.Int64()]))
	copy(ip, io.spoofedIPs[randIndex.Int64()])
	io.mu.RUnlock()
	return ip
}

func isBogonIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return true
	}
	b0 := ip4[0]
	b1 := ip4[1]

	switch {
	case b0 == 0: // 0.0.0.0/8
		return true
	case b0 == 10: // 10.0.0.0/8
		return true
	case b0 == 100 && b1 >= 64 && b1 <= 127: // 100.64.0.0/10
		return true
	case b0 == 127: // 127.0.0.0/8
		return true
	case b0 == 169 && b1 == 254: // 169.254.0.0/16
		return true
	case b0 == 172 && b1 >= 16 && b1 <= 31: // 172.16.0.0/12
		return true
	case b0 == 192 && b1 == 0: // 192.0.0.0/24 (incl 192.0.2.0/24 test)
		return true
	case b0 == 192 && b1 == 168: // 192.168.0.0/16
		return true
	case b0 == 198 && (b1 == 18 || b1 == 19): // 198.18.0.0/15
		return true
	case b0 == 198 && b1 == 51: // 198.51.100.0/24 (test)
		return true
	case b0 == 203 && b1 == 0: // 203.0.113.0/24 (test)
		return true
	case b0 >= 224: // 224.0.0.0/4 multicast & 240/4 reserved
		return true
	default:
		return false
	}
}

func NewProxyRotator(proxies []*Proxy, logger *logrus.Logger) *ProxyRotator {
	if logger == nil {
		logger = logrus.New()
	}
	return &ProxyRotator{
		proxies:          proxies,
		logger:           logger,
		rotationStrategy: "round_robin",
	}
}

func (io *IPObfuscator) AttachRotator(rotator *ProxyRotator) {
	io.mu.Lock()
	defer io.mu.Unlock()
	io.proxyRotator = rotator
}

func (io *IPObfuscator) BuildRotatorFromCurrent(strategy string) {
	io.mu.RLock()
	proxies := make([]*Proxy, len(io.proxies))
	copy(proxies, io.proxies)
	io.mu.RUnlock()

	r := NewProxyRotator(proxies, io.logger)
	r.SetRotationStrategy(strategy)
	io.AttachRotator(r)
}

func (pr *ProxyRotator) NextProxy() (*Proxy, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if len(pr.proxies) == 0 {
		return nil, fmt.Errorf("no proxies available")
	}

	var proxy *Proxy

	switch pr.rotationStrategy {
	case "round_robin":
		proxy = pr.proxies[pr.current]
		pr.current = (pr.current + 1) % len(pr.proxies)
	case "random":
		randIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pr.proxies))))
		proxy = pr.proxies[randIndex.Int64()]
	case "best_performing":
		bestScore := -1.0
		for _, p := range pr.proxies {
			score := 0.7*p.SuccessRate + 0.3*(1.0-(float64(p.Latency.Milliseconds())/5000.0))
			if score > bestScore {
				bestScore = score
				proxy = p
			}
		}
	default:
		proxy = pr.proxies[pr.current]
		pr.current = (pr.current + 1) % len(pr.proxies)
	}

	proxy.LastUsed = time.Now()
	return proxy, nil
}

func (pr *ProxyRotator) SetRotationStrategy(strategy string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.rotationStrategy = strategy
}

func (pr *ProxyRotator) AddProxy(proxy *Proxy) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.proxies = append(pr.proxies, proxy)
}

func (pr *ProxyRotator) RemoveProxy(address string, port int) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for i, proxy := range pr.proxies {
		if proxy.Address == address && proxy.Port == port {
			pr.proxies = append(pr.proxies[:i], pr.proxies[i+1:]...)
			if pr.current >= len(pr.proxies) && len(pr.proxies) > 0 {
				pr.current = pr.current % len(pr.proxies)
			} else if len(pr.proxies) == 0 {
				pr.current = 0
			}
			break
		}
	}
}

func (pr *ProxyRotator) GetStats() map[string]interface{} {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	stats := map[string]interface{}{
		"total_proxies":     len(pr.proxies),
		"rotation_strategy": pr.rotationStrategy,
		"current_index":     pr.current,
	}

	byType := make(map[string]int)
	for _, proxy := range pr.proxies {
		byType[proxy.Type]++
	}
	stats["proxies_by_type"] = byType

	return stats
}

func (io *IPObfuscator) GetStats() map[string]interface{} {
	io.mu.RLock()
	defer io.mu.RUnlock()

	techs := make(map[string]map[string]interface{}, len(io.techniques))
	for k, v := range io.techniques {
		techs[k] = map[string]interface{}{
			"success_rate": v.SuccessRate,
			"latency":      v.Latency,
			"complexity":   v.Complexity,
		}
	}

	return map[string]interface{}{
		"proxies":             len(io.proxies),
		"active_technique":    io.activeTechnique,
		"techniques":          techs,
		"spoofed_pool_size":   len(io.spoofedIPs),
		"rotator_attached":    io.proxyRotator != nil,
		"rotator_strategy":    func() string { if io.proxyRotator != nil { return io.proxyRotator.rotationStrategy }; return "" }(),
	}
}

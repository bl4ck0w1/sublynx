package security

import (
	"dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
	"github.com/bl4ck0w1/sublynx/pkg/models"
)

type SSLAnalyzer struct {
	timeout        time.Duration
	logger         *logrus.Logger
	mu             sync.RWMutex
	trustedRoots   *x509.CertPool
	revocationList []string
	ciphers        []uint16
	curves         []tls.CurveID
}

func NewSSLAnalyzer(timeout time.Duration, logger *logrus.Logger) *SSLAnalyzer {
	if logger == nil {
		logger = logrus.New()
	}

	trustedRoots, _ := x509.SystemCertPool()
	if trustedRoots == nil {
		trustedRoots = x509.NewCertPool()
	}
	revocationList := []string{}

	return &SSLAnalyzer{
		timeout:        timeout,
		logger:         logger,
		trustedRoots:   trustedRoots,
		revocationList: revocationList,
		ciphers:        getAllCiphers(),
		curves:         getAllCurves(),
	}
}

func (s *SSLAnalyzer) AnalyzeTLS(host string, port int) (*models.TLSAnalysis, error) {
	analysis := &models.TLSAnalysis{
		Host:       host,
		Port:       port,
		AnalyzedAt: time.Now(),
		Findings:   make([]models.TLSFinding, 0),
	}

	conn, err := s.connectWithTLS(host, port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	s.analyzeCertificate(state, analysis)
	s.analyzeProtocolSupport(state, analysis)
	s.analyzeCipherSuites(state, analysis)
	s.analyzeKeyExchange(state, analysis)
	s.analyzeExtensions(state, analysis)
	s.checkVulnerabilities(state, analysis)
	analysis.SecurityScore = s.calculateSecurityScore(analysis)

	return analysis, nil
}

func (s *SSLAnalyzer) connectWithTLS(host string, port int) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: s.timeout}
	configs := []*tls.Config{
		{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		},
		{
			MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS11,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		},
	}

	var lastErr error
	addr := fmt.Sprintf("%s:%d", host, port)
	for _, cfg := range configs {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
func (s *SSLAnalyzer) analyzeCertificate(state tls.ConnectionState, analysis *models.TLSAnalysis) {
	if len(state.PeerCertificates) == 0 {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "no_certificate",
			Severity:    models.SeverityCritical,
			Description: "No certificate presented by server",
			Confidence:  1.0,
		})
		return
	}

	for i, cert := range state.PeerCertificates {
		certAnalysis := s.analyzeSingleCertificate(cert, i == 0)
		analysis.Certificates = append(analysis.Certificates, certAnalysis)
		for _, finding := range certAnalysis.Findings {
			analysis.Findings = append(analysis.Findings, finding)
		}
	}

	s.verifyCertificateChain(state, analysis)
}

func (s *SSLAnalyzer) analyzeSingleCertificate(cert *x509.Certificate, isLeaf bool) models.CertificateAnalysis {
	a := models.CertificateAnalysis{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		KeyAlgorithm:  cert.PublicKeyAlgorithm.String(),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		DNSNames:      cert.DNSNames,
		Findings:      make([]models.TLSFinding, 0),
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		a.Findings = append(a.Findings, models.TLSFinding{
			Type:        "certificate_expired",
			Severity:    models.SeverityCritical,
			Description: "Certificate has expired",
			Confidence:  1.0,
		})
	} else if now.Add(30 * 24 * time.Hour).After(cert.NotAfter) {
		a.Findings = append(a.Findings, models.TLSFinding{
			Type:        "certificate_expiring_soon",
			Severity:    models.SeverityMedium,
			Description: "Certificate will expire within 30 days",
			Confidence:  1.0,
		})
	}

	keyBits := s.analyzeKeyStrength(cert)
	if keyBits > 0 && keyBits < 2048 {
		a.Findings = append(a.Findings, models.TLSFinding{
			Type:        "weak_key",
			Severity:    models.SeverityHigh,
			Description: fmt.Sprintf("Weak key strength: %d bits", keyBits),
			Confidence:  1.0,
		})
	}

	if isWeakSignatureAlgorithm(cert.SignatureAlgorithm) {
		a.Findings = append(a.Findings, models.TLSFinding{
			Type:        "weak_signature_algorithm",
			Severity:    models.SeverityHigh,
			Description: "Weak signature algorithm: " + cert.SignatureAlgorithm.String(),
			Confidence:  1.0,
		})
	}

	if !cert.BasicConstraintsValid {
		a.Findings = append(a.Findings, models.TLSFinding{
			Type:        "missing_basic_constraints",
			Severity:    models.SeverityLow,
			Description: "Certificate missing basic constraints",
			Confidence:  1.0,
		})
	}

	if isLeaf && cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		a.Findings = append(a.Findings, models.TLSFinding{
			Type:        "missing_key_encipherment",
			Severity:    models.SeverityMedium,
			Description: "Leaf certificate missing key encipherment usage",
			Confidence:  1.0,
		})
	}

	return a
}

func (s *SSLAnalyzer) analyzeKeyStrength(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case *dsa.PublicKey:
		return pub.P.BitLen()
	default:
		return 0
	}
}

func isWeakSignatureAlgorithm(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

func (s *SSLAnalyzer) verifyCertificateChain(state tls.ConnectionState, analysis *models.TLSAnalysis) {
	opts := x509.VerifyOptions{
		Roots:         s.trustedRoots,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
		DNSName:       state.ServerName,
	}

	if len(state.PeerCertificates) > 1 {
		for _, cert := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
	}

	leaf := state.PeerCertificates[0]
	if _, err := leaf.Verify(opts); err != nil {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "certificate_chain_invalid",
			Severity:    models.SeverityHigh,
			Description: "Certificate chain verification failed: " + err.Error(),
			Confidence:  1.0,
		})
	} else {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "certificate_chain_valid",
			Severity:    models.SeverityInfo,
			Description: "Certificate chain is valid",
			Confidence:  1.0,
		})
	}
}

func (s *SSLAnalyzer) analyzeProtocolSupport(state tls.ConnectionState, analysis *models.TLSAnalysis) {
	switch state.Version {
	case tls.VersionTLS10:
		analysis.NegotiatedProtocol = "TLS 1.0"
	case tls.VersionTLS11:
		analysis.NegotiatedProtocol = "TLS 1.1"
	case tls.VersionTLS12:
		analysis.NegotiatedProtocol = "TLS 1.2"
	case tls.VersionTLS13:
		analysis.NegotiatedProtocol = "TLS 1.3"
	default:
		analysis.NegotiatedProtocol = "Unknown"
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "unknown_protocol",
			Severity:    models.SeverityMedium,
			Description: "Unknown protocol version negotiated",
			Confidence:  1.0,
		})
	}

	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "weak_protocol",
			Severity:    models.SeverityHigh,
			Description: "Weak protocol negotiated: " + analysis.NegotiatedProtocol,
			Confidence:  1.0,
		})
	}
}

func (s *SSLAnalyzer) analyzeCipherSuites(state tls.ConnectionState, analysis *models.TLSAnalysis) {
	analysis.NegotiatedCipher = tls.CipherSuiteName(state.CipherSuite)
	if isWeakCipher(state.CipherSuite) {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "weak_cipher",
			Severity:    models.SeverityHigh,
			Description: "Weak cipher suite: " + analysis.NegotiatedCipher,
			Confidence:  1.0,
		})
	}
}

func isWeakCipher(cs uint16) bool {
	switch cs {
	case tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return true
	default:
		return false
	}
}

func (s *SSLAnalyzer) analyzeKeyExchange(state tls.ConnectionState, analysis *models.TLSAnalysis) {
	csName := tls.CipherSuiteName(state.CipherSuite)
	switch {
	case strings.Contains(csName, "ECDHE"):
		analysis.KeyExchange = "ECDHE"
	case strings.Contains(csName, "DHE"):
		analysis.KeyExchange = "DHE"
	case strings.Contains(csName, "RSA"):
		analysis.KeyExchange = "RSA"
	default:
		analysis.KeyExchange = "Unknown"
	}

	if analysis.KeyExchange == "RSA" {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "static_key_exchange",
			Severity:    models.SeverityMedium,
			Description: "Static RSA key exchange (no forward secrecy)",
			Confidence:  1.0,
		})
	}
}

func (s *SSLAnalyzer) analyzeExtensions(state tls.ConnectionState, analysis *models.TLSAnalysis) {
	if len(state.OCSPResponse) > 0 {
		analysis.OCSPStapling = true
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "ocsp_stapling_enabled",
			Severity:    models.SeverityInfo,
			Description: "OCSP stapling is enabled",
			Confidence:  1.0,
		})
	} else {
		analysis.OCSPStapling = false
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "ocsp_stapling_disabled",
			Severity:    models.SeverityLow,
			Description: "OCSP stapling is disabled",
			Confidence:  1.0,
		})
	}

	analysis.SessionResumption = state.DidResume
	if state.DidResume {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "session_resumption_enabled",
			Severity:    models.SeverityInfo,
			Description: "Session resumption is enabled",
			Confidence:  1.0,
		})
	}
}

func (s *SSLAnalyzer) checkVulnerabilities(state tls.ConnectionState, analysis *models.TLSAnalysis) {
	if s.checkHeartbleedVulnerability(state) {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "heartbleed_vulnerable",
			Severity:    models.SeverityCritical,
			Description: "Server may be vulnerable to Heartbleed (heuristic)",
			Confidence:  0.5,
		})
	}

	if state.Version <= tls.VersionTLS11 && strings.Contains(tls.CipherSuiteName(state.CipherSuite), "RSA") {
		analysis.Findings = append(analysis.Findings, models.TLSFinding{
			Type:        "robot_vulnerable",
			Severity:    models.SeverityHigh,
			Description: "Potential RSA padding oracle risk (heuristic)",
			Confidence:  0.6,
		})
	}
}

func (s *SSLAnalyzer) checkHeartbleedVulnerability(_ tls.ConnectionState) bool {
	return false
}

func (s *SSLAnalyzer) calculateSecurityScore(analysis *models.TLSAnalysis) float64 {
	score := 1.0
	for _, f := range analysis.Findings {
		switch f.Severity {
		case models.SeverityCritical:
			score -= 0.3
		case models.SeverityHigh:
			score -= 0.2
		case models.SeverityMedium:
			score -= 0.1
		case models.SeverityLow:
			score -= 0.05
		}
	}
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

func getAllCiphers() []uint16 {
	return []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
}

func getAllCurves() []tls.CurveID {
	return []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519}
}

func (s *SSLAnalyzer) BatchAnalyzeTLS(hosts []string, port int) ([]*models.TLSAnalysis, error) {
	var results []*models.TLSAnalysis
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			analysis, err := s.AnalyzeTLS(host, port)
			if err != nil {
				s.logger.Warnf("TLS analysis failed for %s:%d: %v", host, port, err)
				return
			}
			mu.Lock()
			results = append(results, analysis)
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return results, nil
}

func (s *SSLAnalyzer) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"timeout":           s.timeout.String(),
		"trusted_roots":     len(s.trustedRoots.Subjects()),
		"revocation_list":   len(s.revocationList),
		"supported_ciphers": len(s.ciphers),
		"supported_curves":  len(s.curves),
	}
}

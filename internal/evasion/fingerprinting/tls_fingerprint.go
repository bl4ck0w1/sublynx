package fingerprinting

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	utls "github.com/refraction-networking/utls"
)

type TLSFingerprinter struct {
	fingerprints map[string]utls.ClientHelloID
	logger       *logrus.Logger
	mu           sync.RWMutex
}

func NewTLSFingerprinter(logger *logrus.Logger) *TLSFingerprinter {
	if logger == nil {
		logger = logrus.New()
	}
	tf := &TLSFingerprinter{
		fingerprints: make(map[string]utls.ClientHelloID),
		logger:       logger,
	}
	tf.initializeFingerprints()
	return tf
}

func (tf *TLSFingerprinter) initializeFingerprints() {
	tf.fingerprints["chrome"] = utls.HelloChrome_Auto
	tf.fingerprints["firefox"] = utls.HelloFirefox_Auto
	tf.fingerprints["safari"] = utls.HelloSafari_Auto
	tf.fingerprints["edge"] = utls.HelloEdge_Auto
	tf.fingerprints["android"] = utls.HelloAndroid_11_OkHttp
	tf.fingerprints["ios"] = utls.HelloIOS_Auto
	tf.fingerprints["ios_13_1"] = utls.HelloIOS_13_1
	tf.fingerprints["golang"] = utls.HelloGolang
	tf.fingerprints["random"] = utls.HelloRandomized
	tf.fingerprints["random_alpn"] = utls.HelloRandomizedALPN
	tf.fingerprints["random_noalpn"] = utls.HelloRandomizedNoALPN
}

func (tf *TLSFingerprinter) GetFingerprint(name string) (utls.ClientHelloID, error) {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	if fp, ok := tf.fingerprints[name]; ok {
		return fp, nil
	}
	return utls.ClientHelloID{}, fmt.Errorf("fingerprint not found: %s", name)
}

func (tf *TLSFingerprinter) AddFingerprint(name string, id utls.ClientHelloID) error {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	if _, exists := tf.fingerprints[name]; exists {
		return fmt.Errorf("fingerprint already exists: %s", name)
	}
	tf.fingerprints[name] = id
	return nil
}

func (tf *TLSFingerprinter) RemoveFingerprint(name string) {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	delete(tf.fingerprints, name)
}

func (tf *TLSFingerprinter) GetRandomFingerprint() utls.ClientHelloID {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	if len(tf.fingerprints) == 0 {
		return utls.HelloGolang
	}
	values := make([]utls.ClientHelloID, 0, len(tf.fingerprints))
	for _, v := range tf.fingerprints {
		values = append(values, v)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(values))))
	if err != nil {
		return values[0]
	}
	return values[n.Int64()]
}

func (tf *TLSFingerprinter) GetFingerprintNames() []string {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	names := make([]string, 0, len(tf.fingerprints))
	for name := range tf.fingerprints {
		names = append(names, name)
	}
	return names
}

func (tf *TLSFingerprinter) NewUTLSConfig(serverName string) *utls.Config {
	return &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false, 
	}
}

func (tf *TLSFingerprinter) DialWithFingerprint(
	ctx context.Context,
	network, address, serverName, fingerprintName string,
	cfg *utls.Config,
) (*utls.UConn, error) {
	fp, err := tf.GetFingerprint(fingerprintName)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	if deadline, ok := ctx.Deadline(); ok {
		d.Timeout = time.Until(deadline)
	}
	rawConn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}
	if cfg == nil {
		cfg = tf.NewUTLSConfig(serverName)
	} else if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	uconn := utls.UClient(rawConn, cfg, fp)
	if err := uconn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("utls handshake failed: %w", err)
	}
	return uconn, nil
}

func (tf *TLSFingerprinter) WrapNetConn(
	conn net.Conn,
	serverName, fingerprintName string,
	cfg *utls.Config,
) (*utls.UConn, error) {
	fp, err := tf.GetFingerprint(fingerprintName)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = tf.NewUTLSConfig(serverName)
	} else if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	return utls.UClient(conn, cfg, fp), nil
}

func (tf *TLSFingerprinter) BuildCustomHello(build func(*utls.ClientHelloSpec)) utls.ClientHelloID {
	spec := &utls.ClientHelloSpec{}
	if build != nil {
		build(spec)
	}
	custom := utls.HelloCustom
	custom.Spec = spec
	return custom
}

func (tf *TLSFingerprinter) GetFingerprintStats() map[string]interface{} {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return map[string]interface{}{
		"total_fingerprints": len(tf.fingerprints),
		"fingerprint_names":  tf.GetFingerprintNames(),
	}
}

func (tf *TLSFingerprinter) TestFingerprint(targetAddr, serverName, fingerprintName string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := tf.DialWithFingerprint(ctx, "tcp", targetAddr, serverName, fingerprintName, nil)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

func (tf *TLSFingerprinter) BatchTestFingerprints(targetAddr, serverName string, fps []string, timeout time.Duration) map[string]bool {
	results := make(map[string]bool, len(fps))
	for _, name := range fps {
		ok, err := tf.TestFingerprint(targetAddr, serverName, name, timeout)
		results[name] = (err == nil) && ok
	}
	return results
}

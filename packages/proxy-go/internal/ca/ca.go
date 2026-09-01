package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	Dir  string
	mu   sync.Mutex
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	leaf map[string]*tls.Certificate
}

func HomeDir() string {
	if d := os.Getenv("SHROODLER_PROXY_HOME"); d != "" {
		return d
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "shroodler-proxy")
}

func NewStore(dir string) *Store {
	if dir == "" {
		dir = HomeDir()
	}
	return &Store{Dir: dir, leaf: map[string]*tls.Certificate{}}
}

func (s *Store) certPath() string { return filepath.Join(s.Dir, "ca.pem") }
func (s *Store) keyPath() string  { return filepath.Join(s.Dir, "ca.key") }

func (s *Store) Generate() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Shroodler Proxy Root CA", Organization: []string{"Shroodler"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(s.certPath(), certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(s.keyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	s.cert, s.key = cert, key
	return nil
}

func (s *Store) Load() error {
	certPEM, err := os.ReadFile(s.certPath())
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(s.keyPath())
	if err != nil {
		return err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return err
	}
	s.cert, s.key = cert, key
	return nil
}

func (s *Store) Export(path string) error {
	if err := s.ensure(); err != nil {
		return err
	}
	b, err := os.ReadFile(s.certPath())
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func (s *Store) Uninstall(confirm bool) error {
	if !confirm {
		return fmt.Errorf("refusing to uninstall CA without --yes; would remove %s and %s", s.certPath(), s.keyPath())
	}
	_ = os.Remove(s.certPath())
	_ = os.Remove(s.keyPath())
	return nil
}

func (s *Store) ensure() error {
	if s.cert != nil && s.key != nil {
		return nil
	}
	if _, err := os.Stat(s.certPath()); err != nil {
		return fmt.Errorf("CA not generated; run shroodler-proxy ca generate")
	}
	return s.Load()
}

func (s *Store) Leaf(host string) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensure(); err != nil {
		return nil, err
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if c, ok := s.leaf[h]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: h},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{h},
	}
	if ip := net.ParseIP(h); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.cert, &key.PublicKey, s.key)
	if err != nil {
		return nil, err
	}
	leaf := tls.Certificate{Certificate: [][]byte{der, s.cert.Raw}, PrivateKey: key}
	s.leaf[h] = &leaf
	return &leaf, nil
}

func (s *Store) CertPEM() ([]byte, error) {
	return os.ReadFile(s.certPath())
}

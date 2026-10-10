// Package proxy manages optional, authorised HTTPS interception: a locally
// generated CA that the operator installs on test devices by hand, a mitmdump
// service, and ingestion of the decrypted HTTP transactions.
//
// Consent is the whole design. The CA private key never leaves the appliance,
// is never pushed to a device, and interception only happens for devices whose
// owner has explicitly installed and trusted the CA. Nothing is covert.
package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CAInfo describes the interception CA for display. It never includes the key.
type CAInfo struct {
	Present     bool   `json:"present"`
	Subject     string `json:"subject"`
	SHA256      string `json:"sha256"`      // fingerprint, colon-separated
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
	Serial      string `json:"serial"`
	DaysLeft    int    `json:"days_left"`
	KeyType     string `json:"key_type"`
}

// caPaths returns the key+cert path (mitmproxy format) and the public cert path.
func caPaths(dir string) (combined, certOnly string) {
	return filepath.Join(dir, "mitmproxy-ca.pem"), filepath.Join(dir, "mitmproxy-ca-cert.pem")
}

// EnsureCA creates the interception CA if absent, in the mitmproxy confdir layout.
// RSA-2048 is used (not EC) for the broadest device trust-store compatibility.
func EnsureCA(dir, hostname string) error {
	combined, certOnly := caPaths(dir)
	if _, err := os.Stat(combined); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cn := "PiLens Interception CA"
	if hostname != "" {
		cn = "PiLens Interception CA (" + hostname + ")"
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"PiLens appliance"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	// mitmproxy reads the key+cert from mitmproxy-ca.pem (0600) and derives the rest.
	if err := writeFile(combined, append(append([]byte{}, keyPEM...), certPEM...), 0o600); err != nil {
		return err
	}
	// Public cert for download / device install (never contains the key).
	if err := writeFile(certOnly, certPEM, 0o644); err != nil {
		return err
	}
	writeFile(filepath.Join(dir, "mitmproxy-ca-cert.cer"), certPEM, 0o644)
	return nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	os.Chmod(tmp, mode)
	return os.Rename(tmp, path)
}

// PublicCertPEM returns the CA's public certificate (safe to distribute). It never
// returns the private key.
func PublicCertPEM(dir string) ([]byte, error) {
	_, certOnly := caPaths(dir)
	b, err := os.ReadFile(certOnly)
	if err != nil {
		return nil, errors.New("interception CA not generated yet")
	}
	if strings.Contains(string(b), "PRIVATE KEY") { // defensive: must never happen
		return nil, errors.New("refusing to serve a file containing a private key")
	}
	return b, nil
}

// Info reads the CA metadata for display.
func Info(dir string) CAInfo {
	_, certOnly := caPaths(dir)
	b, err := os.ReadFile(certOnly)
	if err != nil {
		return CAInfo{Present: false}
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return CAInfo{Present: false}
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return CAInfo{Present: false}
	}
	sum := sha256.Sum256(c.Raw)
	return CAInfo{
		Present:   true,
		Subject:   c.Subject.String(),
		SHA256:    colonHex(sum[:]),
		NotBefore: c.NotBefore.UTC().Format("2006-01-02"),
		NotAfter:  c.NotAfter.UTC().Format("2006-01-02"),
		Serial:    c.SerialNumber.Text(16),
		DaysLeft:  int(time.Until(c.NotAfter).Hours() / 24),
		KeyType:   "RSA 2048",
	}
}

// Rotate deletes the CA so a fresh one is generated. Devices trusting the old CA
// must install the new one; existing interception breaks until they do.
func Rotate(dir, hostname string) error {
	combined, certOnly := caPaths(dir)
	for _, p := range []string{combined, certOnly, filepath.Join(dir, "mitmproxy-ca-cert.cer"), filepath.Join(dir, "mitmproxy-ca.p12"), filepath.Join(dir, "mitmproxy-ca-cert.p12"), filepath.Join(dir, "mitmproxy-dhparam.pem")} {
		os.Remove(p)
	}
	return EnsureCA(dir, hostname)
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Fingerprint of a cert file, for the install instructions ("verify this matches").
func Fingerprint(dir string) string {
	return fmt.Sprintf("SHA-256 %s", Info(dir).SHA256)
}

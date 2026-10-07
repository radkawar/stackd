// Package devtls provides explicitly trusted, local development TLS certificates.
// Its CA is not publicly trusted; clients must opt in to its public certificate.
package devtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	authorityName       = "stackd development CA"
	leafLifetime        = 24 * time.Hour
	leafRenewBefore     = time.Hour
	maximumCachedLeaves = 256
)

var (
	// ErrNameNotAllowed means the requested name is outside the explicit scope.
	ErrNameNotAllowed = errors.New("devtls: name is not allowed")
	// ErrAuthorityExpired requires an explicit replacement and client trust update.
	// Open never silently rotates the CA, including after expiry.
	ErrAuthorityExpired = errors.New("devtls: development CA has expired")
)

// Config specifies private state and the only names the authority may issue.
// Each Domain permits itself and its dot-boundary descendants, not wildcards.
// IPAddresses permit exact addresses only; no address is discovered implicitly.
type Config struct {
	Directory   string
	Domains     []string
	IPAddresses []netip.Addr
}

// Authority retains a persisted CA and an in-memory, bounded leaf cache.
// Certificates are ECDSA P-256. The CA lasts ten years; leaves last at most
// 24 hours and never outlive it. Expired CAs are errors, not automatic rotations.
// Authority is safe for concurrent use and does not retain open state files.
type Authority struct {
	directory string
	domains   []string
	addresses []netip.Addr
	ca        *x509.Certificate
	key       *ecdsa.PrivateKey
	publicPEM []byte
	gate      chan struct{}
	leaves    map[string]*tls.Certificate
}

// Open creates or reopens an authority in a private directory. A single atomic
// private bundle preserves the CA certificate and key as one durable identity.
// Existing unsafe, incomplete, invalid or expired state is never replaced.
func Open(ctx context.Context, config Config) (*Authority, error) {
	if ctx == nil {
		return nil, errors.New("devtls: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("devtls: open: %w", err)
	}
	if config.Directory == "" {
		return nil, errors.New("devtls: private state directory is required")
	}
	domains := make([]string, 0, len(config.Domains))
	seenDomains := make(map[string]bool, len(config.Domains))
	for _, domain := range config.Domains {
		name, err := dnsName(domain)
		if err != nil {
			return nil, fmt.Errorf("devtls: domain %q: %w", domain, err)
		}
		if !seenDomains[name] {
			domains = append(domains, name)
			seenDomains[name] = true
		}
	}
	addresses := make([]netip.Addr, 0, len(config.IPAddresses))
	seenAddresses := make(map[netip.Addr]bool, len(config.IPAddresses))
	for _, address := range config.IPAddresses {
		if !address.IsValid() || address.Zone() != "" {
			return nil, fmt.Errorf("devtls: invalid explicit IP address %q", address)
		}
		address = address.Unmap()
		if address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("devtls: invalid explicit IP address %q", address)
		}
		if !seenAddresses[address] {
			addresses = append(addresses, address)
			seenAddresses[address] = true
		}
	}
	directory, ca, key, publicPEM, err := openState(ctx, config.Directory)
	if err != nil {
		return nil, err
	}
	return &Authority{
		directory: directory, domains: domains, addresses: addresses,
		ca: ca, key: key, publicPEM: publicPEM,
		gate: make(chan struct{}, 1), leaves: make(map[string]*tls.Certificate),
	}, nil
}

// TLSConfig returns a fresh server configuration with TLS 1.2 or newer and an
// on-demand certificate callback. It does not disable any TLS verification.
// A DNS SNI receives one exact DNS SAN. An IP SNI receives one configured IP SAN.
// Clients normally omit SNI for IP literals: a no-SNI handshake receives an
// IP-only certificate covering configured IPAddresses, or fails if none exist.
func (a *Authority) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello == nil {
				return nil, errors.New("devtls: client hello is required")
			}
			ctx := hello.Context()
			if ctx == nil {
				// A caller may select a certificate directly without a handshake.
				ctx = context.Background()
			}
			return a.certificate(ctx, hello.ServerName)
		},
	}
}

// CAFile is the absolute path of the persisted public PEM certificate only.
func (a *Authority) CAFile() string { return publicPath(a.directory) }

// CACertificate returns a caller-owned copy of the public PEM certificate.
func (a *Authority) CACertificate() []byte { return bytes.Clone(a.publicPEM) }

// Export atomically writes only the public certificate to path (mode 0644).
// Its parent must already exist. Symlinks, nonregular files and private state
// destinations are refused; no private key is ever exported.
func (a *Authority) Export(path string) error { return a.export(path) }

func dnsName(value string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(value, "."))
	if name == "" || len(name) > 253 {
		return "", errors.New("DNS name must contain 1 to 253 ASCII characters")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", errors.New("IP literals belong in IPAddresses")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return "", errors.New("DNS names must use ASCII letters, digits and interior hyphens")
			}
		}
	}
	return name, nil
}

func (a *Authority) certificate(ctx context.Context, requested string) (*tls.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("devtls: issue certificate: %w", err)
	}
	name := ""
	var addresses []netip.Addr
	if requested == "" {
		if len(a.addresses) == 0 {
			return nil, fmt.Errorf("%w: missing SNI and no configured IP address", ErrNameNotAllowed)
		}
		addresses = a.addresses
	} else if address, err := netip.ParseAddr(requested); err == nil {
		if address.Zone() != "" {
			return nil, fmt.Errorf("%w: scoped IP address %q", ErrNameNotAllowed, requested)
		}
		address = address.Unmap()
		for _, allowed := range a.addresses {
			if address == allowed {
				addresses = []netip.Addr{address}
				break
			}
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("%w: IP address %q", ErrNameNotAllowed, requested)
		}
	} else {
		var err error
		name, err = dnsName(requested)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrNameNotAllowed, requested, err)
		}
		allowed := false
		for _, domain := range a.domains {
			if name == domain || len(name) > len(domain) && name[len(name)-len(domain)-1] == '.' && strings.HasSuffix(name, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: DNS name %q", ErrNameNotAllowed, requested)
		}
	}
	cacheKey := name
	if name == "" && requested != "" {
		cacheKey = addresses[0].String()
	}
	select {
	case a.gate <- struct{}{}:
		defer func() { <-a.gate }()
	case <-ctx.Done():
		return nil, fmt.Errorf("devtls: waiting to issue certificate: %w", ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("devtls: issue certificate: %w", err)
	}
	now := time.Now()
	if err := validAuthorityTime(a.ca, now); err != nil {
		return nil, err
	}
	if cert := a.leaves[cacheKey]; cert != nil && !now.Before(cert.Leaf.NotBefore) && now.Before(cert.Leaf.NotAfter) {
		if now.Add(leafRenewBefore).Before(cert.Leaf.NotAfter) || cert.Leaf.NotAfter.Equal(a.ca.NotAfter) {
			return cert, nil
		}
	}
	cert, err := a.issue(ctx, name, addresses, now)
	if err != nil {
		return nil, err
	}
	if len(a.leaves) >= maximumCachedLeaves && a.leaves[cacheKey] == nil {
		// Bound memory even when an authorized suffix receives arbitrary names.
		for cached := range a.leaves {
			delete(a.leaves, cached)
			break
		}
	}
	a.leaves[cacheKey] = cert
	return cert, nil
}

func (a *Authority) issue(ctx context.Context, name string, addresses []netip.Addr, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("devtls: generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("devtls: generate leaf serial: %w", err)
	}
	before := now.Add(-5 * time.Minute)
	if before.Before(a.ca.NotBefore) {
		before = a.ca.NotBefore
	}
	after := now.Add(leafLifetime)
	if after.After(a.ca.NotAfter) {
		after = a.ca.NotAfter
	}
	leaf := &x509.Certificate{
		SerialNumber: serial, NotBefore: before, NotAfter: after,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if name != "" {
		leaf.DNSNames = []string{name}
	}
	for _, address := range addresses {
		leaf.IPAddresses = append(leaf.IPAddresses, net.IP(address.AsSlice()))
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("devtls: issue certificate: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.ca, &key.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("devtls: sign leaf certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("devtls: parse issued leaf: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("devtls: issue certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, nil
}

func randomSerial() (*big.Int, error) {
	// Set a high bit so the random 128-bit serial is always positive and nonzero.
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return nil, err
	}
	bytes[0] |= 0x80
	return new(big.Int).SetBytes(bytes[:]), nil
}

func validAuthorityTime(ca *x509.Certificate, now time.Time) error {
	if !now.Before(ca.NotAfter) {
		return ErrAuthorityExpired
	}
	if now.Before(ca.NotBefore) {
		return errors.New("devtls: development CA is not yet valid")
	}
	return nil
}

func generateAuthority(ctx context.Context) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("devtls: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("devtls: generate CA serial: %w", err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: authorityName},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("devtls: generate CA: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("devtls: sign CA certificate: %w", err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("devtls: parse generated CA: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("devtls: marshal CA key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle := append(bytes.Clone(publicPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	return ca, key, publicPEM, bundle, nil
}

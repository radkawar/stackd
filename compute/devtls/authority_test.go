//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func openTestAuthority(t *testing.T, config Config) *Authority {
	t.Helper()
	if config.Directory == "" {
		config.Directory = privateTestDirectory(t)
	}
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func testRoots(t *testing.T, authority *Authority) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CACertificate()) {
		t.Fatal("public certificate did not populate trust roots")
	}
	return roots
}

func TestPersistedAuthorityAndPublicExport(t *testing.T) {
	authority := openTestAuthority(t, Config{Domains: []string{"local.test"}})
	public := authority.CACertificate()
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("public export is not exactly one certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsCA || !root.MaxPathLenZero || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("certificate is not a leaf-signing root CA")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root self-signature: %v", err)
	}
	if _, err := root.Verify(x509.VerifyOptions{Roots: testRoots(t, authority)}); err != nil {
		t.Fatalf("trusted root verification: %v", err)
	}
	if root.NotAfter.Before(time.Now().AddDate(9, 0, 0)) || root.NotAfter.After(time.Now().AddDate(10, 0, 1)) {
		t.Fatalf("unexpected CA expiry: %s", root.NotAfter)
	}
	for name, mode := range map[string]os.FileMode{bundleFile: 0600, publicFile: 0644, lockFile: 0600} {
		info, err := os.Stat(filepath.Join(authority.directory, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s permission: info=%v err=%v", name, info, err)
		}
	}
	if !filepath.IsAbs(authority.CAFile()) {
		t.Fatal("CA path must be absolute")
	}
	persistedPublic, err := os.ReadFile(authority.CAFile())
	if err != nil || !bytes.Equal(public, persistedPublic) {
		t.Fatalf("CAFile contains a different public certificate: %v", err)
	}
	public[0] ^= 1
	if bytes.Equal(public, authority.CACertificate()) {
		t.Fatal("caller could mutate retained public certificate")
	}
	reopened := openTestAuthority(t, Config{Directory: authority.directory, Domains: []string{"different.test"}})
	if !bytes.Equal(authority.CACertificate(), reopened.CACertificate()) {
		t.Fatal("CA changed on reopen with a new issuance scope")
	}
	if _, err := reopened.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "local.test"}); !errors.Is(err, ErrNameNotAllowed) {
		t.Fatalf("old scope survived reopening: %v", err)
	}
	exported := filepath.Join(t.TempDir(), "development-ca.pem")
	if err := authority.Export(exported); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exported)
	if err != nil || !bytes.Equal(data, authority.CACertificate()) || bytes.Contains(data, []byte("PRIVATE KEY")) {
		t.Fatalf("exported nonpublic material or different CA: %v", err)
	}
	info, err := os.Stat(exported)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("public export permissions: %v %v", info, err)
	}
	if err := authority.Export(authority.CAFile()); err != nil {
		t.Fatalf("re-exporting public CA: %v", err)
	}
	for _, name := range []string{bundleFile, lockFile, "other-private-state"} {
		if err := authority.Export(filepath.Join(authority.directory, name)); err == nil {
			t.Fatalf("export accepted private state destination %s", name)
		}
	}
	if err := authority.Export(""); err == nil {
		t.Fatal("empty public export destination was accepted")
	}
	if err := authority.Export(filepath.Join(t.TempDir(), "missing", "ca.pem")); err == nil {
		t.Fatal("export with missing parent silently succeeded")
	}
	link := filepath.Join(t.TempDir(), "ca-link.pem")
	if err := os.Symlink(exported, link); err != nil {
		t.Fatal(err)
	}
	if err := authority.Export(link); err == nil {
		t.Fatal("export accepted a symlink destination")
	}
}

func TestLeafSANScopeAndTrust(t *testing.T) {
	authority := openTestAuthority(t, Config{
		Domains:     []string{"LOCAL.TEST.", "localhost", "local.test"},
		IPAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"), netip.MustParseAddr("::ffff:127.0.0.1")},
	})
	roots := testRoots(t, authority)
	for _, requested := range []string{"local.test", "a.b.local.test", "MiXeD.LOCAL.TEST.", "localhost", "127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		t.Run(requested, func(t *testing.T) {
			cert, err := authority.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: requested})
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			name := strings.ToLower(strings.TrimSuffix(requested, "."))
			if address, err := netip.ParseAddr(name); err == nil {
				name = address.Unmap().String()
				if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != name || len(leaf.DNSNames) != 0 {
					t.Fatalf("unexpected IP SANs: %v / %v", leaf.IPAddresses, leaf.DNSNames)
				}
			} else if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name || len(leaf.IPAddresses) != 0 {
				t.Fatalf("unexpected DNS SANs: %v / %v", leaf.DNSNames, leaf.IPAddresses)
			}
			if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
				t.Fatal("leaf has inappropriate signing privileges")
			}
			if leaf.NotAfter.After(time.Now().Add(leafLifetime)) || leaf.NotAfter.Before(time.Now().Add(leafLifetime-time.Minute)) || leaf.NotAfter.After(authority.ca.NotAfter) {
				t.Fatalf("unexpected leaf expiry %s", leaf.NotAfter)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
				t.Fatalf("trusted certificate did not verify: %v", err)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "wrong.local.test"}); err == nil {
				t.Fatal("certificate verified for a different name")
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: name}); err == nil {
				t.Fatal("certificate verified without trusting the development CA")
			}
			tamperedDER := bytes.Clone(cert.Certificate[0])
			tamperedDER[len(tamperedDER)-1] ^= 1
			tampered, err := x509.ParseCertificate(tamperedDER)
			if err != nil {
				t.Fatal(err)
			}
			if err := tampered.CheckSignatureFrom(authority.ca); err == nil {
				t.Fatal("modified certificate retained a valid CA signature")
			}
		})
	}
	for _, requested := range []string{"badlocal.test", "local.test.other", "other.test", "*.local.test", "a..local.test", "local.test:443", "127.0.0.2", "::2", "fe80::1%eth0", " local.test", "local.test\x00"} {
		if _, err := authority.TLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: requested}); !errors.Is(err, ErrNameNotAllowed) {
			t.Fatalf("out-of-scope name %q: %v", requested, err)
		}
	}
	cert, err := authority.TLSConfig().GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.DNSNames) != 0 || len(cert.Leaf.IPAddresses) != 2 {
		t.Fatalf("no-SNI certificate contains names beyond configured IPs: %+v", cert.Leaf)
	}
	for _, address := range []string{"127.0.0.1", "::1"} {
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: address}); err != nil {
			t.Fatalf("no-SNI IP certificate: %v", err)
		}
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "local.test"}); err == nil {
		t.Fatal("no-SNI certificate admitted a DNS name")
	}
	withoutIPs := openTestAuthority(t, Config{Domains: []string{"local.test"}})
	if _, err := withoutIPs.TLSConfig().GetCertificate(&tls.ClientHelloInfo{}); !errors.Is(err, ErrNameNotAllowed) {
		t.Fatalf("no-SNI request discovered an unconfigured address: %v", err)
	}
	if _, err := authority.TLSConfig().GetCertificate(nil); err == nil {
		t.Fatal("nil client hello accepted")
	}
}

func handshake(t *testing.T, serverConfig, clientConfig *tls.Config) (error, error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	clientRaw, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer clientRaw.Close()
	if err := clientRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	go func() {
		serverRaw, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		if err := serverRaw.SetDeadline(deadline); err != nil {
			serverRaw.Close()
			serverResult <- err
			return
		}
		serverResult <- tls.Server(serverRaw, serverConfig).HandshakeContext(ctx)
		serverRaw.Close()
	}()
	clientErr := tls.Client(clientRaw, clientConfig).HandshakeContext(ctx)
	clientRaw.Close()
	return <-serverResult, clientErr
}

func TestRealTLSHandshakeRequiresScopedNameAndTrust(t *testing.T) {
	authority := openTestAuthority(t, Config{Domains: []string{"local.test"}, IPAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}})
	roots := testRoots(t, authority)
	for _, name := range []string{"service.local.test", "127.0.0.1", "::1"} {
		serverErr, clientErr := handshake(t, authority.TLSConfig(), &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12})
		if serverErr != nil || clientErr != nil {
			t.Fatalf("trusted handshake for %s: server=%v client=%v", name, serverErr, clientErr)
		}
	}
	serverErr, clientErr := handshake(t, authority.TLSConfig(), &tls.Config{ServerName: "service.local.test", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12})
	var unknown x509.UnknownAuthorityError
	if clientErr == nil || !errors.As(clientErr, &unknown) {
		t.Fatalf("untrusted CA was not rejected: server=%v client=%v", serverErr, clientErr)
	}
	serverErr, clientErr = handshake(t, authority.TLSConfig(), &tls.Config{ServerName: "outside.test", RootCAs: roots, MinVersion: tls.VersionTLS12})
	if !errors.Is(serverErr, ErrNameNotAllowed) || clientErr == nil {
		t.Fatalf("out-of-scope SNI handshake: server=%v client=%v", serverErr, clientErr)
	}
	serverErr, clientErr = handshake(t, authority.TLSConfig(), &tls.Config{ServerName: "127.0.0.2", RootCAs: roots, MinVersion: tls.VersionTLS12})
	var wrongAddress x509.HostnameError
	if clientErr == nil || !errors.As(clientErr, &wrongAddress) {
		t.Fatalf("unconfigured no-SNI IP was not rejected: server=%v client=%v", serverErr, clientErr)
	}
	withoutIPs := openTestAuthority(t, Config{Domains: []string{"local.test"}})
	serverErr, clientErr = handshake(t, withoutIPs.TLSConfig(), &tls.Config{ServerName: "127.0.0.1", RootCAs: testRoots(t, withoutIPs), MinVersion: tls.VersionTLS12})
	if !errors.Is(serverErr, ErrNameNotAllowed) || clientErr == nil {
		t.Fatalf("IP handshake without configured addresses: server=%v client=%v", serverErr, clientErr)
	}
	serverErr, clientErr = handshake(t, authority.TLSConfig(), &tls.Config{ServerName: "service.local.test", RootCAs: roots, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if serverErr == nil || clientErr == nil {
		t.Fatalf("TLS below 1.2 was admitted: server=%v client=%v", serverErr, clientErr)
	}
}

func TestIssuanceConcurrencyCancellationAndCacheBound(t *testing.T) {
	authority := openTestAuthority(t, Config{Domains: []string{"local.test"}})
	const callers = 24
	results := make(chan *tls.Certificate, callers)
	errorsCh := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			certificate, err := authority.certificate(context.Background(), "shared.local.test")
			results <- certificate
			errorsCh <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first []byte
	for certificate := range results {
		if first == nil {
			first = certificate.Certificate[0]
		}
		if !bytes.Equal(first, certificate.Certificate[0]) {
			t.Fatal("concurrent requests issued different leaves for the same name")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := authority.certificate(ctx, "cancelled.local.test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled issuance: %v", err)
	}
	authority.gate <- struct{}{}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
	_, err := authority.certificate(ctx, "waiting.local.test")
	cancel()
	<-authority.gate
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled issuance lock wait: %v", err)
	}
	for i := range maximumCachedLeaves + 3 {
		if _, err := authority.certificate(context.Background(), fmt.Sprintf("name-%d.local.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(authority.leaves) > maximumCachedLeaves {
		t.Fatalf("leaf cache grew unbounded: %d", len(authority.leaves))
	}
}

func TestConfigRejectsInvalidScopeWithoutCreatingState(t *testing.T) {
	for _, domain := range []string{"", ".", "*.local.test", "-name.local.test", "name-.local.test", "a..local.test", "127.0.0.1", "https://local.test", "local.test:443", "local.test..", "local_test", "é.local.test", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 127) + "test"} {
		t.Run(domain, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			if _, err := Open(context.Background(), Config{Directory: path, Domains: []string{domain}}); err == nil {
				t.Fatalf("accepted invalid domain %q", domain)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid scope created state: %v", err)
			}
		})
	}
	for _, address := range []netip.Addr{{}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"), netip.MustParseAddr("::ffff:0.0.0.0"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("ff02::1"), netip.MustParseAddr("fe80::1%eth0")} {
		if _, err := Open(context.Background(), Config{Directory: filepath.Join(t.TempDir(), "state"), IPAddresses: []netip.Addr{address}}); err == nil {
			t.Fatalf("accepted invalid address %s", address)
		}
	}
	if _, err := Open(context.Background(), Config{}); err == nil {
		t.Fatal("missing private state directory accepted")
	}
	path := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(ctx, Config{Directory: path}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Open: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled Open created state: %v", err)
	}
	// An empty scope can export trust, but cannot issue any leaf.
	noNames := openTestAuthority(t, Config{})
	if _, err := noNames.certificate(context.Background(), "local.test"); !errors.Is(err, ErrNameNotAllowed) {
		t.Fatalf("empty scope issued a certificate: %v", err)
	}
}

func historicalBundle(t *testing.T, before, after time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: authorityName},
		NotBefore: before, NotAfter: after, IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
}

func TestAuthorityExpiryIsExplicitAndBoundsLeaves(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name          string
		before, after time.Time
		expired       bool
	}{
		{name: "expired", before: now.Add(-48 * time.Hour), after: now.Add(-time.Hour), expired: true},
		{name: "not-yet-valid", before: now.Add(time.Hour), after: now.Add(48 * time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := privateTestDirectory(t)
			bundle := historicalBundle(t, test.before, test.after)
			if err := os.WriteFile(filepath.Join(path, bundleFile), bundle, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Open(context.Background(), Config{Directory: path, Domains: []string{"local.test"}})
			if err == nil || test.expired && !errors.Is(err, ErrAuthorityExpired) {
				t.Fatalf("invalid CA lifetime accepted: %v", err)
			}
			persisted, readErr := os.ReadFile(filepath.Join(path, bundleFile))
			if readErr != nil || !bytes.Equal(persisted, bundle) {
				t.Fatalf("invalid CA lifetime silently rotated trust: %v", readErr)
			}
		})
	}
	path := privateTestDirectory(t)
	bundle := historicalBundle(t, now.Add(-time.Minute), now.Add(30*time.Minute))
	if err := os.WriteFile(filepath.Join(path, bundleFile), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	authority := openTestAuthority(t, Config{Directory: path, Domains: []string{"local.test"}})
	cert, err := authority.certificate(context.Background(), "local.test")
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Leaf.NotAfter.Equal(authority.ca.NotAfter) || cert.Leaf.NotBefore.Before(authority.ca.NotBefore) {
		t.Fatal("leaf lifetime is not constrained to CA lifetime")
	}
	cached, err := authority.certificate(context.Background(), "local.test")
	if err != nil || !bytes.Equal(cached.Certificate[0], cert.Certificate[0]) {
		t.Fatalf("near-expiry CA caused repeated unnecessary leaf renewal: %v", err)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: testRoots(t, authority), DNSName: "local.test", CurrentTime: authority.ca.NotAfter.Add(time.Second)}); err == nil {
		t.Fatal("expired leaf still verified")
	}
}

func TestLeafRenewalRetainsAuthority(t *testing.T) {
	authority := openTestAuthority(t, Config{Domains: []string{"local.test"}})
	public := authority.CACertificate()
	nearExpiry, err := authority.issue(context.Background(), "renew.local.test", nil, time.Now().Add(-leafLifetime+30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nearExpiry.Leaf.Verify(x509.VerifyOptions{Roots: testRoots(t, authority), DNSName: "renew.local.test"}); err != nil {
		t.Fatalf("near-expiry fixture does not verify: %v", err)
	}
	authority.leaves["renew.local.test"] = nearExpiry
	renewed, err := authority.certificate(context.Background(), "renew.local.test")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(renewed.Certificate[0], nearExpiry.Certificate[0]) || !renewed.Leaf.NotAfter.After(nearExpiry.Leaf.NotAfter) {
		t.Fatal("near-expiry leaf was not renewed")
	}
	if !bytes.Equal(authority.CACertificate(), public) {
		t.Fatal("leaf renewal changed trusted CA identity")
	}
	if _, err := renewed.Leaf.Verify(x509.VerifyOptions{Roots: testRoots(t, authority), DNSName: "renew.local.test"}); err != nil {
		t.Fatalf("renewed certificate does not verify: %v", err)
	}
}

package iam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOIDCDiscoveryRejectsCustomTLSDialers(t *testing.T) {
	var calls atomic.Int32
	dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
	for _, transport := range []*http.Transport{
		{DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			calls.Add(1)
			return dialer.DialContext(ctx, network, address)
		}},
		{DialTLS: func(network, address string) (net.Conn, error) {
			calls.Add(1)
			return dialer.DialContext(context.Background(), network, address)
		}},
	} {
		if source, err := NewHTTPOIDCDiscovery(transport); err == nil || source != nil {
			t.Fatal("custom TLS dialer can bypass configured certificate verification")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("constructor performed network I/O")
	}
}

func TestOIDCDiscoverySnapshotsCertificateRoots(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted peer reached HTTP processing")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	source, err := NewHTTPOIDCDiscovery(transport)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating caller-owned configuration after construction must not install a
	// new CA that makes the public-root path bypass a wrong configured pin.
	roots.AddCert(server.Certificate())
	transport.TLSClientConfig.InsecureSkipVerify = true
	_, err = source.Discover(context.Background(), OIDCDiscoveryRequest{
		IssuerURL: server.URL, Thumbprints: []string{strings.Repeat("0", 40)},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match a configured thumbprint") {
		t.Fatalf("caller changed retained TLS trust: %v", err)
	}
}

func TestOIDCDiscoveryRejectsTypedNilDefaultTransport(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	var absent *http.Transport
	http.DefaultTransport = absent
	if source, err := NewHTTPOIDCDiscovery(nil); err == nil || source != nil {
		t.Fatal("typed-nil default transport accepted")
	}
}

func TestOIDCHTTPDiscoveryTrustAndMetadata(t *testing.T) {
	var server *httptest.Server
	var bad atomic.Value
	bad.Store("")
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		switch r.URL.Path {
		case "/issuer/.well-known/openid-configuration":
			switch bad.Load().(string) {
			case "issuer":
				io.WriteString(w, `{"issuer":"https://unconfigured.example.com","jwks_uri":"`+server.URL+`/keys"}`)
			case "http":
				io.WriteString(w, `{"issuer":"`+server.URL+`/issuer","jwks_uri":"http://unconfigured.example.com/keys"}`)
			case "duplicate":
				io.WriteString(w, `{"issuer":"`+server.URL+`/issuer","issuer":"`+server.URL+`/issuer","jwks_uri":"`+server.URL+`/keys"}`)
			case "redirect":
				http.Redirect(w, r, "https://unconfigured.example.com/config", http.StatusFound)
			case "large":
				io.WriteString(w, strings.Repeat(" ", 1<<20)+"{}")
			default:
				json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL + "/issuer", "jwks_uri": server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			}
		case "/keys":
			if bad.Load().(string) == "empty" {
				io.WriteString(w, `{"keys":[]}`)
			} else {
				io.WriteString(w, `{"keys":[{"kid":"first","kty":"RSA","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB","key_ops":["verify"]}]}`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	source, err := NewHTTPOIDCDiscovery(&http.Transport{})
	if err != nil {
		t.Fatal(err)
	}
	request := OIDCDiscoveryRequest{IssuerURL: server.URL + "/issuer"}
	result, err := source.Discover(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Thumbprints) != 1 || len(result.SigningKeys) != 1 || result.SigningKeys[0].Operations[0] != "verify" || !result.CacheUntil.After(time.Now()) {
		t.Fatalf("discovery=%+v", result)
	}
	request.Thumbprints = result.Thumbprints
	if _, err := source.Discover(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.Thumbprints = []string{strings.Repeat("0", 40)}
	if _, err := source.Discover(context.Background(), request); err == nil {
		t.Fatal("untrusted certificate ignored configured pin")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	trusted, err := NewHTTPOIDCDiscovery(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.Discover(context.Background(), request); err != nil {
		t.Fatalf("public CA must take precedence over thumbprint: %v", err)
	}
	request.Thumbprints = result.Thumbprints
	for _, value := range []string{"issuer", "http", "duplicate", "redirect", "large", "empty"} {
		t.Run(value, func(t *testing.T) {
			bad.Store(value)
			if _, err := source.Discover(context.Background(), request); err == nil {
				t.Fatal("invalid discovery accepted")
			}
		})
	}
}

func TestOIDCDiscoveryCancellation(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer server.Close()
	source, err := NewHTTPOIDCDiscovery(&http.Transport{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := source.Discover(ctx, OIDCDiscoveryRequest{IssuerURL: server.URL}); done <- err }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled discovery=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("discovery ignored cancellation")
	}
}

func TestOIDCTLSIntermediatePinsHostnameAndChain(t *testing.T) {
	now := time.Now()
	makeCert := func(name string, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ca {
			template.KeyUsage |= x509.KeyUsageCertSign
		}
		if parent == nil {
			parent = template
			parentKey = key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	root, rk := makeCert("root", true, nil, nil)
	intermediate, ik := makeCert("intermediate", true, root, rk)
	leaf, _ := makeCert("issuer.example.com", false, intermediate, ik)
	chain := []*x509.Certificate{leaf, intermediate, root}
	state := tls.ConnectionState{ServerName: "issuer.example.com", PeerCertificates: chain}
	pin := OIDCChainThumbprint(chain)
	if pin != OIDCChainThumbprint(chain[:2]) {
		t.Fatal("root inclusion changed top intermediate thumbprint")
	}
	if err := verifyOIDCTLS(state, nil, []string{pin}); err != nil {
		t.Fatal(err)
	}
	state.ServerName = "attacker.example.com"
	if err := verifyOIDCTLS(state, nil, []string{pin}); err == nil {
		t.Fatal("pin disabled hostname verification")
	}
	state.ServerName = "issuer.example.com"
	state.PeerCertificates = []*x509.Certificate{leaf, root, intermediate}
	if err := verifyOIDCTLS(state, nil, []string{pin}); err == nil {
		t.Fatal("wrong chain order accepted")
	}
	state.PeerCertificates = []*x509.Certificate{leaf, intermediate, intermediate}
	if err := verifyOIDCTLS(state, nil, []string{pin}); err == nil {
		t.Fatal("duplicate chain accepted")
	}
}

func TestParseOIDCDiscoveryRejectsAmbiguousKeysAndCertificates(t *testing.T) {
	const issuer = "https://oidc.eks.us-east-1.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF"
	configuration := []byte(`{"issuer":"` + issuer + `","jwks_uri":"` + issuer + `/keys","id_token_signing_alg_values_supported":["RS256"]}`)
	for _, row := range []struct {
		name, keys string
	}{
		{"duplicate key identifier", `{"keys":[{"kid":"first","kid":"second","kty":"RSA"}]}`},
		{"duplicate key operations", `{"keys":[{"kid":"first","key_ops":["verify"],"key_ops":["sign"]}]}`},
		{"trailing key document", `{"keys":[{"kid":"first","kty":"RSA"}]} {"keys":[]}`},
		{"invalid certificate encoding", `{"keys":[{"kid":"first","x5c":["!"]}]}`},
		{"invalid certificate DER", `{"keys":[{"kid":"first","x5c":["AQAB"]}]}`},
	} {
		t.Run(row.name, func(t *testing.T) {
			if _, err := ParseOIDCDiscovery(issuer, configuration, []byte(row.keys), time.Time{}); err == nil {
				t.Fatal("malformed public signing-key document accepted")
			}
		})
	}
}

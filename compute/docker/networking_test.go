package docker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func testCertificate(t *testing.T, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "runtime networking test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true}
	if ca {
		template.IsCA, template.KeyUsage = true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
	} else {
		template.Subject.CommonName = "host.docker.internal"
		template.DNSNames, template.KeyUsage, template.ExtKeyUsage = []string{"host.docker.internal"}, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestNetworkingRejectsUnusableResolvers(t *testing.T) {
	for _, value := range []string{"", "0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "fd00::53", "10.0.0.2:53", "10.0.0.02", " 10.0.0.2", "resolver.example"} {
		if err := (Networking{DNS: []string{value}}).Validate(); err == nil {
			t.Fatalf("unusable runtime DNS %q accepted", value)
		}
	}
	if err := (Networking{DNS: []string{"10.0.0.2", "10.0.0.2"}}).Validate(); err == nil {
		t.Fatal("duplicate runtime DNS accepted")
	}
	if err := (Networking{DNS: []string{"10.0.0.2", "192.0.2.53"}}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedDNSAdaptsOnlyEnabledAmazonProvidedDNS(t *testing.T) {
	provider, custom := netip.MustParseAddr("10.90.0.2"), netip.MustParseAddr("10.90.5.53")
	runtime := Networking{DNS: []string{"192.0.2.10", "192.0.2.11"}}
	unused := func() ([]string, error) {
		t.Fatal("daemon discovery used despite configured resolvers")
		return nil, nil
	}
	for _, test := range []struct {
		name     string
		selected []netip.Addr
		enabled  bool
		want     []string
	}{
		{"provider", []netip.Addr{provider}, true, runtime.DNS},
		{"custom exact", []netip.Addr{custom}, true, []string{"10.90.5.53"}},
		{"ordered mix", []netip.Addr{custom, provider}, true, []string{"10.90.5.53", "192.0.2.10", "192.0.2.11"}},
		{"provider disabled", []netip.Addr{provider}, false, []string{"127.0.0.1"}},
		{"custom with disabled support", []netip.Addr{custom, provider}, false, []string{"10.90.5.53"}},
		{"no DHCP DNS", nil, true, []string{"127.0.0.1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := runtime.SelectedDNS(test.selected, provider, test.enabled, unused)
			if err != nil || !slices.Equal(got, test.want) {
				t.Fatalf("got %v, %v; want %v", got, err, test.want)
			}
		})
	}
	got, err := Networking{}.SelectedDNS([]netip.Addr{provider}, provider, true, func() ([]string, error) { return []string{"198.51.100.1"}, nil })
	if err != nil || !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Fatalf("unconfigured provider did not use daemon discovery: %v, %v", got, err)
	}
	if _, err := (Networking{}).SelectedDNS([]netip.Addr{provider}, provider, true, nil); err == nil {
		t.Fatal("AmazonProvidedDNS invented a resolver")
	}
}

func TestPrepareTrustScopesBundleWithoutOverridingUserTrust(t *testing.T) {
	_, _, ca := testCertificate(t, true, nil, nil)
	networking := Networking{CAFile: writeFile(t, ca)}
	if err := networking.Validate(); err != nil {
		t.Fatal(err)
	}
	backing := make([]string, 1, 4)
	backing[0] = "CUSTOMER=1"
	config := ContainerConfig{Env: backing, Labels: map[string]string{"owner": "x"}, HostConfig: ContainerHostConfig{Mounts: []ContainerMount{{Type: "volume", Source: "data", Target: "/data"}}}}
	trust, err := networking.PrepareTrust(&config, []string{"PATH=/bin"}, "")
	if err != nil || trust == nil {
		t.Fatalf("trust not prepared: %v", err)
	}
	if !slices.Contains(config.Env, "AWS_CA_BUNDLE=/stackd-trust/ca-bundle.pem") || backing[:2][1] != "" {
		t.Fatalf("scoped bundle not injected without aliasing caller env: %v", config.Env)
	}
	mount := config.HostConfig.Mounts[len(config.HostConfig.Mounts)-1]
	if mount.Type != "volume" || mount.Source != "" || mount.Target != RuntimeTrustDirectory {
		t.Fatalf("bundle must use an anonymous container-owned volume, not a host bind: %+v", mount)
	}
	if len(config.Labels[RuntimeCALabel]) != 64 {
		t.Fatal("selected CA identity missing")
	}
	for _, environment := range [][]string{{"AWS_CA_BUNDLE=/custom.pem"}, {"SSL_CERT_FILE=/custom.pem"}, {"SSL_CERT_DIR="}} {
		for _, image := range []bool{false, true} {
			config := ContainerConfig{Env: []string{"A=1"}}
			imageEnvironment := []string(nil)
			if image {
				imageEnvironment = environment
			} else {
				config.Env = append(config.Env, environment...)
			}
			before := slices.Clone(config.Env)
			trust, err := networking.PrepareTrust(&config, imageEnvironment, "")
			if err != nil || trust != nil || !slices.Equal(config.Env, before) || len(config.HostConfig.Mounts) != 0 || config.Labels[RuntimeCALabel] != "" {
				t.Fatalf("user trust %v (image %v) was overridden: %v %v", environment, image, config.Env, err)
			}
		}
	}
	config = ContainerConfig{}
	if trust, err := networking.PrepareTrust(&config, nil, "/stackd"); err != nil || trust == nil || !slices.Equal(config.Env, []string{"AWS_CA_BUNDLE=/stackd/ca-bundle.pem"}) || len(config.HostConfig.Mounts) != 0 {
		t.Fatalf("owned volume directory not honored: %v %v", config, err)
	}
	config = ContainerConfig{HostConfig: ContainerHostConfig{Mounts: []ContainerMount{{Type: "volume", Target: "/stackd-trust/"}}}}
	if _, err := networking.PrepareTrust(&config, nil, ""); err == nil {
		t.Fatal("customer mount overlapping trust directory accepted")
	}
	if trust, err := (Networking{}).PrepareTrust(&config, nil, ""); err != nil || trust != nil {
		t.Fatal("zero Networking changed trust")
	}
}

func TestRuntimeCAAcceptsOnlyPublicCACertificates(t *testing.T) {
	caCertificate, caKey, ca := testCertificate(t, true, nil, nil)
	_, _, leaf := testCertificate(t, false, caCertificate, caKey)
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	for name, data := range map[string][]byte{"leaf": leaf, "private key": append(slices.Clone(ca), private...), "empty": nil, "garbage": []byte("not pem"), "trailing": append(slices.Clone(ca), []byte("trailing")...)} {
		if err := (Networking{CAFile: writeFile(t, data)}).Validate(); err == nil {
			t.Fatalf("%s accepted as runtime CA", name)
		}
	}
	if err := (Networking{CAFile: filepath.Join(t.TempDir(), "missing.pem")}).Validate(); err == nil {
		t.Fatal("missing CA file accepted")
	}
	if err := (Networking{CAFile: t.TempDir()}).Validate(); err == nil {
		t.Fatal("directory accepted as CA file")
	}
	_, _, second := testCertificate(t, true, nil, nil)
	if err := (Networking{CAFile: writeFile(t, []byte(strings.Join([]string{string(ca), string(second)}, "\n")))}).Validate(); err != nil {
		t.Fatal(err)
	}
}

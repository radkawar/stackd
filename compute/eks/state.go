package eks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type diskState struct {
	Version                    int
	ID                         string
	Token                      string
	Name                       string
	DockerHost                 string
	NativePort                 int
	ProxyPort                  int
	ListenHost                 string
	AdvertiseHost              string
	CA                         string
	Ready                      bool
	Deleting                   bool
	KubernetesVersion          string
	InitialVersion             string
	UpgradeTarget              string
	BridgeHost                 string
	BridgePort                 int
	WorkerAdvertiseHost        string
	NativeLogging              bool
	AuditPolicyHash            string
	ServiceAccountIssuer       string
	NativeServiceAccountIssuer bool
}

func (k *K3d) resourceDir(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(k.config.DataDir, hex.EncodeToString(sum[:]))
}

func privateDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("eks: %s must be a private 0700 directory, not a symlink", dir)
	}
	return nil
}

func readState(dir, id string) (diskState, error) {
	var state diskState
	if err := privateDirectory(dir); err != nil {
		return state, err
	}
	data, err := readPrivate(filepath.Join(dir, "owner.json"))
	if err != nil {
		return state, err
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("eks: invalid ownership metadata: %w", err)
	}
	token, tokenErr := hex.DecodeString(state.Token)
	if state.Version != 1 || state.ID != id || tokenErr != nil || len(token) != 32 || state.Name != "stackd-"+state.Token[:24] || state.NativePort < 1 || state.ProxyPort < 1 {
		return state, errors.New("eks: ownership metadata does not match requested cluster")
	}
	if state.KubernetesVersion == "" {
		state.KubernetesVersion = KubernetesVersion
		state.InitialVersion = KubernetesVersion
	}
	if !SupportsVersion(state.KubernetesVersion) || !SupportsVersion(state.InitialVersion) || state.UpgradeTarget != "" && !UpgradeAllowed(state.KubernetesVersion, state.UpgradeTarget) {
		return state, errors.New("eks: invalid retained native version")
	}
	return state, nil
}

func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("eks: %s must be a private 0600 regular file", path)
	}
	return os.ReadFile(path)
}

func saveState(dir string, state diskState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writePrivate(dir, "owner.json", data)
}

func writePrivate(dir, name string, data []byte) error {
	file, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func freePort(host string) (int, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return port, listener.Close()
}

func (k *K3d) loadOrPrepare(id string) (diskState, string, error) {
	dir := k.resourceDir(id)
	state, err := readState(dir, id)
	if err == nil {
		if state.DockerHost != k.config.DockerHost {
			return state, dir, errors.New("eks: DockerHost differs from persisted native ownership")
		}
		if state.Deleting {
			return state, dir, errors.New("eks: cluster deletion is in progress")
		}
		if state.ListenHost != k.config.ListenHost || state.AdvertiseHost != k.config.AdvertiseHost {
			return state, dir, errors.New("eks: listener configuration differs from persisted stable endpoint")
		}
		if state.WorkerAdvertiseHost != k.config.WorkerAdvertiseHost {
			return state, dir, errors.New("eks: worker endpoint differs from persisted native ownership")
		}
		return state, dir, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return state, dir, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return state, dir, err
	}
	if err = privateDirectory(dir); err != nil {
		return state, dir, err
	}
	// No native side effects are permitted until owner.json is durably present.
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return state, dir, err
	}
	state = diskState{Version: 1, ID: id, Token: hex.EncodeToString(token), ListenHost: k.config.ListenHost, AdvertiseHost: k.config.AdvertiseHost}
	state.DockerHost = k.config.DockerHost
	state.WorkerAdvertiseHost = k.config.WorkerAdvertiseHost
	state.Name = "stackd-" + state.Token[:24]
	if state.NativePort, err = freePort(state.nativeHost()); err != nil {
		return state, dir, err
	}
	for state.ProxyPort == 0 || state.ProxyPort == state.NativePort {
		if state.ProxyPort, err = freePort(state.ListenHost); err != nil {
			return state, dir, err
		}
	}
	ca, cert, key, err := newProxyIdentity(state.AdvertiseHost)
	if err != nil {
		return state, dir, err
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"ca.crt", ca}, {"proxy.crt", cert}, {"proxy.key", key}} {
		if err = writePrivate(dir, file.name, file.data); err != nil {
			return state, dir, err
		}
	}
	state.CA = base64.StdEncoding.EncodeToString(ca)
	return state, dir, saveState(dir, state)
}

func newProxyIdentity(host string) ([]byte, []byte, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "stackd EKS proxy CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err = rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func proxyCertificate(dir string) (tls.Certificate, error) {
	cert, err := readPrivate(filepath.Join(dir, "proxy.crt"))
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := readPrivate(filepath.Join(dir, "proxy.key"))
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(cert, key)
}

func (c *nativeCluster) endpoint() Endpoint {
	return Endpoint{URL: "https://" + net.JoinHostPort(c.state.AdvertiseHost, fmt.Sprint(c.state.ProxyPort)), CertificateAuthority: c.state.CA}
}

func (c *nativeCluster) serve(certificate tls.Certificate) {
	_ = c.server.Serve(tls.NewListener(c.listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}))
}

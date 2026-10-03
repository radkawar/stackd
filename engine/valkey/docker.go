package valkey

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
)

// Image is installed explicitly. Runtime creation and API calls never pull.
const Image = "valkey/valkey@sha256:1cb6b20b70d927560cc4cc5397b5f045e74aa603ff7696274778880bb6fadc75"
const controllerUser = "stackd-controller"
const labelPrefix = "stackd.valkey."

// DockerConfig addresses a local Docker daemon. The caller supplies a trusted
// server certificate for TLS deployments. Native files are sensitive local
// storage, not an emulation of AWS-managed physical storage encryption.
type DockerConfig struct {
	Host, Namespace, Image, TLSCertificate, TLSKey string
	StartupTimeout                                 time.Duration
}
type Docker struct {
	client           *docker.Client
	namespace, image string
	certificate, key []byte
	tlsConfig        *tls.Config
	startupTimeout   time.Duration
	gate             chan struct{}
	mu               sync.Mutex
	closed           bool
}

var immutableImage = regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`)
var _ Runtime = (*Docker)(nil)

func NewDocker(c DockerConfig) (*Docker, error) {
	if c.Namespace == "" {
		return nil, errors.New("valkey requires a stable unique namespace")
	}
	if c.Host != "" && !strings.HasPrefix(c.Host, "unix://") {
		return nil, errors.New("valkey host-network endpoints require a local Unix Docker daemon")
	}
	if c.Image == "" {
		c.Image = Image
	}
	if !immutableImage.MatchString(c.Image) {
		return nil, errors.New("valkey image must be pinned by sha256")
	}
	if c.StartupTimeout == 0 {
		c.StartupTimeout = 90 * time.Second
	}
	if c.StartupTimeout < 0 {
		return nil, errors.New("valkey startup timeout must be positive")
	}
	d := &Docker{namespace: c.Namespace, startupTimeout: c.StartupTimeout, gate: make(chan struct{}, 1)}
	if (c.TLSCertificate == "") != (c.TLSKey == "") {
		return nil, errors.New("valkey TLS certificate and key must be configured together")
	}
	if c.TLSCertificate != "" {
		var err error
		d.certificate, err = os.ReadFile(c.TLSCertificate)
		if err != nil {
			return nil, err
		}
		d.key, err = os.ReadFile(c.TLSKey)
		if err != nil {
			return nil, err
		}
		pair, err := tls.X509KeyPair(d.certificate, d.key)
		if err != nil {
			return nil, fmt.Errorf("valkey TLS certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, err
		}
		if err = cert.VerifyHostname("127.0.0.1"); err != nil {
			return nil, fmt.Errorf("valkey TLS certificate must cover 127.0.0.1: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(d.certificate) {
			return nil, errors.New("invalid Valkey TLS trust chain")
		}
		d.tlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := docker.New(ctx, docker.Config{Host: c.Host})
	if err != nil {
		return nil, err
	}
	d.client = client
	var image struct {
		ID string `json:"Id"`
		OS string `json:"Os"`
	}
	if err = client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(c.Image)+"/json", nil, &image); err != nil {
		client.Close()
		return nil, fmt.Errorf("install pinned Valkey image explicitly: %w", err)
	}
	if image.ID == "" || image.OS != "linux" {
		client.Close()
		return nil, errors.New("valkey requires the installed Linux image")
	}
	d.image = image.ID
	return d, nil
}

// Close detaches from retained processes and bytes; it never removes resources.
func (d *Docker) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.client.Close()
	return nil
}
func (d *Docker) lock(ctx context.Context) error {
	select {
	case d.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		d.unlock()
		return errors.New("valkey runtime is closed")
	}
	return nil
}
func (d *Docker) unlock() { <-d.gate }
func (d *Docker) name(id, role string) string {
	return fmt.Sprintf("stackd-valkey-%s-%x", role, sha256.Sum256([]byte(d.namespace+"\x00"+id)))
}
func (d *Docker) labels(id, role string) map[string]string {
	return map[string]string{labelPrefix + "namespace": d.namespace, labelPrefix + "id": id, labelPrefix + "role": role, labelPrefix + "layout": "native-v1"}
}
func (d *Docker) checkOwner(labels map[string]string, id, role string) error {
	for k, v := range d.labels(id, role) {
		if labels[k] != v {
			return errors.New("refusing foreign or conflicting Valkey native resource")
		}
	}
	return nil
}
func dockerStatus(err error, status int) bool {
	var e *docker.Error
	return errors.As(err, &e) && e.StatusCode == status
}

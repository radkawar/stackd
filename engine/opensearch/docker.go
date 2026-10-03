// Package opensearch runs the real upstream OpenSearch engine. AWS control
// intent and public authorization belong to the service and its gateway.
package opensearch

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	service "stackd/internal/services/opensearch"
)

// Image must be installed explicitly. The runtime never pulls or substitutes a
// different search engine. EngineVersion is the AWS version mapped to Version.
const (
	Image         = "opensearchproject/opensearch@sha256:9e0b3b3b6805811bd63d9b9503ffe34a58ba33d03cc346000e318c6ff5c05bd9"
	Version       = "2.19.4"
	EngineVersion = "OpenSearch_2.19"
	labelPrefix   = "stackd.opensearch."
)

// DockerConfig requires a stable persisted namespace and one controller per
// namespace. Client is caller-owned; otherwise Host selects the Docker daemon.
// The controller must share the daemon's host network namespace: the returned
// native target is loopback-only and must never be advertised to AWS clients.
// The local host and Docker administrators are trusted. The unauthenticated
// native node has a dedicated bridge with inter-container communication disabled;
// only the IAM gateway is public. This is not native fine-grained authentication,
// TLS, VPC, KMS or outbound-network policy enforcement.
type DockerConfig struct {
	Host, Namespace string
	Client          *docker.Client
	StartupTimeout  time.Duration
}

type Docker struct {
	client           *docker.Client
	ownsClient       bool
	native           *http.Client
	namespace, image string
	startupTimeout   time.Duration
	gate             chan struct{}
	lifetime         context.Context
	cancel           context.CancelFunc
	closeOnce        sync.Once
}

var _ service.Runtime = (*Docker)(nil)

func NewDocker(config DockerConfig) (*Docker, error) {
	if config.Namespace == "" {
		return nil, errors.New("OpenSearch Docker namespace is required and must survive controller restart")
	}
	if config.Client != nil && config.Host != "" {
		return nil, errors.New("OpenSearch Docker Client and Host are mutually exclusive")
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 3 * time.Minute
	}
	if config.StartupTimeout < 0 {
		return nil, errors.New("OpenSearch startup timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := config.Client
	owned := client == nil
	if owned {
		var err error
		client, err = docker.New(ctx, docker.Config{Host: config.Host})
		if err != nil {
			return nil, err
		}
	}
	var image struct {
		ID string `json:"Id"`
		OS string `json:"Os"`
	}
	err := client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(Image)+"/json", nil, &image)
	if err != nil || image.ID == "" || image.OS != "linux" {
		if owned {
			client.Close()
		}
		if err == nil {
			err = errors.New("installed image is not a Linux OpenSearch image")
		}
		return nil, fmt.Errorf("OpenSearch requires explicitly installed %s: %w", Image, err)
	}
	lifetime, stop := context.WithCancel(context.Background())
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second}
	return &Docker{client: client, ownsClient: owned, native: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, namespace: config.Namespace, image: image.ID, startupTimeout: config.StartupTimeout, gate: make(chan struct{}, 1), lifetime: lifetime, cancel: stop}, nil
}

// Close cancels controller work, joins the lifecycle gate and detaches. Processes,
// private endpoints, owned networks and named data volumes deliberately remain.
func (d *Docker) Close() error {
	d.closeOnce.Do(func() {
		d.cancel()
		d.gate <- struct{}{}
		defer func() { <-d.gate }()
		d.native.CloseIdleConnections()
		if d.ownsClient {
			d.client.Close()
		}
	})
	return nil
}

func (d *Docker) enter(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	select {
	case d.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-d.lifetime.Done():
		return nil, nil, errors.New("OpenSearch runtime is closed")
	}
	if d.lifetime.Err() != nil {
		<-d.gate
		return nil, nil, errors.New("OpenSearch runtime is closed")
	}
	if err := ctx.Err(); err != nil {
		<-d.gate
		return nil, nil, err
	}
	operation, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.lifetime, cancel)
	return operation, func() { stop(); cancel(); <-d.gate }, nil
}
func (d *Docker) name(id, role string) string {
	return fmt.Sprintf("stackd-opensearch-%s-%x", role, sha256.Sum256([]byte(d.namespace+"\x00"+id)))
}
func (d *Docker) labels(id, role string) map[string]string {
	return map[string]string{labelPrefix + "namespace": d.namespace, labelPrefix + "id": id, labelPrefix + "role": role, labelPrefix + "layout": "native-v1", labelPrefix + "version": Version}
}
func (d *Docker) checkOwner(labels map[string]string, id, role string) error {
	for key, want := range d.labels(id, role) {
		if labels[key] != want {
			return errors.New("refusing conflicting or foreign OpenSearch Docker resource")
		}
	}
	return nil
}
func dockerStatus(err error, status int) bool {
	var remote *docker.Error
	return errors.As(err, &remote) && remote.StatusCode == status
}
func option(options map[string]string, name, fallback string) string {
	if value, ok := options[name]; ok {
		return value
	}
	return fallback
}
func validateSpecification(spec service.NativeSpecification) error {
	if spec.ID == "" {
		return errors.New("OpenSearch incarnation is required")
	}
	if spec.EngineVersion != EngineVersion {
		return fmt.Errorf("unsupported native OpenSearch version %q; only %s is supported", spec.EngineVersion, EngineVersion)
	}
	return ValidateAdvancedOptions(spec.AdvancedOptions)
}

// ValidateAdvancedOptions admits only settings applied to the actual native
// process. Changing either setting restarts the single node, preserving data.
func ValidateAdvancedOptions(options map[string]string) error {
	for name, value := range options {
		switch name {
		case "indices.query.bool.max_clause_count":
			count, err := strconv.ParseInt(value, 10, 32)
			if err != nil || count < 1 || strings.Trim(value, "0123456789") != "" {
				return fmt.Errorf("%s must be a positive decimal int32", name)
			}
		case "rest.action.multi.allow_explicit_index":
			if value != "true" && value != "false" {
				return fmt.Errorf("%s must be true or false", name)
			}
		default:
			return fmt.Errorf("unsupported native OpenSearch advanced option %q", name)
		}
	}
	return nil
}

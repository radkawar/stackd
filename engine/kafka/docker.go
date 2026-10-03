// Package kafka runs public MSK data planes using installed Apache Kafka brokers.
// It is independent of the private Kinesis log and its service-clock retention.
package kafka

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"stackd/compute/docker"
	msk "stackd/internal/services/kafka"
)

// DockerImage is the installed-only Apache Kafka 3.7.1 image.
const DockerImage = "apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68"
const labelPrefix = "stackd.msk."
const configPath = "/stackd/config"
const dataPath = "/var/lib/kafka/data"
const adminUser = "__stackd_native_admin"

var immutableImage = regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`)

// DockerConfig selects an already installed image; the client remains caller-owned.
type DockerConfig struct {
	Client *docker.Client
	// Image may name the pinned image by immutable ID or digest, never different
	// content while the service advertises Kafka 3.7.1.
	Image string
	// EndpointHost is a loopback IP published by the Docker daemon. Empty uses
	// 127.0.0.1. No VPC, security-group, public or remote routing is emulated.
	EndpointHost string
	// StartupTimeout bounds native creation, configuration and readiness.
	// Zero selects three minutes.
	StartupTimeout time.Duration
}

// Docker retains exact incarnation-owned containers, volumes and one network.
// Close detaches; only Delete destroys resources. Native calls must occur outside
// the consumer's repository transactions.
type Docker struct {
	client                       *docker.Client
	image, imageID, endpointHost string
	imageEnv                     []string
	startupTimeout               time.Duration
	gate                         chan struct{}
	closed                       bool
}

var _ msk.Runtime = (*Docker)(nil)

func NewDocker(ctx context.Context, cfg DockerConfig) (*Docker, error) {
	if cfg.Client == nil {
		return nil, errors.New("MSK Docker client is required")
	}
	if cfg.Image == "" {
		cfg.Image = DockerImage
	}
	if !immutableImage.MatchString(cfg.Image) {
		return nil, errors.New("kafka image must be an immutable sha256 image ID or digest reference")
	}
	if cfg.EndpointHost == "" {
		cfg.EndpointHost = "127.0.0.1"
	}
	ip := net.ParseIP(cfg.EndpointHost)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("MSK endpoints require an explicit loopback IP; remote/public networking is unsupported")
	}
	if cfg.StartupTimeout == 0 {
		cfg.StartupTimeout = 180 * time.Second
	}
	if cfg.StartupTimeout < 0 {
		return nil, errors.New("kafka startup timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	var image struct {
		ID     string `json:"Id"`
		OS     string `json:"Os"`
		Config struct{ Env []string }
	}
	if err := cfg.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(DockerImage)+"/json", nil, &image); err != nil {
		return nil, fmt.Errorf("install Kafka image explicitly (%s); automatic pulling is disabled: %w", DockerImage, err)
	}
	if image.ID == "" || image.OS != "linux" {
		return nil, errors.New("kafka requires an installed Linux image")
	}
	if cfg.Image != DockerImage {
		var override struct {
			ID string `json:"Id"`
		}
		if err := cfg.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(cfg.Image)+"/json", nil, &override); err != nil {
			return nil, err
		}
		if override.ID != image.ID {
			return nil, errors.New("kafka 3.7.1 requires the pinned Apache image content")
		}
	}
	return &Docker{client: cfg.Client, image: DockerImage, imageID: image.ID, imageEnv: image.Config.Env, endpointHost: cfg.EndpointHost, startupTimeout: cfg.StartupTimeout, gate: make(chan struct{}, 1)}, nil
}

func resourceName(spec msk.Specification, role string) string {
	sum := sha256.Sum256([]byte(spec.Partition + "\x00" + spec.AccountID + "\x00" + spec.Region + "\x00" + spec.ARN + "\x00" + spec.Incarnation))
	return fmt.Sprintf("stackd-msk-%x-%s", sum[:16], role)
}

func (d *Docker) labels(spec msk.Specification, role string) map[string]string {
	return map[string]string{labelPrefix + "id": spec.Incarnation, labelPrefix + "arn": spec.ARN, labelPrefix + "partition": spec.Partition, labelPrefix + "account": spec.AccountID, labelPrefix + "region": spec.Region, labelPrefix + "role": role, labelPrefix + "image": d.image, labelPrefix + "layout": "kraft-public-v1", labelPrefix + "brokers": strconv.Itoa(int(spec.Brokers))}
}

func (d *Docker) checkLabels(got map[string]string, spec msk.Specification, role string) error {
	for key, want := range d.labels(spec, role) {
		if got[key] != want {
			return fmt.Errorf("MSK ownership conflict for %s: %s differs", role, key)
		}
	}
	return nil
}

func dockerStatus(err error, status int) bool {
	var e *docker.Error
	return errors.As(err, &e) && e.StatusCode == status
}

func (d *Docker) lock(ctx context.Context) error {
	select {
	case d.gate <- struct{}{}:
		if d.closed {
			<-d.gate
			return errors.New("MSK runtime is closed")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (d *Docker) unlock() { <-d.gate }

func (d *Docker) Close() error {
	d.gate <- struct{}{}
	d.closed = true
	d.unlock()
	return nil
}

func pause(ctx context.Context) error {
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

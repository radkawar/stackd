package kinesis

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"stackd/compute/docker"
)

// DockerImage is the installed-only Apache Kafka image used for stream logs.
const DockerImage = "apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68"

const (
	dockerLabelPrefix   = "stackd.kinesis."
	dockerDataPath      = "/var/lib/kafka/data"
	dockerConfiguration = "kraft-durable-v1"
)

// DockerConfig selects an already installed, layout-compatible Kafka image.
type DockerConfig struct {
	// Client remains caller-owned and must outlive the runtime and its logs.
	Client *docker.Client
	// Image must be an immutable image ID or digest reference; empty uses DockerImage.
	Image string
	// EndpointHost reaches the daemon's published loopback port, without scheme
	// or port. Remote engines require an explicit route/tunnel to their loopback.
	// Empty selects 127.0.0.1.
	EndpointHost string
	// StartupTimeout bounds preparation and native readiness. Zero selects 60s.
	StartupTimeout time.Duration
}

// Docker owns one retained Kafka broker and volume per stream incarnation.
type Docker struct {
	client                       *docker.Client
	image, imageID, endpointHost string
	imageEnv                     []string
	startupTimeout               time.Duration
	gate                         chan struct{}
}

var _ Runtime = (*Docker)(nil)

func NewDocker(ctx context.Context, config DockerConfig) (*Docker, error) {
	if config.Client == nil {
		return nil, errors.New("kinesis Docker client is required")
	}
	if config.Image == "" {
		config.Image = DockerImage
	}
	if !regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`).MatchString(config.Image) {
		return nil, errors.New("kafka image must be an immutable sha256 ID or digest-qualified reference")
	}
	if config.EndpointHost == "" {
		config.EndpointHost = "127.0.0.1"
	}
	if net.ParseIP(config.EndpointHost) == nil && strings.ContainsAny(config.EndpointHost, ":/?#@[]\\ \t\r\n") {
		return nil, errors.New("kafka endpoint host must be a hostname or unbracketed IP without scheme or port")
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 60 * time.Second
	}
	if config.StartupTimeout < 0 {
		return nil, errors.New("kafka startup timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, config.StartupTimeout)
	defer cancel()
	var image struct {
		ID     string `json:"Id"`
		OS     string `json:"Os"`
		Config struct{ Env []string }
	}
	if err := config.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(config.Image)+"/json", nil, &image); err != nil {
		return nil, fmt.Errorf("kafka image must be installed locally (%s): %w", config.Image, err)
	}
	if image.ID == "" || image.OS != "linux" {
		return nil, fmt.Errorf("kafka requires an installed Linux image, got id=%q os=%q", image.ID, image.OS)
	}
	registerNativeProtocol()
	return &Docker{client: config.Client, image: config.Image, imageID: image.ID, imageEnv: image.Config.Env, endpointHost: config.EndpointHost, startupTimeout: config.StartupTimeout, gate: make(chan struct{}, 1)}, nil
}

func validateSpecification(spec Specification) error {
	if spec.ID == "" || spec.Partition == "" || spec.AccountID == "" || spec.Region == "" {
		return errors.New("kinesis stream ID, partition, account and region are required")
	}
	return nil
}

func resourceName(spec Specification, role string) string {
	return fmt.Sprintf("stackd-kinesis-%s-%x", role, sha256.Sum256([]byte(spec.ID)))
}

func (d *Docker) labels(spec Specification, role string) map[string]string {
	return map[string]string{
		dockerLabelPrefix + "id":            spec.ID,
		dockerLabelPrefix + "partition":     spec.Partition,
		dockerLabelPrefix + "account":       spec.AccountID,
		dockerLabelPrefix + "region":        spec.Region,
		dockerLabelPrefix + "role":          role,
		dockerLabelPrefix + "image":         d.image,
		dockerLabelPrefix + "configuration": dockerConfiguration,
	}
}

func (d *Docker) checkLabels(labels map[string]string, spec Specification, role string) error {
	for key, expected := range d.labels(spec, role) {
		if labels[key] != expected {
			return fmt.Errorf("kafka Docker %s ownership/configuration conflict: %s=%q, expected %q", role, key, labels[key], expected)
		}
	}
	return nil
}

func dockerStatus(err error, status int) bool {
	var remote *docker.Error
	return errors.As(err, &remote) && remote.StatusCode == status
}

func (d *Docker) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case d.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Docker) Open(ctx context.Context, spec Specification) (Log, error) {
	if err := validateSpecification(spec); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer func() { <-d.gate }()
	state, err := d.prepare(ctx, spec)
	if err != nil {
		return nil, err
	}
	endpoint, err := state.endpoint(d.endpointHost)
	if err != nil {
		return nil, err
	}
	log := newLog(endpoint)
	if err := log.ready(ctx); err != nil {
		log.Close()
		return nil, d.failure(ctx, state.ID, err)
	}
	return log, nil
}

// Remove also finds resources left behind by an interrupted Open. Every resource
// is checked before destruction; a foreign name collision is never adopted.
func (d *Docker) Remove(ctx context.Context, spec Specification) error {
	if err := validateSpecification(spec); err != nil {
		return err
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	var result error
	for _, role := range []string{"broker", "init"} {
		state, err := d.inspect(ctx, resourceName(spec, role))
		if dockerStatus(err, http.StatusNotFound) {
			continue
		}
		if err == nil {
			err = d.checkContainer(state, spec, role)
		}
		if err == nil {
			err = d.removeContainer(ctx, state.ID)
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("remove Kafka %s: %w", role, err))
		}
	}
	if result != nil {
		return result
	}
	volume, err := d.inspectVolume(ctx, resourceName(spec, "data"))
	if dockerStatus(err, http.StatusNotFound) {
		return nil
	}
	if err == nil {
		err = d.checkVolume(volume, spec)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return err
	}
	removal, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err = d.client.JSON(removal, http.MethodDelete, "/volumes/"+url.PathEscape(volume.Name), nil, nil)
	if dockerStatus(err, http.StatusNotFound) {
		err = nil
	}
	return errors.Join(err, ctx.Err())
}

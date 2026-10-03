package dynamodb

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

// DockerImage is the pinned upstream Amazon DynamoDB Local 3.3.1 image. The
// administrator must install it locally; this adapter never pulls images.
const DockerImage = "amazon/dynamodb-local@sha256:ff89bd48ff32cd8d9be5fee8873b65b8854dc408f1afe881be6eb00247bc0dab"

const (
	dockerLabelPrefix = "stackd.dynamodb."
	dockerDataPath    = "/home/dynamodblocal/data"
)

// DockerConfig selects an already installed DynamoDB Local engine.
type DockerConfig struct {
	// Client is caller-owned and must outlive this runtime and its databases.
	Client *docker.Client
	// Image must be an immutable sha256 image ID or digest-qualified reference.
	// Empty selects DockerImage. Overrides must provide the same image layout,
	// Java entrypoint and dynamodblocal user as the pinned upstream image.
	Image string
	// EndpointHost is the host through which the daemon's published loopback
	// port is reachable, without scheme or port. Empty selects 127.0.0.1.
	// Remote daemons require an explicitly configured route/tunnel to loopback.
	EndpointHost string
	// StartupTimeout bounds preparation and actual API readiness. Zero is 60s.
	StartupTimeout time.Duration
}

// Docker owns labelled, durable regional instances, not the shared Docker
// transport. Close on a database releases only that handle; Remove destroys it.
type Docker struct {
	client                       *docker.Client
	image, imageID, endpointHost string
	startupTimeout               time.Duration
	gate                         chan struct{}
}

var _ Runtime = (*Docker)(nil)

func NewDocker(ctx context.Context, config DockerConfig) (*Docker, error) {
	if config.Client == nil {
		return nil, errors.New("DynamoDB Docker client is required")
	}
	if config.Image == "" {
		config.Image = DockerImage
	}
	if !regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`).MatchString(config.Image) {
		return nil, errors.New("DynamoDB Local image must be an immutable sha256 ID or digest-qualified reference")
	}
	if config.EndpointHost == "" {
		config.EndpointHost = "127.0.0.1"
	}
	if net.ParseIP(config.EndpointHost) == nil && (strings.ContainsAny(config.EndpointHost, ":/?#@[]\\ \t\r\n") || config.EndpointHost == "") {
		return nil, errors.New("DynamoDB endpoint host must be a hostname or unbracketed IP address without scheme or port")
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 60 * time.Second
	}
	if config.StartupTimeout < 0 {
		return nil, errors.New("DynamoDB startup timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, config.StartupTimeout)
	defer cancel()
	var image struct {
		ID string `json:"Id"`
		OS string `json:"Os"`
	}
	if err := config.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(config.Image)+"/json", nil, &image); err != nil {
		return nil, fmt.Errorf("DynamoDB Local image must be installed locally (%s): %w", config.Image, err)
	}
	if image.ID == "" || image.OS != "linux" {
		return nil, fmt.Errorf("DynamoDB Local requires an installed Linux image, got id=%q os=%q", image.ID, image.OS)
	}
	return &Docker{client: config.Client, image: config.Image, imageID: image.ID, endpointHost: config.EndpointHost, startupTimeout: config.StartupTimeout, gate: make(chan struct{}, 1)}, nil
}

func validateSpecification(spec Specification) error {
	if spec.ID == "" || spec.Partition == "" || spec.AccountID == "" || spec.Region == "" {
		return errors.New("DynamoDB database ID, partition, account and region are required")
	}
	return nil
}

func resourceName(spec Specification, role string) string {
	return fmt.Sprintf("stackd-dynamodb-%s-%x", role, sha256.Sum256([]byte(spec.ID)))
}

func (d *Docker) labels(spec Specification, role string) map[string]string {
	return map[string]string{
		dockerLabelPrefix + "id":            spec.ID,
		dockerLabelPrefix + "partition":     spec.Partition,
		dockerLabelPrefix + "account":       spec.AccountID,
		dockerLabelPrefix + "region":        spec.Region,
		dockerLabelPrefix + "role":          role,
		dockerLabelPrefix + "image":         d.image,
		dockerLabelPrefix + "configuration": "shared-durable-v1",
	}
}

func checkOwner(labels map[string]string, spec Specification, role string) error {
	for key, expected := range map[string]string{"id": spec.ID, "partition": spec.Partition, "account": spec.AccountID, "region": spec.Region, "role": role} {
		if labels[dockerLabelPrefix+key] != expected {
			return fmt.Errorf("DynamoDB Docker %s ownership conflict: %s=%q, expected %q", role, key, labels[dockerLabelPrefix+key], expected)
		}
	}
	return nil
}

func (d *Docker) checkConfiguration(labels map[string]string) error {
	if labels[dockerLabelPrefix+"image"] != d.image || labels[dockerLabelPrefix+"configuration"] != "shared-durable-v1" {
		return errors.New("DynamoDB Docker resource has conflicting image or database configuration")
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

func (d *Docker) Open(ctx context.Context, spec Specification) (Database, error) {
	if err := validateSpecification(spec); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer func() { <-d.gate }()
	container, err := d.prepare(ctx, spec)
	if err != nil {
		return nil, err
	}
	endpoint, err := container.endpoint(d.endpointHost)
	if err != nil {
		return nil, d.failure(ctx, container.ID, err)
	}
	db := newDatabase(d, spec, container.ID, endpoint)
	if err := db.ready(ctx); err != nil {
		db.Close()
		return nil, d.failure(ctx, container.ID, err)
	}
	return db, nil
}

// Remove accepts genuinely absent resources, but never removes a resource whose
// owner labels differ. Names also identify resources left by interrupted Open.
func (d *Docker) Remove(ctx context.Context, spec Specification) error {
	if err := validateSpecification(spec); err != nil {
		return err
	}
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	var result error
	for _, role := range []string{"database", "init"} {
		state, err := d.inspect(ctx, resourceName(spec, role))
		if dockerStatus(err, http.StatusNotFound) {
			continue
		}
		if err == nil {
			err = checkOwner(state.Config.Labels, spec, role)
		}
		if err == nil {
			err = d.removeContainer(ctx, state.ID)
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("remove DynamoDB %s container: %w", role, err))
		}
	}
	if result != nil {
		return result
	}
	volume, err := d.inspectVolume(ctx, resourceName(spec, "data"))
	if dockerStatus(err, http.StatusNotFound) {
		return result
	}
	if err == nil {
		err = checkOwner(volume.Labels, spec, "data")
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		// As with container removal, join committed destruction before another
		// Open can adopt this database's resources.
		removal, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		err = d.client.JSON(removal, http.MethodDelete, "/volumes/"+url.PathEscape(volume.Name)+"?force=true", nil, nil)
		cancel()
		if dockerStatus(err, http.StatusNotFound) {
			err = nil
		}
		err = errors.Join(err, ctx.Err())
	}
	if err != nil {
		result = errors.Join(result, fmt.Errorf("remove DynamoDB volume: %w", err))
	}
	return result
}

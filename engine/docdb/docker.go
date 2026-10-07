package docdb

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	"stackd/compute/ports"

	"github.com/xdg-go/stringprep"
)

// MongoImage is Docker Official Image mongo:7.0.43-jammy, resolved from the
// upstream OCI index. Linux amd64 manifest: sha256:609d76574151bee8b148caee83cd9fec8b5f695e5a6db9f1e0f9dced0673574e.
// Provenance: https://github.com/docker-library/mongo/tree/8d9ef3e640d2925aa11c50524f656f7fc8b4d4f7/7.0
// Installation is explicit; NewDocker only inspects already installed images.
const MongoImage = "mongo@sha256:84c4a18b60a0e73d1577112b0a600b46cab477c64cfe0ff36d0647bbca055bd0"
const MongoVersion = "7.0.43"
const labelPrefix = "stackd.docdb."
const replicaSet = "stackd"

// DockerConfig selects an explicitly installed immutable image and stable
// installation namespace. One controller owns a namespace. Client is borrowed;
// Host is used only when Client is absent. The daemon must expose local loopback.
// PortRange bounds new automatic endpoints, never explicit or retained ports.
type DockerConfig struct {
	Host, Namespace, Image string
	Client                 *docker.Client
	StartupTimeout         time.Duration
	PortRange              ports.Range
}

type Docker struct {
	client           *docker.Client
	ownsClient       bool
	namespace, image string
	startupTimeout   time.Duration
	portRange        ports.Range
	gate             chan struct{}
	mu               sync.Mutex
	closed           bool
}

var _ Runtime = (*Docker)(nil)
var immutableImage = regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`)

func NewDocker(config DockerConfig) (*Docker, error) {
	if err := config.PortRange.Validate(); err != nil {
		return nil, err
	}
	if config.Namespace == "" {
		return nil, errors.New("DocumentDB Docker namespace is required and must survive controller restart")
	}
	if config.Client != nil && config.Host != "" {
		return nil, errors.New("DocumentDB Docker Client and Host are mutually exclusive")
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 3 * time.Minute
	}
	if config.StartupTimeout < 0 {
		return nil, errors.New("DocumentDB startup timeout must be positive")
	}
	if config.Image == "" {
		config.Image = MongoImage
	}
	if !immutableImage.MatchString(config.Image) {
		return nil, errors.New("DocumentDB image must be an immutable sha256 ID or digest-qualified reference")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, owned := config.Client, config.Client == nil
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
	err := client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(config.Image)+"/json", nil, &image)
	if err == nil && (image.ID == "" || image.OS != "linux") {
		err = errors.New("DocumentDB requires an installed Linux MongoDB image")
	}
	if err != nil {
		if owned {
			client.Close()
		}
		return nil, fmt.Errorf("DocumentDB image must be installed locally (%s): %w", config.Image, err)
	}
	return &Docker{client: client, ownsClient: owned, namespace: config.Namespace, image: image.ID, startupTimeout: config.StartupTimeout, portRange: config.PortRange, gate: make(chan struct{}, 1)}, nil
}

// Close detaches without changing retained native resources.
func (d *Docker) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.ownsClient {
		d.client.Close()
	}
	return nil
}
func (d *Docker) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
		return errors.New("DocumentDB runtime is closed")
	}
	return nil
}
func (d *Docker) unlock() { <-d.gate }
func (d *Docker) name(id, role string) string {
	return fmt.Sprintf("stackd-docdb-%s-%x", role, sha256.Sum256([]byte(d.namespace+"\x00"+id)))
}
func (d *Docker) labels(id, role string) map[string]string {
	return map[string]string{labelPrefix + "namespace": d.namespace, labelPrefix + "id": id, labelPrefix + "role": role, labelPrefix + "layout": "mongo-tls-v1"}
}
func (d *Docker) checkOwner(labels map[string]string, id, role string) error {
	for key, want := range d.labels(id, role) {
		if labels[key] != want {
			return errors.New("refusing conflicting or foreign DocumentDB Docker resource")
		}
	}
	return nil
}
func dockerStatus(err error, status int) bool {
	var remote *docker.Error
	return errors.As(err, &remote) && remote.StatusCode == status
}
func validateSpecification(spec Specification) error {
	if spec.ID == "" {
		return errors.New("native document database incarnation is required")
	}
	if spec.Username == "" || strings.IndexByte(spec.Username, 0) >= 0 {
		return errors.New("native document database username is required and cannot contain NUL")
	}
	if err := validatePassword(spec.Password); err != nil {
		return err
	}
	if spec.Port < 0 || spec.Port > 65535 {
		return errors.New("invalid native document database port")
	}
	return nil
}
func validatePassword(password string) error {
	if password == "" || strings.IndexByte(password, 0) >= 0 {
		return errors.New("native document database password must be nonempty and contain no NUL")
	}
	// Match the official driver's SCRAM-SHA-256 admission before any native
	// resource is allocated. SASLprep errors may include credential characters.
	if _, err := stringprep.SASLprep.Prepare(password); err != nil {
		return errors.New("native document database password is not valid for SCRAM-SHA-256")
	}
	return nil
}
func portString(port int32) string { return strconv.Itoa(int(port)) }
func strconvPort(value string) (int32, error) {
	port, err := strconv.ParseInt(value, 10, 32)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("invalid retained native document database port")
	}
	return int32(port), nil
}

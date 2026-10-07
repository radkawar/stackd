package rds

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
	"sync"
	"time"

	"stackd/compute/docker"
	"stackd/compute/ports"
)

// These upstream images are installed explicitly; this runtime never pulls.
const (
	PostgresImage   = "postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652"
	MySQLImage      = "mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d"
	PostgresVersion = "17.11"
	MySQLVersion    = "8.4.11"
	labelPrefix     = "stackd.rds."
)

// DockerConfig selects a local Docker engine and a stable installation namespace.
// Client, when supplied, remains caller-owned. Host is used only without Client.
// EndpointHost addresses the daemon's loopback via a caller-established route;
// an empty value uses 127.0.0.1. Images must implement the pinned upstream layout.
// PortRange bounds new automatic SQL endpoints, never explicit or retained ports.
type DockerConfig struct {
	Host, Namespace, PostgresImage, MySQLImage string
	Client                                     *docker.Client
	EndpointHost                               string
	StartupTimeout                             time.Duration
	PortRange                                  ports.Range
}

// Docker serializes native lifecycle effects; one controller owns a namespace.
// The durable owner identity is namespace + opaque incarnation, not a user name.
type Docker struct {
	client                    *docker.Client
	ownsClient                bool
	namespace, endpointHost   string
	postgresImage, mysqlImage string
	startupTimeout            time.Duration
	portRange                 ports.Range
	gate                      chan struct{}
	mu                        sync.Mutex
	closed                    bool
}

var _ Runtime = (*Docker)(nil)
var immutableImage = regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`)
var sqlName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,62}$`)

func NewDocker(config DockerConfig) (*Docker, error) {
	if err := config.PortRange.Validate(); err != nil {
		return nil, err
	}
	if config.Namespace == "" {
		return nil, errors.New("RDS Docker namespace is required and must survive controller restart")
	}
	if config.Client != nil && config.Host != "" {
		return nil, errors.New("RDS Docker Client and Host are mutually exclusive")
	}
	if config.EndpointHost == "" {
		config.EndpointHost = "127.0.0.1"
	}
	if net.ParseIP(config.EndpointHost) == nil && strings.ContainsAny(config.EndpointHost, ":/?#@[]\\ \t\r\n") {
		return nil, errors.New("invalid native RDS endpoint host")
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 3 * time.Minute
	}
	if config.StartupTimeout < 0 {
		return nil, errors.New("RDS startup timeout must be positive")
	}
	if config.PostgresImage == "" {
		config.PostgresImage = PostgresImage
	}
	if config.MySQLImage == "" {
		config.MySQLImage = MySQLImage
	}
	if !immutableImage.MatchString(config.PostgresImage) || !immutableImage.MatchString(config.MySQLImage) {
		return nil, errors.New("RDS images must be immutable sha256 IDs or digest-qualified references")
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
	d := &Docker{client: client, ownsClient: owned, namespace: config.Namespace, endpointHost: config.EndpointHost, startupTimeout: config.StartupTimeout, portRange: config.PortRange, gate: make(chan struct{}, 1)}
	for _, item := range []struct {
		reference string
		target    *string
	}{{config.PostgresImage, &d.postgresImage}, {config.MySQLImage, &d.mysqlImage}} {
		var image struct {
			ID string `json:"Id"`
			OS string `json:"Os"`
		}
		if err := client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(item.reference)+"/json", nil, &image); err != nil {
			if owned {
				client.Close()
			}
			return nil, fmt.Errorf("RDS image must be installed locally (%s): %w", item.reference, err)
		}
		if image.ID == "" || image.OS != "linux" {
			if owned {
				client.Close()
			}
			return nil, errors.New("RDS requires installed Linux native database images")
		}
		*item.target = image.ID
	}
	return d, nil
}

// Close detaches. Running processes, ports, named volumes and snapshots remain.
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
		return errors.New("RDS runtime is closed")
	}
	return nil
}
func (d *Docker) unlock() { <-d.gate }
func (d *Docker) name(id, role string) string {
	return fmt.Sprintf("stackd-rds-%s-%x", role, sha256.Sum256([]byte(d.namespace+"\x00"+id)))
}
func (d *Docker) labels(id, role string) map[string]string {
	return map[string]string{labelPrefix + "namespace": d.namespace, labelPrefix + "id": id, labelPrefix + "role": role, labelPrefix + "layout": "native-v1"}
}
func (d *Docker) checkOwner(labels map[string]string, id, role string) error {
	for key, expected := range d.labels(id, role) {
		if labels[key] != expected {
			return errors.New("refusing conflicting or foreign RDS Docker resource")
		}
	}
	return nil
}
func (d *Docker) image(engine string) string {
	kind, _ := family(engine)
	if kind == "postgres" {
		return d.postgresImage
	}
	return d.mysqlImage
}
func dockerStatus(err error, status int) bool {
	var remote *docker.Error
	return errors.As(err, &remote) && remote.StatusCode == status
}
func validateSpecification(spec Specification) error {
	kind, err := family(spec.Engine)
	if err != nil {
		return err
	}
	if spec.ID == "" {
		return errors.New("native database incarnation is required")
	}
	if (spec.Database != "" && !sqlName.MatchString(spec.Database)) || !sqlName.MatchString(spec.Username) {
		return errors.New("native database and username must be SQL identifiers of at most 63 ASCII characters")
	}
	if kind == "mysql" && len(spec.Username) > 32 {
		return errors.New("MySQL username must be at most 32 characters")
	}
	if spec.Password == "" || strings.IndexByte(spec.Password, 0) >= 0 {
		return errors.New("native password must be nonempty and contain no NUL")
	}
	if spec.Port < 0 || spec.Port > 65535 || spec.RetainedPort < 0 || spec.RetainedPort > 65535 {
		return errors.New("invalid native database port")
	}
	return ValidateParameters(spec.Engine, spec.Parameters)
}

// ValidateParameters rejects settings that could bypass authentication, move
// durable files, expose additional listeners, or turn credential logging on.
// Native parsing still decides whether a supported setting's value is valid.
func ValidateParameters(engine string, parameters map[string]string) error {
	kind, err := family(engine)
	if err != nil {
		return err
	}
	for name, value := range parameters {
		allowed := false
		if kind == "postgres" {
			switch name {
			case "max_connections", "shared_buffers", "work_mem", "maintenance_work_mem", "statement_timeout", "idle_in_transaction_session_timeout", "timezone":
				allowed = true
			}
		} else {
			switch name {
			case "max_connections", "innodb_buffer_pool_size", "wait_timeout", "interactive_timeout", "sql_mode", "time_zone", "character_set_server", "collation_server":
				allowed = true
			}
		}
		if !allowed {
			return fmt.Errorf("unsupported native %s parameter %q", kind, name)
		}
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("invalid native parameter %q", name)
		}
	}
	return nil
}

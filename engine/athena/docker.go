package athena

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
)

// DockerImage is Trino 476, Apache-2.0, resolved from the upstream OCI tag.
// Installation is explicit: this adapter never pulls images or contacts AWS.
const DockerImage = "trinodb/trino@sha256:00125e40d063bc4816d165482f6044872b18b56026fb959d3b28ce1f96ffbbee"

// DockerConfig uses a caller-owned Docker transport. A witnessed local Linux
// daemon uses host networking with loopback-only SQL and callback listeners.
// Other daemons retain bridge networking and require callback routes both ways.
type DockerConfig struct {
	Client                                                          *docker.Client
	Image, HiveDDLImage, EndpointHost, CallbackListen, CallbackHost string
	// StateDirectory is private, durable ownership state, exclusively locked
	// until Close completes. Reopen it to reap exact-owned restart orphans.
	StateDirectory              string
	StartupTimeout, IdleTimeout time.Duration
}

type Docker struct {
	client                                                              *docker.Client
	imageID, hiveDDLImageID, endpointHost, callbackListen, callbackHost string
	startupTimeout, idleTimeout                                         time.Duration
	hostNetwork                                                         bool
	transport                                                           *http.Transport
	http                                                                *http.Client
	gate                                                                chan struct{}
	mu                                                                  sync.Mutex
	active                                                              map[string]*activeExecution
	engines                                                             map[string]*warmEngine
	stateDirectory                                                      string
	stateLock                                                           *os.File
	lifetime                                                            context.Context
	stop                                                                context.CancelFunc
	work                                                                sync.WaitGroup
	closed                                                              bool
	closeOnce                                                           sync.Once
	closeDone                                                           chan struct{}
}

type activeExecution struct {
	cancel     context.CancelFunc
	done       chan struct{}
	cleanupErr error // published before done closes
}

var _ Runtime = (*Docker)(nil)
var immutableImage = regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`)
var executionHandle = regexp.MustCompile(`^stackd-athena-[a-f0-9]{64}$`)
var catalogName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,127}$`)

func NewDocker(ctx context.Context, config DockerConfig) (*Docker, error) {
	if config.Client == nil {
		return nil, errors.New("athena Docker client is required")
	}
	if config.Image == "" {
		config.Image = DockerImage
	}
	if !immutableImage.MatchString(config.Image) {
		return nil, errors.New("trino image must be an immutable sha256 ID or digest-qualified reference")
	}
	if config.HiveDDLImage == "" {
		config.HiveDDLImage = HiveDDLImage
	}
	if !immutableImage.MatchString(config.HiveDDLImage) {
		return nil, errors.New("hive DDL parser image must be an immutable sha256 ID or digest-qualified reference")
	}
	var image struct {
		ID string `json:"Id"`
		OS string `json:"Os"`
	}
	if err := config.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(config.Image)+"/json", nil, &image); err != nil {
		return nil, fmt.Errorf("trino image must be installed locally: %w", err)
	}
	if image.ID == "" || image.OS != "linux" {
		return nil, errors.New("trino requires a Linux image")
	}
	var parserImage struct {
		ID string `json:"Id"`
		OS string `json:"Os"`
	}
	if err := config.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(config.HiveDDLImage)+"/json", nil, &parserImage); err != nil {
		return nil, fmt.Errorf("hive DDL parser image must be installed locally: %w", err)
	}
	if parserImage.ID == "" || parserImage.OS != "linux" {
		return nil, errors.New("hive DDL parser requires a Linux image")
	}
	if config.EndpointHost == "" {
		config.EndpointHost = "127.0.0.1"
	}
	hostNetwork, err := localNetwork(ctx, config.Client, image.ID)
	if err != nil {
		return nil, err
	}
	if hostNetwork {
		config.EndpointHost = "127.0.0.1"
		if config.CallbackListen == "" {
			config.CallbackListen = "127.0.0.1:0"
		}
		if config.CallbackHost == "" {
			config.CallbackHost = "127.0.0.1"
		}
	} else {
		if config.CallbackListen == "" {
			config.CallbackListen = "0.0.0.0:0"
		}
		if config.CallbackHost == "" {
			config.CallbackHost = "host.docker.internal"
		}
	}
	for _, host := range []string{config.EndpointHost, config.CallbackHost} {
		if net.ParseIP(host) == nil && strings.ContainsAny(host, ":/?#@[]\\ \t\r\n") {
			return nil, errors.New("trino endpoint and callback hosts must be plain hostnames or IP addresses")
		}
	}
	if _, _, err := net.SplitHostPort(config.CallbackListen); err != nil {
		return nil, fmt.Errorf("trino callback listener: %w", err)
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 2 * time.Minute
	}
	if config.StartupTimeout < 0 {
		return nil, errors.New("trino startup timeout must be positive")
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 2 * time.Minute
	}
	if config.IdleTimeout < 0 {
		return nil, errors.New("trino idle timeout must be positive")
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, IdleConnTimeout: 90 * time.Second}
	lifetime, stop := context.WithCancel(context.Background())
	d := &Docker{client: config.Client, imageID: image.ID, hiveDDLImageID: parserImage.ID, endpointHost: config.EndpointHost, callbackListen: config.CallbackListen, callbackHost: config.CallbackHost, hostNetwork: hostNetwork, startupTimeout: config.StartupTimeout, idleTimeout: config.IdleTimeout, transport: transport, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, gate: make(chan struct{}, 1), active: make(map[string]*activeExecution), engines: make(map[string]*warmEngine), stateDirectory: config.StateDirectory, lifetime: lifetime, stop: stop, closeDone: make(chan struct{})}
	if err := d.openState(ctx); err != nil {
		stop()
		transport.CloseIdleConnections()
		return nil, err
	}
	d.work.Add(1)
	go d.expireIdle()
	return d, nil
}

func (d *Docker) remove(ctx context.Context, handle string) error {
	return errors.Join(d.removeOwned(ctx, handle+"-hiveddl", handle), d.removeOwned(ctx, handle, handle))
}

func (d *Docker) removeOwned(ctx context.Context, name, handle string) error {
	var state containerState
	err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
	var remote *docker.Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Config.Labels["stackd.athena.owner"] != "" ||
		state.Config.Labels["stackd.athena.execution"] != handle || state.Config.Labels["stackd.athena.engine"] != "trino-476" {
		return errors.New("refusing to remove foreign Trino container")
	}
	return d.client.RemoveContainer(ctx, state.ID)
}

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string
}
type containerState struct {
	ID              string `json:"Id"`
	Image           string
	Config          struct{ Labels map[string]string }
	NetworkSettings struct{ Ports map[string][]portBinding }
	State           struct {
		Running  bool
		ExitCode int
		Error    string
	}
}
type containerConfig struct {
	docker.ContainerConfig
	Hostname     string `json:",omitempty"`
	ExposedPorts map[string]struct{}
	HostConfig   struct {
		docker.ContainerHostConfig
		PortBindings map[string][]portBinding
		Tmpfs        map[string]string
	}
}

func (d *Docker) containerConfig(handle string, configuration []byte) containerConfig {
	var c containerConfig
	c.Image, c.User = d.imageID, "1000:1000"
	c.Labels = map[string]string{"stackd.athena.execution": handle, "stackd.athena.engine": "trino-476"}
	c.Entrypoint = []string{"/bin/sh", "-c"}
	c.Cmd = []string{"set -eu; printf '%s' \"$STACKD_TRINO_CONFIG\" | base64 -d | tar -xf - -C /tmp; unset STACKD_TRINO_CONFIG; exec /usr/lib/trino/bin/launcher run --data-dir /data/trino --etc-dir /tmp/stackd-athena"}
	c.Env = []string{"AWS_EC2_METADATA_DISABLED=true", "STACKD_TRINO_CONFIG=" + base64.StdEncoding.EncodeToString(configuration)}
	c.HostConfig.ContainerHostConfig = docker.ContainerHostConfig{NetworkMode: "bridge", ReadonlyRootfs: true, Memory: 4 << 30, MemorySwap: 4 << 30, CPUPeriod: 100000, CPUQuota: 200000, PidsLimit: 512, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, ExtraHosts: []string{"host.docker.internal:host-gateway"}, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "2"}}}
	// Trino's JNA/codec libraries extract native code into java.io.tmpdir.
	// Docker tmpfs defaults to noexec; only this bounded scratch mount needs exec.
	c.HostConfig.Tmpfs = map[string]string{"/tmp": "rw,nosuid,nodev,exec,size=256m,mode=1777", "/data/trino": "rw,nosuid,nodev,size=256m,uid=1000,gid=1000"}
	c.ExposedPorts = map[string]struct{}{"8080/tcp": {}}
	c.HostConfig.PortBindings = map[string][]portBinding{"8080/tcp": {{HostIP: "127.0.0.1"}}}
	if d.hostNetwork {
		c.HostConfig.NetworkMode = "host"
		c.HostConfig.ExtraHosts = nil
		c.ExposedPorts, c.HostConfig.PortBindings = nil, nil
		// The image's health check assumes container-local port 8080.
		// Startup and worker readiness are owned explicitly by this adapter.
		c.Healthcheck = &docker.ContainerHealthConfig{Test: []string{"NONE"}}
	}
	return c
}

func (d *Docker) ready(ctx context.Context, endpoint, id, handle string) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/info", nil)
		response, err := d.http.Do(req)
		if err == nil {
			var info struct {
				Starting    bool
				NodeVersion struct{ Version string }
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&info)
			response.Body.Close()
			if response.StatusCode == 200 && decodeErr == nil && !info.Starting {
				if info.NodeVersion.Version != "476" {
					return fmt.Errorf("expected Trino 476, got %q", info.NodeVersion.Version)
				}
				// HTTP startup precedes catalog publication to the scheduler.
				// A real JMX split must execute on this exact owned worker before
				// any customer catalog is created or customer SQL is submitted.
				ownedWorker := false
				probe := Request{Catalog: "__stackd_worker", SQL: `SELECT node FROM __stackd_worker.current."java.lang:type=runtime"`}
				probeErr := executeSQL(ctx, d.http, endpoint, probe, "stackd-readiness", func(page Page) error {
					for _, row := range page.Data {
						if len(row) != 1 {
							return errors.New("invalid native worker readiness row")
						}
						var node string
						if err := json.Unmarshal(row[0], &node); err != nil {
							return err
						}
						if node != handle {
							return fmt.Errorf("unexpected native worker %q", node)
						}
						ownedWorker = true
					}
					return nil
				})
				if probeErr == nil && ownedWorker {
					return nil
				}
				if probeErr != nil {
					var nativeError *QueryError
					if !errors.As(probeErr, &nativeError) || nativeError.ErrorName != "NO_NODES_AVAILABLE" {
						return fmt.Errorf("trino worker readiness: %w", probeErr)
					}
				}
			}
		}
		var state containerState
		if err := d.client.JSON(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &state); err != nil {
			return err
		}
		if !state.State.Running {
			return fmt.Errorf("trino exited during startup (exit %d): %s", state.State.ExitCode, state.State.Error)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("trino readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

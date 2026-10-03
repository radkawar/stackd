package eks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Config selects an explicitly owned local runtime. No kubeconfig is discovered
// from the environment. Binary must be k3d v5.8.3; k3s is pinned independently.
type Config struct {
	DataDir             string
	DockerHost          string
	Binary              string
	ListenHost          string
	AdvertiseHost       string
	WorkerAdvertiseHost string
	WorkerNetworks      WorkerNetworks
	PodIdentityCA       []byte
}

// K3d owns one schedulable k3s server per cluster and an authenticated TLS proxy.
// Closing the owner preserves Kubernetes, workloads, ports and private identity.
type K3d struct {
	config   Config
	lock     *os.File
	op       sync.Mutex
	mu       sync.RWMutex
	clusters map[string]*nativeCluster
	closed   bool
}

type nativeCluster struct {
	state               diskState
	dir                 string
	client              *http.Client
	transport           *http.Transport
	server              *http.Server
	listener            net.Listener
	grantMu             sync.Mutex
	bridge              *nativeBridge
	logs                *nativeLogs
	fargateAuthorize    func(context.Context, string) error
	fargateProfiles     func(context.Context) ([]FargateSpecification, error)
	podIdentityEndpoint string
	podIdentityService  http.Handler
	region              string
}

func NewK3d(config Config) (*K3d, error) {
	config.PodIdentityCA = slices.Clone(config.PodIdentityCA)
	if config.DataDir == "" {
		return nil, errors.New("eks: DataDir is required")
	}
	if config.DockerHost == "" {
		return nil, errors.New("eks: DockerHost is required")
	}
	if config.Binary == "" {
		config.Binary = "k3d"
	}
	if config.ListenHost == "" {
		config.ListenHost = "127.0.0.1"
	}
	if config.AdvertiseHost == "" {
		config.AdvertiseHost = config.ListenHost
	}
	if strings.ContainsAny(config.AdvertiseHost, "/?#@") || config.AdvertiseHost == "" {
		return nil, errors.New("eks: AdvertiseHost must be a hostname or IP")
	}
	if ip := net.ParseIP(config.AdvertiseHost); ip != nil && ip.IsUnspecified() {
		return nil, errors.New("eks: an explicit AdvertiseHost is required for a wildcard listener")
	}
	if config.WorkerAdvertiseHost != "" {
		ip := net.ParseIP(config.WorkerAdvertiseHost)
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
			return nil, errors.New("eks: WorkerAdvertiseHost must be an explicit guest-reachable host IP")
		}
	}
	binary, err := exec.LookPath(config.Binary)
	if err != nil {
		return nil, fmt.Errorf("eks: k3d binary: %w", err)
	}
	config.Binary = binary
	k := &K3d{config: config}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	version, err := k.command(ctx, config.Binary, "version")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(version), "k3d version "+K3dVersion+"\n") {
		return nil, fmt.Errorf("eks: require k3d %s; found %s", K3dVersion, strings.TrimSpace(string(version)))
	}
	config.DataDir, err = filepath.Abs(config.DataDir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(config.DataDir, 0700); err != nil {
		return nil, err
	}
	if err = privateDirectory(config.DataDir); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(config.DataDir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("eks: runtime directory already in use: %w", err)
	}
	return &K3d{config: config, lock: lock, clusters: make(map[string]*nativeCluster)}, nil
}

func (k *K3d) Ensure(ctx context.Context, specification Specification, handler http.Handler) (Endpoint, error) {
	if specification.ID == "" || handler == nil {
		return Endpoint{}, errors.New("eks: cluster ID and authentication handler are required")
	}
	if specification.Version != "" && !SupportsVersion(specification.Version) {
		return Endpoint{}, errors.New("eks: unsupported pinned Kubernetes version")
	}
	k.op.Lock()
	defer k.op.Unlock()
	k.mu.RLock()
	closed, existing := k.closed, k.clusters[specification.ID]
	k.mu.RUnlock()
	if closed {
		return Endpoint{}, errors.New("eks: runtime is closed")
	}
	if existing != nil {
		existing.bridge.auditMu.Lock()
		existing.bridge.auditSink = specification.AuditSink
		existing.bridge.auditMu.Unlock()
		if err := retainServiceAccountIssuer(&existing.state, existing.dir, specification.ServiceAccountIssuer); err != nil {
			return Endpoint{}, err
		}
		if err := k.installServiceAccountIssuer(ctx, &existing.state, existing.dir); err != nil {
			return Endpoint{}, err
		}
		k.mu.Lock()
		existing.fargateAuthorize = specification.FargateAuthorize
		existing.fargateProfiles = specification.FargateProfiles
		existing.podIdentityEndpoint = specification.PodIdentityEndpoint
		existing.podIdentityService = specification.PodIdentityHandler
		existing.region = specification.Region
		k.mu.Unlock()
		if err := k.upgradeNative(ctx, existing, specification.Version); err != nil {
			return Endpoint{}, err
		}
		if err := existing.waitReady(ctx); err != nil {
			return Endpoint{}, err
		}
		if err := existing.ensureNativeMetrics(ctx); err != nil {
			return Endpoint{}, err
		}
		if specification.PodIdentityHandler != nil || existing.state.ServiceAccountIssuer != "" {
			if err := existing.ensurePodIdentity(ctx); err != nil {
				return Endpoint{}, err
			}
		}
		if err := existing.logs.configure(specification, false); err != nil {
			return Endpoint{}, err
		}
		return existing.endpoint(), nil
	}
	state, dir, err := k.loadOrPrepare(specification.ID)
	if err != nil {
		return Endpoint{}, err
	}
	if err = retainServiceAccountIssuer(&state, dir, specification.ServiceAccountIssuer); err != nil {
		return Endpoint{}, err
	}
	if state.KubernetesVersion == "" {
		state.KubernetesVersion = specification.Version
		if state.KubernetesVersion == "" {
			state.KubernetesVersion = KubernetesVersion
		}
		state.InitialVersion = state.KubernetesVersion
		if err = saveState(dir, state); err != nil {
			return Endpoint{}, err
		}
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(state.ListenHost, fmt.Sprint(state.ProxyPort)))
	if err != nil {
		return Endpoint{}, fmt.Errorf("eks: stable proxy endpoint: %w", err)
	}
	defer func() {
		if listener != nil {
			listener.Close()
		}
	}()
	bridge, err := k.ensureNative(ctx, &state, dir, specification.AuditSink)
	if err != nil {
		return Endpoint{}, err
	}
	attached := false
	defer func() {
		if !attached {
			bridge.close()
		}
	}()
	cluster, err := openNative(state, dir)
	if err != nil {
		return Endpoint{}, err
	}
	defer func() {
		if !attached {
			cluster.transport.CloseIdleConnections()
		}
	}()
	cluster.bridge = bridge
	cluster.fargateAuthorize = specification.FargateAuthorize
	cluster.fargateProfiles = specification.FargateProfiles
	cluster.podIdentityEndpoint = specification.PodIdentityEndpoint
	cluster.podIdentityService = specification.PodIdentityHandler
	cluster.region = specification.Region
	fargatePath := "/fargate/" + cluster.bridgeCapability("fargate")
	bridge.mux.Handle(fargatePath+"/", http.StripPrefix(fargatePath, k.fargateAdmission(state.ID)))
	podPath := "/podidentity/" + cluster.bridgeCapability("podidentity")
	bridge.mux.Handle(podPath+"/", http.StripPrefix(podPath, k.podIdentityHandler(cluster)))
	if err = cluster.waitReady(ctx); err != nil {
		return Endpoint{}, err
	}
	if err = k.upgradeNative(ctx, cluster, specification.Version); err != nil {
		return Endpoint{}, err
	}
	if err = cluster.ensureNativeMetrics(ctx); err != nil {
		return Endpoint{}, err
	}
	if specification.PodIdentityHandler != nil || cluster.state.ServiceAccountIssuer != "" {
		if err = cluster.ensurePodIdentity(ctx); err != nil {
			return Endpoint{}, err
		}
	}
	cluster.state.Ready = true
	if err = saveState(dir, cluster.state); err != nil {
		return Endpoint{}, err
	}
	cluster.logs, err = k.startLogs(ctx, cluster.state, dir, specification, bridge)
	if err != nil {
		return Endpoint{}, err
	}
	defer func() {
		if !attached {
			cluster.logs.close()
		}
	}()
	cluster.listener = listener
	cluster.server = &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	certificate, err := proxyCertificate(dir)
	if err != nil {
		return Endpoint{}, err
	}
	k.mu.Lock()
	k.clusters[specification.ID] = cluster
	k.mu.Unlock()
	go cluster.serve(certificate)
	listener = nil
	attached = true
	return cluster.endpoint(), nil
}

func (k *K3d) Delete(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("eks: cluster ID is required")
	}
	k.op.Lock()
	defer k.op.Unlock()
	k.mu.RLock()
	closed := k.closed
	k.mu.RUnlock()
	if closed {
		return errors.New("eks: runtime is closed")
	}
	dir := k.resourceDir(id)
	state, err := readState(dir, id)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.DockerHost != k.config.DockerHost {
		return errors.New("eks: DockerHost differs from persisted native ownership")
	}
	containers, err := k.ownedContainers(ctx, state)
	if err != nil {
		return err
	}
	network, err := k.ownedNetwork(ctx, state)
	if err != nil {
		return err
	}
	volume, err := k.ownedVolume(ctx, state)
	if err != nil {
		return err
	}
	if err = k.deleteUpgradeSource(ctx, state); err != nil {
		return err
	}
	state.Deleting = true
	if err = saveState(dir, state); err != nil {
		return err
	}
	k.mu.Lock()
	cluster := k.clusters[id]
	delete(k.clusters, id)
	k.mu.Unlock()
	if cluster != nil {
		cluster.server.Close()
		cluster.logs.close()
		cluster.bridge.close()
		cluster.transport.CloseIdleConnections()
	}
	if len(containers) != 0 {
		args := []string{"container", "rm", "-f", "-v"}
		for _, container := range containers {
			args = append(args, container.ID)
		}
		if _, err = k.command(ctx, "docker", args...); err != nil {
			return err
		}
	}
	if volume != "" {
		if _, err = k.command(ctx, "docker", "volume", "rm", volume); err != nil {
			return err
		}
	}
	if network != "" {
		if _, err = k.command(ctx, "docker", "network", "rm", network); err != nil {
			return err
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		switch file.Name() {
		case "owner.json", "admin.kubeconfig", "proxy.crt", "proxy.key", "ca.crt", "bridge-ca.crt", "bridge.crt", "bridge.key", "audit-policy.yaml", "audit-webhook.kubeconfig", "native-logging.yaml", "native-irsa.yaml", "log-cursor.json", "authenticator.jsonl", "audit.events", "upgrade-k3s", "stackd-flannel.json", "control-plane-entrypoint.sh":
		default:
			return fmt.Errorf("eks: refusing to remove unexpected resource file %q", file.Name())
		}
	}
	// Remove only our explicit files; an unexpected file prevents directory removal.
	for _, name := range []string{"admin.kubeconfig", "proxy.crt", "proxy.key", "ca.crt", "bridge-ca.crt", "bridge.crt", "bridge.key", "audit-policy.yaml", "audit-webhook.kubeconfig", "native-logging.yaml", "native-irsa.yaml", "log-cursor.json", "authenticator.jsonl", "audit.events", "upgrade-k3s", "stackd-flannel.json", "control-plane-entrypoint.sh"} {
		if err = os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err = os.Remove(filepath.Join(dir, "owner.json")); err != nil {
		return err
	}
	return os.Remove(dir)
}

func (k *K3d) Close() error {
	k.op.Lock()
	defer k.op.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	k.closed = true
	var errs []error
	for _, cluster := range k.clusters {
		errs = append(errs, cluster.server.Close())
		cluster.logs.close()
		errs = append(errs, cluster.bridge.close())
		cluster.transport.CloseIdleConnections()
	}
	k.clusters = nil
	errs = append(errs, k.lock.Close())
	return errors.Join(errs...)
}

func (k *K3d) command(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = k.commandEnvironment()
	out, err := cmd.Output()
	if err != nil {
		return nil, nativeCommandFailure(binary, args, cmd.Env, out, err)
	}
	return out, nil
}

func (k *K3d) commandEnvironment() []string {
	var result []string
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		switch name {
		case "KUBECONFIG", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_TLS", "DOCKER_CERT_PATH":
		default:
			result = append(result, variable)
		}
	}
	return append(result, "KUBECONFIG=/dev/null", "DOCKER_HOST="+k.config.DockerHost)
}

package ecs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"stackd/compute/docker"
	"stackd/compute/network"
)

const (
	dockerTaskLabel = "stackd.ecs.task"
	dockerRoleLabel = "stackd.ecs.role"
)

// Networks owns VPC bridge lifetime across container and guest runtimes.
type Networks interface {
	WithBridge(context.Context, network.Specification, func(network.Bridge) error) error
	Release(context.Context, string) error
	ApplyPolicy(context.Context, string, network.Specification, network.Policy, string, network.Options, network.Bridge) error
	RemovePolicy(context.Context, string, string) error
}

// DockerConfig selects the Engine and VPC bridge owner. Networking.DNS replaces
// only an enabled EC2-selected AmazonProvidedDNS entry; with Networking.DNS set,
// custom DHCP servers stay exact and disabled VPC DNS answers nothing. Empty DNS
// keeps the daemon's resolver configuration. Networking.CAFile adds a scoped
// AWS SDK bundle to new customer containers (see docker.Networking). Retained
// tasks keep the DNS and trust their native resources were created with.
type DockerConfig struct {
	// Client remains caller-owned and must outlive all task environments.
	Client     *docker.Client
	Networks   Networks
	Networking docker.Networking
}

// DockerExecutor uses a local rootful Linux Engine with systemd/cgroup v2.
// Preparation/removal serialize native shared-network ownership, not execution
// of customer processes. It does not install images or change daemon settings.
type DockerExecutor struct {
	client     *docker.Client
	networks   Networks
	networking docker.Networking
	mu         sync.Mutex
	tasks      map[string]*dockerEnvironment
}

func NewDockerExecutor(ctx context.Context, config DockerConfig) (*DockerExecutor, error) {
	if config.Client == nil {
		return nil, errors.New("ECS Docker client is required")
	}
	if config.Networks == nil {
		return nil, errors.New("ECS shared native network owner is required")
	}
	if err := config.Networking.Validate(); err != nil {
		return nil, fmt.Errorf("ECS runtime networking: %w", err)
	}
	var info struct {
		OSType, CgroupDriver, CgroupVersion string
		SecurityOptions                     []string
	}
	if err := config.Client.JSON(ctx, http.MethodGet, "/info", nil, &info); err != nil {
		return nil, fmt.Errorf("inspect ECS Docker capabilities: %w", err)
	}
	if info.OSType != "linux" || info.CgroupDriver != "systemd" || info.CgroupVersion != "2" {
		return nil, errors.New("ECS Docker execution requires Linux with systemd and cgroup v2")
	}
	for _, option := range info.SecurityOptions {
		if strings.Contains(option, "rootless") || strings.Contains(option, "userns") {
			return nil, errors.New("ECS Docker execution requires rootful Docker without user-namespace remapping")
		}
	}
	var image dockerImage
	if err := config.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(docker.ToolkitImage)+"/json", nil, &image); err != nil {
		return nil, fmt.Errorf("ECS toolkit image must be installed locally (%s): %w", docker.ToolkitImage, err)
	}
	config.Networking.DNS = slices.Clone(config.Networking.DNS)
	return &DockerExecutor{client: config.Client, networks: config.Networks, networking: config.Networking, tasks: make(map[string]*dockerEnvironment)}, nil
}

func (d *DockerExecutor) Prepare(ctx context.Context, spec Specification) (Environment, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing := d.tasks[spec.TaskARN]; existing != nil {
		return existing, nil
	}
	if spec.TaskARN == "" || spec.CPUUnits <= 0 || spec.MemoryBytes <= 0 || len(spec.Containers) == 0 || spec.Metadata == nil {
		return nil, errors.New("ECS execution requires a task identity, positive aggregate limits, containers and metadata handler")
	}
	dns, search, err := d.taskDNS(spec.Network)
	if err != nil {
		return nil, err
	}
	containers, err := d.resolveImages(ctx, spec)
	if err != nil {
		return nil, err
	}
	e := &dockerEnvironment{executor: d, spec: spec, containers: containers}
	// The retained task remains the recovery owner on failure. Do not delete
	// surviving customer processes merely because controller reattachment failed.
	e.group, err = prepareTaskGroup(ctx, d.client, spec.TaskARN, dockerTaskLimits{CPUUnits: spec.CPUUnits, MemoryBytes: spec.MemoryBytes}, docker.ToolkitImage)
	if err != nil {
		return nil, err
	}
	err = d.networks.WithBridge(ctx, spec.Network, func(bridge network.Bridge) error {
		e.network = bridge
		var err error
		e.metadata, err = prepareMetadata(ctx, d.client, dockerMetadataSpec{
			TaskARN: spec.TaskARN, NetworkName: bridge.Name, Image: docker.ToolkitImage,
			Address: spec.Network.Address, Gateway: spec.Network.Gateway, MACAddress: spec.Network.MAC,
			DNS: dns, DNSSearch: search,
			Handler:   spec.Metadata,
			Configure: e.configureNetwork,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := e.prepareVolumes(ctx); err != nil {
		return nil, errors.Join(err, e.metadata.close())
	}
	if err := e.prepareContainers(ctx); err != nil {
		return nil, errors.Join(err, e.metadata.close())
	}
	e.lifetime, e.cancel = context.WithCancel(context.Background())
	d.tasks[spec.TaskARN] = e
	return e, nil
}

type dockerEnvironment struct {
	executor       *DockerExecutor
	spec           Specification
	network        network.Bridge
	group          string
	metadata       *dockerMetadata
	containers     map[string]dockerContainer
	lifetime       context.Context
	cancel         context.CancelFunc
	policyMu       sync.Mutex
	policyReady    bool
	peer, callback string
}

func dockerResourceName(kind, key string) string {
	return fmt.Sprintf("stackd-ecs-%s-%x", kind, sha256.Sum256([]byte(key)))
}

func dockerNotFound(err error) bool {
	var remote *docker.Error
	return errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound
}

func (e *dockerEnvironment) Close() error {
	e.executor.mu.Lock()
	defer e.executor.mu.Unlock()
	e.cancel()
	if e.executor.tasks[e.spec.TaskARN] == e {
		delete(e.executor.tasks, e.spec.TaskARN)
	}
	return e.metadata.close()
}

// taskDNS renders resolvers for a fresh namespace anchor. Customer containers
// join that namespace and share its resolv.conf; Docker rejects per-container
// DNS in container network mode.
func (d *DockerExecutor) taskDNS(spec network.Specification) ([]string, []string, error) {
	if len(d.networking.DNS) == 0 {
		return nil, nil, nil
	}
	servers, err := d.networking.SelectedDNS(spec.DNS, spec.Pool.Masked().Addr().Next().Next(), spec.DNSSupport, nil)
	if err != nil {
		return nil, nil, err
	}
	search := strings.Fields(spec.DomainName)
	if len(search) == 0 {
		search = []string{"."}
	}
	return servers, search, nil
}

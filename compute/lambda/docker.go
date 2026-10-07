package lambda

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"stackd/compute/docker"
)

// Runtime images are deliberately immutable and platform-specific.
// Images must already exist in Docker; execution never pulls or contacts a registry.
const (
	Python312X8664Image      = "public.ecr.aws/lambda/python@sha256:a89893d9c93a9ffbf9e35ca32d7cadc635cbf3a9aec94480c75ed07150a05daa"
	Python312ARM64Image      = "public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e"
	Python313X8664Image      = "public.ecr.aws/lambda/python@sha256:1db929eee2769af5a502cb0ac7409245a1f5b8f8cb37f43832e9983f7a0aed53"
	Python313ARM64Image      = "public.ecr.aws/lambda/python@sha256:48fb06e4f76b6512f055afe0659bffecb2439affd9d0a4d98afba0fdde7bc08f"
	Node22X8664Image         = "public.ecr.aws/lambda/nodejs@sha256:0c33b7174dc800aaf810b3f6075aadec654aaf81d96b974a33f91cacf0bbe569"
	Node22ARM64Image         = "public.ecr.aws/lambda/nodejs@sha256:2f80915b7e49e3ae37a84be1110d313113d3e0c027d3564b489f46d10aae320a"
	ProvidedAL2023X8664Image = "public.ecr.aws/lambda/provided@sha256:0439bff81ff967d34c098fa6d23a0059ff90d339dc8984f1dda007bde039a44f"
	ProvidedAL2023ARM64Image = "public.ecr.aws/lambda/provided@sha256:b501fd60cfbd920688576f5cfd6040bf3533a15ce160673758c77ca2dabd312e"
)

// RuntimePlatform identifies a Lambda runtime and its AWS architecture:
// x86_64 or arm64, not Docker's amd64 spelling.
type RuntimePlatform struct {
	Runtime      string
	Architecture string
}

// DockerConfig configures the Lambda execution backend. Client must be constructed
// by docker.New; its caller owns the shared transport and closes it only after all
// runtime consumers have closed their environments.
// ListenAddress defaults to 0.0.0.0:0; each environment gets its own listener.
// CallbackHost is an IP or hostname reachable from the Docker host's containers.
// Empty CallbackHost uses Docker's Linux host-gateway mapping. The explicit name
// host.docker.internal uses Docker Desktop's container DNS without a host override.
// Other explicit hosts are resolved by the controller and mapped in the container.
// Remote engines require an explicit CallbackHost and a reachable listener.
// Images maps runtime/architecture pairs to immutable image digests; nil enables
// Python 3.12/3.13, Node.js 22 and provided.al2023 on x86_64 and arm64 using the pinned
// images above. Explicit maps are exact overrides. Additional runtimes must
// implement the Runtime API.
// HotReload maps unqualified function ARNs to opt-in development directories.
// StartupTimeout defaults to 30 seconds and is an upper bound, not a ready delay.
// TelemetryHelpers maps AWS architectures to absolute local paths of prebuilt
// static linux telemetry-buffer executables. They are copied to the selected
// Engine, never built or downloaded at runtime.
// Namespace is a stable, instance-unique native resource owner. StorageImage is
// an installed immutable Linux image providing util-linux and e2fsprogs; the
// default is StorageImage. Storage helpers require a rootful Docker daemon with
// privileged containers, loop devices and ext4 support, not a privileged client.
type DockerConfig struct {
	Client           *docker.Client
	Namespace        string
	StorageImage     string
	ListenAddress    string
	CallbackHost     string
	Images           map[RuntimePlatform]string
	HotReload        map[string]HotReloadDirectories
	TelemetryHelpers map[string]string
	StartupTimeout   time.Duration
}

type DockerExecutor struct {
	engine         *docker.Client
	config         DockerConfig
	mu             sync.RWMutex
	closed         bool
	recoveryErr    error
	reaperStop     context.CancelFunc
	reaperDone     chan struct{}
	owner          string
	ownerVolume    string
	guard          io.ReadWriteCloser
	lifetime       context.Context
	stop           context.CancelFunc
	imagePins      map[string]Image
	imagePinsReady bool
}

// NewDockerExecutor validates Lambda runtime configuration using a caller-owned
// Engine client. Prepare separately verifies the configured local image.
func NewDockerExecutor(ctx context.Context, config DockerConfig) (*DockerExecutor, error) {
	if config.Client == nil {
		return nil, fmt.Errorf("lambda Docker client is required")
	}
	if config.Namespace == "" {
		return nil, fmt.Errorf("lambda Docker requires a stable unique namespace")
	}
	if config.StorageImage == "" {
		config.StorageImage = StorageImage
	}
	if !immutableImage(config.StorageImage) {
		return nil, fmt.Errorf("lambda storage helper requires an immutable image@sha256 digest")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if config.ListenAddress == "" {
		config.ListenAddress = "0.0.0.0:0"
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 30 * time.Second
	}
	if config.StartupTimeout < 0 {
		return nil, fmt.Errorf("docker startup timeout must be positive")
	}
	if config.Images == nil {
		config.Images = map[RuntimePlatform]string{
			{Runtime: "python3.12", Architecture: "x86_64"}:      Python312X8664Image,
			{Runtime: "python3.12", Architecture: "arm64"}:       Python312ARM64Image,
			{Runtime: "python3.13", Architecture: "x86_64"}:      Python313X8664Image,
			{Runtime: "python3.13", Architecture: "arm64"}:       Python313ARM64Image,
			{Runtime: "nodejs22.x", Architecture: "x86_64"}:      Node22X8664Image,
			{Runtime: "nodejs22.x", Architecture: "arm64"}:       Node22ARM64Image,
			{Runtime: "provided.al2023", Architecture: "x86_64"}: ProvidedAL2023X8664Image,
			{Runtime: "provided.al2023", Architecture: "arm64"}:  ProvidedAL2023ARM64Image,
		}
	}
	images := make(map[RuntimePlatform]string, len(config.Images))
	for platform, image := range config.Images {
		if !immutableImage(image) {
			return nil, fmt.Errorf("runtime %q architecture %q requires an immutable image@sha256 digest", platform.Runtime, platform.Architecture)
		}
		images[platform] = image
	}
	config.Images = images
	helpers := make(map[string]string, len(config.TelemetryHelpers))
	for architecture, filename := range config.TelemetryHelpers {
		helpers[architecture] = filename
	}
	config.TelemetryHelpers = helpers
	hotReload, err := normalizeHotReload(config.HotReload)
	if err != nil {
		return nil, err
	}
	config.HotReload = hotReload
	d := &DockerExecutor{engine: config.Client, config: config}
	if err := d.openOwner(ctx); err != nil {
		return nil, err
	}
	reaperContext, stopReaper := context.WithCancel(d.lifetime)
	d.reaperStop = stopReaper
	d.reaperDone = make(chan struct{})
	go d.recoverLateCreates(reaperContext)
	return d, nil
}

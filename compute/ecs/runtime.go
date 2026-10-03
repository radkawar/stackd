// Package ecs defines the external container lifecycle used by the ECS control
// plane. AWS desired state, dependency ordering and authorization belong to the
// service, not to the container driver.
package ecs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"stackd/compute/network"
)

// ErrNetworkPolicy identifies a failed native authorization boundary. Retained
// processes must not continue merely because other reattachment errors retry.
var ErrNetworkPolicy = errors.New("unable to enforce ECS network policy")

// Executor prepares or reopens the backend resources of an accepted task.
// Preparation does not start customer containers. The caller must apply network
// policy and commit observed attachment facts before starting them.
type Executor interface {
	Prepare(context.Context, Specification) (Environment, error)
	// Processes attaches only to existing owned containers. Destruction must
	// not require usable images, networking policy or a metadata callback.
	Processes(context.Context, Specification) (TaskProcesses, error)
	// Remove also cleans partial preparation using the retained task inputs.
	Remove(context.Context, Specification) error
}

// Specification contains the resolved, immutable execution inputs of one task.
// TaskARN identifies retained resources across controller restarts. Metadata
// belongs to the current controller process and authorizes its opaque request
// paths; it must never expose execution-role credentials to customer containers.
type Specification struct {
	TaskARN      string
	Architecture string
	CPUUnits     int64
	MemoryBytes  int64
	Containers   []ContainerSpecification
	Volumes      []string
	Network      network.Specification
	Metadata     http.Handler
}

// ContainerSpecification translates service inputs into actual process and
// engine resource settings. It deliberately has no essential/dependency fields:
// the ECS state machine owns when a container should start or stop.
type ContainerSpecification struct {
	Name        string
	Image       string
	Entrypoint  []string
	Command     []string
	Environment []string
	// ResolveEnvironment is called only when creating a new native container,
	// not on reattachment. Its result is sent to native Env but never retained
	// in this specification or other task metadata.
	ResolveEnvironment     func(context.Context) ([]string, error)
	WorkingDirectory       string
	User                   string
	CPUShares              int64
	MemoryBytes            int64
	MemoryReservationBytes int64
	ReadonlyRootFilesystem bool
	HealthCheck            *HealthCheck
	Mounts                 []Mount
}

type HealthCheck struct {
	Command     []string
	Interval    time.Duration
	Timeout     time.Duration
	StartPeriod time.Duration
	Retries     int
}

type Mount struct {
	Volume   string
	Path     string
	ReadOnly bool
}

// TaskProcesses observes and stops existing native processes without creating
// resources or granting permission to start a customer container.
type TaskProcesses interface {
	Inspect(context.Context) ([]ContainerStatus, error)
	Stop(context.Context, string, time.Duration) error
	Logs(context.Context, string, time.Time, func(LogRecord) error) error
}

// Environment owns this process's connection to a task's real backend resources.
// Close detaches listeners and streams without stopping retained customer
// processes. Executor.Remove owns destruction, including failed preparations.
// An allocated runtime ID is not evidence that a process has started.
type Environment interface {
	TaskProcesses
	SetNetworkPolicy(context.Context, network.Policy) error
	Stats(context.Context, string) (json.RawMessage, error)
	Usage(context.Context, string) (ContainerUsage, error)
	Start(context.Context, string) error
	Close() error
}

type ContainerState string

const (
	ContainerCreated ContainerState = "created"
	ContainerRunning ContainerState = "running"
	ContainerExited  ContainerState = "exited"
)

type HealthState string

const (
	HealthUnknown   HealthState = "UNKNOWN"
	HealthHealthy   HealthState = "HEALTHY"
	HealthUnhealthy HealthState = "UNHEALTHY"
)

// ContainerStatus reports native engine facts. Timestamps are the engine's wall
// time; the service owns timestamps at its deterministic API/event boundary.
// ExitCode is absent when a process has never started.
type ContainerStatus struct {
	Name        string
	RuntimeID   string
	ImageDigest string
	DockerName  string
	ImageID     string
	CreatedAt   time.Time
	Labels      map[string]string
	CPUShares   int64
	MemoryBytes int64
	State       ContainerState
	Health      HealthState
	ExitCode    *int
	StartedAt   time.Time
	FinishedAt  time.Time
	Error       string
	OOMKilled   bool
}

// ContainerUsage is one native observation of an owned container. ObservedAt is
// the engine's wall time; CPUTime is cumulative CPU consumed across all cores,
// not a rate. MemoryBytes is the engine's cache-adjusted working set. Missing
// native observations are errors, not zero-valued utilization samples.
type ContainerUsage struct {
	ObservedAt  time.Time
	CPUTime     time.Duration
	MemoryBytes uint64
}

// LogRecord is an observed engine log entry. Its wall-clock timestamp can be
// used as the native log cursor; the consuming service owns publication and its
// service-time timestamp. Message is valid only during the Logs callback.
type LogRecord struct {
	Time    time.Time
	Stderr  bool
	Message []byte
}

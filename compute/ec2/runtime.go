// Package ec2 implements native guest execution. The service owns AWS desired
// state, authorization, deadlines and EBS disk identity; this package reports
// actual native process and block-device outcomes.
package ec2

import (
	"context"
	"errors"
	"net/http"
	"time"

	"stackd/compute/network"
)

var ErrNotFound = errors.New("native instance not found")

// Config selects the native Linux QEMU backend. The controller and service
// contracts are portable; configuring guest execution on other hosts is rejected.
type Config struct {
	SystemBinary   string
	ImageBinary    string
	NBDBinary      string
	IOBinary       string
	StateDirectory string
	BIOSPath       string
	UEFICodePath   string
	UEFIVarsPath   string
	Networks       GuestNetworks
	CPULimits      ProcessLimits
}

// CapabilityError rejects a request the configured native backend cannot honor.
type CapabilityError struct{ Feature string }

func (e *CapabilityError) Error() string { return "QEMU capability unavailable: " + e.Feature }

type Executor interface {
	Prepare(context.Context, Specification) (Instance, error)
	Reopen(context.Context, Specification) (Instance, error)
	Remove(context.Context, Specification) error
}

type CPU struct{ Sockets, Cores, Threads int }

type Specification struct {
	InstanceARN  string
	Architecture string
	BootMode     string
	CPU          CPU
	MemoryBytes  int64
	// Hibernation exposes the standard guest-agent channel. The image owns
	// Linux suspend-to-disk support and its root-volume resume configuration.
	Hibernation bool
	// Disks is desired/resolved state. During reattachment nonroot hotplug
	// intents may not yet match the native graph; the root must always match.
	Disks    []Disk
	Network  network.Specification
	Metadata http.Handler
}

// Disk refers to the EBS-owned, authoritative native qcow2 file. Key is the
// unwrapped KMS material, encoded as a base64 UTF-8 LUKS passphrase at the native
// boundary. It is neither logged nor persisted by this package. Reconnection and
// live reads/backups use the surviving VM's secret and do not require Key.
// Delete-on-termination and attachment metadata remain entirely EBS-owned.
type Disk struct {
	ID        string
	Path      string
	Encrypted bool
	Key       []byte
	Root      bool
}

type DiskSource struct {
	Path      string
	Format    string
	Encrypted bool
	Key       []byte
}

type Extent struct {
	Start  int64 `json:"start"`
	Length int64 `json:"length"`
	Data   bool  `json:"data"`
	Zero   bool  `json:"zero"`
}

// ExtentsKnown is false only for an offline encrypted ciphertext copy without
// unwrapped material. The owner must carry retained stopped-volume allocation
// metadata; a nil extent result must never be interpreted as an empty disk.
type BackupResult struct {
	Extents      []Extent
	ExtentsKnown bool
}

// DiskStatus reports actual guest-visible native attachment, not desired EBS
// metadata. ID is empty when the current Specification does not map the node;
// Device, NodeName, Path and Serial still diagnose the unknown attachment.
type DiskStatus struct {
	ID        string
	Device    string
	NodeName  string
	Path      string
	Serial    string
	Encrypted bool
	Root      bool
}

type State string

const (
	Running  State = "running"
	Paused   State = "paused"
	Shutdown State = "shutdown"
	Exited   State = "exited"
	Error    State = "error"
)

type Status struct {
	State       State
	NativeState string
	PID         int
	// PID plus Linux starttime distinguishes a replacement from PID reuse.
	StartTimeTicks uint64
	Error          string
}

// Health reports native network and live disk-read observations.
// DisksReachable is meaningful only when the caller requests disk checks.
type Health struct {
	Network        NetworkHealth
	DisksReachable bool
	// HibernationReady observes a synchronized guest agent advertising S4.
	// It does not claim the guest has saved memory successfully.
	HibernationReady bool
}

// Start resumes a prepared/paused guest, not a shutdown guest. Stop terminates
// the VMM and observes exit; Powerdown only requests ACPI guest shutdown.
// Close releases controller resources without stopping the guest or deleting
// its persistent physical attachment. Remove owns destructive native cleanup.
type Instance interface {
	Inspect(context.Context) (Status, error)
	CheckHealth(ctx context.Context, checkDisks bool) (Health, error)
	Start(context.Context) error
	Pause(context.Context) error
	Powerdown(context.Context) error
	// Hibernate requests genuine guest suspend-to-disk. Acceptance does not
	// imply shutdown or preserved memory; Inspect observes the native outcome.
	Hibernate(context.Context) error
	Reset(context.Context) error
	Stop(context.Context) error
	Console(context.Context, int64, int) ([]byte, error)
	// Screenshot returns a JPEG of the real guest framebuffer. WakeUp injects
	// a harmless keyboard modifier; it must never start a stopped instance.
	Screenshot(ctx context.Context, wakeUp bool) ([]byte, error)
	SetNetwork(context.Context, network.Specification) error
	CPUUsage(context.Context) (time.Duration, error)
	NetworkUsage(context.Context) (NetworkUsage, error)
	SetCPUQuota(context.Context, CPUQuota) error
	AttachDisk(context.Context, Disk) error
	DetachDisk(context.Context, Disk) error
	AttachedDisks(context.Context) ([]DiskStatus, error)
	Close() error
}

// GuestNetworks is supplied by the physical shared-network owner. Prepare must
// reopen a persistent TAP and rebind DHCP/metadata/policy after controller loss.
// It must not replace a surviving guest's TAP. Close detaches local listeners;
// Remove deletes the physical attachment, including partially prepared ones.
type GuestNetworks interface {
	Prepare(context.Context, string, network.Specification, http.Handler) (GuestAttachment, error)
	Remove(context.Context, string, network.Specification) error
}

// NetworkHealth observes native Ethernet attachment and IPv4 ARP responsiveness,
// not the guest's operating system or application health.
type NetworkHealth struct {
	// Attached requires an up TAP with a connected backend on its expected bridge.
	Attached bool
	// Reachable requires an actual reply to this probe, not a cached neighbor.
	Reachable bool
}

// NetworkUsage contains cumulative counters from the guest's actual attachment.
// InterfaceIndex distinguishes a replacement TAP whose counters start over.
// Directions are from the guest's perspective, not the host TAP's perspective.
type NetworkUsage struct {
	InterfaceIndex    int
	BytesIn, BytesOut uint64
}

type GuestAttachment interface {
	TAPName() string
	Configure(context.Context, network.Specification) error
	CheckHealth(context.Context) (NetworkHealth, error)
	NetworkUsage(context.Context) (NetworkUsage, error)
	Close() error
}

// CPUQuota is a native CPU bandwidth quota, not an AWS credit policy.
// Runtime == 0 requests unlimited native bandwidth.
type CPUQuota struct{ Period, Runtime time.Duration }

// ProcessLimits is the injected shared cgroup/systemd owner. Apply must move the
// actual VMM and all its threads into the owned scope and enforce the quota.
type ProcessLimits interface {
	Apply(context.Context, string, int, CPUQuota) error
	Remove(context.Context, string) error
}

package network

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// FlowIdentity is authoritative EC2 attachment ownership, never inferred from a
// packet address. NetworkID must be the full VPC ARN returned by VPCARN.
type FlowIdentity struct {
	Partition string `json:"partition"`
	AccountID string `json:"account_id"`
	// VPCOwnerAccountID identifies the shared VPC's owner. Empty means the
	// attachment and VPC have the same owner; AccountID always owns the ENI.
	VPCOwnerAccountID string `json:"vpc_owner_account_id,omitempty"`
	Region            string `json:"region"`
	VPCID             string `json:"vpc_id"`
	SubnetID          string `json:"subnet_id"`
	InterfaceID       string `json:"interface_id"`
}

func (i FlowIdentity) VPCARN() string {
	account := i.VPCOwnerAccountID
	if account == "" {
		account = i.AccountID
	}
	return fmt.Sprintf("arn:%s:ec2:%s:%s:vpc/%s", i.Partition, i.Region, account, i.VPCID)
}

func (i FlowIdentity) Validate(networkID string) error {
	for _, value := range []string{i.Partition, i.AccountID, i.Region, i.VPCID, i.SubnetID, i.InterfaceID} {
		if !flowIdentityPart.MatchString(value) {
			return fmt.Errorf("invalid flow attachment identity")
		}
	}
	if i.VPCOwnerAccountID != "" && !flowIdentityPart.MatchString(i.VPCOwnerAccountID) {
		return fmt.Errorf("invalid flow VPC owner identity")
	}
	if networkID != i.VPCARN() {
		return fmt.Errorf("flow attachment identity does not match full VPC ARN %q", networkID)
	}
	return nil
}

var flowIdentityPart = regexp.MustCompile(`^[a-zA-Z0-9-]{1,128}$`)

// FlowBinding is immutable once registered. EngineID/BootID/PeerIfIndex may be
// empty at admission: the daemon fills them from its verified native namespace.
// Generation is an opaque policy epoch supplied by the renderer; each policy
// replacement must use a fresh epoch and retire the previous registration.
type FlowBinding struct {
	Identity    FlowIdentity `json:"identity"`
	NetworkID   string       `json:"network_id"`
	PolicyTable string       `json:"policy_table"`
	PublicOwner string       `json:"public_owner"`
	Bridge      string       `json:"bridge"`
	PeerName    string       `json:"peer_name"`
	PeerIfIndex int          `json:"peer_ifindex"`
	MTU         int          `json:"mtu"`
	Address     netip.Addr   `json:"address"`
	MAC         string       `json:"mac"`
	EngineID    string       `json:"engine_id"`
	BootID      string       `json:"boot_id"`
	Generation  string       `json:"generation"`
}

type FlowRegistration struct {
	Group      uint16 `json:"group"`
	Token      string `json:"token"`
	Generation string `json:"generation"`
}

// Prefix is nft's non-terminating log prefix. Direction is ingress/egress and
// action is ACCEPT/REJECT; only terminal ENI verdict sites may use it.
func (r FlowRegistration) Prefix(direction, action string) string {
	return "sf:" + r.Token + ":" + direction + ":" + action
}

// TODO: Comeback add native IPv6 capture and segment-count witnesses for TCP payloads, fragments and offloaded packets; report gaps until those counts are provable.
type FlowObservation struct {
	Binding            FlowBinding `json:"binding"`
	Token              string      `json:"token"`
	Generation         string      `json:"generation"`
	Direction          string      `json:"direction"`
	Action             string      `json:"action"`
	Protocol           uint8       `json:"protocol"`
	SourceAddress      netip.Addr  `json:"source_address"`
	DestinationAddress netip.Addr  `json:"destination_address"`
	SourcePort         uint16      `json:"source_port"`
	DestinationPort    uint16      `json:"destination_port"`
	IPBytes            uint32      `json:"ip_bytes"`
	Packets            uint32      `json:"packets"`
	TCPFlags           uint8       `json:"tcp_flags"`
	ObservedAt         time.Time   `json:"observed_at"`
	TimestampSource    string      `json:"timestamp_source"`
}

// Gaps are evidence of incomplete coverage, not fabricated packet observations.
// Empty Token means every binding in this collector may be affected.
type FlowGap struct {
	Token      string    `json:"token,omitempty"`
	Generation string    `json:"generation"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Reason     string    `json:"reason"`
}

type FlowRecord struct {
	Cursor      uint64           `json:"cursor"`
	Observation *FlowObservation `json:"observation,omitempty"`
	Gap         *FlowGap         `json:"gap,omitempty"`
}

type FlowReadLimits struct {
	MaxRecords int `json:"max_records"`
	MaxBytes   int `json:"max_bytes"`
}

type FlowHealth struct {
	Ready      bool      `json:"ready"`
	EngineID   string    `json:"engine_id"`
	BootID     string    `json:"boot_id"`
	Generation string    `json:"generation"`
	Group      uint16    `json:"group"`
	Acked      uint64    `json:"acked"`
	Head       uint64    `json:"head"`
	Watermark  time.Time `json:"watermark"`
	Incomplete bool      `json:"incomplete"`
}

// FlowCoverage is current native policy-generation evidence, not a subscription
// or an observation. Ready requires verified owned rules/counters and a drained
// receiver. Missing coverage is incomplete; collector readiness alone is never
// authority for a healthy empty flow-log interval.
type FlowCoverage struct {
	Binding    FlowBinding `json:"binding"`
	Token      string      `json:"token"`
	Generation string      `json:"generation"`
	Ready      bool        `json:"ready"`
	Watermark  time.Time   `json:"watermark"`
}

type FlowBatch struct {
	Records  []FlowRecord   `json:"records"`
	Cursor   uint64         `json:"cursor"`
	Health   FlowHealth     `json:"health"`
	Coverage []FlowCoverage `json:"coverage"`
}

// FlowReconcile is submitted only after an observed successful, serialized native
// policy operation. Through bounds replacement reconciliation to registrations
// no newer than the committed token. Empty Through requires proven table removal.
type FlowReconcile struct {
	PolicyTable string           `json:"policy_table"`
	PublicOwner string           `json:"public_owner"`
	Through     FlowRegistration `json:"through"`
}

// NativeFlowCollector outlives controllers. Ack follows durable consumer commit;
// Retire is permitted only after rules no longer reference a registration.
// Close does not stop the receiver or remove retained native resources.
type NativeFlowCollector interface {
	Register(context.Context, FlowBinding) (FlowRegistration, error)
	Retire(context.Context, FlowRegistration) error
	Reconcile(context.Context, FlowReconcile) error
	Read(context.Context, uint64, FlowReadLimits) (FlowBatch, error)
	Ack(context.Context, uint64) error
	Health(context.Context) (FlowHealth, error)
	Gap(context.Context, FlowGap) error
	Close() error
}

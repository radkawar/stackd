package ec2

import (
	"context"
	"time"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
)

// FlowLogRecord retains selectors, rather than a snapshot of matching ENIs.
// Incarnation fences deletion and any future reuse of an external identifier.
type FlowLogRecord struct {
	Key                                                       ResourceKey
	Incarnation                                               string
	ResourceID, ResourceType, TrafficType                     string
	DestinationType, Destination, LogGroupName, PermissionARN string
	LogFormat                                                 string
	FormatVersion                                             int
	AggregationSeconds                                        int
	HivePartitions, HourPartitions                            bool
	Tags                                                      api.TagList
	CreatedAt                                                 time.Time
	Status, DeliveryStatus, DeliveryError                     string
	CaptureError                                              string
	Version                                                   uint64
}

// Token is the service's client-token/record-format group identity, not a
// raw request token. Deleted members are filtered against current FlowLog rows;
// a requested deleted resource can be admitted again with a fresh identifier.
type FlowLogTokenKey struct {
	Scope Scope
	Token string
}
type FlowLogAdmissionResult struct{ ResourceID, FlowLogID, ErrorCode, ErrorMessage string }
type FlowLogTokenRecord struct {
	Key FlowLogTokenKey
	// Fingerprint is retained request evidence, not an equality/mismatch rule.
	Fingerprint string
	Results     []FlowLogAdmissionResult
}

// Exactly one capture checkpoint exists per repository. Cursor is opaque native
// authority; commit it atomically with every subscription's affected aggregates.
type FlowLogCaptureState struct {
	Cursor  string
	Due     time.Time
	Version uint64
}

type FlowLogInterface struct {
	Key                                             ResourceKey
	Incarnation, NetworkID, Address                 string
	VPCID, SubnetID, InstanceID, AvailabilityZoneID string
}

type FlowLogObservation struct {
	InterfaceKey                      ResourceKey
	Incarnation                       string
	SourceAddress, DestinationAddress string
	SourcePort, DestinationPort       uint16
	Protocol                          uint8
	Action, Direction                 string
	Packets, Bytes                    uint64
	Start, End                        time.Time
	TCPFlags                          uint8
	Lost                              bool
}
type FlowLogCaptureBatch struct {
	Cursor       string
	Observations []FlowLogObservation
	// More means the durable native journal has observations beyond Cursor.
	// CoverageError describes current coverage, independently of historical loss.
	More          bool
	CoverageError string
}

// Read reconciles the complete desired binding set and returns durable,
// non-destructive observations. Acknowledge follows the EC2 checkpoint commit.
type FlowLogCapture interface {
	Read(context.Context, []FlowLogInterface, string) (FlowLogCaptureBatch, error)
	Acknowledge(context.Context, string) error
}

type FlowLogAggregateKey struct {
	FlowLogKey ResourceKey
	ID         string
}
type FlowLogAggregateRecord struct {
	Key                               FlowLogAggregateKey
	Incarnation                       string
	Interface                         FlowLogInterface
	SourceAddress, DestinationAddress string
	SourcePort, DestinationPort       uint16
	Protocol                          uint8
	Action, Direction                 string
	Packets, Bytes                    uint64
	Start, End, Due                   time.Time
	TCPFlags                          uint8
	Lost                              bool
}

type FlowLogLine struct {
	Start                time.Time
	InterfaceID, Message string
}

// A sealed delivery is immutable apart from retry scheduling/version. Stable
// Key.ID is the destination deduplication identity across crashes and retries.
type FlowLogDeliveryRecord struct {
	Key                                                       ResourceKey
	FlowLogKey                                                ResourceKey
	Incarnation                                               string
	DestinationType, Destination, LogGroupName, PermissionARN string
	HivePartitions, HourPartitions                            bool
	Header                                                    string
	Lines                                                     []FlowLogLine
	WindowStart                                               time.Time
	Due                                                       time.Time
	Version                                                   uint64
}
type FlowLogDestination interface {
	// Validate is configuring-caller admission only (including PassRole and
	// destination setup). Background jobs must never invoke it to regain access.
	Validate(context.Context, FlowLogRecord) *awswire.Error
	// Write obtains current delivery authority for each real immutable batch.
	Write(context.Context, FlowLogDeliveryRecord, []FlowLogLine) *awswire.Error
}

package integrations

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"stackd/compute/network"
	"stackd/internal/services/ec2"
)

const (
	ec2FlowCaptureMaxRecords = 1024
	ec2FlowCaptureMaxBytes   = 1024 * 1024
)

// EC2FlowCapture reads the retained native journal. The root owns collector
// startup and shutdown; only Acknowledge may release committed native records.
type EC2FlowCapture struct {
	Collector network.NativeFlowCollector
}

var _ ec2.FlowLogCapture = EC2FlowCapture{}

func (a EC2FlowCapture) Read(ctx context.Context, desired []ec2.FlowLogInterface, cursor string) (ec2.FlowLogCaptureBatch, error) {
	after, err := ec2FlowCaptureCursor(cursor, true)
	if err != nil {
		return ec2.FlowLogCaptureBatch{}, err
	}
	if a.Collector == nil {
		return ec2.FlowLogCaptureBatch{}, errors.New("native flow collector is unavailable")
	}
	batch, err := a.Collector.Read(ctx, after, network.FlowReadLimits{MaxRecords: ec2FlowCaptureMaxRecords, MaxBytes: ec2FlowCaptureMaxBytes})
	if err != nil {
		return ec2.FlowLogCaptureBatch{}, fmt.Errorf("read native flow journal: %w", err)
	}
	if len(batch.Records) > ec2FlowCaptureMaxRecords || batch.Cursor < after || batch.Cursor > batch.Health.Head || batch.Health.Acked > after {
		return ec2.FlowLogCaptureBatch{}, errors.New("native flow journal returned an invalid batch range")
	}
	// Do not expose a checkpoint for a partially decoded or inconsistent batch.
	previous := after
	for _, record := range batch.Records {
		if record.Cursor <= previous || record.Cursor > batch.Cursor || (record.Observation == nil) == (record.Gap == nil) {
			return ec2.FlowLogCaptureBatch{}, errors.New("native flow journal returned an incomplete batch")
		}
		previous = record.Cursor
	}
	if previous != batch.Cursor {
		return ec2.FlowLogCaptureBatch{}, errors.New("native flow journal checkpoint does not end at the last record")
	}

	bindings := make(map[ec2.ResourceKey]ec2.FlowLogInterface, len(desired))
	for _, binding := range desired {
		if _, exists := bindings[binding.Key]; exists {
			return ec2.FlowLogCaptureBatch{}, errors.New("duplicate desired flow interface")
		}
		bindings[binding.Key] = binding
	}
	out := ec2.FlowLogCaptureBatch{Cursor: strconv.FormatUint(batch.Cursor, 10), More: batch.Health.Head > batch.Cursor}
	if len(batch.Records) > 0 {
		out.Observations = make([]ec2.FlowLogObservation, 0, len(batch.Records)+1)
	}
	globalLoss := false
	for _, record := range batch.Records {
		if gap := record.Gap; gap != nil {
			// A token is not an ENI identity. Without its retained immutable
			// registry entry, a token-specific gap must remain global.
			out.Observations = append(out.Observations, ec2.FlowLogObservation{Lost: true, Start: gap.Start, End: gap.End})
			globalLoss = true
			continue
		}
		native := record.Observation
		key := ec2FlowCaptureKey(native.Binding.Identity)
		desiredBinding, known := bindings[key]
		valid := native.Binding.Identity.Validate(native.Binding.NetworkID) == nil && ec2FlowCaptureObservationValid(native)
		if !known && valid {
			// The collector also retains traffic for unsubscribed interfaces.
			// A scoped immutable binding outside desired is not evidence of loss.
			continue
		}
		if !known || !valid || !ec2FlowCaptureBindingMatches(&native.Binding, desiredBinding) {
			out.Observations = append(out.Observations, ec2.FlowLogObservation{Lost: true, Start: native.ObservedAt, End: native.ObservedAt})
			globalLoss = true
			continue
		}
		out.Observations = append(out.Observations, ec2.FlowLogObservation{
			InterfaceKey: key, Incarnation: native.Binding.Identity.InterfaceID,
			SourceAddress: native.SourceAddress.String(), DestinationAddress: native.DestinationAddress.String(),
			SourcePort: native.SourcePort, DestinationPort: native.DestinationPort,
			Protocol: native.Protocol, Action: native.Action, Direction: native.Direction,
			Packets: uint64(native.Packets), Bytes: uint64(native.IPBytes),
			Start: native.ObservedAt, End: native.ObservedAt, TCPFlags: native.TCPFlags,
		})
	}

	if !ec2FlowCaptureCovered(batch, bindings) {
		// Current coverage is separate from historical packet loss. Preserve
		// valid records and the cursor without advertising current readiness.
		out.CoverageError = "native flow coverage is not verified for all desired interfaces"
		if batch.Cursor != after && !globalLoss {
			out.Observations = append(out.Observations, ec2.FlowLogObservation{Lost: true, Start: batch.Health.Watermark, End: batch.Health.Watermark})
		}
	}
	return out, nil
}

func (a EC2FlowCapture) Acknowledge(ctx context.Context, cursor string) error {
	through, err := ec2FlowCaptureCursor(cursor, false)
	if err != nil {
		return err
	}
	if a.Collector == nil {
		return errors.New("native flow collector is unavailable")
	}
	if err := a.Collector.Ack(ctx, through); err != nil {
		return fmt.Errorf("acknowledge native flow journal: %w", err)
	}
	return nil
}

func ec2FlowCaptureCursor(cursor string, initial bool) (uint64, error) {
	if cursor == "" && initial {
		return 0, nil
	}
	for _, digit := range cursor {
		if digit < '0' || digit > '9' {
			return 0, errors.New("invalid native flow cursor: expected an unsigned decimal integer")
		}
	}
	value, err := strconv.ParseUint(cursor, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid native flow cursor: %w", err)
	}
	return value, nil
}

func ec2FlowCaptureKey(identity network.FlowIdentity) ec2.ResourceKey {
	return ec2.ResourceKey{Scope: ec2.Scope{Partition: identity.Partition, AccountID: identity.AccountID, Region: identity.Region}, ID: identity.InterfaceID}
}

func ec2FlowCaptureBindingMatches(binding *network.FlowBinding, desired ec2.FlowLogInterface) bool {
	address, err := netip.ParseAddr(desired.Address)
	return err == nil && binding.Identity.Validate(binding.NetworkID) == nil &&
		ec2FlowCaptureKey(binding.Identity) == desired.Key && desired.Incarnation == binding.Identity.InterfaceID &&
		binding.NetworkID == desired.NetworkID && binding.Identity.VPCID == desired.VPCID &&
		binding.Identity.SubnetID == desired.SubnetID && binding.Address == address
}

func ec2FlowCaptureObservationValid(observation *network.FlowObservation) bool {
	return observation.Token != "" && observation.Generation != "" && observation.Generation == observation.Binding.Generation &&
		observation.Binding.EngineID != "" && observation.Binding.BootID != "" &&
		observation.SourceAddress.IsValid() && observation.DestinationAddress.IsValid() &&
		observation.SourceAddress.Is4() == observation.DestinationAddress.Is4() &&
		(observation.Action == "ACCEPT" || observation.Action == "REJECT") &&
		(observation.Direction == "ingress" || observation.Direction == "egress") &&
		observation.Packets > 0 && observation.IPBytes > 0 && !observation.ObservedAt.IsZero()
}

func ec2FlowCaptureCovered(batch network.FlowBatch, desired map[ec2.ResourceKey]ec2.FlowLogInterface) bool {
	health := batch.Health
	if !health.Ready || health.Incomplete || health.EngineID == "" || health.BootID == "" || health.Group == 0 || health.Watermark.IsZero() {
		return false
	}
	covered := make(map[ec2.ResourceKey]bool, len(desired))
	for index := range batch.Coverage {
		coverage := &batch.Coverage[index]
		key := ec2FlowCaptureKey(coverage.Binding.Identity)
		binding, exists := desired[key]
		if exists && coverage.Ready && coverage.Token != "" && coverage.Generation != "" &&
			coverage.Generation == coverage.Binding.Generation && coverage.Binding.EngineID == health.EngineID &&
			coverage.Binding.BootID == health.BootID && coverage.Watermark.Equal(health.Watermark) &&
			ec2FlowCaptureBindingMatches(&coverage.Binding, binding) {
			covered[key] = true
		}
	}
	return len(covered) == len(desired)
}

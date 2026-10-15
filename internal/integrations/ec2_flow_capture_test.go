package integrations

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"stackd/compute/network"
	"stackd/internal/services/ec2"
)

type flowCaptureCollector struct {
	network.NativeFlowCollector
	batch           network.FlowBatch
	readErr, ackErr error
	after           uint64
	limits          network.FlowReadLimits
	reads           int
	acks            []uint64
	beforeAck       func()
}

func (c *flowCaptureCollector) Read(_ context.Context, after uint64, limits network.FlowReadLimits) (network.FlowBatch, error) {
	c.reads++
	c.after, c.limits = after, limits
	return c.batch, c.readErr
}

func (c *flowCaptureCollector) Ack(_ context.Context, through uint64) error {
	if c.beforeAck != nil {
		c.beforeAck()
	}
	c.acks = append(c.acks, through)
	return c.ackErr
}

func flowCaptureFixture() (*flowCaptureCollector, ec2.FlowLogInterface, network.FlowObservation) {
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	identity := network.FlowIdentity{Partition: "aws", AccountID: "222222222222", VPCOwnerAccountID: "111111111111", Region: "us-east-1", VPCID: "vpc-owner", SubnetID: "subnet-shared", InterfaceID: "eni-participant"}
	binding := network.FlowBinding{Identity: identity, NetworkID: identity.VPCARN(), Address: netip.MustParseAddr("10.0.0.4"), EngineID: "engine-one", BootID: "boot-one", Generation: "policy-one"}
	desired := ec2.FlowLogInterface{Key: ec2FlowCaptureKey(identity), Incarnation: identity.InterfaceID, NetworkID: binding.NetworkID, Address: binding.Address.String(), VPCID: identity.VPCID, SubnetID: identity.SubnetID}
	observation := network.FlowObservation{Binding: binding, Token: "immutable-token", Generation: binding.Generation, Direction: "egress", Action: "ACCEPT", Protocol: 6, SourceAddress: binding.Address, DestinationAddress: netip.MustParseAddr("10.0.0.8"), SourcePort: 41000, DestinationPort: 443, IPBytes: 84, Packets: 1, TCPFlags: 18, ObservedAt: stamp, TimestampSource: "kernel"}
	collector := &flowCaptureCollector{batch: network.FlowBatch{
		Cursor:   42,
		Records:  []network.FlowRecord{{Cursor: 42, Observation: &observation}},
		Health:   network.FlowHealth{Ready: true, EngineID: binding.EngineID, BootID: binding.BootID, Generation: "receiver-one", Group: 1234, Acked: 41, Head: 42, Watermark: stamp},
		Coverage: []network.FlowCoverage{{Binding: binding, Token: observation.Token, Generation: binding.Generation, Ready: true, Watermark: stamp}},
	}}
	return collector, desired, observation
}

func TestEC2FlowCaptureMapsNativePacketWithoutAddressOwnershipInference(t *testing.T) {
	collector, desired, native := flowCaptureFixture()
	adapter := EC2FlowCapture{Collector: collector}
	batch, err := adapter.Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil {
		t.Fatal(err)
	}
	want := ec2.FlowLogObservation{InterfaceKey: desired.Key, Incarnation: desired.Incarnation, SourceAddress: "10.0.0.4", DestinationAddress: "10.0.0.8", SourcePort: 41000, DestinationPort: 443, Protocol: 6, Action: "ACCEPT", Direction: "egress", Packets: 1, Bytes: 84, Start: native.ObservedAt, End: native.ObservedAt, TCPFlags: 18}
	if batch.Cursor != "42" || !reflect.DeepEqual(batch.Observations, []ec2.FlowLogObservation{want}) {
		t.Fatalf("native packet was changed: %+v", batch)
	}
	if batch.Observations[0].InterfaceKey.Scope.AccountID != "222222222222" {
		t.Fatal("VPC owner replaced the authoritative ENI owner")
	}
	if collector.after != 41 || collector.limits.MaxRecords != 1024 || collector.limits.MaxBytes != 1024*1024 || len(collector.acks) != 0 {
		t.Fatalf("read did not preserve bounded non-destructive access: %+v", collector)
	}
}

func TestEC2FlowCaptureIsolatesOverlappingAddressesAndInterfaceNames(t *testing.T) {
	collector, first, native := flowCaptureFixture()
	other := native
	other.Binding.Identity.AccountID = "333333333333"
	other.Binding.Identity.VPCOwnerAccountID = ""
	other.Binding.NetworkID = other.Binding.Identity.VPCARN()
	other.Token = "other-immutable-token"
	other.IPBytes = 96
	other.Direction, other.Action = "ingress", "REJECT"
	second := first
	second.Key = ec2FlowCaptureKey(other.Binding.Identity)
	second.NetworkID = other.Binding.NetworkID
	collector.batch.Records = append(collector.batch.Records, network.FlowRecord{Cursor: 43, Observation: &other})
	collector.batch.Cursor, collector.batch.Health.Head = 43, 43
	collector.batch.Coverage = append(collector.batch.Coverage, network.FlowCoverage{Binding: other.Binding, Token: other.Token, Generation: other.Generation, Ready: true, Watermark: collector.batch.Health.Watermark})
	batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{first, second}, "41")
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Observations) != 2 || batch.Observations[0].InterfaceKey != first.Key || batch.Observations[1].InterfaceKey != second.Key || batch.Observations[1].Bytes != 96 || batch.Observations[1].Action != "REJECT" || batch.Observations[1].Direction != "ingress" {
		t.Fatalf("overlapping scoped interfaces were mixed: %+v", batch)
	}
}

func TestEC2FlowCaptureUnknownAndOldBindingsBecomeGaps(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*ec2.FlowLogInterface, *network.FlowObservation)
	}{
		{"unknown-invalid-identity", func(_ *ec2.FlowLogInterface, o *network.FlowObservation) {
			o.Binding.Identity.InterfaceID = "eni:invalid"
		}},
		{"old-incarnation", func(i *ec2.FlowLogInterface, _ *network.FlowObservation) { i.Incarnation = "new-incarnation" }},
		{"wrong-network", func(i *ec2.FlowLogInterface, _ *network.FlowObservation) {
			i.NetworkID = "arn:aws:ec2:us-east-1:999999999999:vpc/vpc-owner"
		}},
		{"changed-subnet", func(i *ec2.FlowLogInterface, _ *network.FlowObservation) { i.SubnetID = "subnet-other" }},
		{"changed-address", func(i *ec2.FlowLogInterface, _ *network.FlowObservation) { i.Address = "10.0.0.9" }},
		{"wrong-generation", func(_ *ec2.FlowLogInterface, o *network.FlowObservation) { o.Generation = "unrelated-policy" }},
		{"missing-token", func(_ *ec2.FlowLogInterface, o *network.FlowObservation) { o.Token = "" }},
		{"missing-packet-count", func(_ *ec2.FlowLogInterface, o *network.FlowObservation) { o.Packets = 0 }},
		{"missing-byte-count", func(_ *ec2.FlowLogInterface, o *network.FlowObservation) { o.IPBytes = 0 }},
		{"invalid-timestamp", func(_ *ec2.FlowLogInterface, o *network.FlowObservation) { o.ObservedAt = time.Time{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector, desired, native := flowCaptureFixture()
			test.change(&desired, &native)
			collector.batch.Records[0].Observation = &native
			batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
			if err != nil {
				t.Fatal(err)
			}
			if batch.Cursor != "42" || len(batch.Observations) != 1 || !batch.Observations[0].Lost || batch.Observations[0].InterfaceKey != (ec2.ResourceKey{}) || batch.Observations[0].Bytes != 0 || !batch.Observations[0].Start.Equal(native.ObservedAt) {
				t.Fatalf("unknown evidence was attributed to a live address: %+v", batch)
			}
		})
	}
}

func TestEC2FlowCaptureNativeGapsAreGlobalAndKeepTheirTimes(t *testing.T) {
	for _, token := range []string{"", "immutable-token", "retired-token"} {
		t.Run(token, func(t *testing.T) {
			collector, desired, native := flowCaptureFixture()
			gap := network.FlowGap{Token: token, Generation: "old-receiver", Start: native.ObservedAt.Add(-time.Second), End: native.ObservedAt, Reason: "netlink-overrun"}
			collector.batch.Records = []network.FlowRecord{{Cursor: 42, Gap: &gap}}
			batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
			if err != nil {
				t.Fatal(err)
			}
			want := ec2.FlowLogObservation{Lost: true, Start: gap.Start, End: gap.End}
			if !reflect.DeepEqual(batch.Observations, []ec2.FlowLogObservation{want}) || len(collector.acks) != 0 {
				t.Fatalf("native gap was narrowed or fabricated: %+v", batch)
			}
		})
	}
}

func TestEC2FlowCaptureEmptyRequiresEveryCurrentBindingCoverage(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*flowCaptureCollector, *[]ec2.FlowLogInterface)
	}{
		{"missing-registry", func(c *flowCaptureCollector, _ *[]ec2.FlowLogInterface) { c.batch.Coverage = nil }},
		{"unready-registry", func(c *flowCaptureCollector, _ *[]ec2.FlowLogInterface) { c.batch.Coverage[0].Ready = false }},
		{"missing-interface", func(_ *flowCaptureCollector, desired *[]ec2.FlowLogInterface) {
			other := (*desired)[0]
			other.Key.ID, other.Incarnation = "eni-other", "eni-other"
			*desired = append(*desired, other)
		}},
		{"old-snapshot", func(c *flowCaptureCollector, _ *[]ec2.FlowLogInterface) {
			c.batch.Coverage[0].Watermark = c.batch.Health.Watermark.Add(-time.Second)
		}},
		{"old-boot", func(c *flowCaptureCollector, _ *[]ec2.FlowLogInterface) {
			c.batch.Coverage[0].Binding.BootID = "old-boot"
		}},
		{"other-engine", func(c *flowCaptureCollector, _ *[]ec2.FlowLogInterface) {
			c.batch.Coverage[0].Binding.EngineID = "other-engine"
		}},
		{"other-generation", func(c *flowCaptureCollector, _ *[]ec2.FlowLogInterface) {
			c.batch.Coverage[0].Generation = "other-generation"
		}},
		{"unbound-receiver", func(c *flowCaptureCollector, _ *[]ec2.FlowLogInterface) { c.batch.Health.Ready = false }},
		{"pending-loss", func(c *flowCaptureCollector, _ *[]ec2.FlowLogInterface) { c.batch.Health.Incomplete = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector, binding, _ := flowCaptureFixture()
			collector.batch.Records = nil
			collector.batch.Cursor, collector.batch.Health.Head = 41, 41
			desired := []ec2.FlowLogInterface{binding}
			test.change(collector, &desired)
			batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), desired, "41")
			if err != nil || batch.Cursor != "41" || batch.CoverageError == "" || len(batch.Observations) != 0 || len(collector.acks) != 0 {
				t.Fatalf("unproven coverage became healthy empty data: %+v, %v", batch, err)
			}
		})
	}
	collector, desired, _ := flowCaptureFixture()
	collector.batch.Records = nil
	collector.batch.Cursor, collector.batch.Health.Head = 41, 41
	batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil || batch.Cursor != "41" || batch.CoverageError != "" || len(batch.Observations) != 0 {
		t.Fatalf("verified empty native batch was rejected: %+v, %v", batch, err)
	}
}

func TestEC2FlowCaptureUnverifiedCoverageDoesNotDiscardRealPackets(t *testing.T) {
	collector, desired, native := flowCaptureFixture()
	collector.batch.Coverage = nil
	batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil {
		t.Fatal(err)
	}
	if batch.Cursor != "42" || batch.CoverageError == "" || len(batch.Observations) != 2 || batch.Observations[0].Lost || !batch.Observations[1].Lost || batch.Observations[1].InterfaceKey != (ec2.ResourceKey{}) || !batch.Observations[1].Start.Equal(native.ObservedAt) {
		t.Fatalf("unverified coverage lost packet evidence or became healthy: %+v", batch)
	}
}

func TestEC2FlowCaptureRejectsIncompleteBatchesWithoutAdvancingOrAck(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*flowCaptureCollector)
	}{
		{"backward-checkpoint", func(c *flowCaptureCollector) { c.batch.Cursor = 40 }},
		{"past-head", func(c *flowCaptureCollector) { c.batch.Cursor = 43 }},
		{"acked-past-input", func(c *flowCaptureCollector) { c.batch.Health.Acked = 42 }},
		{"unread-checkpoint", func(c *flowCaptureCollector) { c.batch.Records = nil }},
		{"missing-body", func(c *flowCaptureCollector) {
			c.batch.Records = append(c.batch.Records, network.FlowRecord{Cursor: 43})
			c.batch.Cursor, c.batch.Health.Head = 43, 43
		}},
		{"both-bodies", func(c *flowCaptureCollector) { c.batch.Records[0].Gap = &network.FlowGap{} }},
		{"out-of-order", func(c *flowCaptureCollector) { c.batch.Records = append(c.batch.Records, c.batch.Records[0]) }},
		{"oversized-record-count", func(c *flowCaptureCollector) { c.batch.Records = make([]network.FlowRecord, 1025) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector, desired, _ := flowCaptureFixture()
			test.change(collector)
			batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
			if err == nil || batch.Cursor != "" || len(batch.Observations) != 0 || len(collector.acks) != 0 {
				t.Fatalf("partial batch escaped: %+v, %v", batch, err)
			}
		})
	}
}

func TestEC2FlowCaptureCursorErrorsAndCollectorErrorsAreHonest(t *testing.T) {
	for _, cursor := range []string{"native-41", "-1", "+1", " 41", "41\n", "18446744073709551616"} {
		collector, desired, _ := flowCaptureFixture()
		adapter := EC2FlowCapture{Collector: collector}
		if _, err := adapter.Read(t.Context(), []ec2.FlowLogInterface{desired}, cursor); err == nil || collector.reads != 0 {
			t.Fatalf("corrupt cursor reached native reader: %q", cursor)
		}
		if err := adapter.Acknowledge(t.Context(), cursor); err == nil || len(collector.acks) != 0 {
			t.Fatalf("corrupt cursor reached native acknowledgement: %q", cursor)
		}
	}
	collector, desired, _ := flowCaptureFixture()
	failure := errors.New("retained spool is corrupt")
	collector.readErr = failure
	batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if !errors.Is(err, failure) || batch.Cursor != "" || len(batch.Observations) != 0 || len(collector.acks) != 0 {
		t.Fatalf("native error became data or a new checkpoint: %+v, %v", batch, err)
	}
	collector.ackErr = failure
	if err := (EC2FlowCapture{Collector: collector}).Acknowledge(t.Context(), "42"); !errors.Is(err, failure) {
		t.Fatalf("native acknowledgement failure was suppressed: %v", err)
	}
	if err := (EC2FlowCapture{Collector: collector}).Acknowledge(t.Context(), ""); err == nil {
		t.Fatal("empty acknowledgement became journal zero")
	}
	if _, err := (EC2FlowCapture{}).Read(t.Context(), nil, ""); err == nil {
		t.Fatal("missing collector became healthy empty data")
	}
	if err := (EC2FlowCapture{}).Acknowledge(t.Context(), "0"); err == nil {
		t.Fatal("missing collector accepted acknowledgement")
	}
}

func TestEC2FlowCaptureAckRemainsConsumerControlledAcrossReplayAndRestart(t *testing.T) {
	collector, desired, _ := flowCaptureFixture()
	adapter := EC2FlowCapture{Collector: collector}
	first, err := adapter.Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := adapter.Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil || !reflect.DeepEqual(first, replayed) || len(collector.acks) != 0 {
		t.Fatalf("uncommitted read consumed native records: %+v, %v", replayed, err)
	}
	committed := true
	collector.beforeAck = func() {
		if !committed {
			t.Fatal("native records were acknowledged before consumer commit")
		}
	}
	// A new adapter can reclaim a checkpoint committed by the old controller.
	restarted := EC2FlowCapture{Collector: collector}
	if err := restarted.Acknowledge(t.Context(), first.Cursor); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(collector.acks, []uint64{42}) {
		t.Fatalf("wrong global journal checkpoint acknowledged: %v", collector.acks)
	}
}

func TestEC2FlowCaptureInitialAndMaximumDecimalCursor(t *testing.T) {
	collector, desired, _ := flowCaptureFixture()
	collector.batch.Health.Acked = 0
	if _, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, ""); err != nil || collector.after != 0 {
		t.Fatalf("initial cursor was not native zero: %v", err)
	}
	collector.batch.Records = nil
	collector.batch.Cursor, collector.batch.Health.Head, collector.batch.Health.Acked = math.MaxUint64, math.MaxUint64, math.MaxUint64
	const maximum = "18446744073709551615"
	batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, maximum)
	if err != nil || collector.after != math.MaxUint64 || batch.Cursor != maximum {
		t.Fatalf("native cursor was truncated: %+v, %v", batch, err)
	}
}

func TestEC2FlowCaptureIgnoresValidUnsubscribedInterfaces(t *testing.T) {
	for _, sameAddress := range []bool{false, true} {
		collector, desired, native := flowCaptureFixture()
		unsubscribed := native
		unsubscribed.Binding.Identity.InterfaceID = "eni-unsubscribed"
		unsubscribed.Token = "unsubscribed-token"
		if !sameAddress {
			unsubscribed.Binding.Address = netip.MustParseAddr("10.0.0.99")
			unsubscribed.SourceAddress = unsubscribed.Binding.Address
		}
		collector.batch.Records = []network.FlowRecord{{Cursor: 42, Observation: &unsubscribed}}
		batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
		if err != nil || batch.Cursor != "42" || batch.CoverageError != "" || len(batch.Observations) != 0 {
			t.Fatalf("unsubscribed traffic became selected ENI loss (same address=%t): %+v, %v", sameAddress, batch, err)
		}
	}
}

func TestEC2FlowCapturePreservesQueuedPacketsAcrossPolicyReplacement(t *testing.T) {
	collector, desired, native := flowCaptureFixture()
	collector.batch.Coverage[0].Binding.Generation = "replacement-policy"
	collector.batch.Coverage[0].Generation = "replacement-policy"
	collector.batch.Coverage[0].Token = "replacement-token"
	batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil || batch.CoverageError != "" || len(batch.Observations) != 1 || batch.Observations[0].Lost || batch.Observations[0].Bytes != uint64(native.IPBytes) {
		t.Fatalf("current coverage discarded an authoritative queued packet: %+v, %v", batch, err)
	}
}

func TestEC2FlowCaptureHistoricalLossDoesNotInvalidateCurrentCoverage(t *testing.T) {
	collector, desired, native := flowCaptureFixture()
	collector.batch.Records = []network.FlowRecord{{Cursor: 42, Gap: &network.FlowGap{Start: native.ObservedAt.Add(-time.Second), End: native.ObservedAt, Reason: "historic-overrun"}}}
	batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil || batch.CoverageError != "" || len(batch.Observations) != 1 || !batch.Observations[0].Lost {
		t.Fatalf("historical loss was confused with current readiness: %+v, %v", batch, err)
	}
}

func TestEC2FlowCaptureReportsBoundedJournalBacklog(t *testing.T) {
	collector, desired, _ := flowCaptureFixture()
	collector.batch.Health.Head = 45
	batch, err := (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil || batch.Cursor != "42" || !batch.More || batch.CoverageError != "" || len(collector.acks) != 0 {
		t.Fatalf("bounded native backlog was hidden or consumed: %+v, %v", batch, err)
	}
	collector.batch.Health.Head = 42
	batch, err = (EC2FlowCapture{Collector: collector}).Read(t.Context(), []ec2.FlowLogInterface{desired}, "41")
	if err != nil || batch.More {
		t.Fatalf("fully drained native batch retained backlog: %+v, %v", batch, err)
	}
}

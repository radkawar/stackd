package ec2

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	native "stackd/compute/ec2"
	"stackd/compute/network"
	api "stackd/internal/awsapi/ec2"
)

type retirementMetrics struct{ performanceCapture }

func (*retirementMetrics) RecordInstanceHealthMetrics(context.Context, ResourceKey, *InstanceHealthRecord) error {
	return nil
}

type retirementInstance struct {
	native.Instance
	status   native.Status
	usage    time.Duration
	network  native.NetworkUsage
	closeErr error
}

func (h *retirementInstance) Inspect(context.Context) (native.Status, error)  { return h.status, nil }
func (h *retirementInstance) CPUUsage(context.Context) (time.Duration, error) { return h.usage, nil }
func (h *retirementInstance) NetworkUsage(context.Context) (native.NetworkUsage, error) {
	return h.network, nil
}
func (h *retirementInstance) Stop(context.Context) error {
	h.status.State = native.Exited
	return nil
}
func (h *retirementInstance) Start(context.Context) error {
	h.status.State = native.Running
	return nil
}
func (h *retirementInstance) SetCPUQuota(context.Context, native.CPUQuota) error      { return nil }
func (h *retirementInstance) SetNetwork(context.Context, network.Specification) error { return nil }
func (h *retirementInstance) Console(context.Context, int64, int) ([]byte, error)     { return nil, nil }
func (h *retirementInstance) Close() error                                            { return h.closeErr }
func (h *retirementInstance) CheckHealth(context.Context, bool) (native.Health, error) {
	return native.Health{Network: native.NetworkHealth{Attached: true, Reachable: true}, DisksReachable: true}, nil
}

type retirementVolumes struct{ InstanceVolumes }

func (retirementVolumes) StopInstanceVolumes(context.Context, api.Instance) error { return nil }
func (retirementVolumes) PrepareInstanceVolumes(context.Context, api.Instance) ([]native.Disk, error) {
	return nil, nil
}

type retirementExecutor struct {
	native.Executor
	replacement *retirementInstance
}

func (e retirementExecutor) Prepare(context.Context, native.Specification) (native.Instance, error) {
	return e.replacement, nil
}

type retirementImages struct{ InstanceImageSnapshots }

func (retirementImages) CaptureImageSnapshots(context.Context, []string) error {
	return errors.New("snapshot capture failed")
}
func (retirementImages) FailImageSnapshots(context.Context, []string, string) error { return nil }

func newRetirementInstance(t *testing.T) (metadataTestInstance, *retirementInstance, *retirementMetrics) {
	t.Helper()
	local := newMetadataTestInstance(t)
	local.record.Data.InstanceType = new(api.InstanceType("t3.nano"))
	local.record.Data.CpuOptions = &api.CpuOptions{CoreCount: new(api.Integer(1)), ThreadsPerCore: new(api.Integer(2))}
	local.record.RuntimePrepared = true
	local.record.Performance.NativePID = 10
	local.record.Performance.NativeStartTimeTicks = 20
	local.record.Performance.InterfaceIndex = 30
	local.record.Performance.CPUUsage = time.Second
	local.record.Performance.BytesIn, local.record.Performance.BytesOut = 100, 200
	local.record.Performance.ObservedAt = time.Now().Add(-time.Minute)
	local.record.Performance.SampleAt = local.clock.Now().Add(-time.Minute)
	local.record.Performance.WindowAt = local.clock.Now().Truncate(5 * time.Minute)
	vpc := VPCRecord{Key: key(local.ctx, "vpc-0123456789abcdef0"), Data: api.Vpc{VpcId: new(api.String("vpc-0123456789abcdef0")), CidrBlock: new(api.String("10.0.0.0/16"))}}
	subnet := SubnetRecord{Key: key(local.ctx, "subnet-0123456789abcdef0"), Data: api.Subnet{SubnetId: new(api.String("subnet-0123456789abcdef0")), VpcId: vpc.Data.VpcId, CidrBlock: new(api.String("10.0.1.0/24"))}}
	eni := NetworkInterfaceRecord{Key: key(local.ctx, "eni-0123456789abcdef0"), Data: api.NetworkInterface{
		NetworkInterfaceId: new(api.String("eni-0123456789abcdef0")), OwnerId: new(api.String(local.record.Key.Scope.AccountID)),
		MacAddress: new(api.String("02:00:00:00:00:01")), PrivateIpAddress: new(api.String("10.0.1.10")), VpcId: vpc.Data.VpcId, SubnetId: subnet.Data.SubnetId,
		Attachment: &api.NetworkInterfaceAttachment{InstanceId: local.record.Data.InstanceId, DeviceIndex: new(api.Integer(0))},
	}}
	local.record.Data.NetworkInterfaces = api.InstanceNetworkInterfaceList{{NetworkInterfaceId: eni.Data.NetworkInterfaceId}}
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
		if err := tx.PutVPC(vpc); err != nil {
			return err
		}
		if err := tx.PutSubnet(subnet); err != nil {
			return err
		}
		if err := tx.PutNetworkInterface(eni); err != nil {
			return err
		}
		return tx.PutInstance(local.record)
	}); err != nil {
		t.Fatal(err)
	}
	handle := &retirementInstance{status: native.Status{PID: 10, StartTimeTicks: 20, State: native.Running}, usage: 31 * time.Second, network: native.NetworkUsage{InterfaceIndex: 30, BytesIn: 117, BytesOut: 229}}
	metrics := &retirementMetrics{}
	local.service.instanceMetrics = metrics
	local.service.instanceVolumes = retirementVolumes{}
	local.service.instanceHandles = map[ResourceKey]native.Instance{local.record.Key: handle}
	return local, handle, metrics
}

func retirementRecord(t *testing.T, local metadataTestInstance) InstanceRecord {
	t.Helper()
	var record InstanceRecord
	if err := local.service.repository.View(local.ctx, func(tx Reader) error {
		var err error
		record, err = tx.Instance(local.record.Key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return record
}

func assertRetirementCheckpoint(t *testing.T, local metadataTestInstance, record InstanceRecord, metrics *retirementMetrics) float64 {
	t.Helper()
	if len(metrics.samples) != 0 {
		t.Fatalf("partial retirement window published before retirement: %+v", metrics.samples)
	}
	p := record.Performance
	elapsed := p.ObservedAt.Sub(local.record.Performance.ObservedAt)
	wantCPU := 100 * float64(30*time.Second) / (float64(elapsed) * 2)
	if p.CPUUsage != 31*time.Second || p.BytesIn != 117 || p.BytesOut != 229 || p.CPUCount != 1 || math.Abs(p.CPUSum-wantCPU) > 1e-9 || p.NetworkIn != 17 || p.NetworkOut != 29 || !p.NetworkObserved {
		t.Fatalf("checkpoint did not retain measured cursor/window: %+v, want CPU %v, network 17/29", p, wantCPU)
	}
	return wantCPU
}

func assertRetirementPublication(t *testing.T, metrics *retirementMetrics, wantCPU float64) {
	t.Helper()
	if len(metrics.samples) != 1 {
		t.Fatalf("retirement publication count = %d, want 1", len(metrics.samples))
	}
	sample := metrics.samples[0]
	if sample.CPUCount != 1 || math.Abs(sample.CPUSum-wantCPU) > 1e-9 || sample.NetworkIn != 17 || sample.NetworkOut != 29 || !sample.NetworkObserved {
		t.Fatalf("final measured contribution = %+v, want CPU %v, network 17/29", sample, wantCPU)
	}
}

func TestInstancePerformanceCheckpointSurvivesCleanupFailure(t *testing.T) {
	local, handle, metrics := newRetirementInstance(t)
	local.record.Intent = InstanceIntentStop
	local.record.Force = true
	local.record.Data.State = &api.InstanceState{Name: new(api.InstanceStateName("stopping")), Code: new(api.Integer(64))}
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error { return tx.PutInstance(local.record) }); err != nil {
		t.Fatal(err)
	}
	handle.closeErr = errors.New("controller cleanup failed after VMM exit")
	if err := local.service.advanceInstance(local.ctx, local.record); !errors.Is(err, handle.closeErr) {
		t.Fatalf("retirement error = %v", err)
	}
	record := retirementRecord(t, local)
	wantCPU := assertRetirementCheckpoint(t, local, record, metrics)
	if handle.status.State != native.Exited || instanceState(record) != "stopping" {
		t.Fatal("failure did not occur between native exit and stopped-state commit")
	}
	handle.closeErr = nil
	if err := local.service.advanceInstance(local.ctx, record); err != nil {
		t.Fatal(err)
	}
	record = retirementRecord(t, local)
	if instanceState(record) != "stopped" || record.Performance.NativePID != 0 || len(metrics.samples) != 1 {
		t.Fatalf("cleanup retry replayed or lost terminal checkpoint: state=%s performance=%+v samples=%+v", instanceState(record), record.Performance, metrics.samples)
	}
	assertRetirementPublication(t, metrics, wantCPU)
}

func TestImagePerformanceCheckpointSurvivesCaptureFailureAndReplacement(t *testing.T) {
	local, handle, metrics := newRetirementInstance(t)
	handle.status.State = native.Shutdown
	local.service.instanceImages = retirementImages{}
	image := ImageRecord{Key: key(local.ctx, "ami-0123456789abcdef0"), Create: &ImageCreation{InstanceID: local.record.Key.ID, InstanceGeneration: local.record.Generation, Phase: "shutdown-wait"}, Data: api.Image{State: new(api.ImageState("pending"))}}
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error { return tx.PutImage(image) }); err != nil {
		t.Fatal(err)
	}
	if err := local.service.advanceImage(local.ctx, image); err != nil {
		t.Fatal(err)
	}
	record := retirementRecord(t, local)
	wantCPU := assertRetirementCheckpoint(t, local, record, metrics)
	if err := local.service.repository.View(local.ctx, func(tx Reader) error {
		var err error
		image, err = tx.Image(image.Key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if str(image.Data.State) != "failed" || image.Create == nil || image.Create.Phase != "boot" || !record.NextActionAt.IsZero() {
		t.Fatalf("capture failure lost image reboot ownership: image=%+v instance=%+v", image, record)
	}
	if err := local.clock.Advance(10 * time.Minute); err != nil {
		t.Fatal(err)
	}
	// The replacement has its own counters. Neither ten minutes of backup time
	// nor the old VMM's final usage belongs in its first performance observation.
	replacement := &retirementInstance{status: native.Status{PID: 11, StartTimeTicks: 21, State: native.Paused}, usage: time.Millisecond, network: native.NetworkUsage{InterfaceIndex: 31, BytesIn: 3, BytesOut: 5}}
	local.service.instanceRuntime = retirementExecutor{replacement: replacement}
	if err := local.service.advanceImage(local.ctx, image); err != nil {
		t.Fatal(err)
	}
	record = retirementRecord(t, local)
	if err := local.service.advanceInstance(local.ctx, record); err != nil {
		t.Fatal(err)
	}
	record = retirementRecord(t, local)
	if record.Intent != InstanceIntentObserve || instanceState(record) != "running" || record.Performance.NativePID != 11 || record.Performance.CPUUsage != time.Millisecond || record.Performance.BytesIn != 3 || record.Performance.BytesOut != 5 {
		t.Fatalf("image replacement did not establish a new baseline: %+v", record)
	}
	if len(metrics.samples) != 1 || record.Performance.CPUCount != 0 || record.Performance.NetworkObserved {
		t.Fatalf("image backup downtime published synthetic usage: performance=%+v samples=%+v", record.Performance, metrics.samples)
	}
	assertRetirementPublication(t, metrics, wantCPU)
}

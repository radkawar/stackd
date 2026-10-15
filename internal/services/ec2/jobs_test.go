package ec2

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	native "stackd/compute/ec2"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/scheduler"
)

// This executor blocks the native call boundary. Actual guest boot and HTTP
// evidence belongs to the QEMU Terraform fixture, not this scheduling test.
type blockedComputeExecutor struct {
	native.Executor
	entered chan struct{}
	calls   atomic.Int32
}

func (e *blockedComputeExecutor) Reopen(context.Context, native.Specification) (native.Instance, error) {
	return nil, native.ErrNotFound
}

func (e *blockedComputeExecutor) Prepare(ctx context.Context, _ native.Specification) (native.Instance, error) {
	e.calls.Add(1)
	select {
	case e.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

type computeTestVolumes struct{ retirementVolumes }

func (computeTestVolumes) ResolveInstanceVolumes(context.Context, api.Instance) ([]native.Disk, error) {
	return nil, nil
}

type computeTestDeadline struct {
	due time.Time
	ran atomic.Bool
}

func (d *computeTestDeadline) Next(context.Context) (scheduler.Job, bool, error) {
	return scheduler.Job{Key: "unrelated-metadata", Due: d.due}, !d.ran.Load(), nil
}

func (d *computeTestDeadline) Run(context.Context, scheduler.Job) error {
	d.ran.Store(true)
	return nil
}

func TestNativeComputeDoesNotHoldSharedDrain(t *testing.T) {
	local, _, _ := newRetirementInstance(t)
	local.record.Intent = InstanceIntentStart
	local.record.RuntimePrepared = false
	local.record.NextActionAt = local.clock.Now()
	local.record.ReservationID = "r-0123456789abcdef0"
	local.record.Data.State = &api.InstanceState{Name: new(api.InstanceStateName("pending")), Code: new(api.Integer(0))}
	if err := local.service.repository.Update(local.ctx, func(tx Transaction) error {
		if err := tx.PutReservation(ReservationRecord{
			Key: key(local.ctx, local.record.ReservationID), InstanceIDs: []string{local.record.Key.ID},
		}); err != nil {
			return err
		}
		return tx.PutInstance(local.record)
	}); err != nil {
		t.Fatal(err)
	}
	executor := &blockedComputeExecutor{entered: make(chan struct{}, 1)}
	local.service.instanceRuntime = executor
	local.service.instanceVolumes = computeTestVolumes{}
	local.service.instanceHandles = nil
	deadline := &computeTestDeadline{due: local.clock.Now().Add(time.Second)}
	other := scheduler.New(local.clock, deadline)
	joined, err := scheduler.Join(nil, local.service.JobDriver(), other)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(local.ctx, 5*time.Second)
	defer cancel()
	drained := make(chan error, 1)
	go func() { _, err := joined.RunDue(ctx, 100); drained <- err }()
	select {
	case <-executor.entered:
	case <-ctx.Done():
		t.Fatal("native preparation was not dispatched")
	}
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("native preparation held the shared drain")
	}
	for range 3 {
		if _, err := joined.RunDue(ctx, 100); err != nil {
			t.Fatal(err)
		}
	}
	if executor.calls.Load() != 1 {
		t.Fatal("native work was dispatched more than once")
	}

	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("DescribeInstances")
	out, rejected := local.service.ExecuteCommand(ctx, awsapi.DecodedRequest{
		Operation: op, Protocol: model.Protocol,
		Input: &api.DescribeInstancesRequest{InstanceIds: api.InstanceIdStringList{api.InstanceId(local.record.Key.ID)}},
	})
	if rejected != nil {
		t.Fatal(rejected)
	}
	instances := out.(*api.DescribeInstancesResult).Reservations[0].Instances
	if len(instances) != 1 || str(instances[0].State.Name) != "pending" {
		t.Fatal("blocked native work was represented as a running guest")
	}
	if err := local.clock.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := joined.RunDue(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if !deadline.ran.Load() {
		t.Fatal("unrelated metadata deadline did not publish")
	}

	closed := make(chan error, 1)
	go func() { closed <- local.service.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not cancel and join native work")
	}
	retained := retirementRecord(t, local)
	if retained.Intent != InstanceIntentStart || instanceState(retained) != "pending" || retained.NextActionAt.IsZero() {
		t.Fatal("cancellation discarded the durable launch intent")
	}

	recoveredExecutor := &blockedComputeExecutor{entered: make(chan struct{}, 1)}
	recovered := New(Config{Repository: local.service.repository, Clock: local.clock,
		InstanceRuntime: recoveredExecutor, InstanceVolumes: computeTestVolumes{}})
	t.Cleanup(func() {
		if err := recovered.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := recovered.JobDriver().RunDue(ctx, 100); err != nil {
		t.Fatal(err)
	}
	select {
	case <-recoveredExecutor.entered:
	case <-ctx.Done():
		t.Fatal("reopened service did not recover retained native work")
	}
}

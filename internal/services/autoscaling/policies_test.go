package autoscaling

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudwatch"
)

type policyTestIdentity struct{ denied bool }

func (i *policyTestIdentity) Context(ctx context.Context, _ GroupRecord) (context.Context, error) {
	if i.denied {
		return nil, failure("AccessDenied", "execution role denied")
	}
	return ctx, nil
}

func ownedControlService(t *testing.T) (*Service, context.Context, GroupRecord, *clock.Manual, *policyTestIdentity) {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 27, 4, 49, 0, 0, time.UTC))
	repository := NewMemoryRepository(nil)
	identity := &policyTestIdentity{}
	scope := Scope{Partition: "aws", AccountID: "000000000000", Region: "us-east-1"}
	key := GroupKey{Scope: scope, Name: "stackd-asg-8ca6c1c99b8e"}
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: scope.AccountID})
	g := GroupRecord{Key: key, ID: "control", Data: api.AutoScalingGroup{AutoScalingGroupName: new(api.XmlStringMaxLen255(key.Name)), AutoScalingGroupARN: new(api.ResourceName(key.ARN("control"))), MinSize: new(api.AutoScalingGroupMinSize(0)), MaxSize: new(api.AutoScalingGroupMaxSize(20)), DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(2)), DefaultCooldown: new(api.Cooldown(7)), SuspendedProcesses: api.SuspendedProcesses{{ProcessName: new(api.XmlStringMaxLen255("Launch"))}}}}
	s := New(Config{Repository: repository, Clock: source, Identity: identity})
	t.Cleanup(func() { s.jobs.Close() })
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutGroup(g) }); err != nil {
		t.Fatal(err)
	}
	return s, ctx, g, source, identity
}

type nativeControlCall struct {
	Label, Code   string
	Input, Output json.RawMessage
}

func nativeControl(t *testing.T, label string) nativeControlCall {
	t.Helper()
	call, ok := nativeControlCalls(t, "controls.json")[label]
	if !ok {
		t.Fatalf("native control %q missing", label)
	}
	return call
}

func TestNativePolicyChangesDesiredWhileLaunchSuspended(t *testing.T) {
	s, ctx, g, _, identity := ownedControlService(t)
	var put api.PutScalingPolicyInput
	call := nativeControl(t, "put-simple-policy")
	if err := json.Unmarshal(call.Input, &put); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.putScalingPolicy(ctx, tx, &put); return err }); err != nil {
		t.Fatal(err)
	}
	var execute api.ExecutePolicyInput
	if err := json.Unmarshal(nativeControl(t, "execute-policy-suspended").Input, &execute); err != nil {
		t.Fatal(err)
	}
	identity.denied = true
	if err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.executePolicy(ctx, tx, &execute); return err }); err == nil {
		t.Fatal("revoked execution role changed desired capacity")
	}
	identity.denied = false
	if err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.executePolicy(ctx, tx, &execute); return err }); err != nil {
		t.Fatal(err)
	}
	var native api.DescribeAutoScalingGroupsOutput
	if err := json.Unmarshal(nativeControl(t, "describe-policy-capacity").Output, &native); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		actual, err := r.Group(g.Key)
		if err != nil {
			return err
		}
		if *actual.Data.DesiredCapacity != *native.AutoScalingGroups[0].DesiredCapacity {
			t.Fatalf("desired=%d native=%d", *actual.Data.DesiredCapacity, *native.AutoScalingGroups[0].DesiredCapacity)
		}
		instances, err := r.Instances(g.Key)
		if len(instances) != 0 {
			t.Fatal("suspended Launch produced membership")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyPercentageAndStepBoundaries(t *testing.T) {
	for _, c := range []struct {
		base, adjustment, magnitude int32
		want                        float64
	}{{10, 25, 1, 12}, {10, -25, 1, 8}, {1, 1, 1, 2}, {1, -1, 1, 0}, {4, 25, 2, 6}, {4, -25, 2, 2}, {math.MaxInt32, math.MaxInt32, 1, float64(math.MaxInt32) + math.Trunc(float64(math.MaxInt32)*float64(math.MaxInt32)/100)}} {
		if got := adjustedCapacity(c.base, c.adjustment, "PercentChangeInCapacity", c.magnitude); got != c.want {
			t.Fatalf("percent (%d,%d,%d)=%g want %g", c.base, c.adjustment, c.magnitude, got, c.want)
		}
	}
	p := api.ScalingPolicy{AdjustmentType: new(api.XmlStringMaxLen255("ChangeInCapacity")), StepAdjustments: api.StepAdjustments{{MetricIntervalUpperBound: new(api.MetricScale(-10)), ScalingAdjustment: new(api.PolicyIncrement(-3))}, {MetricIntervalLowerBound: new(api.MetricScale(-10)), MetricIntervalUpperBound: new(api.MetricScale(0)), ScalingAdjustment: new(api.PolicyIncrement(-1))}, {MetricIntervalLowerBound: new(api.MetricScale(0)), MetricIntervalUpperBound: new(api.MetricScale(10)), ScalingAdjustment: new(api.PolicyIncrement(1))}, {MetricIntervalLowerBound: new(api.MetricScale(10)), ScalingAdjustment: new(api.PolicyIncrement(3))}}}
	if err := validateSteps(p.StepAdjustments, "ChangeInCapacity"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ metric, want float64 }{{40, 7}, {40.1, 9}, {50, 11}, {59.9, 11}, {60, 13}} {
		got, matched := stepCapacity(p, 10, c.metric, 50)
		if !matched || got != c.want {
			t.Fatalf("metric %g -> %g/%v want %g", c.metric, got, matched, c.want)
		}
	}
	p.StepAdjustments[1].MetricIntervalLowerBound = new(api.MetricScale(-9))
	if err := validateSteps(p.StepAdjustments, "ChangeInCapacity"); err == nil {
		t.Fatal("accepted interval gap")
	}
}

func TestStepWarmupCreditsPendingCapacity(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		g.Data.DesiredCapacity = new(api.AutoScalingGroupDesiredCapacity(10))
		if err := tx.PutGroup(g); err != nil {
			return err
		}
		for n := range 10 {
			instance := InstanceRecord{Group: g.Key, GroupID: g.ID, InServiceAt: source.Now().Add(-time.Hour), Data: api.Instance{InstanceId: new(api.XmlStringMaxLen19("i-" + string(rune('a'+n)))), LifecycleState: new(api.LifecycleState("InService"))}}
			if err := tx.PutInstance(instance); err != nil {
				return err
			}
		}
		_, err := s.putScalingPolicy(ctx, tx, &api.PutScalingPolicyInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, PolicyName: new(api.XmlStringMaxLen255("step")), PolicyType: new(api.XmlStringMaxLen64("StepScaling")), AdjustmentType: new(api.XmlStringMaxLen255("PercentChangeInCapacity")), EstimatedInstanceWarmup: new(api.EstimatedInstanceWarmup(120)), StepAdjustments: api.StepAdjustments{{MetricIntervalLowerBound: new(api.MetricScale(0)), MetricIntervalUpperBound: new(api.MetricScale(10)), ScalingAdjustment: new(api.PolicyIncrement(10))}, {MetricIntervalLowerBound: new(api.MetricScale(10)), ScalingAdjustment: new(api.PolicyIncrement(30))}}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	execute := func(metric float64, want int32, version uint64) {
		t.Helper()
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.executePolicy(ctx, tx, &api.ExecutePolicyInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, PolicyName: new(api.ResourceName("step")), MetricValue: new(api.MetricScale(metric)), BreachThreshold: new(api.MetricScale(60))})
			if err != nil {
				return err
			}
			actual, err := tx.Group(g.Key)
			if err == nil && (int32(*actual.Data.DesiredCapacity) != want || actual.PendingInstanceWarmup == nil || *actual.PendingInstanceWarmup != 120) {
				t.Fatalf("desired/warmup=%d/%v want %d/120", *actual.Data.DesiredCapacity, actual.PendingInstanceWarmup, want)
			}
			if err == nil && actual.ScaleUpVersion != version {
				t.Fatalf("policy transition to desired=%d produced counter=%d want %d", want, actual.ScaleUpVersion, version)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	execute(60, 11, 1)
	execute(62, 11, 1)
	execute(70, 13, 2)
}

func TestPolicyContinuationIsScopedAndStableAcrossDeletion(t *testing.T) {
	scope := Scope{Partition: "aws", AccountID: "123", Region: "us-east-1"}
	key := func(s string) string { return s }
	rows, next, err := pageRows(scope, "DescribePolicies", []string{"g"}, new(api.MaxRecords(1)), nil, []string{"b", "a", "c"}, key)
	if err != nil || len(rows) != 1 || rows[0] != "a" || next == nil {
		t.Fatalf("first page=%v,%v,%v", rows, next, err)
	}
	rows, _, err = pageRows(scope, "DescribePolicies", []string{"g"}, new(api.MaxRecords(2)), next, []string{"b", "c"}, key)
	if err != nil || len(rows) != 2 || rows[0] != "b" || rows[1] != "c" {
		t.Fatalf("continuation after deletion=%v,%v", rows, err)
	}
	scope.AccountID = "other"
	_, _, err = pageRows(scope, "DescribePolicies", []string{"g"}, nil, next, []string{"b"}, key)
	if err == nil || !errors.As(err, new(*awswire.Error)) {
		t.Fatalf("cross-account cursor error=%v", err)
	}
}

func TestSimpleCooldownStartsAtActualActivityCompletion(t *testing.T) {
	s, ctx, g, source, _ := ownedControlService(t)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.putScalingPolicy(ctx, tx, &api.PutScalingPolicyInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, PolicyName: new(api.XmlStringMaxLen255("simple")), AdjustmentType: new(api.XmlStringMaxLen255("ChangeInCapacity")), ScalingAdjustment: new(api.PolicyIncrement(1)), Cooldown: new(api.Cooldown(3))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	execute := func(want int32) {
		t.Helper()
		if err := s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.executePolicy(ctx, tx, &api.ExecutePolicyInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, PolicyName: new(api.ResourceName("simple")), HonorCooldown: new(api.HonorCooldown(true))})
			if err != nil {
				return err
			}
			actual, err := tx.Group(g.Key)
			if err == nil && int32(*actual.Data.DesiredCapacity) != want {
				t.Fatalf("cooldown desired=%d want %d", *actual.Data.DesiredCapacity, want)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	execute(3)
	activity := ActivityRecord{Key: ActivityKey{Scope: g.Key.Scope, ID: "launch"}, Group: g.Key, GroupID: g.ID, Kind: "launch", Data: api.Activity{ActivityId: new(api.XmlString("launch")), StartTime: new(source.Now()), StatusCode: new(api.ScalingActivityStatusCode("InProgress"))}}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutActivity(activity) }); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	execute(3)
	activity.Data.EndTime = new(source.Now())
	activity.Data.StatusCode = new(api.ScalingActivityStatusCode("Successful"))
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutActivity(activity) }); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	execute(3)
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	execute(4)
}

func TestCloudWatchPolicyDeliveryUsesScopedAuthority(t *testing.T) {
	s, ctx, g, _, _ := ownedControlService(t)
	s.jobs.Close() // This test observes admission; EC2 reconciliation is separate.
	var policyARN string
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		out, err := s.putScalingPolicy(ctx, tx, &api.PutScalingPolicyInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, PolicyName: new(api.XmlStringMaxLen255("alarm")), AdjustmentType: new(api.XmlStringMaxLen255("ExactCapacity")), ScalingAdjustment: new(api.PolicyIncrement(1))})
		if err == nil {
			policyARN = value(out.PolicyARN)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rejected := s.ApplyAlarm(ctx, policyARN, cloudwatch.ScalingAlarmSignal{}); rejected == nil || rejected.StatusCode != 403 {
		t.Fatalf("unsigned alarm delivery=%v", rejected)
	}
	forged := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "cloudwatch.amazonaws.com", SourceARN: "arn:aws:cloudwatch:us-east-1:999999999999:alarm:foreign"})
	if rejected := s.ApplyAlarm(forged, policyARN, cloudwatch.ScalingAlarmSignal{}); rejected == nil || rejected.StatusCode != 403 {
		t.Fatalf("cross-account alarm delivery=%v", rejected)
	}
	delivery := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "cloudwatch.amazonaws.com", SourceARN: "arn:aws:cloudwatch:us-east-1:000000000000:alarm:owned"})
	if rejected := s.ApplyAlarm(delivery, policyARN, cloudwatch.ScalingAlarmSignal{}); rejected != nil {
		t.Fatal(rejected)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		actual, err := r.Group(g.Key)
		if err == nil && *actual.Data.DesiredCapacity != 1 {
			t.Fatalf("authenticated alarm desired=%d", *actual.Data.DesiredCapacity)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTrackingCapacityAvoidsOverflowBeforeGroupBounds(t *testing.T) {
	if got := trackingCapacity(2, 1e308, 1e308); got != 2 {
		t.Fatalf("equal huge metric/target capacity=%g", got)
	}
	if got := trackingCapacity(2, 1e308, 1e-308); got != math.MaxInt32 {
		t.Fatalf("saturating capacity=%g", got)
	}
	if got := trackingCapacity(10, 21, 50); got != 5 {
		t.Fatalf("conservative scale-in rounding=%g", got)
	}
}

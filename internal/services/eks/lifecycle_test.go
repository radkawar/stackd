package eks

import (
	"context"
	"net/http"
	"testing"
	"time"

	"stackd/clock"
	native "stackd/compute/eks"
	"stackd/internal/awsapi"
	cwapi "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/internal/services/cloudwatch"
)

// This fault-injection runtime never fabricates readiness: creation remains
// blocked until owner cancellation, just like an unavailable native API.
type blockedClusterRuntime struct {
	native.Runtime
	entered, exited chan struct{}
}

func (r *blockedClusterRuntime) Ensure(ctx context.Context, _ native.Specification, _ http.Handler) (native.Endpoint, error) {
	close(r.entered)
	<-ctx.Done()
	close(r.exited)
	return native.Endpoint{}, ctx.Err()
}

func TestBlockedNativeEffectDoesNotStarveAlarmDeadline(t *testing.T) {
	epoch := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	source := clock.NewManual(epoch)
	repository := NewMemoryRepository(nil)
	key := Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "native-blocked"}
	if err := repository.Update(t.Context(), func(tx Transaction) error {
		return tx.PutCluster(Cluster{Key: key, ID: "native-incarnation", Status: "CREATING", Operation: "create", Generation: 1, Due: epoch})
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &blockedClusterRuntime{entered: make(chan struct{}), exited: make(chan struct{})}
	eks := New(Config{Repository: repository, Clock: source, Runtime: runtime})
	alarms := cloudwatch.New(cloudwatch.Config{Clock: source})
	jobs, err := scheduler.Join(nil, eks.JobDriver(), alarms.JobDriver())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eks.Close(); _ = alarms.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: key.AccountID})
	input := &cwapi.PutMetricAlarmInput{AlarmName: new(cwapi.AlarmName("native-isolation")), Namespace: new(cwapi.Namespace("EKSRegression")), MetricName: new(cwapi.MetricName("NativeEffectBlocked")), Statistic: new(cwapi.StatisticMaximum), Period: new(cwapi.Period(10)), EvaluationPeriods: new(cwapi.EvaluationPeriods(1)), Threshold: new(cwapi.Threshold(1)), ComparisonOperator: new(cwapi.ComparisonOperatorGreaterThanThreshold), TreatMissingData: new(cwapi.TreatMissingData("breaching"))}
	if _, rejected := alarms.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: awscatalog.Operation{Name: "PutMetricAlarm"}, Input: input}); rejected != nil {
		t.Fatal(rejected)
	}
	select {
	case <-runtime.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native effect did not begin")
	}
	if err := source.Advance(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	drain, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := jobs.RunDue(drain, 100); err != nil {
		t.Fatalf("blocked native effect starved shared service-time drain: %v", err)
	}
	output, rejected := alarms.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: awscatalog.Operation{Name: "DescribeAlarms"}, Input: &cwapi.DescribeAlarmsInput{AlarmNames: cwapi.AlarmNames{"native-isolation"}}})
	if rejected != nil {
		t.Fatal(rejected)
	}
	state := output.(*cwapi.DescribeAlarmsOutput).MetricAlarms[0].StateValue
	if state == nil || *state != "ALARM" {
		t.Fatalf("real CloudWatch due transition was starved: %v", state)
	}
	if err := eks.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.exited:
	default:
		t.Fatal("Close did not join cancelled native owner")
	}
	if err := repository.View(t.Context(), func(reader Reader) error {
		retained, err := reader.Cluster(key)
		if err != nil {
			return err
		}
		if retained.Status != "CREATING" || retained.Operation != "create" || retained.Generation != 1 || !retained.Due.Equal(epoch) {
			t.Fatalf("cancelled effect changed retained retry intent: %+v", retained)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

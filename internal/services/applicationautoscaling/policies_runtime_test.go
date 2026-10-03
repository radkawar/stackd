package applicationautoscaling

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/applicationautoscaling"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
	"stackd/internal/services/cloudwatch"
	"stackd/storage/memory"
)

type runtimeFixture struct {
	Start    time.Time
	Policies []struct {
		Name    string
		Initial Capacity
		Policy  api.ScalingPolicy
		Steps   []struct {
			Name           string
			At             int
			Metric         *float64
			Below          bool
			Complete       bool
			Deployment     *bool
			Reopen         bool
			Reject         bool
			DeferExecution bool
			ActivityStatus string
			Desired        int32
			Running        int32
		}
	}
	Schedules []struct {
		Name     string
		Schedule string
		Steps    []struct {
			At       int
			Error    string
			Min, Max int32
			Desired  int32
			NextName string
			NextAt   int
		}
	}
}

func readRuntimeFixture(t *testing.T) runtimeFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture runtimeFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// The boundary retains desired and actual capacity separately in the same
// transaction domain as AAS. Only an explicit lifecycle completion changes actual
// capacity; accepting SetCapacity is not a completed scaling activity.
type runtimeResources struct {
	store  *memory.Store[Capacity]
	reject atomic.Bool
}

func (r *runtimeResources) Capacity(ctx context.Context, _ TargetKey) (out Capacity, err error) {
	err = r.store.View(ctx, func(state *Capacity, _ *memory.Transaction) error {
		out = *state
		return nil
	})
	return
}

func (r *runtimeResources) Admit(ctx context.Context, key TargetKey) (Capacity, error) {
	return r.Capacity(ctx, key)
}

func (r *runtimeResources) HighResolutionReady(context.Context, TargetKey, string) (bool, error) {
	return true, nil
}

func (r *runtimeResources) ALBTargetGroupAttached(context.Context, TargetKey, string) (bool, error) {
	return false, nil
}

func (r *runtimeResources) SetCapacity(ctx context.Context, _ TargetKey, desired int32) error {
	return r.store.Update(ctx, func(state *Capacity, _ *memory.Transaction) error {
		state.Desired = desired
		if r.reject.Load() {
			return invalid("Resource command rejected")
		}
		return nil
	})
}

type runtimeIdentity struct{}

func (runtimeIdentity) Context(ctx context.Context, _ TargetKey, _ string) (context.Context, error) {
	return ctx, nil
}

func runtimeTarget() (context.Context, TargetRecord) {
	scope := Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	key := TargetKey{Scope: scope, Namespace: "ecs", ResourceID: "service/cluster/service", Dimension: "ecs:service:DesiredCount"}
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
		PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.AccountID,
	})
	return ctx, TargetRecord{ID: "runtime", Key: key, Data: api.ScalableTarget{
		MinCapacity: new(api.ResourceCapacity(0)), MaxCapacity: new(api.ResourceCapacity(10)),
		ScalableTargetARN: new(api.XmlString("arn:aws:application-autoscaling:us-east-1:123456789012:scalable-target/runtime")),
	}}
}

func assertRuntimeCapacity(t *testing.T, resources *runtimeResources, desired, running int32) {
	t.Helper()
	capacity, err := resources.Capacity(context.Background(), TargetKey{})
	if err != nil {
		t.Fatal(err)
	}
	if capacity.Desired != desired || capacity.Running != running {
		t.Fatalf("capacity desired/running = %d/%d, want %d/%d", capacity.Desired, capacity.Running, desired, running)
	}
}

func TestPolicyRuntimeTransitions(t *testing.T) {
	fixture := readRuntimeFixture(t)
	for _, scenario := range fixture.Policies {
		t.Run(scenario.Name, func(t *testing.T) {
			ctx, target := runtimeTarget()
			domain := memory.NewDomain()
			repository := NewMemoryRepository(domain)
			resources := &runtimeResources{store: memory.New(domain, scenario.Initial, func(v Capacity) Capacity { return v })}
			source := clock.NewManual(fixture.Start)
			config := Config{Repository: repository, Resources: resources, Identity: runtimeIdentity{}, Clock: source}
			s := New(config)
			// The fixture owns draining, including the pause between accepting
			// intent and reopening. ApplyAlarm's Wake must not execute it first.
			s.jobs.Close()
			jobs := scheduler.New(source, targetJobs{s}, scheduleJobs{s}, activityJobs{s})
			t.Cleanup(func() { jobs.Close(); _ = s.Close() })
			policyARN := "arn:aws:autoscaling:us-east-1:123456789012:scalingPolicy:runtime:resource/ecs/service/cluster/service:policyName/runtime"
			policy := scenario.Policy
			policy.PolicyARN = new(api.ResourceIdMaxLen1600(policyARN))
			record := PolicyRecord{Key: PolicyKey{TargetKey: target.Key, Name: "runtime"}, Data: policy}
			if policy.TargetTrackingScalingPolicyConfiguration != nil {
				record.ManagedActionID = "runtime"
				record.Data.Alarms = api.Alarms{
					{AlarmName: new(api.ResourceId("runtime-high"))},
					{AlarmName: new(api.ResourceId("runtime-low"))},
				}
				policyARN += ":createdBy/" + record.ManagedActionID
			}
			if err := repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutTarget(target); err != nil {
					return err
				}
				return tx.PutPolicy(record)
			}); err != nil {
				t.Fatal(err)
			}
			alarmCtx := awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{
				Name: "cloudwatch.amazonaws.com", SourceARN: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:runtime",
			})
			assertRuntimeCapacity(t, resources, scenario.Initial.Desired, scenario.Initial.Running)
			var activityID string
			for _, step := range scenario.Steps {
				t.Run(step.Name, func(t *testing.T) {
					if err := source.Advance(fixture.Start.Add(time.Duration(step.At) * time.Second).Sub(source.Now())); err != nil {
						t.Fatal(err)
					}
					if step.Reopen {
						jobs.Close()
						if err := s.Close(); err != nil {
							t.Fatal(err)
						}
						s = New(config)
						s.jobs.Close()
						jobs = scheduler.New(source, targetJobs{s}, scheduleJobs{s}, activityJobs{s})
					}
					if step.Complete || step.Deployment != nil {
						if err := resources.store.Update(ctx, func(capacity *Capacity, tx *memory.Transaction) error {
							if step.Deployment != nil {
								capacity.DeploymentInProgress = *step.Deployment
							}
							if step.Complete {
								capacity.Running = capacity.Desired
								return s.ObserveCapacity(tx.Context(), target.Key, capacity.Desired, capacity.Running)
							}
							return nil
						}); err != nil {
							t.Fatal(err)
						}
					}
					if step.Metric != nil {
						reason, err := json.Marshal(map[string]any{"recentDatapoints": []float64{*step.Metric}, "threshold": 50, "queryDate": source.Now().Format(time.RFC3339Nano)})
						if err != nil {
							t.Fatal(err)
						}
						comparison := "GreaterThanThreshold"
						if step.Below {
							comparison = "LessThanThreshold"
						}
						resources.reject.Store(step.Reject)
						if rejected := s.ApplyAlarm(alarmCtx, policyARN, cloudwatch.ScalingAlarmSignal{Comparison: comparison, ReasonData: string(reason)}); rejected != nil {
							t.Fatalf("alarm admission: %v", rejected)
						}
					}
					if !step.DeferExecution {
						if _, err := jobs.RunDue(ctx, 100); err != nil && !step.Reject {
							t.Fatal(err)
						}
					}
					if step.ActivityStatus != "" {
						if err := repository.Update(ctx, func(tx Transaction) error {
							out, err := s.describeScalingActivities(tx.Context(), tx, &api.DescribeScalingActivitiesInput{
								ServiceNamespace: new(api.ServiceNamespace(target.Key.Namespace)),
								ResourceId:       new(api.ResourceIdMaxLen1600(target.Key.ResourceID)),
							})
							if err != nil {
								return err
							}
							if len(out.ScalingActivities) != 1 || value(out.ScalingActivities[0].StatusCode) != step.ActivityStatus {
								t.Fatalf("activity = %+v, want %s", out.ScalingActivities, step.ActivityStatus)
							}
							activity := out.ScalingActivities[0]
							pending := step.ActivityStatus == "Pending" || step.ActivityStatus == "InProgress"
							if (activity.EndTime == nil) != pending {
								t.Errorf("activity %s completion timestamp = %v", step.ActivityStatus, activity.EndTime)
							}
							if activityID != "" && value(activity.ActivityId) != activityID {
								t.Error("execution/recovery replaced the accepted activity")
							}
							activityID = value(activity.ActivityId)
							return nil
						}); err != nil {
							t.Fatal(err)
						}
					}
					assertRuntimeCapacity(t, resources, step.Desired, step.Running)
				})
			}
		})
	}
}

func TestScheduledRuntimeRejectedOccurrence(t *testing.T) {
	fixture := readRuntimeFixture(t)
	for _, scenario := range fixture.Schedules {
		t.Run(scenario.Name, func(t *testing.T) {
			ctx, target := runtimeTarget()
			target.Data.MaxCapacity = new(api.ResourceCapacity(5))
			domain := memory.NewDomain()
			repository := NewMemoryRepository(domain)
			resources := &runtimeResources{store: memory.New(domain, Capacity{Desired: 2, Running: 2}, func(v Capacity) Capacity { return v })}
			source := clock.NewManual(fixture.Start)
			s := New(Config{Repository: repository, Resources: resources, Identity: runtimeIdentity{}, Clock: source})
			t.Cleanup(func() { _ = s.Close() })
			if err := repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutTarget(target); err != nil {
					return err
				}
				for _, action := range []struct {
					name, schedule string
					bounds         api.ScalableTargetAction
				}{
					{"one-sided", scenario.Schedule, api.ScalableTargetAction{MinCapacity: new(api.ResourceCapacity(4))}},
					{"later-valid", "at(2026-09-17T00:02:00)", api.ScalableTargetAction{MinCapacity: new(api.ResourceCapacity(4)), MaxCapacity: new(api.ResourceCapacity(5))}},
				} {
					_, err := s.putScheduledAction(tx.Context(), tx, &api.PutScheduledActionInput{
						ServiceNamespace: new(api.ServiceNamespace("ecs")), ResourceId: new(api.ResourceIdMaxLen1600(target.Key.ResourceID)),
						ScalableDimension: new(api.ScalableDimension(target.Key.Dimension)), ScheduledActionName: new(api.ScheduledActionName(action.name)),
						Schedule: new(api.ResourceIdMaxLen1600(action.schedule)), ScalableTargetAction: &action.bounds,
						StartTime: new(fixture.Start.Add(time.Minute)),
					})
					if err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// A later valid target update makes the accepted one-sided action
			// incompatible only when that action eventually executes.
			if err := repository.Update(ctx, func(tx Transaction) error {
				target.Data.MaxCapacity = new(api.ResourceCapacity(3))
				return tx.PutTarget(target)
			}); err != nil {
				t.Fatal(err)
			}
			jobs := scheduleJobs{s}
			for _, step := range scenario.Steps {
				if err := source.Advance(fixture.Start.Add(time.Duration(step.At) * time.Second).Sub(source.Now())); err != nil {
					t.Fatal(err)
				}
				job, found, err := jobs.Next(ctx)
				if err != nil || !found || !job.Due.Equal(source.Now()) {
					t.Fatalf("at %ds: due job = %v, found %v, error %v", step.At, job, found, err)
				}
				rejected := wireError(jobs.Run(ctx, job))
				if step.Error == "" && rejected != nil || step.Error != "" && (rejected == nil || rejected.Code != step.Error) {
					t.Fatalf("at %ds: schedule error = %v, want code %q", step.At, rejected, step.Error)
				}
				if err := jobs.Run(ctx, job); err != nil {
					t.Fatalf("at %ds: consumed occurrence retried: %v", step.At, err)
				}
				if _, err := s.JobDriver().RunDue(ctx, 100); err != nil {
					t.Fatal(err)
				}
				assertRuntimeCapacity(t, resources, step.Desired, 2)
				if err := repository.View(ctx, func(reader Reader) error {
					retained, err := reader.Target(target.Key)
					if err == nil && (int32(*retained.Data.MinCapacity) != step.Min || int32(*retained.Data.MaxCapacity) != step.Max) {
						t.Errorf("at %ds: target bounds = %d/%d, want %d/%d", step.At, *retained.Data.MinCapacity, *retained.Data.MaxCapacity, step.Min, step.Max)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				next, found, err := jobs.Next(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if step.NextName == "" {
					if found {
						t.Fatalf("at %ds: unexpected remaining occurrence %v", step.At, next)
					}
				} else if !found || next.Key != scheduleJobKey(ScheduleKey{TargetKey: target.Key, Name: step.NextName}) || !next.Due.Equal(fixture.Start.Add(time.Duration(step.NextAt)*time.Second)) {
					t.Fatalf("at %ds: next occurrence = %v, found %v; want %s at %ds", step.At, next, found, step.NextName, step.NextAt)
				}
			}
		})
	}
}

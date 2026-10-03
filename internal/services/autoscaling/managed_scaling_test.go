package autoscaling

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/journal"
	"stackd/storage/memory"
)

func managedScalingService(t *testing.T) (*Service, context.Context, GroupRecord, journal.Storage) {
	t.Helper()
	s, ctx, group, _, _ := ownedControlService(t)
	// These tests drive admitted mutations and scheduler completion explicitly.
	s.JobDriver().Close()
	calls := nativeControlCalls(t, "lifecycle_native.json")
	group.Data = decodeLifecycleOutput[api.DescribeAutoScalingGroupsOutput](t, calls, "protected-scale-in-group").AutoScalingGroups[0]
	text(&group.Data.AutoScalingGroupName, group.Key.Name)
	text(&group.Data.AutoScalingGroupARN, group.Key.ARN(group.ID))
	group.Data.Instances = nil
	number(&group.Data.MinSize, 0)
	number(&group.Data.MaxSize, 8)
	number(&group.Data.DesiredCapacity, 4)
	group.ScaleUpVersion = 7
	domain := memory.NewDomain()
	s.repository = NewMemoryRepository(domain)
	events := journal.NewMemory(domain)
	s.recorder = apievents.New(events)
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutGroup(group) }); err != nil {
		t.Fatal(err)
	}
	return s, ctx, group, events
}

func managedScalingCommand(t *testing.T, s *Service, ctx context.Context, action string, input any) {
	t.Helper()
	model, _ := awscatalog.LookupService("autoscaling")
	operation, ok := model.Operation(action)
	if !ok {
		t.Fatalf("unknown action %s", action)
	}
	if _, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: input}); rejected != nil {
		t.Fatal(rejected)
	}
}

func managedScalingGroup(t *testing.T, s *Service, ctx context.Context, key GroupKey) GroupRecord {
	t.Helper()
	var group GroupRecord
	if err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		group, err = tx.Group(key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return group
}

func TestScaleUpVersionTracksAcceptedCapacityChanges(t *testing.T) {
	s, ctx, group, _ := managedScalingService(t)
	for _, step := range []struct {
		action  string
		input   any
		desired int64
		version uint64
	}{
		{"SetDesiredCapacity", &api.SetDesiredCapacityInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(5))}, 5, 8},
		{"SetDesiredCapacity", &api.SetDesiredCapacityInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(5))}, 5, 8},
		{"UpdateAutoScalingGroup", &api.UpdateAutoScalingGroupInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, MaxSize: new(api.AutoScalingGroupMaxSize(10))}, 5, 8},
		{"UpdateAutoScalingGroup", &api.UpdateAutoScalingGroupInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, MinSize: new(api.AutoScalingGroupMinSize(6))}, 6, 9},
		{"UpdateAutoScalingGroup", &api.UpdateAutoScalingGroupInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, MinSize: new(api.AutoScalingGroupMinSize(0)), DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(4))}, 4, 9},
		{"UpdateAutoScalingGroup", &api.UpdateAutoScalingGroupInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, DesiredCapacity: new(api.AutoScalingGroupDesiredCapacity(7))}, 7, 10},
		{"UpdateAutoScalingGroup", &api.UpdateAutoScalingGroupInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, MaxSize: new(api.AutoScalingGroupMaxSize(5))}, 5, 10},
		{"SuspendProcesses", &api.SuspendProcessesInput{AutoScalingGroupName: group.Data.AutoScalingGroupName, ScalingProcesses: api.ProcessNames{"Launch"}}, 5, 10},
	} {
		managedScalingCommand(t, s, ctx, step.action, step.input)
		current := managedScalingGroup(t, s, ctx, group.Key)
		if intValue(current.Data.DesiredCapacity) != step.desired || current.ScaleUpVersion != step.version {
			t.Fatalf("%s: desired/counter=%d/%d want %d/%d", step.action, intValue(current.Data.DesiredCapacity), current.ScaleUpVersion, step.desired, step.version)
		}
	}
	before := managedScalingGroup(t, s, ctx, group.Key)
	if err := s.finishGroupPass(ctx, before.Key, before.ID, before.Version, false, nil); err != nil {
		t.Fatal(err)
	}
	after := managedScalingGroup(t, s, ctx, group.Key)
	if after.Version == before.Version || after.ScaleUpVersion != before.ScaleUpVersion {
		t.Fatalf("scheduler generation contaminated capacity ownership: before=%d/%d after=%d/%d", before.Version, before.ScaleUpVersion, after.Version, after.ScaleUpVersion)
	}
}

type managedAttemptRepository struct {
	Repository
	before func(context.Context) error
}

func (r *managedAttemptRepository) Attempt(ctx context.Context, fn func(Transaction) error) error {
	if before := r.before; before != nil {
		r.before = nil
		if err := before(ctx); err != nil {
			return err
		}
	}
	return r.Repository.Attempt(ctx, fn)
}

func TestManagedScalingAdmissionFencesConcurrentCapacityOwner(t *testing.T) {
	for _, mutation := range []string{"scale-up", "scale-up-and-down", "configuration", "incarnation", "bookkeeping"} {
		t.Run(mutation, func(t *testing.T) {
			s, ctx, group, events := managedScalingService(t)
			base := s.repository
			var intervening GroupRecord
			s.repository = &managedAttemptRepository{Repository: base, before: func(ctx context.Context) error {
				if mutation == "bookkeeping" {
					if err := s.finishGroupPass(ctx, group.Key, group.ID, group.Version, false, nil); err != nil {
						return err
					}
				} else if err := base.Update(ctx, func(tx Transaction) error {
					current, err := tx.Group(group.Key)
					if err != nil {
						return err
					}
					switch mutation {
					case "scale-up", "scale-up-and-down":
						if err := s.changeDesired(tx, current, 5, "external scale-up"); err != nil {
							return err
						}
						if mutation == "scale-up" {
							return nil
						}
						current, err = tx.Group(group.Key)
						if err != nil {
							return err
						}
						return s.changeDesired(tx, current, 4, "external scale-down")
					case "configuration":
						number(&current.Data.DefaultCooldown, 43)
					case "incarnation":
						current.ID = "replacement"
						text(&current.Data.AutoScalingGroupARN, current.Key.ARN(current.ID))
					}
					return tx.PutGroup(current)
				}); err != nil {
					return err
				}
				intervening = managedScalingGroup(t, s, ctx, group.Key)
				return nil
			}}
			err := s.UpdateManagedScaling(ctx, group.Key.Name, group.Key.ARN(group.ID), group.ScaleUpVersion, 3, 7)
			current := managedScalingGroup(t, s, ctx, group.Key)
			wantCode := "ResourceContention"
			wantAuditCode := "ResourceContentionFault"
			if mutation == "bookkeeping" {
				wantCode = ""
				wantAuditCode = ""
				if err != nil || intValue(current.Data.DesiredCapacity) != 3 || intValue(current.Data.MaxSize) != 7 || intValue(current.Data.MinSize) != 0 || current.ScaleUpVersion != 7 || current.Version != intervening.Version+1 {
					t.Fatalf("guarded scale-down did not preserve current bookkeeping: group=%+v err=%v", current, err)
				}
			} else {
				if err == nil || wireError(err).Code != wantCode {
					t.Fatalf("stale reduction error=%v", err)
				}
				if !reflect.DeepEqual(current, intervening) {
					t.Fatal("stale guarded reduction overwrote intervening state")
				}
			}
			if errors.Is(err, ErrManagedScaleUp) != (mutation == "scale-up" || mutation == "scale-up-and-down") {
				t.Fatalf("incorrect capacity-owner classification: %v", err)
			}
			calls, err := events.Read(ctx, 0, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(calls) != 1 || calls[0].APICallCompleted.EventName != "UpdateAutoScalingGroup" || calls[0].APICallCompleted.ErrorCode != wantAuditCode {
				t.Fatalf("guarded admission recorded an incorrect API outcome: %+v", calls)
			}
		})
	}
}

func TestManagedScalingReplayPreservesCompletedReduction(t *testing.T) {
	s, ctx, group, events := managedScalingService(t)
	arn := group.Key.ARN(group.ID)
	if err := s.UpdateManagedScaling(ctx, group.Key.Name, arn, 7, 3, 7); err != nil {
		t.Fatal(err)
	}
	completed := managedScalingGroup(t, s, ctx, group.Key)
	for _, target := range [][2]int32{{3, 7}, {4, 8}, {2, 8}, {4, 6}} {
		if err := s.UpdateManagedScaling(ctx, group.Key.Name, arn, 7, target[0], target[1]); err != nil {
			t.Fatal(err)
		}
		current := managedScalingGroup(t, s, ctx, group.Key)
		if current.ScaleUpVersion != completed.ScaleUpVersion || intValue(current.Data.MinSize) != intValue(completed.Data.MinSize) || intValue(current.Data.MaxSize) != intValue(completed.Data.MaxSize) || intValue(current.Data.DesiredCapacity) != intValue(completed.Data.DesiredCapacity) {
			t.Fatalf("replayed target %v restored completed capacity or changed ownership", target)
		}
	}
	calls, err := events.Read(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].APICallCompleted.ErrorCode != "" {
		t.Fatalf("replays emitted synthetic API outcomes: %+v", calls)
	}
}

func TestManagedScalingSnapshotIncludesCurrentMembershipAndScope(t *testing.T) {
	s, ctx, group, _ := managedScalingService(t)
	member := transitionMember(group, "i-current", "InService", s.clock.Now())
	warm := transitionMember(group, "i-warm", "Warmed:Running", s.clock.Now())
	group.Data.WarmPoolConfiguration = &api.WarmPoolConfiguration{}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutGroup(group); err != nil {
			return err
		}
		if err := tx.PutInstance(member); err != nil {
			return err
		}
		return tx.PutInstance(warm)
	}); err != nil {
		t.Fatal(err)
	}
	state, err := s.ManagedScaling(ctx, group.Key.Name, group.Key.ARN(group.ID))
	if err != nil {
		t.Fatal(err)
	}
	if state.ScaleUpVersion != 7 || intValue(state.Group.DesiredCapacity) != 4 || len(state.Group.Instances) != 1 || value(state.Group.Instances[0].InstanceId) != "i-current" || intValue(state.Group.WarmPoolSize) != 1 {
		t.Fatalf("managed snapshot lost capacity or current membership: %+v", state)
	}
	if _, err := s.ManagedScaling(ctx, group.Key.Name, group.Key.ARN("old-incarnation")); err == nil || wireError(err).Code != "ResourceContention" {
		t.Fatalf("managed observation crossed incarnation: %v", err)
	}
	other := awsctx.FromContext(ctx)
	other.Region = "us-west-2"
	if _, err := s.ManagedScaling(awsctx.WithMetadata(ctx, other), group.Key.Name, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("managed observation crossed region: %v", err)
	}
}

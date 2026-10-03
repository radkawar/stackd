package autoscaling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awswire"
)

func nativeControlCalls(t *testing.T, fixture string) map[string]nativeControlCall {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/autoscaling/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Calls      []nativeControlCall
		Additional []struct{ Calls []nativeControlCall } `json:"additional_captures"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	calls := make(map[string]nativeControlCall, len(capture.Calls))
	for _, call := range capture.Calls {
		calls[call.Label] = call
	}
	for i, additional := range capture.Additional {
		for _, call := range additional.Calls {
			calls[fmt.Sprintf("additional/%d/%s", i, call.Label)] = call
		}
	}
	return calls
}

func decodeLifecycleOutput[T any](t *testing.T, calls map[string]nativeControlCall, label string) T {
	t.Helper()
	call, ok := calls[label]
	if !ok || call.Code != "Success" {
		t.Fatalf("missing successful native call %q", label)
	}
	var out T
	if err := json.Unmarshal(call.Output, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

type deletedTemplateInstances struct{ Instances }

func (deletedTemplateInstances) Template(context.Context, api.LaunchTemplateSpecification) (api.LaunchTemplateSpecification, error) {
	return api.LaunchTemplateSpecification{}, errors.New("selected launch template version does not exist")
}

func TestEmptyWarmPoolDeletionDoesNotWaitForActiveLaunch(t *testing.T) {
	s, ctx, g, _, _ := ownedControlService(t)
	s.instances = deletedTemplateInstances{}
	g.Data.SuspendedProcesses = nil
	g.Data.LaunchTemplate = &api.LaunchTemplateSpecification{}
	text(&g.Data.LaunchTemplate.LaunchTemplateId, "lt-deleted-version")
	text(&g.Data.LaunchTemplate.Version, "2")
	g.Data.WarmPoolConfiguration = &api.WarmPoolConfiguration{}
	number(&g.Data.WarmPoolConfiguration.MinSize, 0)
	number(&g.Data.WarmPoolConfiguration.MaxGroupPreparedCapacity, 0)
	text(&g.Data.WarmPoolConfiguration.PoolState, "Running")
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutGroup(g); err != nil {
			return err
		}
		_, err := s.deleteWarmPool(tx.Context(), tx, &api.DeleteWarmPoolInput{AutoScalingGroupName: g.Data.AutoScalingGroupName})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	_, launchErr := s.runGroup(ctx, g.Key, g.ID)
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		g, err = r.Group(g.Key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if g.Data.WarmPoolConfiguration != nil {
		t.Fatalf("empty pool remains deleting behind an unrelated launch: pool=%+v launch=%v", g.Data.WarmPoolConfiguration, launchErr)
	}
}

func TestNativeSuspendedLaunchReservesWarmCapacity(t *testing.T) {
	calls := nativeControlCalls(t, "warm_pool_suspended_launch_native.json")
	nativeGroup := decodeLifecycleOutput[api.DescribeAutoScalingGroupsOutput](t, calls, "suspended-launch-before-resume-group").AutoScalingGroups[0]
	nativePool := decodeLifecycleOutput[api.DescribeWarmPoolOutput](t, calls, "suspended-launch-before-resume-pool")
	for _, next := range []string{"resume", "delete-pool"} {
		t.Run(next, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			s.instances = transitionInstances{}
			name, arn := g.Data.AutoScalingGroupName, g.Data.AutoScalingGroupARN
			g.Data = api.CloneAutoScalingGroup(nativeGroup)
			g.Data.AutoScalingGroupName, g.Data.AutoScalingGroupARN = name, arn
			member := InstanceRecord{Group: g.Key, GroupID: g.ID, JoinedAt: source.Now(), Data: nativePool.Instances[0]}
			id := value(member.Data.InstanceId)
			storeTransition(t, s, ctx, g, member)
			if err := source.Advance(time.Minute); err != nil {
				t.Fatal(err)
			}
			if _, err := s.runGroup(ctx, g.Key, g.ID); err != nil {
				t.Fatal(err)
			}
			member = readTransition(t, s, ctx, g, id)
			if member.TerminationRequested || value(member.Data.LifecycleState) != value(nativePool.Instances[0].LifecycleState) {
				t.Fatalf("suspended scale-out discarded reserved warm instance: %+v", member)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if next == "delete-pool" {
					_, err := s.deleteWarmPool(tx.Context(), tx, &api.DeleteWarmPoolInput{AutoScalingGroupName: name, ForceDelete: new(api.ForceDelete(true))})
					return err
				}
				var in api.ResumeProcessesInput
				if err := json.Unmarshal(calls["suspended-launch-resume"].Input, &in); err != nil {
					return err
				}
				in.AutoScalingGroupName = name
				_, err := s.resumeProcesses(tx.Context(), tx, &in)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if changed, err := s.runGroup(ctx, g.Key, g.ID); err != nil || !changed {
				t.Fatalf("%s did not consume the reserved instance: changed=%t err=%v", next, changed, err)
			}
			member = readTransition(t, s, ctx, g, id)
			if next == "delete-pool" {
				if !member.TerminationRequested {
					t.Fatal("pending desired capacity blocked explicit warm-pool deletion")
				}
			} else if member.TerminationRequested || warmMember(member) {
				t.Fatalf("resumed scale-out did not activate the reserved instance: %+v", member)
			}
		})
	}
}

func TestNativeExplicitTerminationPolicyRequiresAbandonHook(t *testing.T) {
	calls := nativeControlCalls(t, "warm_pool_suspended_launch_native.json")
	call := calls["additional/0/warm-create-zero"]
	var in api.CreateAutoScalingGroupInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		t.Fatal(err)
	}
	s, ctx, _, _, _ := ownedControlService(t)
	_, err := s.prepareCreateAutoScalingGroup(ctx, &in)
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != call.Code {
		t.Fatalf("explicit termination policy: got %v, native code %s", err, call.Code)
	}
}

func TestNativeProtectedScaleInRecordsOneCancelledIntent(t *testing.T) {
	calls := nativeControlCalls(t, "lifecycle_native.json")
	for _, tc := range []struct {
		name, request, snapshot string
		update                  bool
	}{
		{"desired", "protected-desired-zero", "protected-scale-in", false},
		{"bounds", "recovery/max-lowers-desired-protected", "recovery/protected-idle-0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ctx, g, source, _ := ownedControlService(t)
			s.instances = transitionInstances{}
			nativeGroup := decodeLifecycleOutput[api.DescribeAutoScalingGroupsOutput](t, calls, tc.snapshot+"-group").AutoScalingGroups[0]
			nativeActivities := decodeLifecycleOutput[api.DescribeScalingActivitiesOutput](t, calls, tc.snapshot+"-activities").Activities
			var cancelled api.Activity
			for _, activity := range nativeActivities {
				if value(activity.StatusCode) == "Cancelled" {
					cancelled = activity
					break
				}
			}
			if cancelled.StartTime == nil || cancelled.EndTime == nil {
				t.Fatal("native protected cancellation is missing")
			}
			name, arn := g.Data.AutoScalingGroupName, g.Data.AutoScalingGroupARN
			g.Data = api.CloneAutoScalingGroup(nativeGroup)
			g.Data.AutoScalingGroupName, g.Data.AutoScalingGroupARN = name, arn
			g.Data.Instances = nil
			number(&g.Data.DesiredCapacity, 1)
			number(&g.Data.MaxSize, 2)
			if tc.update {
				number(&g.Data.MinSize, 1)
			}
			g.PendingInstanceWarmup = new(int32(180))
			member := InstanceRecord{Group: g.Key, GroupID: g.ID, Data: nativeGroup.Instances[0]}
			if err := source.Advance(cancelled.StartTime.Sub(source.Now())); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				if err := tx.PutGroup(g); err != nil {
					return err
				}
				return tx.PutInstance(member)
			}); err != nil {
				t.Fatal(err)
			}
			requestCtx, err := apievents.Reserve(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var update func(Transaction) (*api.UpdateAutoScalingGroupOutput, error)
			if tc.update {
				var in api.UpdateAutoScalingGroupInput
				if err := json.Unmarshal(calls[tc.request].Input, &in); err != nil {
					t.Fatal(err)
				}
				in.AutoScalingGroupName = name
				update, err = s.prepareUpdateAutoScalingGroup(requestCtx, &in)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := s.repository.Update(requestCtx, func(tx Transaction) error {
				if tc.update {
					_, err := update(tx)
					return err
				}
				var in api.SetDesiredCapacityInput
				if err := json.Unmarshal(calls[tc.request].Input, &in); err != nil {
					return err
				}
				in.AutoScalingGroupName = name
				_, err := s.setDesiredCapacity(tx.Context(), tx, &in)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			var activityID string
			// The native idle snapshots bound this assertion to 20 seconds, not perpetual AWS deduplication.
			for pass := range 5 {
				changed, err := s.runGroup(ctx, g.Key, g.ID)
				if err != nil || changed != (pass == 0) {
					t.Fatalf("pass %d changed=%v err=%v", pass, changed, err)
				}
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					out, err := s.describeScalingActivities(ctx, tx, &api.DescribeScalingActivitiesInput{AutoScalingGroupName: name})
					if err != nil {
						return err
					}
					if len(out.Activities) != 1 {
						t.Fatalf("polling duplicated protected intent: %+v", out.Activities)
					}
					actual := out.Activities[0]
					if pass == 0 {
						activityID = value(actual.ActivityId)
					}
					if value(actual.ActivityId) != activityID || value(actual.StatusCode) != value(cancelled.StatusCode) || intValue(actual.Progress) != intValue(cancelled.Progress) || value(actual.Details) != value(cancelled.Details) || value(actual.AutoScalingGroupState) != value(cancelled.AutoScalingGroupState) || actual.StatusMessage != nil {
						t.Fatalf("protected cancellation differs from native state: %+v", actual)
					}
					if actual.StartTime == nil || actual.EndTime == nil || !actual.StartTime.Equal(*cancelled.StartTime) || !actual.EndTime.Equal(*cancelled.EndTime) {
						t.Fatalf("native second-truncated cancellation times changed: %+v", actual)
					}
					stored, err := tx.Group(g.Key)
					if err != nil {
						return err
					}
					if intValue(stored.Data.DesiredCapacity) != intValue(nativeGroup.DesiredCapacity) || stored.PendingInstanceWarmup != nil {
						t.Fatalf("accepted capacity/warmup=%d/%v", intValue(stored.Data.DesiredCapacity), stored.PendingInstanceWarmup)
					}
					owned, err := tx.Instance(g.Key.Scope, value(member.Data.InstanceId))
					if err == nil && (owned.TerminationRequested || !reflect.DeepEqual(owned.Data, member.Data)) {
						t.Fatalf("protected member changed: %+v", owned)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if pass < 4 {
					if err := source.Advance(5 * time.Second); err != nil {
						t.Fatal(err)
					}
				}
			}
			// A distinct accepted request is not mistaken for another scheduler poll.
			requestCtx, err = apievents.Reserve(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Update(requestCtx, func(tx Transaction) error {
				_, err := s.setDesiredCapacity(tx.Context(), tx, &api.SetDesiredCapacityInput{AutoScalingGroupName: name, DesiredCapacity: nativeGroup.DesiredCapacity})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if changed, err := s.runGroup(ctx, g.Key, g.ID); err != nil || !changed {
				t.Fatalf("new intent changed=%v err=%v", changed, err)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				rows, err := tx.Activities(g.Key.Scope, g.Key.Name, false)
				if err != nil {
					return err
				}
				if len(rows) != 2 || rows[0].Key == rows[1].Key || rows[0].OriginEventID == rows[1].OriginEventID {
					t.Fatalf("distinct accepted intent lost: %+v", rows)
				}
				_, err = s.setInstanceProtection(ctx, tx, &api.SetInstanceProtectionInput{AutoScalingGroupName: name, InstanceIds: api.InstanceIds{*member.Data.InstanceId}, ProtectedFromScaleIn: new(api.ProtectedFromScaleIn(false))})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if changed, err := s.runGroup(ctx, g.Key, g.ID); err != nil || !changed {
				t.Fatalf("unprotected scale-in changed=%v err=%v", changed, err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				owned, err := r.Instance(g.Key.Scope, value(member.Data.InstanceId))
				if err != nil {
					return err
				}
				activity, err := r.Activity(ActivityKey{Scope: g.Key.Scope, ID: owned.ActivityID})
				if err == nil && (!owned.TerminationRequested || activity.Kind != "terminate" || activity.InstanceID != value(member.Data.InstanceId)) {
					t.Fatalf("removing protection did not accept termination: %+v %+v", owned, activity)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type activityReadFailure struct{ Transaction }

func (activityReadFailure) Activity(ActivityKey) (ActivityRecord, error) {
	return ActivityRecord{}, errors.New("activity read unavailable")
}

func TestTerminateReturnsAcceptedActivityWithoutReadback(t *testing.T) {
	for _, multiple := range []bool{false, true} {
		t.Run(fmt.Sprint(multiple), func(t *testing.T) {
			s, ctx, g, _, _ := ownedControlService(t)
			id := "i-termination"
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				return tx.PutInstance(InstanceRecord{Group: g.Key, GroupID: g.ID, Data: api.Instance{InstanceId: new(api.XmlStringMaxLen19(id)), LifecycleState: new(api.LifecycleState("InService"))}})
			}); err != nil {
				t.Fatal(err)
			}
			in := api.TerminateInstanceInAutoScalingGroupInput{InstanceId: new(api.XmlStringMaxLen19(id)), ShouldDecrementDesiredCapacity: new(api.ShouldDecrementDesiredCapacity(true))}
			if multiple {
				in.InstanceId = nil
				in.InstanceIds = api.TerminationInstanceIds{api.XmlStringMaxLen19(id)}
				in.AutoScalingGroupName = g.Data.AutoScalingGroupName
			}
			var response *api.TerminateInstanceInAutoScalingGroupOutput
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				var err error
				response, err = s.terminateInstanceInAutoScalingGroup(ctx, activityReadFailure{tx}, &in)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			var accepted api.Activity
			if multiple {
				if len(response.Activities) != 1 || response.Activity != nil {
					t.Fatalf("multi-instance response=%+v", response)
				}
				accepted = response.Activities[0]
			} else {
				if response.Activity == nil || len(response.Activities) != 0 {
					t.Fatalf("single-instance response=%+v", response)
				}
				accepted = *response.Activity
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				member, err := tx.Instance(g.Key.Scope, id)
				if err != nil {
					return err
				}
				activity, err := tx.Activity(ActivityKey{Scope: g.Key.Scope, ID: member.ActivityID})
				if err != nil {
					return err
				}
				stored, err := tx.Group(g.Key)
				if err != nil {
					return err
				}
				if !member.TerminationRequested || activity.InstanceID != id || !reflect.DeepEqual(accepted, activity.Data) || intValue(stored.Data.DesiredCapacity) != 1 {
					t.Fatalf("accepted response disagrees with committed termination: %+v %+v %+v", accepted, member, activity)
				}
				_, err = s.terminateMember(tx, stored, &member, "repeated internal reconciliation")
				return err
			}); err != nil {
				t.Fatal(err)
			}
			err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.terminateInstanceInAutoScalingGroup(ctx, tx, &in); return err })
			if err == nil || wireError(err).Code != "ScalingActivityInProgress" {
				t.Fatalf("repeat termination error=%v", err)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				rows, err := r.Activities(g.Key.Scope, g.Key.Name, false)
				if err == nil && len(rows) != 1 {
					t.Fatalf("repeat termination duplicated intent: %+v", rows)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestScalingActivityStatusFilterAndDeletingGroupState(t *testing.T) {
	s, ctx, g, _, _ := ownedControlService(t)
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		for _, status := range []string{"Cancelled", "Successful", "Failed", "Cancelled"} {
			activity := s.newActivity(g, "scale-in", "")
			if err := s.completeActivity(ctx, tx, g, activity, status, ""); err != nil {
				return err
			}
		}
		g.Deleting = true
		return tx.PutGroup(g)
	}); err != nil {
		t.Fatal(err)
	}
	filter := api.Filter{Name: new(api.XmlString("Status")), Values: api.Values{"Cancelled"}}
	in := api.DescribeScalingActivitiesInput{AutoScalingGroupName: g.Data.AutoScalingGroupName, Filters: api.Filters{filter}, MaxRecords: new(api.MaxRecords(1))}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		first, err := s.describeScalingActivities(ctx, tx, &in)
		if err != nil {
			return err
		}
		if len(first.Activities) != 1 || first.NextToken == nil || value(first.Activities[0].StatusCode) != "Cancelled" || value(first.Activities[0].AutoScalingGroupState) != "InService" {
			t.Fatalf("filtered first page=%+v", first)
		}
		in.NextToken = first.NextToken
		second, err := s.describeScalingActivities(ctx, tx, &in)
		if err != nil {
			return err
		}
		if len(second.Activities) != 1 || second.NextToken != nil || value(second.Activities[0].StatusCode) != "Cancelled" || value(second.Activities[0].ActivityId) == value(first.Activities[0].ActivityId) {
			t.Fatalf("filtered second page=%+v", second)
		}
		in.NextToken = nil
		in.AutoScalingGroupName = nil
		if _, err := s.describeScalingActivities(ctx, tx, &in); err == nil || wireError(err).Code != "ValidationError" {
			t.Fatalf("account-wide Status accepted: %v", err)
		}
		in.AutoScalingGroupName = g.Data.AutoScalingGroupName
		in.Filters = api.Filters{{Name: new(api.XmlString("activity-status")), Values: api.Values{"Successful"}}}
		if _, err := s.describeScalingActivities(ctx, tx, &in); err == nil || wireError(err).Code != "ValidationError" {
			t.Fatalf("unknown activity filter accepted: %v", err)
		}
		if err := tx.DeleteGroup(g.Key); err != nil {
			return err
		}
		in.Filters = api.Filters{filter}
		in.MaxRecords = nil
		in.IncludeDeletedGroups = new(api.IncludeDeletedGroups(true))
		deleted, err := s.describeScalingActivities(ctx, tx, &in)
		if err != nil {
			return err
		}
		if len(deleted.Activities) != 2 {
			t.Fatalf("deleted group's filtered activities=%+v", deleted)
		}
		for _, activity := range deleted.Activities {
			if value(activity.AutoScalingGroupState) != "Deleted" {
				t.Fatalf("deleted group retained live activity state: %+v", activity)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A storage outage is not evidence that the group does not exist.
type groupReadFailure struct {
	Transaction
	err error
}

func (tx groupReadFailure) Group(GroupKey) (GroupRecord, error) { return GroupRecord{}, tx.err }

func TestTagMutationsPreserveStorageFailures(t *testing.T) {
	s, ctx, g, _, _ := ownedControlService(t)
	storageErr := errors.New("group storage unavailable")
	tags := api.Tags{{ResourceId: new(api.XmlString(g.Key.Name)), Key: new(api.TagKey("purpose")), Value: new(api.TagValue("owned"))}}
	for _, remove := range []bool{false, true} {
		for _, cause := range []error{storageErr, fmt.Errorf("wrapped lookup: %w", ErrNotFound)} {
			err := s.repository.Update(ctx, func(tx Transaction) error {
				failed := groupReadFailure{tx, cause}
				if remove {
					_, err := s.deleteTags(ctx, failed, &api.DeleteTagsInput{Tags: tags})
					return err
				}
				_, err := s.createOrUpdateTags(ctx, failed, &api.CreateOrUpdateTagsInput{Tags: tags})
				return err
			})
			if errors.Is(cause, ErrNotFound) {
				if err == nil || wireError(err).Code != "ValidationError" {
					t.Fatalf("missing group error=%v", err)
				}
			} else if !errors.Is(err, storageErr) {
				t.Fatalf("storage error was converted to missing group: %v", err)
			}
		}
	}
}

func TestNativeScalingActivityTimeFilters(t *testing.T) {
	for _, fixture := range []string{"activity_filters_native.json", "activity_filters_edges_native.json"} {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile("../../../testdata/aws/autoscaling/" + fixture)
			if err != nil {
				t.Fatal(err)
			}
			var capture struct {
				CapturedAt time.Time `json:"captured_at"`
				Calls      []nativeControlCall
			}
			if err := json.Unmarshal(data, &capture); err != nil {
				t.Fatal(err)
			}
			s, ctx, group, source, _ := ownedControlService(t)
			if err := source.Advance(capture.CapturedAt.Sub(source.Now())); err != nil {
				t.Fatal(err)
			}
			var history api.DescribeScalingActivitiesOutput
			if err := json.Unmarshal(capture.Calls[0].Output, &history); err != nil {
				t.Fatal(err)
			}
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				for _, activity := range history.Activities {
					record := ActivityRecord{
						Key:     ActivityKey{Scope: group.Key.Scope, ID: value(activity.ActivityId)},
						Group:   GroupKey{Scope: group.Key.Scope, Name: value(activity.AutoScalingGroupName)},
						GroupID: "deleted-native-group", Data: activity,
					}
					if err := tx.PutActivity(record); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, call := range capture.Calls {
				var in api.DescribeScalingActivitiesInput
				if err := json.Unmarshal(call.Input, &in); err != nil {
					t.Fatal(err)
				}
				// This fixture checks selection and input admission. Native token
				// mutation observations remain evidence for the pagination gap.
				if in.NextToken != nil {
					continue
				}
				t.Run(call.Label, func(t *testing.T) {
					var got *api.DescribeScalingActivitiesOutput
					err := s.repository.Update(ctx, func(tx Transaction) error {
						var err error
						got, err = s.describeScalingActivities(tx.Context(), tx, &in)
						return err
					})
					if call.Code != "Success" {
						if err == nil || wireError(err).Code != call.Code {
							t.Fatalf("got %v, native error %s", err, call.Code)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					var want api.DescribeScalingActivitiesOutput
					if err := json.Unmarshal(call.Output, &want); err != nil {
						t.Fatal(err)
					}
					ids := func(rows api.Activities) []string {
						result := make([]string, len(rows))
						for i, row := range rows {
							result[i] = value(row.ActivityId)
						}
						return result
					}
					if !reflect.DeepEqual(ids(got.Activities), ids(want.Activities)) || (got.NextToken != nil) != (want.NextToken != nil) {
						t.Fatalf("selected %v (more=%t), native %v (more=%t)", ids(got.Activities), got.NextToken != nil, ids(want.Activities), want.NextToken != nil)
					}
				})
			}
		})
	}
}

package autoscaling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/autoscaling"
	ec2api "stackd/internal/awsapi/ec2"
)

type terminationSelectFunc func(context.Context, TerminationPolicyRequest) ([]string, error)

func (f terminationSelectFunc) Select(ctx context.Context, request TerminationPolicyRequest) ([]string, error) {
	return f(ctx, request)
}
func (f terminationSelectFunc) Validate(context.Context, string) error { return nil }

func terminationMember(group GroupRecord, id, zone string, joined time.Time) InstanceRecord {
	member := InstanceRecord{Group: group.Key, GroupID: group.ID, JoinedAt: joined}
	text(&member.Data.InstanceId, id)
	text(&member.Data.AvailabilityZone, zone)
	text(&member.Data.InstanceType, "t3.nano")
	text(&member.Data.LifecycleState, "InService")
	text(&member.Data.HealthStatus, "Healthy")
	return member
}

func TestTerminationLambdaOverridesSuggestionsButNotEligibility(t *testing.T) {
	for _, decision := range []string{"other-zone", "protected", "foreign", "refresh-override", "refresh-outside-cohort"} {
		t.Run(decision, func(t *testing.T) {
			s, ctx, group, source, _ := ownedControlService(t)
			group.Data.TerminationPolicies = api.TerminationPolicies{"arn:aws:lambda:us-east-1:123456789012:function:choose", "OldestInstance"}
			members := []InstanceRecord{
				terminationMember(group, "i-a", "us-east-1a", source.Now().Add(-2*time.Hour)),
				terminationMember(group, "i-b", "us-east-1a", source.Now().Add(-time.Hour)),
				terminationMember(group, "i-c", "us-east-1b", source.Now()),
			}
			cause, selected := "SCALE_IN", "i-c"
			var eligible []string
			if decision == "protected" || decision == "refresh-override" {
				members[2].Data.ProtectedFromScaleIn = new(api.InstanceProtected(true))
			}
			if decision == "foreign" {
				selected = "i-foreign"
			}
			if decision == "refresh-override" {
				cause, eligible = "INSTANCE_REFRESH", []string{"i-c"}
			}
			if decision == "refresh-outside-cohort" {
				cause, eligible = "INSTANCE_REFRESH", []string{"i-a"}
			}
			s.terminationSelector = terminationSelectFunc(func(ctx context.Context, request TerminationPolicyRequest) ([]string, error) {
				if decision == "other-zone" && slices.ContainsFunc(request.Instances, func(i TerminationInstance) bool { return i.InstanceID == "i-c" }) {
					t.Fatal("balanced suggestions included the underpopulated zone")
				}
				return []string{selected}, nil
			})
			got, err := s.selectTerminations(ctx, group, members, cause, 1, eligible)
			if decision == "protected" || decision == "foreign" || decision == "refresh-outside-cohort" {
				if err == nil || len(got) != 0 {
					t.Fatalf("ineligible decision admitted: %v, %v", got, err)
				}
			} else if err != nil || len(got) != 1 || value(got[0].Data.InstanceId) != selected {
				t.Fatalf("valid override rejected: %v, %v", got, err)
			}
		})
	}
}

func TestTerminationExcessCandidatesUsePoliciesNotResponseOrder(t *testing.T) {
	s, ctx, group, source, _ := ownedControlService(t)
	group.Data.TerminationPolicies = api.TerminationPolicies{"arn:aws:lambda:us-east-1:123456789012:function:choose", "OldestInstance"}
	members := []InstanceRecord{terminationMember(group, "i-old", "us-east-1a", source.Now().Add(-time.Hour)), terminationMember(group, "i-new", "us-east-1a", source.Now())}
	s.terminationSelector = terminationSelectFunc(func(context.Context, TerminationPolicyRequest) ([]string, error) {
		return []string{"i-new", "i-old", "i-old"}, nil
	})
	got, err := s.selectTerminations(ctx, group, members, "SCALE_IN", 1, nil)
	if err != nil || len(got) != 1 || value(got[0].Data.InstanceId) != "i-old" {
		t.Fatalf("response order won over policy: %v %v", got, err)
	}
}

func TestTerminationSnapshotFencesMembershipAndDesiredCancellation(t *testing.T) {
	for _, mutation := range []string{"desired", "protection", "detachment", "new-member"} {
		t.Run(mutation, func(t *testing.T) {
			s, ctx, group, source, _ := ownedControlService(t)
			group.Data.SuspendedProcesses = nil
			group.Data.TerminationPolicies = api.TerminationPolicies{"arn:aws:lambda:us-east-1:123456789012:function:choose"}
			number(&group.Data.DesiredCapacity, 0)
			member := terminationMember(group, "i-selected", "us-east-1a", source.Now())
			storeTransition(t, s, ctx, group, member)
			s.terminationSelector = terminationSelectFunc(func(ctx context.Context, request TerminationPolicyRequest) ([]string, error) {
				// This write also proves invocation is not under the repository's
				// write lock; the concurrent API owns the cancellation boundary.
				err := s.repository.Update(ctx, func(tx Transaction) error {
					switch mutation {
					case "desired":
						number(&group.Data.DesiredCapacity, 1)
						group.Version++
						return tx.PutGroup(group)
					case "protection":
						member.Data.ProtectedFromScaleIn = new(api.InstanceProtected(true))
						return tx.PutInstance(member)
					case "detachment":
						return tx.DeleteInstance(group.Key.Scope, value(member.Data.InstanceId))
					default:
						return tx.PutInstance(terminationMember(group, "i-new", "us-east-1b", source.Now()))
					}
				})
				return []string{"i-selected"}, err
			})
			changed, err := s.reconcileCapacity(ctx, group)
			if err != nil || changed {
				t.Fatalf("stale selection admitted: changed=%v err=%v", changed, err)
			}
			if err := s.repository.View(ctx, func(tx Reader) error {
				activities, err := tx.Activities(group.Key.Scope, group.Key.Name, false)
				for _, activity := range activities {
					if activity.Kind == "terminate" {
						t.Error("stale Lambda result created a termination")
					}
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTerminationSelectionDeadlineAndTruncation(t *testing.T) {
	s, ctx, group, source, _ := ownedControlService(t)
	group.Data.TerminationPolicies = api.TerminationPolicies{"arn:aws:lambda:us-east-1:123456789012:function:choose"}
	members := make([]InstanceRecord, 30001)
	for i := range members {
		members[i] = terminationMember(group, fmt.Sprintf("i-%08d", i), "us-east-1a", source.Now())
	}
	request := terminationRequest(group, members, members, "function", "SCALE_IN", 1)
	if !request.HasMoreInstances || len(request.Instances) != 30000 || request.Instances[29999].InstanceID != "i-00029999" || request.CapacityToTerminate[0].Capacity != 1 {
		t.Fatalf("truncation lost capacity or changed boundary: count=%d more=%v capacity=%v", len(request.Instances), request.HasMoreInstances, request.CapacityToTerminate)
	}
	s.terminationSelector = terminationSelectFunc(func(ctx context.Context, request TerminationPolicyRequest) ([]string, error) {
		<-ctx.Done()
		return []string{value(members[0].Data.InstanceId)}, nil
	})
	start := time.Now()
	got, err := s.selectTerminations(ctx, group, members[:1], "SCALE_IN", 1, nil)
	if !errors.Is(err, context.DeadlineExceeded) || len(got) != 0 || time.Since(start) < 2*time.Second {
		t.Fatalf("late decision admitted: %v %v elapsed=%v", got, err, time.Since(start))
	}
}

func TestTerminationNativeInvocationAndExcessDecision(t *testing.T) {
	calls := nativeControlCalls(t, "termination_native.json")
	described := decodeLifecycleOutput[api.DescribeAutoScalingGroupsOutput](t, calls, "termination-second-ready-observed-group").AutoScalingGroups[0]
	instances := decodeLifecycleOutput[ec2api.DescribeInstancesResult](t, calls, "termination-second-ready-observed-ec2")
	key, id, err := parseGroupARN(value(described.AutoScalingGroupARN))
	if err != nil {
		t.Fatal(err)
	}
	group := GroupRecord{Key: key, ID: id, Data: described}
	members := make([]InstanceRecord, 0, len(described.Instances))
	for _, member := range described.Instances {
		record := InstanceRecord{Group: key, GroupID: id, Data: member}
		for _, reservation := range instances.Reservations {
			for _, instance := range reservation.Instances {
				if value(instance.InstanceId) == value(member.InstanceId) {
					record.JoinedAt = time.Time(*instance.LaunchTime)
				}
			}
		}
		if record.JoinedAt.IsZero() {
			t.Fatal("native fixture lacks instance launch time")
		}
		members = append(members, record)
	}
	raw, err := os.ReadFile("../../../testdata/aws/autoscaling/termination_native.json")
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Logs   []struct{ Message string } `json:"invocation_logs"`
		Phases []struct {
			Name, Selected string
			At             time.Time
			ResponseOrder  []string `json:"response_order"`
		}
	}
	if err := json.Unmarshal(raw, &native); err != nil {
		t.Fatal(err)
	}
	var expected TerminationPolicyRequest
	for _, entry := range native.Logs {
		if suffix, ok := strings.CutPrefix(entry.Message, "TERMINATION_INPUT "); ok {
			var event struct{ Event TerminationPolicyRequest }
			if err := json.Unmarshal([]byte(suffix), &event); err != nil {
				t.Fatal(err)
			}
			expected = event.Event
			break
		}
	}
	if expected.AutoScalingGroupARN == "" {
		t.Fatal("native invocation is missing")
	}
	expected.FunctionARN = lambdaTerminationPolicy(group)
	var selected string
	var observedAt time.Time
	var response []string
	for _, phase := range native.Phases {
		if phase.Name == "termination-selected" {
			selected, response, observedAt = phase.Selected, phase.ResponseOrder, phase.At
		}
	}
	if selected == "" {
		t.Fatal("native retirement evidence is missing")
	}
	service := &Service{clock: clock.NewManual(observedAt)}
	service.terminationSelector = terminationSelectFunc(func(ctx context.Context, request TerminationPolicyRequest) ([]string, error) {
		if !reflect.DeepEqual(request, expected) {
			t.Fatalf("native Lambda event = %+v; actual = %+v", expected, request)
		}
		return response, nil
	})
	result, err := service.selectTerminations(t.Context(), group, members, "SCALE_IN", 1, nil)
	if err != nil || len(result) != 1 || value(result[0].Data.InstanceId) != selected {
		t.Fatalf("native selection %s; actual %+v, %v", selected, result, err)
	}
}

func TestTerminationEmptyDecisionRetainsIntentAndNativeCancellation(t *testing.T) {
	calls := nativeControlCalls(t, "termination_native.json")
	native := decodeLifecycleOutput[api.DescribeScalingActivitiesOutput](t, calls, "termination-empty-activities")
	wantStatus := value(native.Activities[0].StatusCode)
	s, ctx, group, source, _ := ownedControlService(t)
	group.Data.SuspendedProcesses = nil
	group.Data.TerminationPolicies = api.TerminationPolicies{"arn:aws:lambda:us-east-1:123456789012:function:choose"}
	number(&group.Data.DesiredCapacity, 0)
	member := terminationMember(group, "i-busy", "us-east-1a", source.Now())
	storeTransition(t, s, ctx, group, member)
	invocations := 0
	s.terminationSelector = terminationSelectFunc(func(context.Context, TerminationPolicyRequest) ([]string, error) { invocations++; return nil, nil })
	for range 2 {
		if _, err := s.reconcileCapacity(ctx, group); err != nil {
			t.Fatal(err)
		}
	}
	if invocations != 2 {
		t.Fatalf("cancelled activity stopped retries: %d invocations", invocations)
	}
	if err := s.repository.View(ctx, func(tx Reader) error {
		current, err := tx.Instance(group.Key.Scope, value(member.Data.InstanceId))
		if err != nil {
			return err
		}
		if current.TerminationRequested || value(current.Data.LifecycleState) != "InService" {
			t.Fatal("empty decision retired the busy member")
		}
		activities, err := tx.Activities(group.Key.Scope, group.Key.Name, false)
		if err != nil {
			return err
		}
		cancelled := 0
		for _, activity := range activities {
			if activity.Kind == "scale-in" {
				cancelled++
				if value(activity.Data.StatusCode) != wantStatus {
					t.Fatalf("native cancellation %q; got %q", wantStatus, value(activity.Data.StatusCode))
				}
			}
		}
		if cancelled != 1 {
			t.Fatalf("retry duplicated cancelled intent: %d activities", cancelled)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

package autoscaling

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/autoscaling"
	"stackd/internal/awswire"
)

// TerminationSelector invokes the customer function under the group's current
// service-linked-role identity. Lambda owns authorization, audit and execution.
// Select must honor cancellation; an expired decision cannot admit retirement.
type TerminationSelector interface {
	Select(context.Context, TerminationPolicyRequest) ([]string, error)
	// Validate checks current function/qualifier authorization without running
	// customer code. API preparation calls it outside the write transaction.
	Validate(context.Context, string) error
}

func (s *Service) validateTerminationPolicy(ctx context.Context, group GroupRecord) error {
	function := lambdaTerminationPolicy(group)
	if function == "" {
		return nil
	}
	if s.terminationSelector == nil || s.identity == nil {
		return unsupported("Lambda custom termination admission is not configured.")
	}
	execution, err := s.identity.Context(ctx, group)
	if err != nil {
		return err
	}
	if err := s.terminationSelector.Validate(execution, function); err != nil {
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.StatusCode >= 500 {
			return err
		}
		return invalid(fmt.Sprintf("Lambda function %s does not have permissions set up to be called by %s.", function, value(group.Data.ServiceLinkedRoleARN)))
	}
	return nil
}

// TerminationPolicyRequest is the documented Lambda event. FunctionARN routes
// the invocation and is deliberately not part of the customer payload.
type TerminationPolicyRequest struct {
	FunctionARN          string                `json:"-"`
	AutoScalingGroupARN  string                `json:"AutoScalingGroupARN"`
	AutoScalingGroupName string                `json:"AutoScalingGroupName"`
	CapacityToTerminate  []TerminationCapacity `json:"CapacityToTerminate"`
	Instances            []TerminationInstance `json:"Instances"`
	Cause                string                `json:"Cause"`
	HasMoreInstances     bool                  `json:"HasMoreInstances,omitempty"`
}

type TerminationCapacity struct {
	AvailabilityZone     string `json:"AvailabilityZone"`
	Capacity             int64  `json:"Capacity"`
	InstanceMarketOption string `json:"InstanceMarketOption"`
}

type TerminationInstance struct {
	AvailabilityZone     string `json:"AvailabilityZone"`
	InstanceID           string `json:"InstanceId"`
	InstanceType         string `json:"InstanceType"`
	InstanceMarketOption string `json:"InstanceMarketOption"`
}

func validateTerminationPolicies(data api.AutoScalingGroup) error {
	groupARN, _ := arn.Parse(value(data.AutoScalingGroupARN))
	for index, raw := range data.TerminationPolicies {
		policy := string(raw)
		switch policy {
		case "Default", "OldestInstance", "NewestInstance", "OldestLaunchTemplate", "ClosestToNextInstanceHour":
			continue
		case "AllocationStrategy", "OldestLaunchConfiguration":
			return unsupported("This Auto Scaling termination policy is not implemented.")
		}
		function, err := arn.Parse(policy)
		if err != nil || function.Service != "lambda" || function.Partition != groupARN.Partition || function.AccountID != groupARN.AccountID || function.Region != groupARN.Region {
			return invalid("The custom termination policy must be a Lambda function ARN in the same account and Region as the Auto Scaling group.")
		}
		parts := strings.Split(function.Resource, ":")
		if len(parts) < 2 || len(parts) > 3 || parts[0] != "function" || parts[1] == "" || len(parts) == 3 && (parts[2] == "" || parts[2] == "$LATEST") {
			return invalid("The custom termination policy must reference a Lambda function, published version or alias, not $LATEST.")
		}
		if index != 0 {
			return invalid("Only one Lambda function is allowed in termination policies, and it must be the first policy.")
		}
	}
	return nil
}

func lambdaTerminationPolicy(group GroupRecord) string {
	if len(group.Data.TerminationPolicies) != 0 && strings.HasPrefix(string(group.Data.TerminationPolicies[0]), "arn:") {
		return string(group.Data.TerminationPolicies[0])
	}
	return ""
}

func terminationEligible(group GroupRecord, member InstanceRecord, cause string, eligibleIDs map[string]struct{}) bool {
	if member.Group != group.Key || member.GroupID != group.ID || member.TerminationRequested || member.DetachRequested || retainedMember(member) {
		return false
	}
	state := value(member.Data.LifecycleState)
	if strings.HasPrefix(state, "Terminating") || state == "Detaching" || state == "Detached" {
		return false
	}
	if eligibleIDs != nil {
		if _, eligible := eligibleIDs[value(member.Data.InstanceId)]; !eligible {
			return false
		}
	}
	// Refresh's preferences own protection, standby and warm-pool eligibility.
	// Its explicit cohort is authoritative; Lambda still cannot escape it.
	if cause == "INSTANCE_REFRESH" && eligibleIDs != nil {
		return true
	}
	return countsCapacity(member) && (member.Data.ProtectedFromScaleIn == nil || !bool(*member.Data.ProtectedFromScaleIn))
}

// selectTerminations performs no repository writes or external effects other
// than the selection invocation. Admission must recheck the group and membership
// with terminationSelectionCurrent in its existing activity transaction.
func (s *Service) selectTerminations(ctx context.Context, group GroupRecord, members []InstanceRecord, cause string, capacity int64, eligibleIDs []string) ([]InstanceRecord, error) {
	if capacity <= 0 {
		return nil, nil
	}
	var eligible map[string]struct{}
	if eligibleIDs != nil {
		eligible = make(map[string]struct{}, len(eligibleIDs))
		for _, id := range eligibleIDs {
			eligible[id] = struct{}{}
		}
	}
	candidates := make([]InstanceRecord, 0, len(members))
	for _, member := range members {
		if terminationEligible(group, member, cause, eligible) {
			candidates = append(candidates, member)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	policies := plainList(group.Data.TerminationPolicies)
	function := lambdaTerminationPolicy(group)
	if function == "" {
		// Ordinary retirement retains one-at-a-time zone balancing; a Lambda
		// decision may intentionally override it for several instances.
		capacity = 1
	}
	if function != "" {
		if s.terminationSelector == nil {
			return nil, unsupported("Lambda custom termination execution is not configured.")
		}
		request := terminationRequest(group, members, candidates, function, cause, capacity)
		selectionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ids, err := s.terminationSelector.Select(selectionCtx, request)
		deadlineErr := selectionCtx.Err()
		cancel()
		if err != nil {
			return nil, err
		}
		if deadlineErr != nil {
			return nil, deadlineErr
		}
		if len(ids) == 0 {
			return nil, nil
		}
		eligible := make(map[string]InstanceRecord, len(candidates))
		for _, member := range candidates {
			eligible[value(member.Data.InstanceId)] = member
		}
		candidates = candidates[:0]
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			member, ok := eligible[id]
			if !ok {
				return nil, fmt.Errorf("autoscaling: Lambda termination response selected ineligible instance %q", id)
			}
			if _, duplicate := seen[id]; duplicate {
				continue
			}
			seen[id] = struct{}{}
			candidates = append(candidates, member)
		}
		policies = policies[1:]
	}
	if len(policies) == 0 {
		policies = []string{"Default"}
	}
	zones := terminationZoneCounts(members)
	now := s.clock.Now()
	slices.SortFunc(candidates, func(a, b InstanceRecord) int {
		// AZ priority shapes suggestions, not an additional restriction on the
		// function's explicitly documented ability to override suggestions.
		if function == "" {
			if difference := zones[value(b.Data.AvailabilityZone)] - zones[value(a.Data.AvailabilityZone)]; difference != 0 {
				return difference
			}
		}
		return compareTerminationPolicies(group, a, b, policies, now)
	})
	if int64(len(candidates)) > capacity {
		candidates = candidates[:capacity]
	}
	return candidates, nil
}

func terminationZoneCounts(members []InstanceRecord) map[string]int {
	zones := make(map[string]int)
	for _, member := range members {
		if countsCapacity(member) && !member.TerminationRequested {
			zones[value(member.Data.AvailabilityZone)]++
		}
	}
	return zones
}

func terminationRequest(group GroupRecord, members, candidates []InstanceRecord, function, cause string, capacity int64) TerminationPolicyRequest {
	request := TerminationPolicyRequest{FunctionARN: function, AutoScalingGroupARN: group.Key.ARN(group.ID), AutoScalingGroupName: group.Key.Name,
		Cause: cause, CapacityToTerminate: []TerminationCapacity{}, Instances: []TerminationInstance{}}
	zones := terminationZoneCounts(members)
	eligibleByZone := make(map[string]int)
	for _, member := range candidates {
		eligibleByZone[value(member.Data.AvailabilityZone)]++
	}
	names := make([]string, 0, len(eligibleByZone))
	for zone := range eligibleByZone {
		names = append(names, zone)
	}
	slices.Sort(names)
	selectedZones := make(map[string]bool)
	removals := make(map[string]int64)
	for capacity > 0 {
		highest, selected := -1, ""
		for _, zone := range names {
			if eligibleByZone[zone] > 0 && zones[zone] > highest {
				highest, selected = zones[zone], zone
			}
		}
		if selected == "" {
			break
		}
		// All equally populated eligible zones supply suggestions, even when
		// this invocation only needs one unit of capacity from that tie.
		for _, zone := range names {
			if eligibleByZone[zone] > 0 && zones[zone] == highest {
				selectedZones[zone] = true
			}
		}
		removals[selected]++
		zones[selected]--
		eligibleByZone[selected]--
		capacity--
	}
	for _, zone := range names {
		if removals[zone] > 0 {
			request.CapacityToTerminate = append(request.CapacityToTerminate, TerminationCapacity{AvailabilityZone: zone, Capacity: removals[zone], InstanceMarketOption: "on-demand"})
		}
	}
	for _, member := range candidates {
		if !selectedZones[value(member.Data.AvailabilityZone)] {
			continue
		}
		if len(request.Instances) == 30000 {
			request.HasMoreInstances = true
			break
		}
		request.Instances = append(request.Instances, TerminationInstance{AvailabilityZone: value(member.Data.AvailabilityZone), InstanceID: value(member.Data.InstanceId), InstanceType: value(member.Data.InstanceType), InstanceMarketOption: "on-demand"})
	}
	return request
}

// The original membership snapshot, not only returned IDs, fences capacity/AZ
// decisions. Repository readers order members by ID. No invocation ledger is
// needed: accepted retirement already belongs to its ordinary scaling activity.
func terminationSelectionCurrent(tx Reader, group GroupRecord, members []InstanceRecord) (bool, error) {
	current, err := tx.Group(group.Key)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if current.ID != group.ID || current.Version != group.Version {
		return false, nil
	}
	actual, err := tx.Instances(group.Key)
	if err != nil {
		return false, err
	}
	return slices.EqualFunc(actual, members, func(a, b InstanceRecord) bool { return reflect.DeepEqual(a, b) }), nil
}

// AWS records an unactionable selection as Cancelled but keeps the scale-in
// intent alive. Reuse the existing activity identity boundary, not an invocation
// ledger, so scheduler polls do not manufacture an activity every few seconds.
func (s *Service) deferLambdaTermination(tx Transaction, group GroupRecord, capacity int64) (bool, error) {
	cause := fmt.Sprintf("%s Desired capacity is %d; %d instances remain.", group.ReconcileCause, intValue(group.Data.DesiredCapacity), capacity)
	activities, err := tx.Activities(group.Key.Scope, group.Key.Name, false)
	if err != nil {
		return false, err
	}
	for _, activity := range activities {
		if activity.GroupID == group.ID && activity.Kind == "scale-in" && activity.OriginEventID == group.OriginEventID && value(activity.Data.Cause) == cause && value(activity.Data.StatusCode) == "Cancelled" {
			return false, nil
		}
	}
	message := "No terminable instances returned from the Lambda function"
	activity := s.newActivity(group, "scale-in", cause)
	text(&activity.Data.Description, "Could not terminate instances due to unactionable response from custom termination policy.  Status Reason: "+message)
	text(&activity.Data.Details, "{}")
	err = s.cancelActivity(tx.Context(), tx, group, activity, message)
	return err == nil, err
}

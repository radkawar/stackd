package integrations

import (
	"context"
	"errors"

	schedulerapi "stackd/internal/awsapi/scheduler"
	sfnapi "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/pipes"
	"stackd/internal/services/scheduler"
)

// An admitted lost reply retains only an identity proved by a current native
// authorized observation of the exact private incarnation.
func cfnWorkflowCreationFailure(ctx context.Context, r cloudformation.ResourceRequest, h cloudformation.ResourceCreationRecoverer, cause error) (cloudformation.ResourceResult, error) {
	result, err := h.RecoverCreation(ctx, r)
	if err == nil {
		return result, cause
	}
	if cfnSFNMissing(err) || cfnPipeMissing(err) {
		return cloudformation.ResourceResult{}, cause
	}
	return cloudformation.ResourceResult{}, errors.Join(cause, err)
}

func (h cfnSchedule) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name := cfnScheduleIdentity(r)
	out, err := cfnComputeCall[schedulerapi.GetScheduleOutput](scheduler.WithCloudFormationSchedule(ctx, cfnMessagingMarker(r)), h.commands, "scheduler", "GetSchedule", map[string]any{"Name": name, "GroupName": group})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnScheduleResult(r, cfnComputeValue(out.GroupName), cfnComputeValue(out.Name)), nil
}
func (h cfnScheduleGroup) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[schedulerapi.GetScheduleGroupOutput](scheduler.WithCloudFormationGroup(ctx, cfnMessagingMarker(r)), h.commands, "scheduler", "GetScheduleGroup", map[string]any{"Name": cfnComputeName(r, "Name", 64)})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnScheduleGroupResult(r, cfnComputeValue(out.Name)), nil
}
func (h cfnStateMachine) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := r.PhysicalID
	if id == "" {
		id = "arn:" + r.Scope.Partition + ":states:" + r.Scope.Region + ":" + r.Scope.Account + ":stateMachine:" + cfnSFNName(r, "StateMachineName")
	}
	out, err := h.describe(cfnSFNCreateContext(ctx, r, "StateMachine"), id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnStateMachineResult(out), nil
}
func (h cfnActivity) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := r.PhysicalID
	if id == "" {
		id = "arn:" + r.Scope.Partition + ":states:" + r.Scope.Region + ":" + r.Scope.Account + ":activity:" + cfnComputeString(r.Properties, "Name")
	}
	out, err := cfnComputeCall[sfnapi.DescribeActivityOutput](cfnSFNCreateContext(ctx, r, "Activity"), h.commands, "stepfunctions", "DescribeActivity", map[string]any{"ActivityArn": id})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnWorkflowResult(cfnComputeValue(out.ActivityArn), cfnComputeValue(out.ActivityArn), cfnComputeValue(out.ActivityArn))
	result.Attributes["Name"] = cfnComputeValue(out.Name)
	return result, nil
}
func (h cfnPipe) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := h.describe(pipes.WithCloudFormationConfiguration(ctx, pipes.CloudFormationConfiguration{Owner: cfnMessagingMarker(r)}), cfnComputeName(r, "Name", 64))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnPipeResult(r, cfnComputeValue(out.Name)), nil
}
func (h cfnStateMachineAlias) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := r.PhysicalID
	if id == "" {
		id = cfnSFNAliasMachine(r.Properties) + ":" + cfnSFNName(r, "Name")
	}
	out, err := cfnComputeCall[sfnapi.DescribeStateMachineAliasOutput](cfnSFNCreateContext(ctx, r, "StateMachineAlias"), h.commands, "stepfunctions", "DescribeStateMachineAlias", map[string]any{"StateMachineAliasArn": id})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id = cfnComputeValue(out.StateMachineAliasArn)
	return cfnWorkflowResult(id, id, id), nil
}
func (h cfnStateMachineVersion) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSFNCreateContext(ctx, r, "StateMachineVersion")
	if r.PhysicalID != "" {
		if _, err := h.Read(ctx, r); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		return cfnWorkflowResult(r.PhysicalID, r.PhysicalID, r.PhysicalID), nil
	}
	input := map[string]any{"StateMachineArn": cfnComputeString(r.Properties, "StateMachineArn")}
	for {
		out, err := cfnComputeCall[sfnapi.ListStateMachineVersionsOutput](ctx, h.commands, "stepfunctions", "ListStateMachineVersions", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		for _, row := range out.StateMachineVersions {
			rr := r
			rr.PhysicalID = cfnComputeValue(row.StateMachineVersionArn)
			if _, err := h.Read(ctx, rr); err == nil {
				return cfnWorkflowResult(rr.PhysicalID, rr.PhysicalID, rr.PhysicalID), nil
			} else if !cfnMessagingMissing(err, "ConflictException") {
				return cloudformation.ResourceResult{}, err
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			break
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
	return cloudformation.ResourceResult{}, &awswire.Error{Code: "ResourceNotFoundException", Message: "No privately owned state machine version exists.", StatusCode: 404}
}

package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/scheduler"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	sched "stackd/internal/services/scheduler"
)

// CloudFormationWorkflowHandlers delegates workflow resources to their typed owners.
// Resource schemas and return values follow the AWS CloudFormation Template Reference:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/resource-type-schemas.html
func CloudFormationWorkflowHandlers(c StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::Scheduler::Schedule":                cfnSchedule{c},
		"AWS::Scheduler::ScheduleGroup":           cfnScheduleGroup{c},
		"AWS::Pipes::Pipe":                        cfnPipe{c},
		"AWS::StepFunctions::StateMachine":        cfnStateMachine{c},
		"AWS::StepFunctions::Activity":            cfnActivity{c},
		"AWS::StepFunctions::StateMachineAlias":   cfnStateMachineAlias{c},
		"AWS::StepFunctions::StateMachineVersion": cfnStateMachineVersion{c},
		"AWS::Events::Archive":                    cfnEventArchive{c},
		"AWS::Events::Connection":                 cfnEventConnection{c},
		"AWS::Events::ApiDestination":             cfnEventAPIDestination{c},
		"AWS::Events::EventBusPolicy":             cfnEventBusPolicy{c},
		"AWS::KinesisFirehose::DeliveryStream":    cfnDeliveryStream{c},
	}
}

// Projection serializes only detached command outputs, never deployment snapshots.
func cfnWorkflowProjection(v any, keys ...string) (cloudformation.Properties, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var p map[string]any
	if err = json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	out := cloudformation.Properties{}
	for _, k := range keys {
		for name, value := range p {
			if strings.EqualFold(k, name) {
				out[k] = value
				break
			}
		}
	}
	return out, nil
}
func cfnWorkflowResult(id, ref, arn string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: id, Ref: ref, Attributes: map[string]any{"Arn": arn}}
}
func cfnWorkflowUserTags(tags map[string]string) []any {
	out := []any{}
	for _, k := range cfnMessagingKeys(tags) {
		out = append(out, map[string]any{"Key": k, "Value": tags[k]})
	}
	return out
}
func cfnWorkflowValidate(p cloudformation.Properties, required []string, allowed ...string) error {
	if err := cfnComputeProperties(p, allowed...); err != nil {
		return err
	}
	return cfnComputeRequired(p, required...)
}
func cfnWorkflowScope(ctx context.Context, r cloudformation.ResourceRequest) error {
	m := awsctx.FromContext(ctx)
	if m.Partition != r.Scope.Partition || m.AccountID != r.Scope.Account || m.Region != r.Scope.Region {
		return fmt.Errorf("workflow request scope does not match current native caller scope")
	}
	if strings.HasPrefix(r.PhysicalID, "arn:") {
		if err := cfnMessagingScopeARN(r, r.PhysicalID, "states"); err != nil {
			return err
		}
	}
	if arn := cfnComputeString(r.Properties, "StateMachineArn"); arn != "" {
		if err := cfnMessagingScopeARN(r, arn, "states"); err != nil {
			return err
		}
	}
	if r.Type == "AWS::StepFunctions::StateMachineAlias" {
		if arn := cfnSFNAliasMachine(r.Properties); arn != "" {
			if err := cfnMessagingScopeARN(r, arn, "states"); err != nil {
				return err
			}
		}
	}
	return nil
}
func cfnWorkflowTags(r cloudformation.ResourceRequest) (map[string]string, error) {
	tags, err := cfnComputeTags(r.Properties)
	if err != nil {
		return nil, err
	}
	for key, value := range r.Tags {
		if _, overridden := tags[key]; !overridden {
			tags[key] = value
		}
	}
	return tags, nil
}
func cfnWorkflowSyncTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, service, arn string, current map[string]string, mapTags bool) error {
	desired, err := cfnWorkflowTags(r)
	if err != nil {
		return err
	}
	removed := cfnComputeRemovedTags(current, desired)
	if len(removed) > 0 {
		if err = cfnComputeRun(ctx, c, service, "UntagResource", map[string]any{"ResourceArn": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	var tagInput any = cfnComputeTagList(desired)
	if mapTags {
		tagInput = desired
	}
	if len(desired) == 0 {
		return nil
	}
	return cfnComputeRun(ctx, c, service, "TagResource", map[string]any{"ResourceArn": arn, "Tags": tagInput})
}

type cfnSchedule struct{ commands StepFunctionsCommands }

func (h cfnSchedule) Validate(p cloudformation.Properties) error {
	return cfnWorkflowValidate(p, []string{"FlexibleTimeWindow", "ScheduleExpression", "Target"}, "Name", "GroupName", "Description", "EndDate", "StartDate", "FlexibleTimeWindow", "KmsKeyArn", "ScheduleExpression", "ScheduleExpressionTimezone", "State", "Target")
}
func (h cfnSchedule) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "GroupName"), h.Validate(b)
}
func cfnScheduleIdentity(r cloudformation.ResourceRequest) (string, string) {
	if group, name, ok := strings.Cut(r.PhysicalID, "|"); ok {
		return group, name
	}
	return fmt.Sprint(cfnComputeDefault(r.Properties, "GroupName", "default")), cfnComputeName(r, "Name", 64)
}
func cfnScheduleResult(r cloudformation.ResourceRequest, group, name string) cloudformation.ResourceResult {
	id := name
	if group != "default" {
		id = group + "|" + name
	}
	return cfnWorkflowResult(id, name, "arn:"+r.Scope.Partition+":scheduler:"+r.Scope.Region+":"+r.Scope.Account+":schedule/"+group+"/"+name)
}
func cfnScheduleToken(r cloudformation.ResourceRequest) string {
	return cfnMessagingHash(cfnMessagingMarker(r))
}
func cfnScheduleContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return sched.WithCloudFormationSchedule(ctx, cfnMessagingMarker(r))
}
func (h cfnSchedule) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name := cfnScheduleIdentity(r)
	result := cfnScheduleResult(r, group, name)
	input := cfnComputeCopy(r.Properties, "Description", "EndDate", "StartDate", "FlexibleTimeWindow", "KmsKeyArn", "ScheduleExpression", "ScheduleExpressionTimezone", "State", "Target")
	input["Name"] = name
	input["GroupName"] = group
	input["ClientToken"] = cfnScheduleToken(r)
	err := cfnComputeRun(sched.WithCloudFormationSchedule(ctx, cfnMessagingMarker(r)), h.commands, "scheduler", "CreateSchedule", input)
	if err != nil {
		return cfnWorkflowCreationFailure(ctx, r, h, err)
	}
	return result, nil
}
func (h cfnSchedule) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name := cfnScheduleIdentity(r)
	result := cfnScheduleResult(r, group, name)
	input := cfnComputeCopy(r.Properties, "Description", "EndDate", "StartDate", "FlexibleTimeWindow", "KmsKeyArn", "ScheduleExpression", "ScheduleExpressionTimezone", "State", "Target")
	input["Name"] = name
	input["GroupName"] = group
	return result, cfnComputeRun(cfnScheduleContext(ctx, r), h.commands, "scheduler", "UpdateSchedule", input)
}
func (h cfnSchedule) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return err
	}
	group, name := cfnScheduleIdentity(r)
	return cfnComputeAbsent(cfnComputeRun(cfnScheduleContext(ctx, r), h.commands, "scheduler", "DeleteSchedule", map[string]any{"Name": name, "GroupName": group}))
}
func (h cfnSchedule) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	group, name := cfnScheduleIdentity(r)
	out, err := cfnComputeCall[api.GetScheduleOutput](ctx, h.commands, "scheduler", "GetSchedule", map[string]any{"Name": name, "GroupName": group})
	if err != nil {
		return nil, err
	}
	return cfnWorkflowProjection(out, "Name", "GroupName", "Description", "EndDate", "StartDate", "FlexibleTimeWindow", "KmsKeyArn", "ScheduleExpression", "ScheduleExpressionTimezone", "State", "Target", "Arn")
}
func (h cfnSchedule) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListSchedulesOutput](ctx, h.commands, "scheduler", "ListSchedules", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.Schedules {
			rr := r
			name := cfnComputeValue(row.Name)
			group := cfnComputeValue(row.GroupName)
			rr.PhysicalID = cfnScheduleResult(r, group, name).PhysicalID
			p, err := h.Read(ctx, rr)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		in["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

type cfnScheduleGroup struct{ commands StepFunctionsCommands }

func (h cfnScheduleGroup) Validate(p cloudformation.Properties) error {
	if err := cfnWorkflowValidate(p, nil, "Name", "Tags"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnScheduleGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func cfnScheduleGroupResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cfnWorkflowResult(name, name, "arn:"+r.Scope.Partition+":scheduler:"+r.Scope.Region+":"+r.Scope.Account+":schedule-group/"+name)
}
func cfnScheduleGroupContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return sched.WithCloudFormationGroup(ctx, cfnMessagingMarker(r))
}
func (h cfnScheduleGroup) tags(ctx context.Context, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, h.commands, "scheduler", "ListTagsForResource", map[string]any{"ResourceArn": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, tag := range out.Tags {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}
func (h cfnScheduleGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 64)
	result := cfnScheduleGroupResult(r, name)
	tags, err := cfnWorkflowTags(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = sched.WithCloudFormationGroup(ctx, cfnMessagingMarker(r))
	err = cfnComputeRun(ctx, h.commands, "scheduler", "CreateScheduleGroup", map[string]any{"Name": name, "ClientToken": cfnScheduleToken(r), "Tags": cfnComputeTagList(tags)})
	if err != nil {
		return cfnWorkflowCreationFailure(ctx, r, h, err)
	}
	return result, nil
}
func (h cfnScheduleGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnScheduleGroupContext(ctx, r)
	result := cfnScheduleGroupResult(r, r.PhysicalID)
	arn := result.Attributes["Arn"].(string)
	tags, err := h.tags(ctx, arn)
	if err != nil {
		return result, err
	}
	return result, cfnWorkflowSyncTags(ctx, h.commands, r, "scheduler", arn, tags, false)
}
func (h cfnScheduleGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(cfnScheduleGroupContext(ctx, r), h.commands, "scheduler", "DeleteScheduleGroup", map[string]any{"Name": cfnComputeName(r, "Name", 64)}))
}
func (h cfnScheduleGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.GetScheduleGroupOutput](ctx, h.commands, "scheduler", "GetScheduleGroup", map[string]any{"Name": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	p, err := cfnWorkflowProjection(out, "Arn", "Name", "State", "CreationDate", "LastModificationDate")
	if err != nil {
		return nil, err
	}
	tags, err := h.tags(ctx, cfnComputeValue(out.Arn))
	p["Tags"] = cfnWorkflowUserTags(tags)
	return p, err
}
func (h cfnScheduleGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListScheduleGroupsOutput](ctx, h.commands, "scheduler", "ListScheduleGroups", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.ScheduleGroups {
			rr := r
			rr.PhysicalID = cfnComputeValue(row.Name)
			p, err := h.Read(ctx, rr)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: rr.PhysicalID, Properties: p})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		in["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

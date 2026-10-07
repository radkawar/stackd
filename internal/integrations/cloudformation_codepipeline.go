package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/codepipeline"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codepipeline-pipeline.html
var cfnPipelineProperties = []string{"Name", "RoleArn", "ArtifactStore", "ArtifactStores", "Stages", "ExecutionMode", "PipelineType", "Triggers", "Variables", "Tags", "DisableInboundStageTransitions", "RestartExecutionOnUpdate"}
var cfnPipelineDeclaration = []string{"Name", "RoleArn", "ArtifactStore", "ArtifactStores", "Stages", "ExecutionMode", "PipelineType", "Triggers", "Variables"}

type cfnCodePipeline struct{ commands StepFunctionsCommands }

func (h cfnCodePipeline) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnPipelineProperties...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "RoleArn", "Stages"); err != nil {
		return err
	}
	if v, ok := p["RestartExecutionOnUpdate"]; ok {
		if _, ok = v.(bool); !ok {
			return fmt.Errorf("RestartExecutionOnUpdate must be boolean")
		}
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnCodePipeline) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnCodePipeline) get(ctx context.Context, id string) (*api.GetPipelineOutput, error) {
	return cfnComputeCall[api.GetPipelineOutput](ctx, h.commands, "codepipeline", "GetPipeline", map[string]any{"name": id})
}
func (h cfnCodePipeline) tags(ctx context.Context, arn string) (map[string]string, error) {
	tags := map[string]string{}
	token := ""
	for {
		out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, h.commands, "codepipeline", "ListTagsForResource", cfnDeveloperPageInput(token, map[string]any{"resourceArn": arn}))
		if err != nil {
			return nil, err
		}
		for _, t := range out.Tags {
			tags[cfnComputeValue(t.Key)] = cfnComputeValue(t.Value)
		}
		next := cfnComputeValue(out.NextToken)
		if next == "" {
			return tags, nil
		}
		if next == token {
			return nil, fmt.Errorf("CodePipeline tag pagination did not advance")
		}
		token = next
	}
}
func cfnPipelineResult(p *api.PipelineDeclaration, arn string) cloudformation.ResourceResult {
	id := cfnComputeValue(p.Name)
	var version any
	if p.Version != nil {
		version = int32(*p.Version)
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": arn, "Version": version}}
}
func cfnPipelineARN(r cloudformation.ResourceRequest, id string) string {
	return "arn:" + r.Scope.Partition + ":codepipeline:" + r.Scope.Region + ":" + r.Scope.Account + ":" + id
}
func cfnPipelineDeclarationInput(p cloudformation.Properties, id string) map[string]any {
	in := cfnDeveloperInput(p, cfnPipelineDeclaration...)
	in["name"] = id
	in["executionMode"] = cfnComputeDefault(p, "ExecutionMode", "SUPERSEDED")
	if v, ok := p["ArtifactStores"].([]any); ok {
		stores := map[string]any{}
		for _, raw := range v {
			row, _ := cfnComputeObject(raw)
			stores[cfnComputeString(row, "Region")] = cfnDeveloperWire(row["ArtifactStore"])
		}
		in["artifactStores"] = stores
	}
	return in
}
func (h cfnCodePipeline) transitions(ctx context.Context, r cloudformation.ResourceRequest, id string) error {
	desired := map[string]any{}
	if raw, ok := r.Properties["DisableInboundStageTransitions"].([]any); ok {
		for _, v := range raw {
			p, ok := cfnComputeObject(v)
			if !ok {
				return fmt.Errorf("stage transitions must be objects")
			}
			desired[cfnComputeString(p, "StageName")] = p["Reason"]
		}
	}
	state, err := cfnComputeCall[api.GetPipelineStateOutput](ctx, h.commands, "codepipeline", "GetPipelineState", map[string]any{"name": id})
	if err != nil {
		return err
	}
	for _, s := range state.StageStates {
		name := cfnComputeValue(s.StageName)
		reason, disable := desired[name]
		in := map[string]any{"pipelineName": id, "stageName": name, "transitionType": "Inbound"}
		op := "EnableStageTransition"
		if disable {
			op = "DisableStageTransition"
			in["reason"] = reason
		}
		if !disable && (s.InboundTransitionState == nil || s.InboundTransitionState.Enabled == nil || bool(*s.InboundTransitionState.Enabled)) {
			continue
		}
		if err = cfnComputeRun(ctx, h.commands, "codepipeline", op, in); err != nil {
			return err
		}
		delete(desired, name)
	}
	if len(desired) > 0 {
		return fmt.Errorf("disabled transition names an absent stage")
	}
	return nil
}
func (h cfnCodePipeline) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeName(r, "Name", 100)
	arn := cfnPipelineARN(r, id)
	rows := map[string]string{}
	ctx = codepipeline.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), id, false, rows)
	_, err := h.get(ctx, id)
	if err == nil {
		if rows[id] != cfnDeveloperClaim(r) {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("pipeline belongs to another incarnation"))
		}
		ctx = codepipeline.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), id, true, nil)
		p, err := h.get(ctx, id)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		result := cfnPipelineResult(p.Pipeline, arn)
		return result, h.transitions(ctx, r, id)
	}
	if !cfnMessagingMissing(err, "PipelineNotFoundException") {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.CreatePipelineOutput](ctx, h.commands, "codepipeline", "CreatePipeline", map[string]any{"pipeline": cfnPipelineDeclarationInput(r.Properties, id), "tags": cfnECRTags(cfnResourceTags(r))})
	if err != nil {
		if admitted, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	result := cfnPipelineResult(out.Pipeline, arn)
	ctx = codepipeline.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), id, true, nil)
	return result, h.transitions(ctx, r, id)
}
func (h cfnCodePipeline) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id := cfnComputeName(r, "Name", 100)
	ctx = codepipeline.WithCloudFormationOwnership(ctx, cfnDeveloperClaim(r), id, true, nil)
	p, err := h.get(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnPipelineResult(p.Pipeline, cfnComputeValue(p.Metadata.PipelineArn)), nil
}
func (h cfnCodePipeline) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnDeveloperPipelineUpdateContext(ctx, r)
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnComputeValue(p.Metadata.PipelineArn)
	tags, err := h.tags(ctx, arn)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.UpdatePipelineOutput](ctx, h.commands, "codepipeline", "UpdatePipeline", map[string]any{"pipeline": cfnPipelineDeclarationInput(r.Properties, r.PhysicalID)})
	result := cfnPipelineResult(p.Pipeline, arn)
	if err != nil {
		return result, err
	}
	result = cfnPipelineResult(out.Pipeline, arn)
	desired := cfnResourceTags(r)
	if removed := cfnComputeRemovedTags(tags, desired); len(removed) > 0 {
		if err = cfnComputeRun(ctx, h.commands, "codepipeline", "UntagResource", map[string]any{"resourceArn": arn, "tagKeys": removed}); err != nil {
			return result, err
		}
	}
	if len(desired) > 0 {
		if err = cfnComputeRun(ctx, h.commands, "codepipeline", "TagResource", map[string]any{"resourceArn": arn, "tags": cfnECRTags(desired)}); err != nil {
			return result, err
		}
	}
	if err = h.transitions(ctx, r, r.PhysicalID); err != nil {
		return result, err
	}
	if restart, _ := r.Properties["RestartExecutionOnUpdate"].(bool); restart {
		err = cfnComputeRun(ctx, h.commands, "codepipeline", "StartPipelineExecution", map[string]any{"name": r.PhysicalID, "clientRequestToken": cfnComputeHash(r.Token + fmt.Sprint(*out.Pipeline.Version))})
	}
	return result, err
}
func (h cfnCodePipeline) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnDeveloperPipelineContext(ctx, r)
	_, err := h.get(ctx, r.PhysicalID)
	if cfnMessagingMissing(err, "PipelineNotFoundException") {
		return nil
	}
	if err != nil {
		return err
	}
	return cfnComputeRun(ctx, h.commands, "codepipeline", "DeletePipeline", map[string]any{"name": r.PhysicalID})
}
func (h cfnCodePipeline) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	p, err := h.get(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	out, err := cfnDeveloperModel(p.Pipeline, cfnPipelineDeclaration...)
	if err != nil {
		return nil, err
	}
	if stores, ok := out["ArtifactStores"].(map[string]any); ok {
		var list []any
		for region, store := range stores {
			list = append(list, map[string]any{"Region": region, "ArtifactStore": store})
		}
		out["ArtifactStores"] = list
	}
	arn := cfnComputeValue(p.Metadata.PipelineArn)
	tags, err := h.tags(ctx, arn)
	if err != nil {
		return nil, err
	}
	out["Tags"] = cfnComputeTagList(tags)
	out["Arn"] = arn
	out["Version"] = p.Pipeline.Version
	state, err := cfnComputeCall[api.GetPipelineStateOutput](ctx, h.commands, "codepipeline", "GetPipelineState", map[string]any{"name": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	var disabled []any
	for _, s := range state.StageStates {
		if t := s.InboundTransitionState; t != nil && t.Enabled != nil && !bool(*t.Enabled) {
			disabled = append(disabled, map[string]any{"StageName": cfnComputeValue(s.StageName), "Reason": cfnComputeValue(t.DisabledReason)})
		}
	}
	out["DisableInboundStageTransitions"] = disabled
	return out, nil
}
func (h cfnCodePipeline) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var rows []cloudformation.ResourceDescription
	token := ""
	for {
		out, err := cfnComputeCall[api.ListPipelinesOutput](ctx, h.commands, "codepipeline", "ListPipelines", cfnDeveloperPageInput(token, map[string]any{}))
		if err != nil {
			return nil, err
		}
		for _, p := range out.Pipelines {
			r.PhysicalID = cfnComputeValue(p.Name)
			model, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: model})
		}
		next := cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
		if next == token {
			return nil, fmt.Errorf("CodePipeline pagination did not advance")
		}
		token = next
	}
}

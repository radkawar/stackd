package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	api "stackd/internal/awsapi/pipes"
	"stackd/internal/services/cloudformation"
	pipes "stackd/internal/services/pipes"
)

// Pipe configuration and asynchronous source activation remain owned by Pipes.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-pipes-pipe.html
type cfnPipe struct{ commands StepFunctionsCommands }

func cfnPipeMissing(err error) bool {
	return cfnComputeMissing(err) || cfnMessagingMissing(err, "NotFoundException")
}
func cfnPipeAbsent(err error) error {
	if cfnPipeMissing(err) {
		return nil
	}
	return err
}
func cfnPipeContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	owner := ""
	if !r.CloudControl {
		owner = cfnMessagingMarker(r)
	}
	return pipes.WithCloudFormationConfiguration(ctx, pipes.CloudFormationConfiguration{Owner: owner})
}
func (h cfnPipe) Validate(p cloudformation.Properties) error {
	if err := cfnWorkflowValidate(p, []string{"RoleArn", "Source", "Target"}, "Name", "Description", "DesiredState", "Enrichment", "EnrichmentParameters", "KmsKeyIdentifier", "LogConfiguration", "RoleArn", "Source", "SourceParameters", "Tags", "Target", "TargetParameters"); err != nil {
		return err
	}
	if tags, ok := p["Tags"]; ok {
		if _, ok = tags.(map[string]any); !ok {
			return fmt.Errorf("tags must be an object")
		}
	}
	return nil
}
func (h cfnPipe) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	if cfnComputeChanged(a, b, "Name", "Source") {
		return true, nil
	}
	for _, kind := range []string{"DynamoDBStreamParameters", "KinesisStreamParameters", "ManagedStreamingKafkaParameters", "SelfManagedKafkaParameters"} {
		pa, _ := cfnComputeObject(a["SourceParameters"])
		pb, _ := cfnComputeObject(b["SourceParameters"])
		va, _ := cfnComputeObject(pa[kind])
		vb, _ := cfnComputeObject(pb[kind])
		for _, key := range []string{"StartingPosition", "StartingPositionTimestamp", "ConsumerGroupID", "TopicName", "AdditionalBootstrapServers"} {
			if !reflect.DeepEqual(va[key], vb[key]) {
				return true, nil
			}
		}
	}
	return false, nil
}
func cfnPipeTags(r cloudformation.ResourceRequest) (map[string]string, error) {
	rr := r
	p := cloudformation.Properties{}
	list := []any{}
	if raw, ok := r.Properties["Tags"]; ok {
		tags, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tags must be an object")
		}
		for _, k := range cfnMessagingKeys(tags) {
			list = append(list, map[string]any{"Key": k, "Value": tags[k]})
		}
	}
	p["Tags"] = list
	rr.Properties = p
	return cfnWorkflowTags(rr)
}
func cfnPipeResult(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cfnWorkflowResult(name, name, "arn:"+r.Scope.Partition+":pipes:"+r.Scope.Region+":"+r.Scope.Account+":pipe/"+name)
}
func (h cfnPipe) describe(ctx context.Context, name string) (*api.DescribePipeOutput, error) {
	return cfnComputeCall[api.DescribePipeOutput](ctx, h.commands, "pipes", "DescribePipe", map[string]any{"Name": name})
}
func cfnPipeTagMap(tags api.TagMap) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		out[string(k)] = string(v)
	}
	return out
}
func (h cfnPipe) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = pipes.WithCloudFormationConfiguration(ctx, pipes.CloudFormationConfiguration{Owner: cfnMessagingMarker(r)})
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 64)
	result := cfnPipeResult(r, name)
	_, err := h.describe(ctx, name)
	if err == nil {
		return result, nil
	}
	if !cfnPipeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "DesiredState", "Enrichment", "EnrichmentParameters", "KmsKeyIdentifier", "LogConfiguration", "RoleArn", "Source", "SourceParameters", "Target", "TargetParameters")
	input["Name"] = name
	input["Tags"], err = cfnPipeTags(r)
	if err != nil {
		return result, err
	}
	if err = cfnComputeRun(ctx, h.commands, "pipes", "CreatePipe", input); err != nil {
		return cfnWorkflowCreationFailure(ctx, r, h, err)
	}
	return result, nil
}
func (h cfnPipe) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnPipeContext(ctx, r)
	result := cfnPipeResult(r, r.PhysicalID)
	old, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	input := cfnComputeCopy(r.Properties, "RoleArn", "Target")
	input["Name"] = r.PhysicalID
	input["TargetParameters"] = cfnComputeDefault(r.Properties, "TargetParameters", map[string]any{})
	for k, v := range map[string]any{"Description": "", "DesiredState": "RUNNING", "Enrichment": "", "EnrichmentParameters": map[string]any{"InputTemplate": ""}, "KmsKeyIdentifier": "", "LogConfiguration": map[string]any{"Level": "OFF"}} {
		input[k] = cfnComputeDefault(r.Properties, k, v)
	}
	var source *api.PipeSourceParameters
	raw, err := json.Marshal(r.Properties["SourceParameters"])
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(raw, &source); err != nil {
		return result, err
	}
	var mutable api.UpdatePipeSourceParameters
	if err = json.Unmarshal(raw, &mutable); err != nil {
		return result, err
	}
	input["SourceParameters"] = &mutable
	owner := ""
	if !r.CloudControl {
		owner = cfnMessagingMarker(r)
	}
	ctx = pipes.WithCloudFormationConfiguration(ctx, pipes.CloudFormationConfiguration{Owner: owner, ReplaceSource: true, Source: source, ReplaceEnrichment: true})
	if err = cfnComputeRun(ctx, h.commands, "pipes", "UpdatePipe", input); err != nil {
		return result, err
	}
	desired, err := cfnPipeTags(r)
	if err != nil {
		return result, err
	}
	current := cfnPipeTagMap(old.Tags)
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err = cfnComputeRun(ctx, h.commands, "pipes", "UntagResource", map[string]any{"ResourceArn": cfnComputeValue(old.Arn), "TagKeys": removed}); err != nil {
			return result, err
		}
	}
	if len(desired) == 0 {
		return result, nil
	}
	return result, cfnComputeRun(ctx, h.commands, "pipes", "TagResource", map[string]any{"ResourceArn": cfnComputeValue(old.Arn), "Tags": desired})
}
func (h cfnPipe) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return err
	}
	name := cfnComputeName(r, "Name", 64)
	return cfnPipeAbsent(cfnComputeRun(cfnPipeContext(ctx, r), h.commands, "pipes", "DeletePipe", map[string]any{"Name": name}))
}
func (h cfnPipe) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnWorkflowProjection(out, "Arn", "CreationTime", "CurrentState", "Description", "DesiredState", "Enrichment", "EnrichmentParameters", "KmsKeyIdentifier", "LastModifiedTime", "LogConfiguration", "Name", "RoleArn", "Source", "SourceParameters", "StateReason", "Target", "TargetParameters")
	tags := map[string]any{}
	for k, v := range cfnPipeTagMap(out.Tags) {
		tags[k] = v
	}
	p["Tags"] = tags
	return p, err
}
func (h cfnPipe) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListPipesOutput](ctx, h.commands, "pipes", "ListPipes", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.Pipes {
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
func (h cfnPipe) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	state := cfnComputeValue(out.CurrentState)
	if state == "CREATE_FAILED" || state == "UPDATE_FAILED" || state == "START_FAILED" || state == "STOP_FAILED" {
		return false, fmt.Errorf("pipe %s: %s", state, cfnComputeValue(out.StateReason))
	}
	return state == cfnComputeValue(out.DesiredState), nil
}
func (h cfnPipe) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.describe(ctx, r.PhysicalID)
	if cfnPipeMissing(err) {
		return true, nil
	}
	return false, err
}

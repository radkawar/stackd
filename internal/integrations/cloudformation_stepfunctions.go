package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	s3api "stackd/internal/awsapi/s3"
	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/cloudformation"
	sfn "stackd/internal/services/stepfunctions"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-stepfunctions-statemachine.html
type cfnStateMachine struct{ commands StepFunctionsCommands }

func cfnSFNContext(ctx context.Context, r cloudformation.ResourceRequest, kind string) context.Context {
	if r.CloudControl {
		return ctx
	}
	return sfn.WithCloudFormationOwner(ctx, kind, cfnMessagingMarker(r))
}
func cfnSFNMissing(err error) bool {
	return cfnComputeMissing(err) || cfnMessagingMissing(err, "StateMachineDoesNotExist", "ActivityDoesNotExist")
}
func cfnSFNAbsent(err error) error {
	if cfnSFNMissing(err) {
		return nil
	}
	return err
}
func (h cfnStateMachine) Validate(p cloudformation.Properties) error {
	if err := cfnWorkflowValidate(p, []string{"RoleArn"}, "Definition", "DefinitionString", "DefinitionS3Location", "DefinitionSubstitutions", "EncryptionConfiguration", "LoggingConfiguration", "RoleArn", "StateMachineName", "StateMachineType", "Tags", "TracingConfiguration"); err != nil {
		return err
	}
	n := 0
	for _, k := range []string{"Definition", "DefinitionString", "DefinitionS3Location"} {
		if p[k] != nil {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("exactly one Definition, DefinitionString or DefinitionS3Location is required")
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnStateMachine) Replacement(a, b cloudformation.Properties) (bool, error) {
	changed := cfnComputeChanged(a, b, "StateMachineName", "StateMachineType")
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnMessagingReplacement(cfnComputeString(a, "StateMachineName") != "" && a["StateMachineName"] == b["StateMachineName"], changed)
}

var cfnDefinitionVariable = regexp.MustCompile(`\$\{([^}]+)\}`)

func (h cfnStateMachine) definition(ctx context.Context, p cloudformation.Properties) (string, error) {
	text := cfnComputeString(p, "DefinitionString")
	if v := p["Definition"]; v != nil {
		var err error
		text, err = cfnComputeDocument(v)
		if err != nil {
			return "", err
		}
	}
	if v := p["DefinitionS3Location"]; v != nil {
		location, ok := cfnComputeObject(v)
		if !ok {
			return "", fmt.Errorf("DefinitionS3Location must be an object")
		}
		provider, ok := h.commands.providers["s3"]
		if !ok {
			return "", fmt.Errorf("S3 object owner unavailable")
		}
		source, ok := provider.executor.(CloudFormationTemplateObjects)
		if !ok {
			return "", fmt.Errorf("S3 object reader unavailable")
		}
		in := &s3api.GetObjectInput{Bucket: new(s3api.BucketName(cfnComputeString(location, "Bucket"))), Key: new(s3api.ObjectKey(cfnComputeString(location, "Key")))}
		if version := cfnComputeString(location, "Version"); version != "" {
			in.VersionId = new(s3api.ObjectVersionId(version))
		}
		out, wire := source.GetObject(ctx, in)
		if wire != nil {
			return "", wire
		}
		text = string(out.Output.Body)
		if !json.Valid([]byte(text)) {
			var object any
			if err := yaml.Unmarshal([]byte(text), &object); err != nil {
				return "", err
			}
			raw, err := json.Marshal(object)
			if err != nil {
				return "", err
			}
			text = string(raw)
		}
	}
	if len(text) > 1048576 {
		return "", fmt.Errorf("state machine definition exceeds 1048576 bytes")
	}
	if substitutions, ok := cfnComputeObject(p["DefinitionSubstitutions"]); ok {
		var substituteErr error
		text = cfnDefinitionVariable.ReplaceAllStringFunc(text, func(match string) string {
			keys := strings.Split(match[2:len(match)-1], ",")
			var b strings.Builder
			for _, key := range keys {
				value, ok := substitutions[key].(string)
				if !ok {
					substituteErr = fmt.Errorf("missing definition substitution %s", key)
					return match
				}
				b.WriteString(value)
			}
			return b.String()
		})
		if substituteErr != nil {
			return "", substituteErr
		}
	}
	if !json.Valid([]byte(text)) {
		return "", fmt.Errorf("invalid state machine definition JSON")
	}
	return text, nil
}
func cfnStateMachineResult(out *api.DescribeStateMachineOutput) cloudformation.ResourceResult {
	id := cfnComputeValue(out.StateMachineArn)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Arn": id, "Name": cfnComputeValue(out.Name), "StateMachineRevisionId": cfnComputeValue(out.RevisionId)}}
}
func (h cfnStateMachine) describe(ctx context.Context, id string) (*api.DescribeStateMachineOutput, error) {
	return cfnComputeCall[api.DescribeStateMachineOutput](ctx, h.commands, "stepfunctions", "DescribeStateMachine", map[string]any{"StateMachineArn": id})
}
func cfnSFNTags(ctx context.Context, c StepFunctionsCommands, id string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsForResourceOutput](ctx, c, "stepfunctions", "ListTagsForResource", map[string]any{"ResourceArn": id})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for _, tag := range out.Tags {
		tags[cfnComputeValue(tag.Key)] = cfnComputeValue(tag.Value)
	}
	return tags, nil
}
func (h cfnStateMachine) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSFNCreateContext(ctx, r, "StateMachine")
	name := cfnSFNName(r, "StateMachineName")
	id := "arn:" + r.Scope.Partition + ":states:" + r.Scope.Region + ":" + r.Scope.Account + ":stateMachine:" + name
	old, err := h.describe(ctx, id)
	if err == nil {
		return cfnStateMachineResult(old), nil
	}
	if !cfnSFNMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	definition, err := h.definition(ctx, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags, err := cfnWorkflowTags(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "RoleArn", "LoggingConfiguration", "TracingConfiguration", "EncryptionConfiguration")
	input["Name"] = name
	input["Type"] = cfnComputeDefault(r.Properties, "StateMachineType", "STANDARD")
	input["Definition"] = definition
	input["Tags"] = cfnComputeTagList(tags)
	out, err := cfnComputeCall[api.CreateStateMachineOutput](cfnSFNCreateContext(ctx, r, "StateMachine"), h.commands, "stepfunctions", "CreateStateMachine", input)
	if err != nil {
		return cfnWorkflowCreationFailure(ctx, r, h, err)
	}
	live, err := h.describe(ctx, cfnComputeValue(out.StateMachineArn))
	if err != nil {
		id := cfnComputeValue(out.StateMachineArn)
		return cfnWorkflowResult(id, id, id), err
	}
	return cfnStateMachineResult(live), nil
}
func (h cfnStateMachine) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSFNContext(ctx, r, "StateMachine")
	definition, err := h.definition(ctx, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := map[string]any{"StateMachineArn": r.PhysicalID, "Definition": definition, "RoleArn": r.Properties["RoleArn"], "LoggingConfiguration": cfnComputeDefault(r.Properties, "LoggingConfiguration", map[string]any{"Level": "OFF"}), "TracingConfiguration": cfnComputeDefault(r.Properties, "TracingConfiguration", map[string]any{"Enabled": false}), "EncryptionConfiguration": cfnComputeDefault(r.Properties, "EncryptionConfiguration", map[string]any{"Type": "AWS_OWNED_KEY"})}
	if err = cfnComputeRun(ctx, h.commands, "stepfunctions", "UpdateStateMachine", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	current, err := cfnSFNTags(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnWorkflowSyncTags(ctx, h.commands, r, "stepfunctions", r.PhysicalID, current, false); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.Result(ctx, r)
}
func (h cfnStateMachine) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return err
	}
	return cfnSFNAbsent(cfnComputeRun(cfnSFNContext(ctx, r, "StateMachine"), h.commands, "stepfunctions", "DeleteStateMachine", map[string]any{"StateMachineArn": r.PhysicalID}))
}
func (h cfnStateMachine) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnStateMachineResult(out), nil
}
func (h cfnStateMachine) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p, err := cfnSFNProjection(out, "RoleArn", "LoggingConfiguration", "TracingConfiguration", "EncryptionConfiguration")
	if err != nil {
		return nil, err
	}
	p["Arn"] = cfnComputeValue(out.StateMachineArn)
	p["StateMachineName"] = cfnComputeValue(out.Name)
	p["StateMachineType"] = cfnComputeValue(out.Type)
	p["StateMachineRevisionId"] = cfnComputeValue(out.RevisionId)
	p["DefinitionString"] = cfnComputeValue(out.Definition)
	tags, err := cfnSFNTags(ctx, h.commands, r.PhysicalID)
	p["Tags"] = cfnWorkflowUserTags(tags)
	return p, err
}
func (h cfnStateMachine) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListStateMachinesOutput](ctx, h.commands, "stepfunctions", "ListStateMachines", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.StateMachines {
			rr := r
			rr.PhysicalID = cfnComputeValue(row.StateMachineArn)
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
func (h cfnStateMachine) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.describe(ctx, r.PhysicalID)
	if cfnSFNMissing(err) {
		return true, nil
	}
	return false, err
}

type cfnActivity struct{ commands StepFunctionsCommands }

func (h cfnActivity) Validate(p cloudformation.Properties) error {
	if err := cfnWorkflowValidate(p, []string{"Name"}, "Name", "Tags", "EncryptionConfiguration"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnActivity) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "EncryptionConfiguration"), h.Validate(b)
}
func (h cfnActivity) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Name", "EncryptionConfiguration")
	tags, err := cfnWorkflowTags(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input["Tags"] = cfnComputeTagList(tags)
	out, err := cfnComputeCall[api.CreateActivityOutput](cfnSFNCreateContext(ctx, r, "Activity"), h.commands, "stepfunctions", "CreateActivity", input)
	if err != nil {
		return cfnWorkflowCreationFailure(ctx, r, h, err)
	}
	id := cfnComputeValue(out.ActivityArn)
	result := cfnWorkflowResult(id, id, id)
	result.Attributes["Name"] = r.Properties["Name"]
	return result, nil
}
func (h cfnActivity) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnSFNContext(ctx, r, "Activity")
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	tags, err := cfnSFNTags(ctx, h.commands, r.PhysicalID)
	result := cfnWorkflowResult(r.PhysicalID, r.PhysicalID, r.PhysicalID)
	result.Attributes["Name"] = r.Properties["Name"]
	if err != nil {
		return result, err
	}
	return result, cfnWorkflowSyncTags(cfnSFNContext(ctx, r, "Activity"), h.commands, r, "stepfunctions", r.PhysicalID, tags, false)
}
func (h cfnActivity) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnWorkflowScope(ctx, r); err != nil {
		return err
	}
	return cfnSFNAbsent(cfnComputeRun(cfnSFNContext(ctx, r, "Activity"), h.commands, "stepfunctions", "DeleteActivity", map[string]any{"ActivityArn": r.PhysicalID}))
}
func (h cfnActivity) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := cfnComputeCall[api.DescribeActivityOutput](ctx, h.commands, "stepfunctions", "DescribeActivity", map[string]any{"ActivityArn": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	p, err := cfnSFNProjection(out, "Name", "EncryptionConfiguration")
	if err != nil {
		return nil, err
	}
	p["Arn"] = cfnComputeValue(out.ActivityArn)
	tags, err := cfnSFNTags(ctx, h.commands, r.PhysicalID)
	p["Tags"] = cfnWorkflowUserTags(tags)
	return p, err
}
func (h cfnActivity) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListActivitiesOutput](ctx, h.commands, "stepfunctions", "ListActivities", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.Activities {
			rr := r
			rr.PhysicalID = cfnComputeValue(row.ActivityArn)
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

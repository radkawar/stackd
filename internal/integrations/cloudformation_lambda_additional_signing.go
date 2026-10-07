package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

type cfnLambdaCodeSigningConfig struct{ commands StepFunctionsCommands }

func cfnLambdaCodeSigningInput(p cloudformation.Properties) (*api.CreateCodeSigningConfigInput, error) {
	if err := cfnComputeProperties(p, "AllowedPublishers", "CodeSigningPolicies", "Description", "Tags"); err != nil {
		return nil, err
	}
	if _, err := cfnLambdaAdditionalTagProperties(p); err != nil {
		return nil, err
	}
	var in api.CreateCodeSigningConfigInput
	if err := cfnMessagingDecode(cfnComputeCopy(p, "AllowedPublishers", "CodeSigningPolicies", "Description"), &in); err != nil {
		return nil, err
	}
	if in.AllowedPublishers == nil || len(in.AllowedPublishers.SigningProfileVersionArns) < 1 || len(in.AllowedPublishers.SigningProfileVersionArns) > 20 {
		return nil, fmt.Errorf("AllowedPublishers requires 1 to 20 SigningProfileVersionArns")
	}
	if in.CodeSigningPolicies == nil {
		in.CodeSigningPolicies = &api.CodeSigningPolicies{UntrustedArtifactOnDeployment: new(api.CodeSigningPolicy("Warn"))}
	}
	policy := cfnComputeValue(in.CodeSigningPolicies.UntrustedArtifactOnDeployment)
	if policy != "Warn" && policy != "Enforce" {
		return nil, fmt.Errorf("UntrustedArtifactOnDeployment must be Warn or Enforce")
	}
	if in.Description == nil {
		in.Description = new(api.Description(""))
	}
	if len(*in.Description) > 256 {
		return nil, fmt.Errorf("description must not exceed 256 characters")
	}
	return &in, nil
}
func (h cfnLambdaCodeSigningConfig) Validate(p cloudformation.Properties) error {
	_, err := cfnLambdaCodeSigningInput(p)
	return err
}
func (h cfnLambdaCodeSigningConfig) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func cfnLambdaCodeSigningResult(out *api.CodeSigningConfig) (cloudformation.ResourceResult, error) {
	if out == nil {
		return cloudformation.ResourceResult{}, fmt.Errorf("lambda returned no CodeSigningConfig")
	}
	id := cfnComputeValue(out.CodeSigningConfigArn)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"CodeSigningConfigArn": id, "CodeSigningConfigId": cfnComputeValue(out.CodeSigningConfigId)}}, nil
}
func (h cfnLambdaCodeSigningConfig) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := cfnLambdaCodeSigningInput(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in.Tags, err = cfnLambdaAdditionalAPITags(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnMessagingCall[api.CreateCodeSigningConfigOutput](cfnLambdaAdditionalContext(ctx, r, true), h.commands, "lambda", "CreateCodeSigningConfig", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaCodeSigningResult(out.CodeSigningConfig)
}
func (h cfnLambdaCodeSigningConfig) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	properties, err := cfnLambdaCodeSigningInput(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnLambdaAdditionalContext(ctx, r, false)
	in := &api.UpdateCodeSigningConfigInput{CodeSigningConfigArn: new(api.CodeSigningConfigArn(r.PhysicalID)), AllowedPublishers: properties.AllowedPublishers, CodeSigningPolicies: properties.CodeSigningPolicies, Description: properties.Description}
	out, err := cfnMessagingCall[api.UpdateCodeSigningConfigOutput](ctx, h.commands, "lambda", "UpdateCodeSigningConfig", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnLambdaAdditionalUpdateTags(ctx, h.commands, r, r.PhysicalID); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaCodeSigningResult(out.CodeSigningConfig)
}
func (h cfnLambdaCodeSigningConfig) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnComputeAbsent(cfnMessagingExec(cfnLambdaAdditionalContext(ctx, r, false), h.commands, "lambda", "DeleteCodeSigningConfig", &api.DeleteCodeSigningConfigInput{CodeSigningConfigArn: new(api.CodeSigningConfigArn(r.PhysicalID))}))
}
func (h cfnLambdaCodeSigningConfig) model(ctx context.Context, config *api.CodeSigningConfig) (cloudformation.Properties, error) {
	if config == nil {
		return nil, fmt.Errorf("lambda returned no CodeSigningConfig")
	}
	properties, err := cfnLambdaAdditionalProperties(config)
	if err != nil {
		return nil, err
	}
	delete(properties, "LastModified")
	tags, err := cfnLambdaAdditionalTags(ctx, h.commands, cfnComputeValue(config.CodeSigningConfigArn))
	if err != nil {
		return nil, err
	}
	properties["Tags"] = cfnResourcePublicTags(tags)
	return properties, nil
}
func (h cfnLambdaCodeSigningConfig) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnLambdaAdditionalContext(ctx, r, false)
	out, err := cfnMessagingCall[api.GetCodeSigningConfigOutput](ctx, h.commands, "lambda", "GetCodeSigningConfig", &api.GetCodeSigningConfigInput{CodeSigningConfigArn: new(api.CodeSigningConfigArn(r.PhysicalID))})
	if err != nil {
		return nil, err
	}
	return h.model(ctx, out.CodeSigningConfig)
}
func (h cfnLambdaCodeSigningConfig) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	in := &api.ListCodeSigningConfigsInput{}
	rows := []cloudformation.ResourceDescription{}
	for {
		out, err := cfnMessagingCall[api.ListCodeSigningConfigsOutput](ctx, h.commands, "lambda", "ListCodeSigningConfigs", in)
		if err != nil {
			return nil, err
		}
		for _, config := range out.CodeSigningConfigs {
			properties, err := h.model(ctx, &config)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: cfnComputeValue(config.CodeSigningConfigArn), Properties: properties})
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return rows, nil
		}
		in.Marker = out.NextMarker
	}
}

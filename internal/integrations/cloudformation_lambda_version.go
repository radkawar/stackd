package integrations

import (
	"context"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
)

type cfnLambdaVersion struct{ commands StepFunctionsCommands }

func (h cfnLambdaVersion) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "FunctionName", "CodeSha256", "Description", "ProvisionedConcurrencyConfig", "RuntimePolicy", "FunctionScalingConfig"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "FunctionName"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "FunctionName", "CodeSha256", "Description"); err != nil {
		return err
	}
	if _, _, err := cfnLambdaProvisioned(p); err != nil {
		return err
	}
	if _, err := cfnLambdaVersionRuntime(p); err != nil {
		return err
	}
	_, err := cfnLambdaVersionScaling(p)
	return err
}

func (h cfnLambdaVersion) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "FunctionName", "CodeSha256", "Description", "ProvisionedConcurrencyConfig", "RuntimePolicy"), h.Validate(b)
}

func cfnLambdaVersionContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return lambda.WithVersionOwner(ctx, lambda.VersionOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

func cfnLambdaVersionIdentity(r cloudformation.ResourceRequest) (string, string, error) {
	function, qualifier, err := cfnLambdaQualifiedIdentity(r)
	if err != nil {
		return "", "", err
	}
	version, err := strconv.ParseUint(qualifier, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != qualifier {
		return "", "", fmt.Errorf("identifier must be a published Lambda version ARN")
	}
	return function, qualifier, nil
}

func cfnLambdaVersionResult(r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	_, version, err := cfnLambdaVersionIdentity(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{"FunctionArn": r.PhysicalID, "Version": version}}, nil
}

func (h cfnLambdaVersion) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	published, err := cfnComputeCall[api.PublishVersionOutput](cfnLambdaVersionContext(ctx, r), h.commands, "lambda", "PublishVersion", cfnComputeCopy(r.Properties, "FunctionName", "CodeSha256", "Description"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeValue(published.FunctionArn)
	result, err := cfnLambdaVersionResult(r)
	if err != nil {
		return result, err
	}
	return result, h.scaling(ctx, r)
}

func (h cfnLambdaVersion) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	// Only scaling changes in place; publication properties replace the version.
	result, err := cfnLambdaVersionResult(r)
	if err != nil {
		return result, err
	}
	return result, h.scaling(ctx, r)
}

func (h cfnLambdaVersion) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	_, err := h.StabilizeDeletion(ctx, r)
	return err
}

func (h cfnLambdaVersion) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	function, version, err := cfnLambdaVersionIdentity(r)
	if err != nil {
		return false, err
	}
	err = cfnComputeAbsent(cfnComputeRun(cfnLambdaVersionContext(ctx, r), h.commands, "lambda", "DeleteFunction", map[string]any{"FunctionName": function, "Qualifier": version}))
	// Native stack deletion stays pending while an alias references the
	// publication. Each retry rechecks current ownership and IAM authority.
	if cfnMessagingMissing(err, "ResourceConflictException") {
		return false, nil
	}
	return err == nil, err
}

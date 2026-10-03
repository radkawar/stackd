package integrations

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
)

type cfnLambdaLayerVersion struct{ commands StepFunctionsCommands }

func (h cfnLambdaLayerVersion) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "LayerName", "Content", "Description", "LicenseInfo", "CompatibleArchitectures", "CompatibleRuntimes"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Content"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "LayerName", "Description", "LicenseInfo"); err != nil {
		return err
	}
	for _, property := range []string{"CompatibleArchitectures", "CompatibleRuntimes"} {
		if _, err := cfnComputeStringList(p, property); err != nil {
			return err
		}
	}
	content, ok := cfnComputeObject(p["Content"])
	if !ok {
		return fmt.Errorf("layer Content must be an object")
	}
	if err := cfnComputeProperties(content, "S3Bucket", "S3Key", "S3ObjectVersion", "S3ObjectStorageMode"); err != nil {
		return err
	}
	if err := cfnComputeRequired(content, "S3Bucket", "S3Key"); err != nil {
		return err
	}
	return cfnComputeStrings(content, "S3Bucket", "S3Key", "S3ObjectVersion", "S3ObjectStorageMode")
}

func (h cfnLambdaLayerVersion) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "LayerName", "Content", "Description", "LicenseInfo", "CompatibleArchitectures", "CompatibleRuntimes"), h.Validate(b)
}

func cfnLambdaLayerContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return lambda.WithLayerVersionOwner(ctx, lambda.LayerVersionOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

func cfnLambdaLayerIdentity(r cloudformation.ResourceRequest) (string, int64, error) {
	parsed, err := arn.Parse(r.PhysicalID)
	if err != nil || parsed.Service != "lambda" {
		return "", 0, fmt.Errorf("identifier must be a Lambda layer version ARN")
	}
	resource, valid := strings.CutPrefix(parsed.Resource, "layer:")
	name, qualifier, qualified := strings.Cut(resource, ":")
	version, err := strconv.ParseInt(qualifier, 10, 64)
	if !valid || !qualified || name == "" || err != nil || version <= 0 || strconv.FormatInt(version, 10) != qualifier {
		return "", 0, fmt.Errorf("identifier must be a Lambda layer version ARN")
	}
	parsed.Resource = "layer:" + name
	return parsed.String(), version, nil
}

func cfnLambdaLayerResult(r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if _, _, err := cfnLambdaLayerIdentity(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{"LayerVersionArn": r.PhysicalID}}, nil
}

func (h cfnLambdaLayerVersion) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeString(r.Properties, "LayerName")
	if name == "" {
		// Native CloudFormation uses the logical ID, without a stack suffix.
		name = r.LogicalID
	}
	if r.PhysicalID != "" {
		var err error
		name, _, err = cfnLambdaLayerIdentity(r)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	input := cfnComputeCopy(r.Properties, "Content", "Description", "LicenseInfo", "CompatibleArchitectures", "CompatibleRuntimes")
	input["LayerName"] = name
	published, err := cfnComputeCall[api.PublishLayerVersionOutput](cfnLambdaLayerContext(ctx, r), h.commands, "lambda", "PublishLayerVersion", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeValue(published.LayerVersionArn)
	return cfnLambdaLayerResult(r)
}

func (h cfnLambdaLayerVersion) Update(_ context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	changed, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if changed {
		return cloudformation.ResourceResult{}, fmt.Errorf("layer versions are immutable and require replacement")
	}
	return cfnLambdaLayerResult(r)
}

func (h cfnLambdaLayerVersion) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name, version, err := cfnLambdaLayerIdentity(r)
	if err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(cfnLambdaLayerContext(ctx, r), h.commands, "lambda", "DeleteLayerVersion", map[string]any{"LayerName": name, "VersionNumber": version}))
}

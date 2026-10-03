package integrations

import (
	"context"
	"fmt"

	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
)

type cfnLambdaResourcePolicy struct{ commands StepFunctionsCommands }

func (h cfnLambdaResourcePolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ResourceArn", "PolicyDocument"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "ResourceArn", "PolicyDocument"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "ResourceArn"); err != nil {
		return err
	}
	if _, ok := p["PolicyDocument"].(map[string]any); !ok {
		return fmt.Errorf("PolicyDocument must be a JSON object")
	}
	_, err := cfnComputeDocument(p["PolicyDocument"])
	return err
}

func (h cfnLambdaResourcePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ResourceArn"), h.Validate(b)
}

func cfnLambdaResourcePolicyARN(r cloudformation.ResourceRequest) string {
	if r.PhysicalID != "" {
		return r.PhysicalID
	}
	return cfnComputeString(r.Properties, "ResourceArn")
}

func (h cfnLambdaResourcePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.put(ctx, r, true)
}

func (h cfnLambdaResourcePolicy) put(ctx context.Context, r cloudformation.ResourceRequest, createOnly bool) (cloudformation.ResourceResult, error) {
	ctx = lambda.WithFunctionPolicyDeployment(ctx, lambda.FunctionPolicyDeployment{
		Owner:      lambda.FunctionPolicyOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token},
		CreateOnly: createOnly,
	})
	document, err := cfnComputeDocument(r.Properties["PolicyDocument"])
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	arn := cfnLambdaResourcePolicyARN(r)
	if err := cfnComputeRun(ctx, h.commands, "lambda", "PutResourcePolicy", map[string]any{"ResourceArn": arn, "Policy": document}); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn}, nil
}

func (h cfnLambdaResourcePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	changed, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if changed {
		return cloudformation.ResourceResult{}, fmt.Errorf("changing the function policy target requires replacement")
	}
	return h.put(ctx, r, false)
}

func (h cfnLambdaResourcePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "lambda", "DeleteResourcePolicy", map[string]any{"ResourceArn": cfnLambdaResourcePolicyARN(r)}))
}

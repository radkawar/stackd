package integrations

import (
	"context"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
)

type cfnLambdaAlias struct{ commands StepFunctionsCommands }

func (h cfnLambdaAlias) Validate(p cloudformation.Properties) error {
	_, err := cfnLambdaAliasProperties(p)
	return err
}

func cfnLambdaAliasProperties(p cloudformation.Properties) (map[string]float64, error) {
	if err := cfnComputeProperties(p, "Name", "FunctionName", "FunctionVersion", "Description", "RoutingConfig", "ProvisionedConcurrencyConfig"); err != nil {
		return nil, err
	}
	if err := cfnComputeRequired(p, "Name", "FunctionName", "FunctionVersion"); err != nil {
		return nil, err
	}
	if err := cfnComputeStrings(p, "Name", "FunctionName", "FunctionVersion", "Description"); err != nil {
		return nil, err
	}
	if _, _, err := cfnLambdaProvisioned(p); err != nil {
		return nil, err
	}
	return cfnLambdaAliasRouting(p)
}

func (h cfnLambdaAlias) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "FunctionName", "Name"), h.Validate(b)
}

func cfnLambdaAliasContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return lambda.WithAliasOwner(ctx, lambda.AliasOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

func cfnLambdaAliasResult(alias *api.AliasConfiguration) cloudformation.ResourceResult {
	id := cfnComputeValue(alias.AliasArn)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"AliasArn": id}}
}

func (h cfnLambdaAlias) input(r cloudformation.ResourceRequest) (map[string]any, error) {
	routing, err := cfnLambdaAliasProperties(r.Properties)
	if err != nil {
		return nil, err
	}
	function, name, err := cfnLambdaQualifiedIdentity(r)
	if err != nil {
		return nil, err
	}
	input := map[string]any{
		"FunctionName": function, "Name": name,
		"FunctionVersion": r.Properties["FunctionVersion"],
		"RoutingConfig":   map[string]any{"AdditionalVersionWeights": routing},
	}
	// Native CloudFormation clears omitted routing but preserves an omitted
	// description. An explicit empty description still clears it.
	if description, present := r.Properties["Description"]; present {
		input["Description"] = description
	}
	return input, nil
}

func (h cfnLambdaAlias) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	input, err := h.input(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	alias, err := cfnComputeCall[api.AliasConfiguration](cfnLambdaAliasContext(ctx, r), h.commands, "lambda", "CreateAlias", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaAliasResult(alias), nil
}

func (h cfnLambdaAlias) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	input, err := h.input(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	alias, err := cfnComputeCall[api.AliasConfiguration](cfnLambdaAliasContext(ctx, r), h.commands, "lambda", "UpdateAlias", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaAliasResult(alias), nil
}

func (h cfnLambdaAlias) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	function, name, err := cfnLambdaQualifiedIdentity(r)
	if err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(cfnLambdaAliasContext(ctx, r), h.commands, "lambda", "DeleteAlias", map[string]any{"FunctionName": function, "Name": name}))
}

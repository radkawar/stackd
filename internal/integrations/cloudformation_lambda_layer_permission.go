package integrations

import (
	"context"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
)

type cfnLambdaLayerPermission struct{ commands StepFunctionsCommands }

func (h cfnLambdaLayerPermission) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Action", "LayerVersionArn", "OrganizationId", "Principal"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Action", "LayerVersionArn", "Principal"); err != nil {
		return err
	}
	return cfnComputeStrings(p, "Action", "LayerVersionArn", "OrganizationId", "Principal")
}

func (h cfnLambdaLayerPermission) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Action", "LayerVersionArn", "OrganizationId", "Principal"), h.Validate(b)
}

func cfnLambdaLayerPermissionContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	if r.CloudControl {
		return ctx
	}
	return lambda.WithLayerPermissionOwner(ctx, lambda.LayerPermissionOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

// Physical identity wins over desired properties during replacement and rollback.
func cfnLambdaLayerPermissionIdentity(r cloudformation.ResourceRequest) (string, int64, string, string, error) {
	layerARN := cfnComputeString(r.Properties, "LayerVersionArn")
	var statement string
	if r.PhysicalID != "" {
		var found bool
		layerARN, statement, found = strings.Cut(r.PhysicalID, "#")
		if !found || statement == "" || strings.Contains(statement, "#") {
			return "", 0, "", "", fmt.Errorf("identifier must contain a layer version ARN and statement ID")
		}
	} else {
		statement = cfnComputeName(r, "", 100)
	}
	r.PhysicalID = layerARN
	name, version, err := cfnLambdaLayerIdentity(r)
	return name, version, statement, layerARN + "#" + statement, err
}

func (h cfnLambdaLayerPermission) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name, version, statement, physicalID, err := cfnLambdaLayerPermissionIdentity(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Action", "OrganizationId", "Principal")
	input["LayerName"], input["VersionNumber"], input["StatementId"] = name, version, statement
	if err := cfnComputeRun(cfnLambdaLayerPermissionContext(ctx, r), h.commands, "lambda", "AddLayerVersionPermission", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: physicalID, Ref: physicalID, Attributes: map[string]any{"Id": physicalID}}, nil
}

func (h cfnLambdaLayerPermission) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	changed, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if changed {
		return cloudformation.ResourceResult{}, fmt.Errorf("layer permission changes require replacement")
	}
	return h.Create(ctx, r)
}

func (h cfnLambdaLayerPermission) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name, version, statement, _, err := cfnLambdaLayerPermissionIdentity(r)
	if err != nil {
		return err
	}
	current, err := cfnComputeCall[api.GetLayerVersionPolicyOutput](ctx, h.commands, "lambda", "GetLayerVersionPolicy", map[string]any{
		"LayerName": name, "VersionNumber": version,
	})
	if err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "lambda", "RemoveLayerVersionPermission", map[string]any{
		"LayerName": name, "VersionNumber": version, "StatementId": statement, "RevisionId": cfnComputeValue(current.RevisionId),
	}))
}

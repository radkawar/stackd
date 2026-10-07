package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecr-replicationconfiguration.html
// The image replication scheduler consumes precisely this owner configuration.
type cfnECRReplication struct{ commands StepFunctionsCommands }

func (h cfnECRReplication) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ReplicationConfiguration"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "ReplicationConfiguration")
}
func (h cfnECRReplication) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func (h cfnECRReplication) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnECRSingletonScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claims := map[string]string{}
	ctx = cfnECRSingletonContext(ctx, r, "ReplicationConfiguration", false, false, claims)
	out, err := cfnComputeCall[api.DescribeRegistryOutput](ctx, h.commands, "ecr", "DescribeRegistry", map[string]any{})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claim := claims[r.Scope.Account]
	if claim == cfnDeveloperClaim(r) {
		return cfnECRSingletonResult(r.Scope.Account), nil
	}
	if claim != "" || (out.ReplicationConfiguration != nil && len(out.ReplicationConfiguration.Rules) > 0) {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("replication configuration belongs to another incarnation"))
	}
	err = cfnComputeRun(ctx, h.commands, "ecr", "PutReplicationConfiguration", cfnDeveloperInput(r.Properties, "ReplicationConfiguration"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnECRSingletonResult(r.Scope.Account), nil
}
func (h cfnECRReplication) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnECRSingletonScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnECRSingletonContext(ctx, r, "ReplicationConfiguration", true, false, nil)
	err := cfnComputeRun(ctx, h.commands, "ecr", "PutReplicationConfiguration", cfnDeveloperInput(r.Properties, "ReplicationConfiguration"))
	return cfnECRSingletonResult(r.Scope.Account), err
}
func (h cfnECRReplication) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnECRSingletonScope(r); err != nil {
		return err
	}
	ctx = cfnECRSingletonContext(ctx, r, "ReplicationConfiguration", true, true, nil)
	return cfnComputeRun(ctx, h.commands, "ecr", "PutReplicationConfiguration", map[string]any{"replicationConfiguration": map[string]any{"rules": []any{}}})
}
func (h cfnECRReplication) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnECRSingletonScope(r); err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.DescribeRegistryOutput](ctx, h.commands, "ecr", "DescribeRegistry", map[string]any{})
	if err != nil {
		return nil, err
	}
	configuration, err := cfnDeveloperModel(out.ReplicationConfiguration)
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties{"RegistryId": cfnComputeValue(out.RegistryId), "ReplicationConfiguration": configuration}, nil
}
func (h cfnECRReplication) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	r.PhysicalID = r.Scope.Account
	p, err := h.Read(ctx, r)
	if err != nil {
		return nil, err
	}
	return []cloudformation.ResourceDescription{{Identifier: r.PhysicalID, Properties: p}}, nil
}

package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecr-registryscanningconfiguration.html
// Scan effects remain under the registry's configured local scanner authority.
type cfnECRScanning struct{ commands StepFunctionsCommands }

func (h cfnECRScanning) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ScanType", "Rules"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "ScanType", "Rules")
}
func (h cfnECRScanning) Replacement(a, b cloudformation.Properties) (bool, error) {
	return false, h.Validate(b)
}
func (h cfnECRScanning) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnECRSingletonScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claims := map[string]string{}
	ctx = cfnECRSingletonContext(ctx, r, "RegistryScanningConfiguration", false, false, claims)
	out, err := cfnComputeCall[api.GetRegistryScanningConfigurationOutput](ctx, h.commands, "ecr", "GetRegistryScanningConfiguration", map[string]any{})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claim := claims[r.Scope.Account]
	if claim == cfnDeveloperClaim(r) {
		return cfnECRSingletonResult(r.Scope.Account), nil
	}
	if claim != "" || (out.ScanningConfiguration != nil && (cfnComputeValue(out.ScanningConfiguration.ScanType) != "BASIC" || len(out.ScanningConfiguration.Rules) > 0)) {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("registry scanning configuration belongs to another incarnation"))
	}
	err = cfnComputeRun(ctx, h.commands, "ecr", "PutRegistryScanningConfiguration", cfnDeveloperInput(r.Properties, "ScanType", "Rules"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnECRSingletonResult(r.Scope.Account), nil
}
func (h cfnECRScanning) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnECRSingletonScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnECRSingletonContext(ctx, r, "RegistryScanningConfiguration", true, false, nil)
	err := cfnComputeRun(ctx, h.commands, "ecr", "PutRegistryScanningConfiguration", cfnDeveloperInput(r.Properties, "ScanType", "Rules"))
	return cfnECRSingletonResult(r.Scope.Account), err
}
func (h cfnECRScanning) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnECRSingletonScope(r); err != nil {
		return err
	}
	ctx = cfnECRSingletonContext(ctx, r, "RegistryScanningConfiguration", true, true, nil)
	return cfnComputeRun(ctx, h.commands, "ecr", "PutRegistryScanningConfiguration", map[string]any{"scanType": "BASIC", "rules": []any{}})
}
func (h cfnECRScanning) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnECRSingletonScope(r); err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetRegistryScanningConfigurationOutput](ctx, h.commands, "ecr", "GetRegistryScanningConfiguration", map[string]any{})
	if err != nil {
		return nil, err
	}
	configuration, err := cfnDeveloperModel(out.ScanningConfiguration)
	if err != nil {
		return nil, err
	}
	configuration["RegistryId"] = cfnComputeValue(out.RegistryId)
	return configuration, nil
}
func (h cfnECRScanning) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	r.PhysicalID = r.Scope.Account
	p, err := h.Read(ctx, r)
	if err != nil {
		return nil, err
	}
	return []cloudformation.ResourceDescription{{Identifier: r.PhysicalID, Properties: p}}, nil
}

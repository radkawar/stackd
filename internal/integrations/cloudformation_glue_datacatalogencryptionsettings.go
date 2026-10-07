package integrations

import (
	"context"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	glueowner "stackd/internal/services/glue"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-datacatalogencryptionsettings.html
type cfnGlueDataCatalogEncryptionSettings struct{ commands StepFunctionsCommands }

func (h cfnGlueDataCatalogEncryptionSettings) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "CatalogId", "DataCatalogEncryptionSettings"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "CatalogId", "DataCatalogEncryptionSettings"); err != nil {
		return err
	}
	return cloudformation.ValidateResourceProperties("AWS::Glue::DataCatalogEncryptionSettings", p)
}
func (h cfnGlueDataCatalogEncryptionSettings) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "CatalogId"), h.Validate(b)
}
func cfnGlueCatalogEncryptionInput(value any) map[string]any {
	p, _ := cfnComputeObject(value)
	input := cfnComputeCopy(p, "EncryptionAtRest")
	if password, ok := cfnComputeObject(p["ConnectionPasswordEncryption"]); ok {
		body := cfnComputeCopy(password, "ReturnConnectionPasswordEncrypted")
		if key, ok := password["KmsKeyId"]; ok {
			body["AwsKmsKeyId"] = key
		}
		input["ConnectionPasswordEncryption"] = body
	} else {
		input["ConnectionPasswordEncryption"] = map[string]any{"ReturnConnectionPasswordEncrypted": false}
	}
	return input
}
func (h cfnGlueDataCatalogEncryptionSettings) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeString(r.Properties, "CatalogId")
	ctx = cfnAnalyticsContext(ctx, r, "glue", "ConnectionEncryption")
	if err := cfnComputeRun(ctx, h.commands, "glue", "PutDataCatalogEncryptionSettings", map[string]any{"CatalogId": id, "DataCatalogEncryptionSettings": cfnGlueCatalogEncryptionInput(r.Properties["DataCatalogEncryptionSettings"])}); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(id, id, nil), nil
}
func (h cfnGlueDataCatalogEncryptionSettings) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAnalyticsContext(ctx, r, "glue", "ConnectionEncryption")
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, nil), cfnComputeRun(ctx, h.commands, "glue", "PutDataCatalogEncryptionSettings", map[string]any{"CatalogId": r.PhysicalID, "DataCatalogEncryptionSettings": cfnGlueCatalogEncryptionInput(r.Properties["DataCatalogEncryptionSettings"])})
}
func (h cfnGlueDataCatalogEncryptionSettings) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.CloudControl {
		ctx = glueowner.WithCloudFormationOwner(ctx, "ConnectionEncryptionDirectRelease", "")
	} else {
		ctx = cfnAnalyticsContext(ctx, r, "glue", "ConnectionEncryptionRelease")
	}
	return cfnComputeRun(ctx, h.commands, "glue", "PutDataCatalogEncryptionSettings", map[string]any{"CatalogId": r.PhysicalID, "DataCatalogEncryptionSettings": map[string]any{"EncryptionAtRest": map[string]any{"CatalogEncryptionMode": "DISABLED"}, "ConnectionPasswordEncryption": map[string]any{"ReturnConnectionPasswordEncrypted": false}}})
}
func (h cfnGlueDataCatalogEncryptionSettings) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnAnalyticsContext(ctx, r, "glue", "ConnectionEncryption")
	out, err := cfnComputeCall[api.GetDataCatalogEncryptionSettingsOutput](ctx, h.commands, "glue", "GetDataCatalogEncryptionSettings", map[string]any{"CatalogId": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	settings, err := cfnAnalyticsMap(out.DataCatalogEncryptionSettings)
	if err != nil {
		return nil, err
	}
	if password, ok := cfnComputeObject(settings["ConnectionPasswordEncryption"]); ok {
		if key, ok := password["AwsKmsKeyId"]; ok {
			password["KmsKeyId"] = key
			delete(password, "AwsKmsKeyId")
		}
	}
	return cloudformation.Properties{"CatalogId": r.PhysicalID, "DataCatalogEncryptionSettings": settings}, nil
}
func (h cfnGlueDataCatalogEncryptionSettings) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	r.PhysicalID = r.Scope.Account
	p, err := h.Read(ctx, r)
	if err != nil {
		return nil, err
	}
	return []cloudformation.ResourceDescription{{Identifier: r.PhysicalID, Properties: p}}, nil
}

package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	"strconv"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-schemaversion.html
func cfnGlueRegistryInput(p map[string]any) map[string]any {
	out := map[string]any{}
	if v, ok := p["Name"]; ok {
		out["RegistryName"] = v
	}
	if v, ok := p["Arn"]; ok {
		out["RegistryArn"] = v
	}
	return out
}
func cfnGlueSchemaInput(p map[string]any) map[string]any {
	return cfnComputeCopy(p, "SchemaArn", "SchemaName", "RegistryName")
}

type cfnGlueSchemaVersion struct{ commands StepFunctionsCommands }

func (h cfnGlueSchemaVersion) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Schema", "SchemaDefinition"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Schema", "SchemaDefinition"); err != nil {
		return err
	}
	return cloudformation.ValidateResourceProperties("AWS::Glue::SchemaVersion", p)
}
func (h cfnGlueSchemaVersion) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Schema", "SchemaDefinition"), h.Validate(b)
}
func (h cfnGlueSchemaVersion) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAnalyticsContext(ctx, r, "glue", "SchemaVersion")
	schema, _ := cfnComputeObject(r.Properties["Schema"])
	out, err := cfnComputeCall[api.RegisterSchemaVersionOutput](ctx, h.commands, "glue", "RegisterSchemaVersion", map[string]any{"SchemaId": cfnGlueSchemaInput(schema), "SchemaDefinition": r.Properties["SchemaDefinition"]})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeValue(out.SchemaVersionId)
	if _, err = h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, map[string]any{"VersionId": r.PhysicalID}), nil
}
func (h cfnGlueSchemaVersion) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if changed, err := h.Replacement(r.Previous, r.Properties); err != nil || changed {
		if err == nil {
			err = fmt.Errorf("schema versions are immutable")
		}
		return cloudformation.ResourceResult{}, err
	}
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, map[string]any{"VersionId": r.PhysicalID}), nil
}
func (h cfnGlueSchemaVersion) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnAnalyticsContext(ctx, r, "glue", "SchemaVersion")
	out, err := cfnComputeCall[api.GetSchemaVersionOutput](ctx, h.commands, "glue", "GetSchemaVersion", map[string]any{"SchemaVersionId": r.PhysicalID})
	if err != nil {
		return cfnAnalyticsAbsent(err)
	}
	if out.VersionNumber == nil {
		return fmt.Errorf("schema version did not return its number")
	}
	deleted, err := cfnComputeCall[api.DeleteSchemaVersionsOutput](ctx, h.commands, "glue", "DeleteSchemaVersions", map[string]any{"SchemaId": map[string]any{"SchemaArn": cfnComputeValue(out.SchemaArn)}, "Versions": strconv.FormatInt(int64(*out.VersionNumber), 10)})
	if err != nil {
		return cfnAnalyticsAbsent(err)
	}
	if len(deleted.SchemaVersionErrors) > 0 {
		return fmt.Errorf("glue rejected schema version deletion: %v", deleted.SchemaVersionErrors)
	}
	return nil
}
func (h cfnGlueSchemaVersion) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnAnalyticsContext(ctx, r, "glue", "SchemaVersion")
	out, err := cfnComputeCall[api.GetSchemaVersionOutput](ctx, h.commands, "glue", "GetSchemaVersion", map[string]any{"SchemaVersionId": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	return cloudformation.Properties{"VersionId": r.PhysicalID, "Schema": map[string]any{"SchemaArn": cfnComputeValue(out.SchemaArn)}, "SchemaDefinition": cfnComputeValue(out.SchemaDefinition)}, nil
}
func (h cfnGlueSchemaVersion) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	schemas, err := (cfnGlueSchema(h)).List(ctx, r)
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.ResourceDescription{}
	for _, schema := range schemas {
		input := map[string]any{"SchemaId": map[string]any{"SchemaArn": schema.Identifier}}
		for {
			out, err := cfnComputeCall[api.ListSchemaVersionsOutput](ctx, h.commands, "glue", "ListSchemaVersions", input)
			if err != nil {
				return nil, err
			}
			for _, v := range out.Schemas {
				if cfnComputeValue(v.Status) == "DELETING" {
					continue
				}
				r.PhysicalID = cfnComputeValue(v.SchemaVersionId)
				p, err := h.Read(ctx, r)
				if err != nil {
					return nil, err
				}
				rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = out.NextToken
		}
	}
	return cfnAnalyticsSort(rows), nil
}
func (h cfnGlueSchemaVersion) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnAnalyticsContext(ctx, r, "glue", "SchemaVersion")
	out, err := cfnComputeCall[api.GetSchemaVersionOutput](ctx, h.commands, "glue", "GetSchemaVersion", map[string]any{"SchemaVersionId": r.PhysicalID})
	if err != nil {
		return false, err
	}
	status := cfnComputeValue(out.Status)
	if status == "AVAILABLE" {
		return true, nil
	}
	if status == "PENDING" {
		return false, nil
	}
	return false, fmt.Errorf("glue schema version is %s", status)
}
func (h cfnGlueSchemaVersion) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := cfnComputeCall[api.GetSchemaVersionOutput](ctx, h.commands, "glue", "GetSchemaVersion", map[string]any{"SchemaVersionId": r.PhysicalID})
	if cfnAnalyticsMissing(err) {
		return true, nil
	}
	return false, err
}

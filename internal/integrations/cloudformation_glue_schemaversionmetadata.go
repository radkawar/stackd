package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	glueowner "stackd/internal/services/glue"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-schemaversionmetadata.html
type cfnGlueSchemaVersionMetadata struct{ commands StepFunctionsCommands }

func (h cfnGlueSchemaVersionMetadata) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SchemaVersionId", "Key", "Value"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SchemaVersionId", "Key", "Value"); err != nil {
		return err
	}
	return cloudformation.ValidateResourceProperties("AWS::Glue::SchemaVersionMetadata", p)
}
func (h cfnGlueSchemaVersionMetadata) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "SchemaVersionId", "Key", "Value"), h.Validate(b)
}

func cfnGlueMetadataContext(ctx context.Context, r cloudformation.ResourceRequest, version, key, value string) context.Context {
	return cfnAnalyticsContext(ctx, r, "glue", glueowner.CloudFormationMetadataOwnerKind(version, key, value))
}
func (h cfnGlueSchemaVersionMetadata) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	version, key, value, err := cfnGlueMetadataIdentity(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := version + "|" + key + "|" + value
	r.PhysicalID = id
	ctx = cfnGlueMetadataContext(ctx, r, version, key, value)
	_, err = h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(id, id, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	err = cfnComputeRun(ctx, h.commands, "glue", "PutSchemaVersionMetadata", map[string]any{"SchemaVersionId": version, "MetadataKeyValue": map[string]any{"MetadataKey": key, "MetadataValue": value}})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(id, id, nil), nil
}
func (h cfnGlueSchemaVersionMetadata) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	changed, err := h.Replacement(r.Previous, r.Properties)
	if changed || err != nil {
		if err == nil {
			err = fmt.Errorf("schema version metadata identity is immutable")
		}
		return cloudformation.ResourceResult{}, err
	}
	if _, err = h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, nil), nil
}
func (h cfnGlueSchemaVersionMetadata) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	version, key, value, err := cfnGlueMetadataIdentity(ctx, h.commands, r)
	if err != nil {
		return err
	}
	ctx = cfnGlueMetadataContext(ctx, r, version, key, value)
	if _, err = h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "RemoveSchemaVersionMetadata", map[string]any{"SchemaVersionId": version, "MetadataKeyValue": map[string]any{"MetadataKey": key, "MetadataValue": value}}))
}
func (h cfnGlueSchemaVersionMetadata) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	version, key, value, err := cfnGlueMetadataIdentity(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	ctx = cfnGlueMetadataContext(ctx, r, version, key, value)
	out, err := cfnComputeCall[api.QuerySchemaVersionMetadataOutput](ctx, h.commands, "glue", "QuerySchemaVersionMetadata", map[string]any{"SchemaVersionId": version, "MetadataList": []any{map[string]any{"MetadataKey": key, "MetadataValue": value}}})
	if err != nil {
		return nil, err
	}
	for k, v := range out.MetadataInfoMap {
		if string(k) != key {
			continue
		}
		if cfnComputeValue(v.MetadataValue) == value {
			return cloudformation.Properties{"SchemaVersionId": version, "Key": key, "Value": value}, nil
		}
		for _, other := range v.OtherMetadataValueList {
			if cfnComputeValue(other.MetadataValue) == value {
				return cloudformation.Properties{"SchemaVersionId": version, "Key": key, "Value": value}, nil
			}
		}
	}
	return nil, &awswire.Error{Code: "EntityNotFoundException", Message: "Schema version metadata does not exist.", StatusCode: 400}
}
func (h cfnGlueSchemaVersionMetadata) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	versions, err := (cfnGlueSchemaVersion(h)).List(ctx, r)
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.ResourceDescription{}
	for _, version := range versions {
		input := map[string]any{"SchemaVersionId": version.Identifier}
		for {
			out, err := cfnComputeCall[api.QuerySchemaVersionMetadataOutput](ctx, h.commands, "glue", "QuerySchemaVersionMetadata", input)
			if err != nil {
				return nil, err
			}
			for k, v := range out.MetadataInfoMap {
				values := []string{cfnComputeValue(v.MetadataValue)}
				for _, other := range v.OtherMetadataValueList {
					values = append(values, cfnComputeValue(other.MetadataValue))
				}
				for _, value := range values {
					p := cloudformation.Properties{"SchemaVersionId": version.Identifier, "Key": string(k), "Value": value}
					rows = append(rows, cloudformation.ResourceDescription{Identifier: version.Identifier + "|" + string(k) + "|" + value, Properties: p})
				}
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			input["NextToken"] = out.NextToken
		}
	}
	return cfnAnalyticsSort(rows), nil
}

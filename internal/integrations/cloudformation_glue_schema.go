package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-schema.html
type cfnGlueSchema struct{ commands StepFunctionsCommands }

func (h cfnGlueSchema) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Registry", "Name", "Description", "DataFormat", "Compatibility", "SchemaDefinition", "CheckpointVersion", "Tags"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Schema", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueSchema) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Registry", "Name", "DataFormat", "SchemaDefinition"), h.Validate(b)
}
func (h cfnGlueSchema) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 255)
	registry := map[string]any{}
	if v, ok := cfnComputeObject(r.Properties["Registry"]); ok {
		registry = cfnGlueRegistryInput(v)
	}
	regName := cfnComputeString(registry, "RegistryName")
	if regName == "" {
		regName = "default-registry"
	}
	id := cfnGlueARN(r, "schema", regName+"/"+name)
	if regARN := cfnComputeString(registry, "RegistryArn"); regARN != "" {
		id = strings.Replace(regARN, ":registry/", ":schema/", 1) + "/" + name
	}
	if r.PhysicalID != "" {
		id = r.PhysicalID
		name = id[strings.LastIndex(id, "/")+1:]
	}
	r.PhysicalID = id
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	_, err := h.Read(ctx, r)
	if err == nil {
		return h.Result(ctx, r)
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "DataFormat", "Compatibility", "SchemaDefinition")
	input["SchemaName"] = name
	input["RegistryId"] = registry
	input["Tags"] = cfnAnalyticsCustomerTags(r)
	out, err := cfnComputeCall[api.CreateSchemaOutput](ctx, h.commands, "glue", "CreateSchema", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	r.PhysicalID = cfnComputeValue(out.SchemaArn)
	return h.Result(ctx, r)
}
func (h cfnGlueSchema) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	input := map[string]any{"SchemaId": map[string]any{"SchemaArn": id}}
	input["Description"] = cfnComputeDefault(r.Properties, "Description", "")
	input["Compatibility"] = r.Properties["Compatibility"]
	if checkpoint, ok := r.Properties["CheckpointVersion"]; ok {
		input["SchemaVersionNumber"] = map[string]any{"VersionNumber": checkpoint}
	}
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateSchema", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnGlueUpdateTags(ctx, h.commands, r, id); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.Result(ctx, r)
}
func (h cfnGlueSchema) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteSchema", map[string]any{"SchemaId": map[string]any{"SchemaArn": id}}))
}
func (h cfnGlueSchema) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	out, err := cfnComputeCall[api.GetSchemaOutput](ctx, h.commands, "glue", "GetSchema", map[string]any{"SchemaId": map[string]any{"SchemaArn": id}})
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"Arn": id, "Name": cfnComputeValue(out.SchemaName), "Registry": map[string]any{"Name": cfnComputeValue(out.RegistryName), "Arn": cfnComputeValue(out.RegistryArn)}, "DataFormat": cfnComputeValue(out.DataFormat), "Compatibility": cfnComputeValue(out.Compatibility)}
	if out.SchemaCheckpoint != nil {
		p["CheckpointVersion"] = int64(*out.SchemaCheckpoint)
	}
	if out.Description != nil {
		p["Description"] = string(*out.Description)
	}
	version, err := cfnComputeCall[api.GetSchemaVersionOutput](ctx, h.commands, "glue", "GetSchemaVersion", map[string]any{"SchemaId": map[string]any{"SchemaArn": id}, "SchemaVersionNumber": map[string]any{"VersionNumber": 1}})
	if err != nil {
		if !cfnAnalyticsMissing(err) {
			return nil, err
		}
	} else {
		p["SchemaDefinition"] = cfnComputeValue(version.SchemaDefinition)
		p["InitialSchemaVersionId"] = cfnComputeValue(version.SchemaVersionId)
	}
	tags, err := cfnGlueTags(ctx, h.commands, id)
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnComputeTagList(tags)
	return p, nil
}
func (h cfnGlueSchema) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListSchemasOutput](ctx, h.commands, "glue", "ListSchemas", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.Schemas {
			if cfnComputeValue(v.SchemaStatus) == "DELETING" {
				continue
			}
			r.PhysicalID = cfnComputeValue(v.SchemaArn)
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
	return cfnAnalyticsSort(rows), nil
}
func (h cfnGlueSchema) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	attrs := map[string]any{"Arn": r.PhysicalID}
	p, err := h.Read(ctx, r)
	if err != nil {
		return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, attrs), err
	}
	if initial, ok := p["InitialSchemaVersionId"]; ok {
		attrs["InitialSchemaVersionId"] = initial
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, attrs), nil
}
func (h cfnGlueSchema) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	out, err := cfnComputeCall[api.GetSchemaOutput](ctx, h.commands, "glue", "GetSchema", map[string]any{"SchemaId": map[string]any{"SchemaArn": r.PhysicalID}})
	if err != nil {
		return false, err
	}
	status := cfnComputeValue(out.SchemaStatus)
	if status == "AVAILABLE" {
		return true, nil
	}
	if status == "PENDING" {
		return false, nil
	}
	return false, fmt.Errorf("glue schema is %s", status)
}
func (h cfnGlueSchema) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	id := r.PhysicalID
	ctx = cfnAnalyticsContext(ctx, r, "glue", id)
	_, err := cfnComputeCall[api.GetSchemaOutput](ctx, h.commands, "glue", "GetSchema", map[string]any{"SchemaId": map[string]any{"SchemaArn": r.PhysicalID}})
	if cfnAnalyticsGone(err) {
		return true, nil
	}
	return false, err
}

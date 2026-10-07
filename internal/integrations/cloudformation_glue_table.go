package integrations

import (
	"context"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-table.html
type cfnGlueTable struct{ commands StepFunctionsCommands }

func (h cfnGlueTable) Validate(p cloudformation.Properties) error {
	if err := cfnGlueTableAdmission(p); err != nil {
		return err
	}
	if err := cfnComputeProperties(p, "DatabaseName", "TableInput", "OpenTableFormatInput", "CatalogId", "Name"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Table", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueTable) Replacement(a, b cloudformation.Properties) (bool, error) {
	av, _ := cfnComputeObject(a["TableInput"])
	bv, _ := cfnComputeObject(b["TableInput"])
	return cfnComputeChanged(a, b, "CatalogId", "DatabaseName", "Name") || cfnComputeChanged(av, bv, "Name"), h.Validate(b)
}
func (h cfnGlueTable) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	catalog := cfnGlueCatalogID(r)
	db := cfnComputeString(r.Properties, "DatabaseName")
	name := cfnComputeString(r.Properties, "Name")
	if v, ok := cfnComputeObject(r.Properties["TableInput"]); ok && name == "" {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 3)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		catalog, db, name = parts[0], parts[1], parts[2]
	}
	if name == "" {
		copy := r
		copy.PhysicalID = ""
		name = cfnComputeName(copy, "Name", 255)
	}
	db, name = strings.ToLower(db), strings.ToLower(name)
	id := catalog + "|" + db + "|" + name
	_ = id
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Table")
	r.PhysicalID = id
	_, err := h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(id, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	body := map[string]any{}
	if v, ok := cfnComputeObject(r.Properties["TableInput"]); ok {
		for k, v := range v {
			body[k] = v
		}
	}
	body["Name"] = name
	input := map[string]any{"CatalogId": catalog, "DatabaseName": db, "TableInput": body}
	if v, ok := r.Properties["OpenTableFormatInput"]; ok {
		input["OpenTableFormatInput"] = v
	}
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateTable", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(id, name, nil), nil
}
func (h cfnGlueTable) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	catalog := cfnGlueCatalogID(r)
	db := cfnComputeString(r.Properties, "DatabaseName")
	name := cfnComputeString(r.Properties, "Name")
	if v, ok := cfnComputeObject(r.Properties["TableInput"]); ok && name == "" {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 3)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		catalog, db, name = parts[0], parts[1], parts[2]
	}
	if name == "" {
		copy := r
		copy.PhysicalID = ""
		name = cfnComputeName(copy, "Name", 255)
	}
	db, name = strings.ToLower(db), strings.ToLower(name)
	id := catalog + "|" + db + "|" + name
	_ = id
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Table")
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	body := map[string]any{}
	if v, ok := cfnComputeObject(r.Properties["TableInput"]); ok {
		for k, v := range v {
			body[k] = v
		}
	}
	body["Name"] = name
	input := map[string]any{"CatalogId": catalog, "DatabaseName": db, "TableInput": body}
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateTable", input); err != nil {
		return cfnAnalyticsResult(id, name, nil), err
	}
	return cfnAnalyticsResult(id, name, nil), nil
}
func (h cfnGlueTable) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	catalog := cfnGlueCatalogID(r)
	db := cfnComputeString(r.Properties, "DatabaseName")
	name := cfnComputeString(r.Properties, "Name")
	if v, ok := cfnComputeObject(r.Properties["TableInput"]); ok && name == "" {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 3)
		if err != nil {
			return err
		}
		catalog, db, name = parts[0], parts[1], parts[2]
	}
	if name == "" {
		copy := r
		copy.PhysicalID = ""
		name = cfnComputeName(copy, "Name", 255)
	}
	db, name = strings.ToLower(db), strings.ToLower(name)
	id := catalog + "|" + db + "|" + name
	_ = id
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Table")
	r.PhysicalID = id
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteTable", map[string]any{"CatalogId": catalog, "DatabaseName": db, "Name": name}))
}
func (h cfnGlueTable) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	catalog := cfnGlueCatalogID(r)
	db := cfnComputeString(r.Properties, "DatabaseName")
	name := cfnComputeString(r.Properties, "Name")
	if v, ok := cfnComputeObject(r.Properties["TableInput"]); ok && name == "" {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 3)
		if err != nil {
			return nil, err
		}
		catalog, db, name = parts[0], parts[1], parts[2]
	}
	if name == "" {
		copy := r
		copy.PhysicalID = ""
		name = cfnComputeName(copy, "Name", 255)
	}
	db, name = strings.ToLower(db), strings.ToLower(name)
	id := catalog + "|" + db + "|" + name
	_ = id
	ctx = cfnAnalyticsContext(ctx, r, "glue", "Table")
	out, err := cfnComputeCall[api.GetTableOutput](ctx, h.commands, "glue", "GetTable", map[string]any{"CatalogId": catalog, "DatabaseName": db, "Name": name})
	if err != nil {
		return nil, err
	}
	body, err := cfnAnalyticsProject(out.Table, "Owner", "ViewOriginalText", "Description", "TableType", "Parameters", "ViewDefinition", "StorageDescriptor", "Retention", "Name", "ViewExpandedText", "TargetTable", "PartitionKeys")
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"CatalogId": catalog, "DatabaseName": db, "Name": name, "Id": id, "TableInput": body}
	return p, nil
}
func (h cfnGlueTable) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	parents, err := cfnGlueTables(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	for _, parent := range parents {
		r.Properties = parent
		r.PhysicalID = cfnComputeString(parent, "CatalogId") + "|" + cfnComputeString(parent, "DatabaseName") + "|" + cfnComputeString(parent, "Name")
		p, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
	}
	return cfnAnalyticsSort(rows), nil
}

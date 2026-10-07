package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-database.html
type cfnGlueDatabase struct{ commands StepFunctionsCommands }

func (h cfnGlueDatabase) Validate(p cloudformation.Properties) error {
	if err := cfnGlueDatabaseCatalogAdmission(p); err != nil {
		return err
	}
	if err := cfnGlueNameAdmission(p, "DatabaseName", "DatabaseInput"); err != nil {
		return err
	}
	if err := cfnComputeProperties(p, "CatalogId", "DatabaseInput", "DatabaseName"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Database", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueDatabase) Replacement(a, b cloudformation.Properties) (bool, error) {
	av, _ := cfnComputeObject(a["DatabaseInput"])
	bv, _ := cfnComputeObject(b["DatabaseInput"])
	return cfnComputeChanged(a, b, "CatalogId", "DatabaseName") || cfnComputeChanged(av, bv, "Name"), h.Validate(b)
}
func (h cfnGlueDatabase) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl && cfnGlueCatalogID(r) != r.Scope.Account {
		return cloudformation.ResourceResult{}, fmt.Errorf("CloudControl Glue Database identifiers select the current root account catalog")
	}
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	catalog := cfnGlueDatabaseCatalogID(r)
	name := cfnComputeString(r.Properties, "DatabaseName")
	if v, ok := cfnComputeObject(r.Properties["DatabaseInput"]); ok && name == "" {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		name = r.PhysicalID
	}
	if name == "" {
		name = cfnComputeName(r, "DatabaseName", 255)
	}
	name = strings.ToLower(name)
	id := name
	_ = id
	ctx = cfnGlueDatabaseClaim(ctx, r, catalog, name)
	r.PhysicalID = id
	_, err := h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(id, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	body := map[string]any{}
	if v, ok := cfnComputeObject(r.Properties["DatabaseInput"]); ok {
		for k, v := range v {
			body[k] = v
		}
	}
	body["Name"] = name
	input := map[string]any{"CatalogId": catalog, "DatabaseInput": body, "Tags": cfnAnalyticsCustomerTags(r)}
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateDatabase", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(id, name, nil), nil
}
func (h cfnGlueDatabase) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	catalog := cfnGlueDatabaseCatalogID(r)
	name := cfnComputeString(r.Properties, "DatabaseName")
	if v, ok := cfnComputeObject(r.Properties["DatabaseInput"]); ok && name == "" {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		name = r.PhysicalID
	}
	if name == "" {
		name = cfnComputeName(r, "DatabaseName", 255)
	}
	name = strings.ToLower(name)
	id := name
	_ = id
	ctx = cfnGlueDatabaseClaim(ctx, r, catalog, name)
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	body := map[string]any{}
	if v, ok := cfnComputeObject(r.Properties["DatabaseInput"]); ok {
		for k, v := range v {
			body[k] = v
		}
	}
	body["Name"] = name
	input := map[string]any{"CatalogId": catalog, "Name": name, "DatabaseInput": body}
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateDatabase", input); err != nil {
		return cfnAnalyticsResult(id, name, nil), err
	}
	return cfnAnalyticsResult(id, name, nil), nil
}
func (h cfnGlueDatabase) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	catalog := cfnGlueDatabaseCatalogID(r)
	name := cfnComputeString(r.Properties, "DatabaseName")
	if v, ok := cfnComputeObject(r.Properties["DatabaseInput"]); ok && name == "" {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		name = r.PhysicalID
	}
	if name == "" {
		name = cfnComputeName(r, "DatabaseName", 255)
	}
	name = strings.ToLower(name)
	id := name
	_ = id
	ctx = cfnGlueDatabaseClaim(ctx, r, catalog, name)
	r.PhysicalID = id
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteDatabase", map[string]any{"CatalogId": catalog, "Name": name}))
}
func (h cfnGlueDatabase) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	catalog := cfnGlueDatabaseCatalogID(r)
	name := cfnComputeString(r.Properties, "DatabaseName")
	if v, ok := cfnComputeObject(r.Properties["DatabaseInput"]); ok && name == "" {
		name = cfnComputeString(v, "Name")
	}
	if r.PhysicalID != "" {
		name = r.PhysicalID
	}
	if name == "" {
		name = cfnComputeName(r, "DatabaseName", 255)
	}
	name = strings.ToLower(name)
	id := name
	_ = id
	ctx = cfnGlueDatabaseClaim(ctx, r, catalog, name)
	out, err := cfnComputeCall[api.GetDatabaseOutput](ctx, h.commands, "glue", "GetDatabase", map[string]any{"CatalogId": catalog, "Name": name})
	if err != nil {
		return nil, err
	}
	body, err := cfnAnalyticsProject(out.Database, "LocationUri", "CreateTableDefaultPermissions", "Description", "Parameters", "TargetDatabase", "FederatedDatabase", "Name")
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{"CatalogId": catalog, "DatabaseName": name, "DatabaseInput": body}
	return p, nil
}
func (h cfnGlueDatabase) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{"CatalogId": r.Scope.Account}
	for {
		out, err := cfnComputeCall[api.GetDatabasesOutput](ctx, h.commands, "glue", "GetDatabases", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.DatabaseList {
			r.Properties = cloudformation.Properties{"CatalogId": r.Scope.Account}
			r.PhysicalID = cfnComputeValue(v.Name)
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

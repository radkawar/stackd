package integrations

import (
	"context"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-catalog.html
type cfnGlueCatalog struct{ commands StepFunctionsCommands }

func (h cfnGlueCatalog) Validate(p cloudformation.Properties) error {
	if err := cfnGlueCatalogAdmission(p); err != nil {
		return err
	}
	if err := cfnComputeProperties(p, "Name", "Description", "Parameters", "FederatedCatalog", "TargetRedshiftCatalog", "CatalogProperties", "CreateTableDefaultPermissions", "CreateDatabaseDefaultPermissions", "AllowFullTableExternalDataAccess", "OverwriteChildResourcePermissionsWithDefault", "Tags"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Glue::Catalog", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnGlueCatalog) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnGlueCatalog) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := strings.ToLower(cfnComputeName(r, "Name", 255))
	catalog := r.Scope.Account + ":" + name
	if r.PhysicalID != "" {
		var err error
		catalog, err = cfnGlueCatalogFromARN(r, r.PhysicalID)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		name = strings.ReplaceAll(strings.TrimPrefix(catalog, r.Scope.Account+":"), ":", "/")
	}
	id := cfnGlueCatalogARN(r, catalog)
	r.PhysicalID = id
	ctx = cfnGlueCatalogClaim(ctx, r, catalog)
	_, err := h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(id, id, map[string]any{"CatalogId": catalog, "ResourceArn": id}), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	body := cfnComputeCopy(r.Properties, "Description", "Parameters", "FederatedCatalog", "TargetRedshiftCatalog", "CatalogProperties", "CreateTableDefaultPermissions", "CreateDatabaseDefaultPermissions", "AllowFullTableExternalDataAccess", "OverwriteChildResourcePermissionsWithDefault")
	input := map[string]any{"Name": name, "CatalogInput": body, "Tags": cfnAnalyticsCustomerTags(r)}
	if err = cfnComputeRun(ctx, h.commands, "glue", "CreateCatalog", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(id, id, map[string]any{"CatalogId": catalog, "ResourceArn": id}), nil
}
func (h cfnGlueCatalog) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := strings.ToLower(cfnComputeName(r, "Name", 255))
	catalog := r.Scope.Account + ":" + name
	if r.PhysicalID != "" {
		var err error
		catalog, err = cfnGlueCatalogFromARN(r, r.PhysicalID)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	id := cfnGlueCatalogARN(r, catalog)
	arn := id
	ctx = cfnGlueCatalogClaim(ctx, r, catalog)
	if _, err := h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	body := cfnComputeCopy(r.Properties, "Description", "Parameters", "FederatedCatalog", "TargetRedshiftCatalog", "CatalogProperties", "CreateTableDefaultPermissions", "CreateDatabaseDefaultPermissions", "AllowFullTableExternalDataAccess", "OverwriteChildResourcePermissionsWithDefault")
	input := map[string]any{"CatalogId": catalog, "CatalogInput": body}
	if err := cfnComputeRun(ctx, h.commands, "glue", "UpdateCatalog", input); err != nil {
		return cfnAnalyticsResult(id, id, map[string]any{"CatalogId": catalog, "ResourceArn": id}), err
	}
	return cfnAnalyticsResult(id, id, map[string]any{"CatalogId": catalog, "ResourceArn": id}), cfnGlueUpdateTags(ctx, h.commands, r, arn)
}
func (h cfnGlueCatalog) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := strings.ToLower(cfnComputeName(r, "Name", 255))
	catalog := r.Scope.Account + ":" + name
	if r.PhysicalID != "" {
		var err error
		catalog, err = cfnGlueCatalogFromARN(r, r.PhysicalID)
		if err != nil {
			return err
		}
	}
	id := cfnGlueCatalogARN(r, catalog)
	r.PhysicalID = id
	ctx = cfnGlueCatalogClaim(ctx, r, catalog)
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "glue", "DeleteCatalog", map[string]any{"CatalogId": catalog}))
}
func (h cfnGlueCatalog) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := strings.ToLower(cfnComputeName(r, "Name", 255))
	catalog := r.Scope.Account + ":" + name
	if r.PhysicalID != "" {
		var err error
		catalog, err = cfnGlueCatalogFromARN(r, r.PhysicalID)
		if err != nil {
			return nil, err
		}
		name = strings.ReplaceAll(strings.TrimPrefix(catalog, r.Scope.Account+":"), ":", "/")
	}
	id := cfnGlueCatalogARN(r, catalog)
	arn := id
	ctx = cfnGlueCatalogClaim(ctx, r, catalog)
	out, err := cfnComputeCall[api.GetCatalogOutput](ctx, h.commands, "glue", "GetCatalog", map[string]any{"CatalogId": catalog})
	if err != nil {
		return nil, err
	}
	body, err := cfnAnalyticsProject(out.Catalog, "Description", "Parameters", "FederatedCatalog", "TargetRedshiftCatalog", "CatalogProperties", "CreateTableDefaultPermissions", "CreateDatabaseDefaultPermissions", "AllowFullTableExternalDataAccess", "OverwriteChildResourcePermissionsWithDefault", "CreateTime", "UpdateTime")
	if err != nil {
		return nil, err
	}
	p := body
	delete(p, "AllowFullTableExternalDataAccess")
	p["Name"] = name
	p["CatalogId"] = catalog
	p["ResourceArn"] = id
	tags, err := cfnGlueTags(ctx, h.commands, arn)
	if err != nil {
		return nil, err
	}
	p["Tags"] = cfnComputeTagList(tags)
	return p, nil
}
func (h cfnGlueCatalog) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	ids, err := cfnGlueCatalogIDs(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if id == r.Scope.Account {
			continue
		}
		r.PhysicalID = cfnGlueCatalogARN(r, id)
		p, err := h.Read(ctx, r)
		if err != nil {
			return nil, err
		}
		rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: p})
	}
	return cfnAnalyticsSort(rows), nil
}

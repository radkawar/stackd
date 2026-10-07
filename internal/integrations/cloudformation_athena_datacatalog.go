package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/services/cloudformation"
	"strings"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-athena-datacatalog.html
type cfnAthenaDataCatalog struct{ commands StepFunctionsCommands }

func (h cfnAthenaDataCatalog) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Description", "Parameters", "Tags", "Type", "Status", "ConnectionType", "Error"); err != nil {
		return err
	}
	if err := cloudformation.ValidateResourceProperties("AWS::Athena::DataCatalog", p); err != nil {
		return err
	}
	_, err := cfnAnalyticsTags(p)
	return err
}
func (h cfnAthenaDataCatalog) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name"), h.Validate(b)
}
func (h cfnAthenaDataCatalog) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "Name", 128)
	if strings.EqualFold(name, "AwsDataCatalog") {
		return cloudformation.ResourceResult{}, fmt.Errorf("the AwsDataCatalog data catalog is service-managed")
	}
	r.PhysicalID = name
	ctx = cfnAthenaDataCatalogClaim(ctx, r, name)
	_, err := h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(name, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if err = cfnAnalyticsNotAdmitted(ctx); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "Type", "Parameters")
	input["Name"] = name
	input["Tags"] = cfnComputeTagList(cfnAnalyticsCustomerTags(r))
	if err = cfnComputeRun(ctx, h.commands, "athena", "CreateDataCatalog", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(name, name, nil), nil
}
func (h cfnAthenaDataCatalog) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := r.PhysicalID
	ctx = cfnAthenaDataCatalogClaim(ctx, r, name)
	input := cfnComputeCopy(r.Properties, "Type", "Parameters")
	input["Name"] = name
	input["Description"] = cfnComputeDefault(r.Properties, "Description", "")
	if err := cfnComputeRun(ctx, h.commands, "athena", "UpdateDataCatalog", input); err != nil {
		return cfnAnalyticsResult(name, name, nil), err
	}
	return cfnAnalyticsResult(name, name, nil), cfnAthenaUpdateTags(ctx, h.commands, r, cfnAthenaARN(r, "datacatalog", name))
}
func (h cfnAthenaDataCatalog) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "Name", 128)
	ctx = cfnAthenaDataCatalogClaim(ctx, r, name)
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "athena", "DeleteDataCatalog", map[string]any{"Name": name}))
}
func (h cfnAthenaDataCatalog) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name := r.PhysicalID
	ctx = cfnAthenaDataCatalogClaim(ctx, r, name)
	out, err := cfnComputeCall[api.GetDataCatalogOutput](ctx, h.commands, "athena", "GetDataCatalog", map[string]any{"Name": name})
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	p, err := cfnAnalyticsProject(out.DataCatalog, "Name", "Description", "Type", "Parameters", "Status", "ConnectionType", "Error")
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	tags, err := cfnAthenaTags(ctx, h.commands, cfnAthenaARN(r, "datacatalog", name))
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	p["Tags"] = cfnComputeTagList(tags)
	return p, nil
}
func (h cfnAthenaDataCatalog) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListDataCatalogsOutput](ctx, h.commands, "athena", "ListDataCatalogs", input)
		if err != nil {
			return nil, cfnAnalyticsReadError(err)
		}
		for _, v := range out.DataCatalogsSummary {
			r.PhysicalID = cfnComputeValue(v.CatalogName)
			p, err := h.Read(ctx, r)
			if err != nil {
				return nil, cfnAnalyticsReadError(err)
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

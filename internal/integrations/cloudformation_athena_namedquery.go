package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-athena-namedquery.html
type cfnAthenaNamedQuery struct{ commands StepFunctionsCommands }

func (h cfnAthenaNamedQuery) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Name", "Database", "Description", "QueryString", "WorkGroup"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Database", "QueryString"); err != nil {
		return err
	}
	return cloudformation.ValidateResourceProperties("AWS::Athena::NamedQuery", p)
}
func (h cfnAthenaNamedQuery) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "Name", "Database", "Description", "QueryString", "WorkGroup"), h.Validate(b)
}
func (h cfnAthenaNamedQuery) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAnalyticsContext(ctx, r, "athena", "NamedQuery")
	input := cfnComputeCopy(r.Properties, "Name", "Database", "Description", "QueryString", "WorkGroup")
	copy := r
	copy.PhysicalID = ""
	input["Name"] = cfnComputeName(copy, "Name", 128)
	input["ClientRequestToken"] = cfnComputeHash(r.StackID+"/"+r.LogicalID+"/"+r.Token) + cfnComputeHash(r.Token)
	out, err := cfnComputeCall[api.CreateNamedQueryOutput](ctx, h.commands, "athena", "CreateNamedQuery", input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeValue(out.NamedQueryId)
	return cfnAnalyticsResult(id, id, map[string]any{"NamedQueryId": id}), nil
}
func (h cfnAthenaNamedQuery) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	changed, err := h.Replacement(r.Previous, r.Properties)
	if changed || err != nil {
		if err == nil {
			err = fmt.Errorf("named queries are immutable")
		}
		return cloudformation.ResourceResult{}, err
	}
	if _, err = h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(r.PhysicalID, r.PhysicalID, map[string]any{"NamedQueryId": r.PhysicalID}), nil
}
func (h cfnAthenaNamedQuery) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnAnalyticsContext(ctx, r, "athena", "NamedQuery")
	if _, err := h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "athena", "DeleteNamedQuery", map[string]any{"NamedQueryId": r.PhysicalID}))
}
func (h cfnAthenaNamedQuery) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ctx = cfnAnalyticsContext(ctx, r, "athena", "NamedQuery")
	out, err := cfnComputeCall[api.GetNamedQueryOutput](ctx, h.commands, "athena", "GetNamedQuery", map[string]any{"NamedQueryId": r.PhysicalID})
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	return cfnAnalyticsMap(out.NamedQuery)
}
func (h cfnAthenaNamedQuery) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	groups, err := (cfnAthenaWorkGroup(h)).List(ctx, r)
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	rows := []cloudformation.ResourceDescription{}
	for _, group := range groups {
		input := map[string]any{"WorkGroup": group.Identifier}
		for {
			out, err := cfnComputeCall[api.ListNamedQueriesOutput](ctx, h.commands, "athena", "ListNamedQueries", input)
			if err != nil {
				return nil, cfnAnalyticsReadError(err)
			}
			for _, id := range out.NamedQueryIds {
				r.PhysicalID = string(id)
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
	}
	return cfnAnalyticsSort(rows), nil
}

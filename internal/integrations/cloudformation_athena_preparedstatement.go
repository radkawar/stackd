package integrations

import (
	"context"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-athena-preparedstatement.html
type cfnAthenaPreparedStatement struct{ commands StepFunctionsCommands }

func (h cfnAthenaPreparedStatement) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "StatementName", "WorkGroup", "Description", "QueryStatement"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "StatementName", "WorkGroup", "QueryStatement"); err != nil {
		return err
	}
	return cloudformation.ValidateResourceProperties("AWS::Athena::PreparedStatement", p)
}
func (h cfnAthenaPreparedStatement) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "StatementName", "WorkGroup"), h.Validate(b)
}
func cfnAthenaStatementIdentity(r cloudformation.ResourceRequest) (string, string, error) {
	if r.PhysicalID != "" {
		parts, err := cfnGlueCompound(r.PhysicalID, 2)
		if err != nil {
			return "", "", err
		}
		return parts[0], parts[1], nil
	}
	return cfnComputeString(r.Properties, "StatementName"), cfnComputeString(r.Properties, "WorkGroup"), nil
}
func (h cfnAthenaPreparedStatement) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.CloudControl = false
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name, group, err := cfnAthenaStatementIdentity(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := name + "|" + group
	r.PhysicalID = id
	ctx = cfnAnalyticsContext(ctx, r, "athena", "PreparedStatement")
	_, err = h.Read(ctx, r)
	if err == nil {
		return cfnAnalyticsResult(id, name, nil), nil
	}
	if !cfnAnalyticsMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, "Description", "QueryStatement")
	input["StatementName"] = name
	input["WorkGroup"] = group
	if err = cfnComputeRun(ctx, h.commands, "athena", "CreatePreparedStatement", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAnalyticsResult(id, name, nil), nil
}
func (h cfnAthenaPreparedStatement) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAnalyticsRequireIdentity(h, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name, group, err := cfnAthenaStatementIdentity(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAnalyticsContext(ctx, r, "athena", "PreparedStatement")
	if _, err = h.Read(ctx, r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := map[string]any{"StatementName": name, "WorkGroup": group, "QueryStatement": r.Properties["QueryStatement"], "Description": cfnComputeDefault(r.Properties, "Description", "")}
	return cfnAnalyticsResult(r.PhysicalID, name, nil), cfnComputeRun(ctx, h.commands, "athena", "UpdatePreparedStatement", input)
}
func (h cfnAthenaPreparedStatement) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name, group, err := cfnAthenaStatementIdentity(r)
	if err != nil {
		return err
	}
	ctx = cfnAnalyticsContext(ctx, r, "athena", "PreparedStatement")
	if _, err = h.Read(ctx, r); err != nil {
		return cfnAnalyticsAbsent(err)
	}
	return cfnAnalyticsAbsent(cfnComputeRun(ctx, h.commands, "athena", "DeletePreparedStatement", map[string]any{"StatementName": name, "WorkGroup": group}))
}
func (h cfnAthenaPreparedStatement) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, group, err := cfnAthenaStatementIdentity(r)
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	ctx = cfnAnalyticsContext(ctx, r, "athena", "PreparedStatement")
	out, err := cfnComputeCall[api.GetPreparedStatementOutput](ctx, h.commands, "athena", "GetPreparedStatement", map[string]any{"StatementName": name, "WorkGroup": group})
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	p, err := cfnAnalyticsProject(out.PreparedStatement, "StatementName", "Description", "QueryStatement")
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	p["WorkGroup"] = group
	return p, nil
}
func (h cfnAthenaPreparedStatement) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	groups, err := (cfnAthenaWorkGroup(h)).List(ctx, r)
	if err != nil {
		return nil, cfnAnalyticsReadError(err)
	}
	rows := []cloudformation.ResourceDescription{}
	for _, group := range groups {
		input := map[string]any{"WorkGroup": group.Identifier}
		for {
			out, err := cfnComputeCall[api.ListPreparedStatementsOutput](ctx, h.commands, "athena", "ListPreparedStatements", input)
			if err != nil {
				return nil, cfnAnalyticsReadError(err)
			}
			for _, v := range out.PreparedStatements {
				r.PhysicalID = cfnComputeValue(v.StatementName) + "|" + group.Identifier
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

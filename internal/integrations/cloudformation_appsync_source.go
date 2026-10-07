package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/services/appsync"
	"stackd/internal/services/cloudformation"
	"strings"
)

var cfnAppSyncSourceProperties = []string{"ApiId", "Name", "Type", "Description", "ServiceRoleArn", "DynamoDBConfig", "LambdaConfig", "HttpConfig", "RelationalDatabaseConfig", "ElasticsearchConfig", "OpenSearchServiceConfig", "EventBridgeConfig", "MetricsConfig"}

type cfnAppSyncSource struct{ commands StepFunctionsCommands }

func (h cfnAppSyncSource) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnAppSyncSourceProperties...); err != nil {
		return err
	}
	return cfnComputeRequired(p, "ApiId", "Name", "Type")
}
func (h cfnAppSyncSource) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApiId", "Name"), h.Validate(b)
}
func cfnAppSyncParts(id, segment string) (string, string, error) {
	_, rest, ok := strings.Cut(id, ":apis/")
	if !ok {
		return "", "", fmt.Errorf("invalid AppSync resource ARN %s", id)
	}
	parts := strings.SplitN(rest, "/"+segment+"/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid AppSync resource ARN %s", id)
	}
	return parts[0], parts[1], nil
}
func cfnAppSyncOwnedContext(ctx context.Context, r cloudformation.ResourceRequest, kind, target string, enforce bool, rows map[string]string) context.Context {
	if r.CloudControl && enforce {
		return ctx
	}
	return appsync.WithCloudFormationOwnership(ctx, kind, cfnDeveloperClaim(r), target, enforce, rows)
}
func cfnAppSyncAPIUpdateContext(ctx context.Context, r cloudformation.ResourceRequest) context.Context {
	return appsync.WithCloudFormationDesiredAPI(cfnAppSyncOwnedContext(ctx, r, "GraphQLApi", cfnAppSyncAPIID(r.PhysicalID), true, nil))
}
func cfnAppSyncScope(r cloudformation.ResourceRequest) error {
	prefix := "arn:" + r.Scope.Partition + ":appsync:" + r.Scope.Region + ":" + r.Scope.Account + ":apis/"
	if strings.HasPrefix(r.PhysicalID, "arn:") && !strings.HasPrefix(r.PhysicalID, prefix) {
		return cfnDeveloperNotFound("AppSync resource", r.PhysicalID)
	}
	return nil
}
func (h cfnAppSyncSource) get(ctx context.Context, apiid, name string) (*api.DataSource, error) {
	out, err := cfnComputeCall[api.GetDataSourceResponse](ctx, h.commands, "appsync", "GetDataSource", map[string]any{"apiId": apiid, "name": name})
	if err != nil {
		return nil, err
	}
	return out.DataSource, nil
}
func cfnAppSyncSourceResult(p *api.DataSource) cloudformation.ResourceResult {
	arn := cfnComputeValue(p.DataSourceArn)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"DataSourceArn": arn, "Name": cfnComputeValue(p.Name)}}
}
func (h cfnAppSyncSource) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeString(r.Properties, "ApiId")
	name := cfnComputeString(r.Properties, "Name")
	target := id + "/" + name
	rows := map[string]string{}
	ctx = cfnAppSyncOwnedContext(ctx, r, "DataSource", target, false, rows)
	p, err := h.get(ctx, id, name)
	if err == nil {
		if rows[target] != cfnDeveloperClaim(r) {
			return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("data source belongs to another incarnation"))
		}
		return cfnAppSyncSourceResult(p), nil
	}
	if !cfnMessagingMissing(err, "NotFoundException") {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "DataSource", target, true, nil)
	out, err := cfnComputeCall[api.CreateDataSourceResponse](ctx, h.commands, "appsync", "CreateDataSource", cfnDeveloperInput(r.Properties, cfnAppSyncSourceProperties...))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAppSyncSourceResult(out.DataSource), nil
}
func (h cfnAppSyncSource) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, name, err := cfnAppSyncParts(r.PhysicalID, "datasources")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "DataSource", id+"/"+name, true, nil)
	in := cfnDeveloperInput(r.Properties, cfnAppSyncSourceProperties...)
	in["apiId"] = id
	in["name"] = name
	in["description"] = cfnComputeDefault(r.Properties, "Description", "")
	in["metricsConfig"] = cfnComputeDefault(r.Properties, "MetricsConfig", "DISABLED")
	out, err := cfnComputeCall[api.UpdateDataSourceResponse](ctx, h.commands, "appsync", "UpdateDataSource", in)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID}, err
	}
	return cfnAppSyncSourceResult(out.DataSource), nil
}
func (h cfnAppSyncSource) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnAppSyncScope(r); err != nil {
		return err
	}
	id, name, err := cfnAppSyncParts(r.PhysicalID, "datasources")
	if err != nil {
		return err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "DataSource", id+"/"+name, true, nil)
	err = cfnComputeRun(ctx, h.commands, "appsync", "DeleteDataSource", map[string]any{"apiId": id, "name": name})
	if cfnMessagingMissing(err, "NotFoundException") {
		return nil
	}
	return err
}
func (h cfnAppSyncSource) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return nil, err
	}
	id, name, err := cfnAppSyncParts(r.PhysicalID, "datasources")
	if err != nil {
		return nil, err
	}
	p, err := h.get(ctx, id, name)
	if err != nil {
		return nil, err
	}
	out, err := cfnDeveloperModel(p, cfnAppSyncSourceProperties...)
	if err != nil {
		return nil, err
	}
	out["ApiId"] = id
	out["DataSourceArn"] = cfnComputeValue(p.DataSourceArn)
	return out, nil
}
func (h cfnAppSyncSource) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apis, err := (cfnAppSyncAPI(h)).apis(ctx)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, a := range apis {
		token := ""
		for {
			out, err := cfnComputeCall[api.ListDataSourcesResponse](ctx, h.commands, "appsync", "ListDataSources", cfnDeveloperPageInput(token, map[string]any{"apiId": cfnComputeValue(a.ApiId)}))
			if err != nil {
				return nil, err
			}
			for _, p := range out.DataSources {
				r.PhysicalID = cfnComputeValue(p.DataSourceArn)
				model, err := h.Read(ctx, r)
				if err != nil {
					return nil, err
				}
				rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: model})
			}
			next := cfnComputeValue(out.NextToken)
			if next == "" {
				break
			}
			if next == token {
				return nil, fmt.Errorf("AppSync data source pagination did not advance")
			}
			token = next
		}
	}
	return rows, nil
}

package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-functionconfiguration.html
var cfnAppSyncFunctionProperties = []string{"ApiId", "Name", "DataSourceName", "Description", "FunctionVersion", "MaxBatchSize", "Code", "CodeS3Location", "RequestMappingTemplate", "RequestMappingTemplateS3Location", "ResponseMappingTemplate", "ResponseMappingTemplateS3Location", "Runtime", "SyncConfig"}

type cfnAppSyncFunction struct{ commands StepFunctionsCommands }

func (h cfnAppSyncFunction) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, cfnAppSyncFunctionProperties...); err != nil {
		return err
	}
	return cfnComputeRequired(p, "ApiId", "Name", "DataSourceName")
}
func (h cfnAppSyncFunction) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApiId"), h.Validate(b)
}
func (h cfnAppSyncFunction) get(ctx context.Context, id, function string) (*api.FunctionConfiguration, error) {
	out, err := cfnComputeCall[api.GetFunctionResponse](ctx, h.commands, "appsync", "GetFunction", map[string]any{"apiId": id, "functionId": function})
	if err != nil {
		return nil, err
	}
	return out.FunctionConfiguration, nil
}
func cfnAppSyncFunctionResult(p *api.FunctionConfiguration) cloudformation.ResourceResult {
	arn := cfnComputeValue(p.FunctionArn)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"FunctionArn": arn, "FunctionId": cfnComputeValue(p.FunctionId), "Name": cfnComputeValue(p.Name), "DataSourceName": cfnComputeValue(p.DataSourceName)}}
}
func (h cfnAppSyncFunction) functions(ctx context.Context, id string) ([]api.FunctionConfiguration, error) {
	var rows []api.FunctionConfiguration
	token := ""
	for {
		out, err := cfnComputeCall[api.ListFunctionsResponse](ctx, h.commands, "appsync", "ListFunctions", cfnDeveloperPageInput(token, map[string]any{"apiId": id}))
		if err != nil {
			return nil, err
		}
		rows = append(rows, out.Functions...)
		next := cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
		if next == token {
			return nil, fmt.Errorf("AppSync function pagination did not advance")
		}
		token = next
	}
}
func (h cfnAppSyncFunction) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeString(r.Properties, "ApiId")
	claims := map[string]string{}
	ctx = cfnAppSyncOwnedContext(ctx, r, "FunctionConfiguration", "", false, claims)
	rows, err := h.functions(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	for i := range rows {
		if claims[id+"/"+cfnComputeValue(rows[i].FunctionId)] == cfnDeveloperClaim(r) {
			return cfnAppSyncFunctionResult(&rows[i]), nil
		}
	}
	in, err := cfnAppSyncCodeInput(ctx, h.commands, r.Properties, cfnAppSyncFunctionProperties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[api.CreateFunctionResponse](ctx, h.commands, "appsync", "CreateFunction", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAppSyncFunctionResult(out.FunctionConfiguration), nil
}
func (h cfnAppSyncFunction) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, function, err := cfnAppSyncParts(r.PhysicalID, "functions")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "FunctionConfiguration", id+"/"+function, true, nil)
	in, err := cfnAppSyncCodeInput(ctx, h.commands, r.Properties, cfnAppSyncFunctionProperties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	in["apiId"] = id
	in["functionId"] = function
	in["description"] = cfnComputeDefault(r.Properties, "Description", "")
	in["maxBatchSize"] = cfnComputeDefault(r.Properties, "MaxBatchSize", 0)
	out, err := cfnComputeCall[api.UpdateFunctionResponse](ctx, h.commands, "appsync", "UpdateFunction", in)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID}, err
	}
	return cfnAppSyncFunctionResult(out.FunctionConfiguration), nil
}
func (h cfnAppSyncFunction) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnAppSyncScope(r); err != nil {
		return err
	}
	id, function, err := cfnAppSyncParts(r.PhysicalID, "functions")
	if err != nil {
		return err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "FunctionConfiguration", id+"/"+function, true, nil)
	err = cfnComputeRun(ctx, h.commands, "appsync", "DeleteFunction", map[string]any{"apiId": id, "functionId": function})
	if cfnMessagingMissing(err, "NotFoundException") {
		return nil
	}
	return err
}
func (h cfnAppSyncFunction) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return nil, err
	}
	id, function, err := cfnAppSyncParts(r.PhysicalID, "functions")
	if err != nil {
		return nil, err
	}
	p, err := h.get(ctx, id, function)
	if err != nil {
		return nil, err
	}
	out, err := cfnDeveloperModel(p, cfnAppSyncFunctionProperties...)
	if err != nil {
		return nil, err
	}
	out["ApiId"] = id
	for k, v := range cfnAppSyncFunctionResult(p).Attributes {
		out[k] = v
	}
	return out, nil
}
func (h cfnAppSyncFunction) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apis, err := (cfnAppSyncAPI(h)).apis(ctx)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, a := range apis {
		functions, err := h.functions(ctx, cfnComputeValue(a.ApiId))
		if err != nil {
			return nil, err
		}
		for _, p := range functions {
			r.PhysicalID = cfnComputeValue(p.FunctionArn)
			model, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: model})
		}
	}
	return rows, nil
}

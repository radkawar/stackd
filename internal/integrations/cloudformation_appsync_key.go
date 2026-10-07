package integrations

import (
	"context"
	"fmt"
	api "stackd/internal/awsapi/appsync"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-apikey.html
// ApiKey attributes are intentionally returned only from the authorized owner.
type cfnAppSyncKey struct{ commands StepFunctionsCommands }

func (h cfnAppSyncKey) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "ApiId", "Description", "Expires"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "ApiId")
}
func (h cfnAppSyncKey) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "ApiId"), h.Validate(b)
}
func (h cfnAppSyncKey) keys(ctx context.Context, id string) ([]api.ApiKey, error) {
	var rows []api.ApiKey
	token := ""
	for {
		out, err := cfnComputeCall[api.ListApiKeysResponse](ctx, h.commands, "appsync", "ListApiKeys", cfnDeveloperPageInput(token, map[string]any{"apiId": id}))
		if err != nil {
			return nil, err
		}
		rows = append(rows, out.ApiKeys...)
		next := cfnComputeValue(out.NextToken)
		if next == "" {
			return rows, nil
		}
		if next == token {
			return nil, fmt.Errorf("AppSync key pagination did not advance")
		}
		token = next
	}
}
func (h cfnAppSyncKey) get(ctx context.Context, id, key string) (*api.ApiKey, error) {
	rows, err := h.keys(ctx, id)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if cfnComputeValue(rows[i].Id) == key {
			return &rows[i], nil
		}
	}
	return nil, &awswire.Error{Code: "NotFoundException", Message: "API key not found", StatusCode: 404}
}
func cfnAppSyncKeyResult(r cloudformation.ResourceRequest, id string, p *api.ApiKey) cloudformation.ResourceResult {
	key := cfnComputeValue(p.Id)
	arn := "arn:" + r.Scope.Partition + ":appsync:" + r.Scope.Region + ":" + r.Scope.Account + ":apis/" + id + "/apikey/" + key
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{"ApiKey": key, "ApiKeyId": key, "Arn": arn}}
}
func (h cfnAppSyncKey) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeString(r.Properties, "ApiId")
	claims := map[string]string{}
	ctx = cfnAppSyncOwnedContext(ctx, r, "ApiKey", "", false, claims)
	rows, err := h.keys(ctx, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	for i := range rows {
		if claims[id+"/"+cfnComputeValue(rows[i].Id)] == cfnDeveloperClaim(r) {
			return cfnAppSyncKeyResult(r, id, &rows[i]), nil
		}
	}
	out, err := cfnComputeCall[api.CreateApiKeyResponse](ctx, h.commands, "appsync", "CreateApiKey", cfnDeveloperInput(r.Properties, "ApiId", "Description", "Expires"))
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnAppSyncKeyResult(r, id, out.ApiKey), nil
}
func (h cfnAppSyncKey) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, key, err := cfnAppSyncParts(r.PhysicalID, "apikey")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "ApiKey", id+"/"+key, true, nil)
	in := cfnDeveloperInput(r.Properties, "Description", "Expires")
	in["apiId"] = id
	in["id"] = key
	in["description"] = cfnComputeDefault(r.Properties, "Description", "")
	out, err := cfnComputeCall[api.UpdateApiKeyResponse](ctx, h.commands, "appsync", "UpdateApiKey", in)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: r.PhysicalID}, err
	}
	return cfnAppSyncKeyResult(r, id, out.ApiKey), nil
}
func (h cfnAppSyncKey) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if err := cfnAppSyncScope(r); err != nil {
		return err
	}
	id, key, err := cfnAppSyncParts(r.PhysicalID, "apikey")
	if err != nil {
		return err
	}
	ctx = cfnAppSyncOwnedContext(ctx, r, "ApiKey", id+"/"+key, true, nil)
	err = cfnComputeRun(ctx, h.commands, "appsync", "DeleteApiKey", map[string]any{"apiId": id, "id": key})
	if cfnMessagingMissing(err, "NotFoundException") {
		return nil
	}
	return err
}
func (h cfnAppSyncKey) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	if err := cfnAppSyncScope(r); err != nil {
		return nil, err
	}
	id, key, err := cfnAppSyncParts(r.PhysicalID, "apikey")
	if err != nil {
		return nil, err
	}
	p, err := h.get(ctx, id, key)
	if err != nil {
		return nil, err
	}
	out, err := cfnDeveloperModel(p, "Description", "Expires")
	if err != nil {
		return nil, err
	}
	out["ApiId"] = id
	for k, v := range cfnAppSyncKeyResult(r, id, p).Attributes {
		out[k] = v
	}
	return out, nil
}
func (h cfnAppSyncKey) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	apis, err := (cfnAppSyncAPI(h)).apis(ctx)
	if err != nil {
		return nil, err
	}
	var rows []cloudformation.ResourceDescription
	for _, a := range apis {
		id := cfnComputeValue(a.ApiId)
		keys, err := h.keys(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, p := range keys {
			r.PhysicalID = cfnAppSyncKeyResult(r, id, &p).PhysicalID
			model, err := h.Read(ctx, r)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: r.PhysicalID, Properties: model})
		}
	}
	return rows, nil
}

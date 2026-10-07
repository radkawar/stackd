package integrations

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func (h cfnRESTGateway) identity(r cloudformation.ResourceRequest) (map[string]any, error) {
	parts := strings.Split(r.PhysicalID, "/")
	input := map[string]any{}
	switch h.kind {
	case "RestApi":
		input["restApiId"] = r.PhysicalID
	case "ApiKey":
		input["apiKey"] = r.PhysicalID
		input["includeValue"] = true
	case "UsagePlan":
		input["usagePlanId"] = r.PhysicalID
	case "Account":
		if r.PhysicalID != "" && r.PhysicalID != r.Scope.Region {
			return nil, fmt.Errorf("account identifier is outside request region")
		}
		return input, nil
	case "Method":
		if len(parts) != 3 {
			return nil, fmt.Errorf("method identifier must be restApiId/resourceId/httpMethod")
		}
		input["restApiId"], input["resourceId"], input["httpMethod"] = parts[0], parts[1], parts[2]
	case "UsagePlanKey":
		if len(parts) != 2 {
			return nil, fmt.Errorf("usage plan key identifier must be usagePlanId/keyId")
		}
		input["usagePlanId"], input["keyId"] = parts[0], parts[1]
	default:
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s identifier must include REST API ID and child ID", h.kind)
		}
		input["restApiId"] = parts[0]
		switch h.kind {
		case "Resource":
			input["resourceId"] = parts[1]
		case "Authorizer":
			input["authorizerId"] = parts[1]
		case "Deployment":
			input["deploymentId"] = parts[1]
		case "Stage":
			input["stageName"] = parts[1]
		default:
			return nil, fmt.Errorf("unknown REST resource %s", h.kind)
		}
	}
	for _, v := range input {
		if text, ok := v.(string); ok && text == "" {
			return nil, fmt.Errorf("resource identifier is required")
		}
	}
	return input, nil
}
func cfnRESTProject(out map[string]any, keys ...string) cloudformation.Properties {
	p := cloudformation.Properties{}
	for _, key := range keys {
		if v, ok := out[cfnRESTWire(key)]; ok {
			p[key] = v
		}
	}
	return p
}
func cfnRESTNested(v any) map[string]any {
	input, _ := v.(map[string]any)
	out := map[string]any{}
	for key, v := range input {
		out[strings.ToUpper(key[:1])+key[1:]] = v
	}
	return out
}
func cfnRESTTags(v any) []any {
	tags, _ := v.(map[string]any)
	out := make([]any, 0, len(tags))
	for _, key := range cfnRESTKeys(tags) {
		out = append(out, map[string]any{"Key": key, "Value": tags[key]})
	}
	return out
}
func cfnRESTIntegration(v any) map[string]any {
	out, _ := v.(map[string]any)
	if out == nil {
		return nil
	}
	p := cfnRESTProject(out, "Type", "Uri", "Credentials", "PassthroughBehavior", "TimeoutInMillis", "CacheNamespace", "ResponseTransferMode")
	p["IntegrationHttpMethod"] = out["httpMethod"]
	return p
}
func cfnRESTReadStages(v any) []any {
	stages, _ := v.([]any)
	out := make([]any, 0, len(stages))
	for _, v := range stages {
		stage := cfnRESTNested(v)
		if throttles, ok := stage["Throttle"].(map[string]any); ok {
			copy := map[string]any{}
			for key, value := range throttles {
				copy[key] = cfnRESTNested(value)
			}
			stage["Throttle"] = copy
		}
		out = append(out, stage)
	}
	return out
}
func cfnRESTReadMethodSettings(v any) []any {
	settings, _ := v.(map[string]any)
	out := make([]any, 0, len(settings))
	for _, key := range cfnRESTKeys(settings) {
		separator := strings.LastIndexByte(key, '/')
		if separator < 0 {
			continue
		}
		setting, _ := settings[key].(map[string]any)
		item := map[string]any(cfnRESTProject(setting, "MetricsEnabled", "LoggingLevel", "DataTraceEnabled", "ThrottlingBurstLimit", "ThrottlingRateLimit"))
		item["ResourcePath"], item["HttpMethod"] = "/"+strings.TrimPrefix(key[:separator], "/"), key[separator+1:]
		if key[:separator] == "*" {
			item["ResourcePath"] = "/*"
		}
		out = append(out, item)
	}
	return out
}
func (h cfnRESTGateway) read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	metadata := awsctx.FromContext(ctx)
	if r.Scope.Partition != metadata.Partition || r.Scope.Account != metadata.AccountID || r.Scope.Region != metadata.Region {
		return nil, &awswire.Error{Code: "NotFoundException", Message: "REST resource identifier is outside the request scope", StatusCode: 404}
	}
	input, err := h.identity(r)
	if err != nil {
		return nil, err
	}
	action := "Get" + h.kind
	switch h.kind {
	case "Resource":
		input["embed"] = []string{"methods"}
	}
	out, err := h.call(ctx, action, input)
	if err != nil {
		return nil, err
	}
	var p cloudformation.Properties
	switch h.kind {
	case "RestApi":
		p = cfnRESTProject(out, "Name", "Description", "DisableExecuteApiEndpoint", "Version", "SecurityPolicy", "BinaryMediaTypes")
		p["RestApiId"], p["RootResourceId"], p["ApiKeySourceType"] = out["id"], out["rootResourceId"], out["apiKeySource"]
		p["EndpointConfiguration"] = cfnRESTNested(out["endpointConfiguration"])
	case "Resource":
		p = cfnRESTProject(out, "ParentId", "PathPart")
		p["RestApiId"], p["ResourceId"] = input["restApiId"], out["id"]
	case "Method":
		p = cfnRESTProject(out, "HttpMethod", "AuthorizationType", "AuthorizerId", "OperationName", "AuthorizationScopes", "ApiKeyRequired")
		p["RestApiId"], p["ResourceId"] = input["restApiId"], input["resourceId"]
		if integration := cfnRESTIntegration(out["methodIntegration"]); integration != nil {
			p["Integration"] = integration
		}
	case "Authorizer":
		p = cfnRESTProject(out, "Name", "Type", "AuthType", "ProviderARNs", "AuthorizerUri", "AuthorizerCredentials", "IdentitySource", "IdentityValidationExpression", "AuthorizerResultTtlInSeconds")
		p["RestApiId"], p["AuthorizerId"] = input["restApiId"], out["id"]
	case "Deployment":
		p = cfnRESTProject(out, "Description")
		p["RestApiId"], p["DeploymentId"] = input["restApiId"], out["id"]
	case "Stage":
		p = cfnRESTProject(out, "StageName", "DeploymentId", "Description", "Variables", "CacheClusterEnabled", "TracingEnabled")
		p["RestApiId"] = input["restApiId"]
		if v := out["accessLogSettings"]; v != nil {
			p["AccessLogSetting"] = cfnRESTNested(v)
		}
		if v := out["methodSettings"]; v != nil {
			p["MethodSettings"] = cfnRESTReadMethodSettings(v)
		}
	case "Account":
		p = cloudformation.Properties{"Id": r.Scope.Region}
		if v := out["cloudwatchRoleArn"]; v != nil {
			p["CloudWatchRoleArn"] = v
		}
	case "ApiKey":
		p = cfnRESTProject(out, "Name", "Description", "Enabled", "CustomerId", "Value")
		p["APIKeyId"] = out["id"]
		stages, _ := out["stageKeys"].([]any)
		mapped := make([]any, 0, len(stages))
		for _, v := range stages {
			api, name, ok := strings.Cut(fmt.Sprint(v), "/")
			if ok {
				mapped = append(mapped, map[string]any{"RestApiId": api, "StageName": name})
			}
		}
		p["StageKeys"] = mapped
	case "UsagePlan":
		p = cfnRESTProject(out, "Description")
		p["Id"], p["UsagePlanName"] = out["id"], out["name"]
		if v := out["throttle"]; v != nil {
			p["Throttle"] = cfnRESTNested(v)
		}
		if v := out["quota"]; v != nil {
			p["Quota"] = cfnRESTNested(v)
		}
		p["ApiStages"] = cfnRESTReadStages(out["apiStages"])
	case "UsagePlanKey":
		p = cloudformation.Properties{"UsagePlanId": input["usagePlanId"], "KeyId": out["id"], "KeyType": out["type"], "Id": out["id"]}
	}
	if h.kind == "RestApi" || h.kind == "Stage" || h.kind == "ApiKey" || h.kind == "UsagePlan" {
		p["Tags"] = cfnRESTTags(out["tags"])
	}
	return p, nil
}
func (h cfnRESTGateway) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	return h.read(ctx, r)
}
func (h cfnRESTGateway) pages(ctx context.Context, action string, input map[string]any) ([]map[string]any, error) {
	if action != "GetStages" {
		input["limit"] = 500
	}
	var rows []map[string]any
	for {
		out, err := h.call(ctx, action, input)
		if err != nil {
			return nil, err
		}
		items, _ := out["item"].([]any)
		if items == nil {
			items, _ = out["items"].([]any)
		}
		for _, v := range items {
			item, ok := v.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s returned invalid list item", action)
			}
			rows = append(rows, item)
		}
		marker, _ := out["position"].(string)
		if marker == "" {
			return rows, nil
		}
		input["position"] = marker
	}
}
func (h cfnRESTGateway) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var ids []string
	switch h.kind {
	case "Account":
		ids = []string{r.Scope.Region}
	case "RestApi", "ApiKey", "UsagePlan":
		rows, err := h.pages(ctx, "Get"+h.kind+"s", map[string]any{})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			id, _ := row["id"].(string)
			ids = append(ids, id)
		}
	case "UsagePlanKey":
		var plans []map[string]any
		if id := cfnComputeString(r.Properties, "UsagePlanId"); id != "" {
			plans = []map[string]any{{"id": id}}
		} else {
			var err error
			plans, err = h.pages(ctx, "GetUsagePlans", map[string]any{})
			if err != nil {
				return nil, err
			}
		}
		for _, plan := range plans {
			id, _ := plan["id"].(string)
			rows, err := h.pages(ctx, "GetUsagePlanKeys", map[string]any{"usagePlanId": id})
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				child, _ := row["id"].(string)
				ids = append(ids, id+"/"+child)
			}
		}
	default:
		var apis []map[string]any
		if id := cfnComputeString(r.Properties, "RestApiId"); id != "" {
			apis = []map[string]any{{"id": id}}
		} else {
			var err error
			apis, err = h.pages(ctx, "GetRestApis", map[string]any{})
			if err != nil {
				return nil, err
			}
		}
		for _, api := range apis {
			id, _ := api["id"].(string)
			action := "Get" + h.kind + "s"
			if h.kind == "Method" {
				action = "GetResources"
			}
			rows, err := h.pages(ctx, action, map[string]any{"restApiId": id})
			if err != nil {
				return nil, err
			}
			for _, row := range rows {
				child, _ := row["id"].(string)
				if h.kind == "Stage" {
					child, _ = row["stageName"].(string)
				}
				if h.kind == "Method" {
					methods, _ := row["resourceMethods"].(map[string]any)
					for _, verb := range cfnRESTKeys(methods) {
						ids = append(ids, id+"/"+child+"/"+verb)
					}
				} else if h.kind != "Resource" || row["parentId"] != nil {
					ids = append(ids, id+"/"+child)
				}
			}
		}
	}
	sort.Strings(ids)
	results := make([]cloudformation.ResourceDescription, 0, len(ids))
	for _, id := range ids {
		request := r
		request.PhysicalID = id
		p, err := h.read(ctx, request)
		if err != nil {
			return nil, err
		}
		results = append(results, cloudformation.ResourceDescription{Identifier: id, Properties: p})
	}
	return results, nil
}
func (h cfnRESTGateway) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.read(ctx, r)
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{}}
	if err != nil {
		return result, err
	}
	switch h.kind {
	case "RestApi":
		result.Ref = fmt.Sprint(p["RestApiId"])
		result.Attributes["RestApiId"] = p["RestApiId"]
		result.Attributes["RootResourceId"] = p["RootResourceId"]
	case "Resource":
		result.Ref = fmt.Sprint(p["ResourceId"])
		result.Attributes["ResourceId"] = p["ResourceId"]
	case "Authorizer":
		result.Ref = fmt.Sprint(p["AuthorizerId"])
		result.Attributes["AuthorizerId"] = p["AuthorizerId"]
	case "Deployment":
		result.Ref = fmt.Sprint(p["DeploymentId"])
		result.Attributes["DeploymentId"] = p["DeploymentId"]
	case "Stage":
		result.Ref = fmt.Sprint(p["StageName"])
	case "Account":
		result.Attributes["Id"] = p["Id"]
	case "ApiKey":
		result.Attributes["APIKeyId"] = p["APIKeyId"]
	case "UsagePlan":
		result.Attributes["Id"] = p["Id"]
	case "UsagePlanKey":
		result.Ref = fmt.Sprint(p["KeyId"]) + ":" + fmt.Sprint(p["UsagePlanId"])
		result.Attributes["Id"] = p["KeyId"]
	}
	return result, nil
}

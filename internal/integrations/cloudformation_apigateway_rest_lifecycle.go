package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"stackd/internal/services/apigateway"
	"stackd/internal/services/cloudformation"
)

func (h cfnRESTGateway) recover(ctx context.Context, r cloudformation.ResourceRequest) (string, error) {
	claim := cfnRESTClaim(r)
	if claim.StackID == "" || claim.LogicalID == "" || claim.Incarnation == "" {
		return "", nil
	}
	rows := map[string]apigateway.Ownership{}
	_, err := h.List(h.context(ctx, r, false, false, rows), r)
	// An authorized native list can identify the admitted incarnation even when
	// a later read fails. Keep its ID for rollback without hiding that failure.
	for id, owner := range rows {
		if owner == claim {
			return id, err
		}
	}
	return "", err
}
func cfnRESTUserTags(r cloudformation.ResourceRequest) map[string]string {
	tags, _ := cfnComputeTags(r.Properties)
	for key, value := range r.Tags {
		if _, ok := tags[key]; !ok {
			tags[key] = value
		}
	}
	return tags
}
func cfnRESTNestedWire(p map[string]any) map[string]any {
	out := map[string]any{}
	for key, v := range p {
		out[cfnRESTWire(key)] = v
	}
	return out
}
func cfnRESTStageInputs(v any) []any {
	stages, _ := v.([]any)
	out := make([]any, 0, len(stages))
	for _, v := range stages {
		stage, _ := cfnComputeObject(v)
		wire := cfnRESTNestedWire(stage)
		if throttles, ok := stage["Throttle"].(map[string]any); ok {
			copy := map[string]any{}
			for key, value := range throttles {
				setting, _ := cfnComputeObject(value)
				copy[key] = cfnRESTNestedWire(setting)
			}
			wire["throttle"] = copy
		}
		out = append(out, wire)
	}
	return out
}
func (h cfnRESTGateway) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if h.kind == "Account" {
		return h.createAccount(ctx, r)
	}
	id, err := h.recover(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{PhysicalID: id}, err
	}
	if id == "" {
		p := r.Properties
		var input map[string]any
		action := "Create" + h.kind
		switch h.kind {
		case "RestApi":
			input = cfnRESTInput(p, "Name", "Description", "Version", "SecurityPolicy", "DisableExecuteApiEndpoint", "BinaryMediaTypes")
			input["name"] = cfnComputeDefault(p, "Name", cfnComputeName(r, "Name", 128))
			input["apiKeySource"] = cfnComputeDefault(p, "ApiKeySourceType", "HEADER")
			endpoint, _ := cfnComputeObject(p["EndpointConfiguration"])
			if endpoint == nil {
				endpoint = map[string]any{"Types": []any{"REGIONAL"}}
			}
			input["endpointConfiguration"] = cfnRESTNestedWire(endpoint)
			input["tags"] = cfnRESTUserTags(r)
			if p["Body"] != nil {
				ctx, err = cfnRESTImportContext(ctx, input, nil, p)
				if err != nil {
					return cloudformation.ResourceResult{}, err
				}
				body, err := json.Marshal(p["Body"])
				if err != nil {
					return cloudformation.ResourceResult{}, err
				}
				action = "ImportRestApi"
				input = cfnRESTInput(p, "FailOnWarnings", "Parameters")
				input["body"] = string(body)
			}
		case "Resource":
			input = cfnRESTInput(p, "RestApiId", "ParentId", "PathPart")
		case "Method":
			action = "PutMethod"
			input = cfnRESTInput(p, "RestApiId", "ResourceId", "HttpMethod", "AuthorizerId", "OperationName", "AuthorizationScopes", "ApiKeyRequired")
			input["authorizationType"] = cfnComputeDefault(p, "AuthorizationType", "NONE")
		case "Authorizer":
			input = cfnRESTInput(p, "RestApiId", "Name", "Type", "AuthType", "ProviderARNs", "AuthorizerUri", "AuthorizerCredentials", "IdentitySource", "IdentityValidationExpression", "AuthorizerResultTtlInSeconds")
			if p["Type"] == "COGNITO_USER_POOLS" && p["IdentitySource"] == nil {
				input["identitySource"] = "method.request.header.Authorization"
			}
		case "Deployment":
			input = cfnRESTInput(p, "RestApiId", "Description", "StageName")
			if stage, ok := cfnComputeObject(p["StageDescription"]); ok {
				if stage["Description"] != nil {
					input["stageDescription"] = stage["Description"]
				}
				if stage["Variables"] != nil {
					input["variables"] = stage["Variables"]
				}
			}
		case "Stage":
			input = cfnRESTInput(p, "RestApiId", "DeploymentId", "Description", "Variables", "CacheClusterEnabled", "TracingEnabled")
			input["stageName"] = cfnComputeDefault(p, "StageName", cfnComputeName(r, "StageName", 128))
			input["tags"] = cfnRESTUserTags(r)
		case "ApiKey":
			input = cfnRESTInput(p, "Name", "Description", "Enabled", "CustomerId", "Value", "GenerateDistinctId")
			input["name"] = cfnComputeDefault(p, "Name", cfnComputeName(r, "Name", 128))
			input["enabled"] = cfnComputeDefault(p, "Enabled", true)
			input["stageKeys"] = cfnRESTStageInputs(p["StageKeys"])
			input["tags"] = cfnRESTUserTags(r)
		case "UsagePlan":
			input = cfnRESTInput(p, "Description")
			input["name"] = cfnComputeDefault(p, "UsagePlanName", cfnComputeName(r, "UsagePlanName", 128))
			input["apiStages"] = cfnRESTStageInputs(p["ApiStages"])
			input["tags"] = cfnRESTUserTags(r)
			if v, ok := cfnComputeObject(p["Throttle"]); ok {
				input["throttle"] = cfnRESTNestedWire(v)
			}
			if v, ok := cfnComputeObject(p["Quota"]); ok {
				input["quota"] = cfnRESTNestedWire(v)
			}
		case "UsagePlanKey":
			input = cfnRESTInput(p, "UsagePlanId", "KeyId", "KeyType")
		}
		out, err := h.call(h.context(ctx, r, false, false, nil), action, input)
		if err != nil {
			// A modeled error can follow a committed owner write or a lost response.
			// Recover only the exact claim through the current authorized native reads.
			admitted, recoveryErr := h.recover(ctx, r)
			if recoveryErr != nil {
				err = errors.Join(err, recoveryErr)
			}
			return cloudformation.ResourceResult{PhysicalID: admitted}, err
		}
		native, _ := out["id"].(string)
		switch h.kind {
		case "Method":
			id = fmt.Sprint(input["restApiId"]) + "/" + fmt.Sprint(input["resourceId"]) + "/" + fmt.Sprint(input["httpMethod"])
		case "Stage":
			name, _ := out["stageName"].(string)
			id = fmt.Sprint(input["restApiId"]) + "/" + name
		case "UsagePlanKey":
			id = fmt.Sprint(input["usagePlanId"]) + "/" + native
		case "Resource", "Authorizer", "Deployment":
			id = fmt.Sprint(input["restApiId"]) + "/" + native
		default:
			id = native
		}
	}
	r.PhysicalID = id
	result, err := h.Result(ctx, r)
	if err != nil {
		return result, err
	}
	// A recovered method or stage may have committed before its nested effects.
	switch h.kind {
	case "Method":
		err = h.configureMethod(h.context(ctx, r, true, false, nil), r, false)
	case "Stage":
		err = h.configureStage(h.context(ctx, r, true, false, nil), r)
	case "Deployment":
		err = h.configureDeploymentStage(ctx, r)
	}
	return result, err
}
func (h cfnRESTGateway) createAccount(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	r.PhysicalID = r.Scope.Region
	rows := map[string]apigateway.Ownership{}
	if _, err := h.read(h.context(ctx, r, false, false, rows), r); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	claim := rows[r.PhysicalID]
	if claim != (apigateway.Ownership{}) && claim != cfnRESTClaim(r) {
		return cloudformation.ResourceResult{}, fmt.Errorf("regional API Gateway account settings are owned by another resource incarnation")
	}
	_, err := h.call(h.context(ctx, r, false, false, nil), "UpdateAccount", map[string]any{"patchOperations": []any{cfnRESTPatch("replace", "/cloudwatchRoleArn", cfnComputeString(r.Properties, "CloudWatchRoleArn"))}})
	result := cloudformation.ResourceResult{PhysicalID: r.PhysicalID, Ref: r.PhysicalID, Attributes: map[string]any{"Id": r.PhysicalID}}
	return result, err
}
func (h cfnRESTGateway) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if replace {
		return cloudformation.ResourceResult{}, fmt.Errorf("%s update requires replacement", h.kind)
	}
	ctx = h.context(ctx, r, true, false, nil)
	current, err := h.read(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input, err := h.identity(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	var patches []any
	p := r.Properties
	switch h.kind {
	case "RestApi":
		patches = append(patches, cfnRESTPatch("replace", "/name", cfnRESTImportMetadata(p, "Name", "title", current["Name"])), cfnRESTPatch("replace", "/description", cfnRESTImportMetadata(p, "Description", "description", "")), cfnRESTPatch("replace", "/version", cfnRESTImportMetadata(p, "Version", "version", "")), cfnRESTPatch("replace", "/disableExecuteApiEndpoint", cfnComputeDefault(p, "DisableExecuteApiEndpoint", false)), cfnRESTPatch("replace", "/apiKeySource", cfnComputeDefault(p, "ApiKeySourceType", "HEADER")))
		patches = append(patches, cfnRESTBinaryPatches(current, p)...)
		if p["Body"] != nil {
			ctx, err = cfnRESTImportContext(ctx, nil, patches, p)
			if err != nil {
				return cloudformation.ResourceResult{}, err
			}
			body, err := json.Marshal(p["Body"])
			if err != nil {
				return cloudformation.ResourceResult{}, err
			}
			input["body"] = string(body)
			input["mode"] = cfnComputeDefault(p, "Mode", "overwrite")
			for _, key := range []string{"FailOnWarnings", "Parameters"} {
				if v, ok := p[key]; ok {
					input[cfnRESTWire(key)] = v
				}
			}
			if _, err := h.call(ctx, "PutRestApi", input); err != nil {
				return cloudformation.ResourceResult{}, err
			}
			patches = nil
		}
	case "Resource":
		return h.Result(ctx, r)
	case "Method":
		err = h.configureMethod(ctx, r, true)
	case "Authorizer":
		patches = cfnRESTAuthorizerPatches(current, p)
	case "Deployment":
		patches = append(patches, cfnRESTPatch("replace", "/description", cfnComputeString(p, "Description")))
	case "Stage":
		err = h.configureStage(ctx, r)
	case "Account":
		patches = append(patches, cfnRESTPatch("replace", "/cloudwatchRoleArn", cfnComputeString(p, "CloudWatchRoleArn")))
	case "ApiKey":
		patches = append(patches, cfnRESTPatch("replace", "/description", cfnComputeString(p, "Description")), cfnRESTPatch("replace", "/enabled", cfnComputeDefault(p, "Enabled", true)))
		if p["CustomerId"] != nil {
			patches = append(patches, cfnRESTPatch("replace", "/customerId", p["CustomerId"]))
		} else if current["CustomerId"] != nil {
			patches = append(patches, cfnRESTPatch("remove", "/customerId", nil))
		}
		for _, stage := range cfnRESTStageList(current, "StageKeys", "RestApiId", "StageName", "/") {
			patches = append(patches, cfnRESTPatch("remove", "/stages", stage))
		}
		for _, stage := range cfnRESTStageList(p, "StageKeys", "RestApiId", "StageName", "/") {
			patches = append(patches, cfnRESTPatch("add", "/stages", stage))
		}
	case "UsagePlan":
		patches = cfnRESTUsagePatches(current, p)
	case "UsagePlanKey":
		return h.Result(ctx, r)
	}
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if len(patches) > 0 {
		input["patchOperations"] = patches
		_, err = h.call(ctx, "Update"+h.kind, input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if h.kind == "Deployment" {
		if err = h.configureDeploymentStage(ctx, r); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if h.kind == "RestApi" || h.kind == "ApiKey" || h.kind == "UsagePlan" {
		if err = h.updateTags(ctx, r, current); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	return h.Result(ctx, r)
}
func cfnRESTStageList(p map[string]any, key, apiField, nameField, separator string) []string {
	stages, _ := p[key].([]any)
	out := make([]string, 0, len(stages))
	for _, v := range stages {
		stage, _ := cfnComputeObject(v)
		out = append(out, cfnComputeString(stage, apiField)+separator+cfnComputeString(stage, nameField))
	}
	return out
}
func cfnRESTAuthorizerPatches(current, p map[string]any) []any {
	patches := []any{cfnRESTPatch("replace", "/name", p["Name"]), cfnRESTPatch("replace", "/type", p["Type"])}
	for _, key := range []string{"AuthType", "AuthorizerCredentials", "AuthorizerUri", "IdentitySource", "IdentityValidationExpression"} {
		desired := cfnComputeString(p, key)
		if key == "AuthType" && desired == "" {
			desired = "custom"
			if p["Type"] == "COGNITO_USER_POOLS" {
				desired = "cognito_user_pools"
			}
		}
		if key == "IdentitySource" && p["Type"] == "COGNITO_USER_POOLS" && desired == "" {
			desired = "method.request.header.Authorization"
		}
		if key == "IdentityValidationExpression" && p["Type"] == "COGNITO_USER_POOLS" {
			continue
		}
		if current[key] != desired {
			patches = append(patches, cfnRESTPatch("replace", "/"+cfnRESTWire(key), desired))
		}
	}
	if p["Type"] != "COGNITO_USER_POOLS" {
		patches = append(patches, cfnRESTPatch("replace", "/authorizerResultTtlInSeconds", cfnComputeDefault(p, "AuthorizerResultTtlInSeconds", 300)))
	}
	previous, _ := current["ProviderARNs"].([]any)
	desired, _ := p["ProviderARNs"].([]any)
	for _, v := range previous {
		patches = append(patches, cfnRESTPatch("remove", "/providerARNs", v))
	}
	for _, v := range desired {
		patches = append(patches, cfnRESTPatch("add", "/providerARNs", v))
	}
	return patches
}
func (h cfnRESTGateway) configureMethod(ctx context.Context, r cloudformation.ResourceRequest, update bool) error {
	input, err := h.identity(r)
	if err != nil {
		return err
	}
	if update {
		current, err := h.read(ctx, r)
		if err != nil {
			return err
		}
		p := r.Properties
		patches := []any{cfnRESTPatch("replace", "/authorizationType", cfnComputeDefault(p, "AuthorizationType", "NONE")), cfnRESTPatch("replace", "/authorizerId", cfnComputeString(p, "AuthorizerId")), cfnRESTPatch("replace", "/operationName", cfnComputeString(p, "OperationName")), cfnRESTPatch("replace", "/apiKeyRequired", cfnComputeDefault(p, "ApiKeyRequired", false))}
		previous, _ := current["AuthorizationScopes"].([]any)
		desired, _ := p["AuthorizationScopes"].([]any)
		for _, v := range previous {
			patches = append(patches, cfnRESTPatch("remove", "/authorizationScopes", v))
		}
		for _, v := range desired {
			patches = append(patches, cfnRESTPatch("add", "/authorizationScopes", v))
		}
		input["patchOperations"] = patches
		// Remove caller-identity forwarding before switching away from AWS_IAM.
		if integration, ok := cfnComputeObject(current["Integration"]); ok && integration["Credentials"] == "arn:aws:iam::*:user/*" && cfnComputeDefault(p, "AuthorizationType", "NONE") != "AWS_IAM" {
			if _, err := h.call(ctx, "DeleteIntegration", cfnRESTInput(current, "RestApiId", "ResourceId", "HttpMethod")); err != nil {
				return err
			}
		}
		if _, err := h.call(ctx, "UpdateMethod", input); err != nil {
			return err
		}
	}
	integration, _ := cfnComputeObject(r.Properties["Integration"])
	input, err = h.identity(r)
	if err != nil {
		return err
	}
	if integration == nil {
		_, err = h.call(ctx, "DeleteIntegration", input)
		return cfnRESTAbsent(err)
	}
	for key, v := range cfnRESTInput(integration, "Type", "IntegrationHttpMethod", "Uri", "Credentials", "ConnectionType", "PassthroughBehavior", "TimeoutInMillis", "CacheNamespace", "ResponseTransferMode") {
		input[key] = v
	}
	_, err = h.call(ctx, "PutIntegration", input)
	return err
}
func (h cfnRESTGateway) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = h.context(ctx, r, true, false, nil)
	current, err := h.read(ctx, r)
	if err != nil {
		return cfnRESTAbsent(err)
	}
	input, err := h.identity(r)
	if err != nil {
		return err
	}
	switch h.kind {
	case "Account":
		// AWS retains the regional role on stack deletion. Release only its claim.
		if r.CloudControl {
			return nil
		} // Direct deletion has no stack claim to release.
		ctx = h.context(ctx, r, true, true, nil)
		_, err = h.call(ctx, "UpdateAccount", map[string]any{"patchOperations": []any{cfnRESTPatch("replace", "/cloudwatchRoleArn", cfnComputeString(current, "CloudWatchRoleArn"))}})
		return err
	case "UsagePlan":
		var patches []any
		for _, stage := range cfnRESTStageList(current, "ApiStages", "ApiId", "Stage", ":") {
			patches = append(patches, cfnRESTPatch("remove", "/apiStages", stage))
		}
		if len(patches) > 0 {
			_, err = h.call(ctx, "UpdateUsagePlan", map[string]any{"usagePlanId": r.PhysicalID, "patchOperations": patches})
			if err != nil {
				return err
			}
		}
	case "Deployment":
		stageHandler := cfnRESTGateway{h.commands, "Stage"}
		stageRequest := r
		stageRequest.Properties = cloudformation.Properties{"RestApiId": input["restApiId"]}
		rows := map[string]apigateway.Ownership{}
		stages, listErr := stageHandler.List(stageHandler.context(ctx, stageRequest, false, false, rows), stageRequest)
		if listErr != nil {
			return listErr
		}
		for _, stage := range stages {
			if stage.Properties["DeploymentId"] == input["deploymentId"] && rows[stage.Identifier] == cfnRESTClaim(r) {
				stageRequest.PhysicalID = stage.Identifier
				if err := stageHandler.Delete(ctx, stageRequest); err != nil {
					return err
				}
			}
		}
	}
	_, err = h.call(ctx, "Delete"+h.kind, input)
	return cfnRESTAbsent(err)
}
func (h cfnRESTGateway) updateTags(ctx context.Context, r cloudformation.ResourceRequest, current map[string]any) error {
	desired := cfnRESTUserTags(r)
	previous, _ := cfnComputeTags(current)
	input, err := h.identity(r)
	if err != nil {
		return err
	}
	path := ""
	switch h.kind {
	case "RestApi":
		path = "/restapis/" + r.PhysicalID
	case "ApiKey":
		path = "/apikeys/" + r.PhysicalID
	case "UsagePlan":
		path = "/usageplans/" + r.PhysicalID
	case "Stage":
		path = "/restapis/" + fmt.Sprint(input["restApiId"]) + "/stages/" + fmt.Sprint(input["stageName"])
	}
	arn := "arn:" + r.Scope.Partition + ":apigateway:" + r.Scope.Region + "::" + path
	removed := cfnComputeRemovedTags(previous, desired)
	if len(removed) > 0 {
		if _, err := h.call(ctx, "UntagResource", map[string]any{"resourceArn": arn, "tagKeys": removed}); err != nil {
			return err
		}
	}
	if len(desired) > 0 {
		_, err = h.call(ctx, "TagResource", map[string]any{"resourceArn": arn, "tags": desired})
	}
	return err
}

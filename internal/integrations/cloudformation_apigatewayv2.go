package integrations

import (
	"context"
	"fmt"
	"reflect"
	"slices"

	"stackd/internal/services/apigatewayv2"
	"stackd/internal/services/cloudformation"
)

// cfnGatewayV2Kind describes one AWS::ApiGatewayV2 resource schema
// (https://schema.cloudformation.us-east-2.amazonaws.com/CloudformationSchema.zip)
// mapped onto the V2 owner's generated command members. Every lifecycle step is
// an owner command; the kind holds no resource state.
type cfnGatewayV2Kind struct {
	typeName, noun, leaf string
	// ids is the schema primaryIdentifier order; parents are create-only
	// identifiers supplied to every command.
	ids, parents []string
	writable     []string
	required     []string
	createOnly   []string
	// local properties are interpreted by the adapter instead of being command members.
	local []string
	// always members are resent on every update because the owner replaces them.
	always      []string
	unsupported map[string]string
	ints, bools []string
	// resets clear a removed property through the owner update command.
	// Removing any other writable property requires a new resource.
	resets   map[string]any
	dynamic  []string
	read     []string
	tagged   bool
	listWith []string
}

var cfnGatewayV2Kinds = []cfnGatewayV2Kind{
	{
		typeName: "AWS::ApiGatewayV2::Api", noun: "Api", leaf: "ApiId", ids: []string{"ApiId"},
		writable: []string{"Name", "Description", "Version", "ProtocolType", "RouteSelectionExpression", "ApiKeySelectionExpression", "DisableExecuteApiEndpoint", "DisableSchemaValidation", "IpAddressType", "CorsConfiguration", "CredentialsArn", "RouteKey", "Target", "Tags", "FailOnWarnings"},
		required: []string{"Name", "ProtocolType"}, createOnly: []string{"ProtocolType"},
		local: []string{"Tags", "FailOnWarnings"},
		// OpenAPI import (ImportApi/ReimportApi) has no owner implementation.
		unsupported: map[string]string{"Body": "OpenAPI import", "BodyS3Location": "OpenAPI import", "BasePath": "OpenAPI import base paths"},
		bools:       []string{"DisableExecuteApiEndpoint", "DisableSchemaValidation", "FailOnWarnings"},
		resets: map[string]any{"Description": "", "Version": "", "DisableExecuteApiEndpoint": false, "DisableSchemaValidation": false,
			"ApiKeySelectionExpression": "$request.header.x-api-key", "IpAddressType": "ipv4", "Tags": nil, "FailOnWarnings": nil},
		read:   []string{"Name", "Description", "Version", "ProtocolType", "RouteSelectionExpression", "ApiKeySelectionExpression", "DisableExecuteApiEndpoint", "IpAddressType", "CorsConfiguration", "Tags", "ApiEndpoint"},
		tagged: true,
	},
	{
		typeName: "AWS::ApiGatewayV2::Integration", noun: "Integration", leaf: "IntegrationId",
		ids: []string{"ApiId", "IntegrationId"}, parents: []string{"ApiId"},
		writable: []string{"IntegrationType", "IntegrationUri", "IntegrationMethod", "IntegrationSubtype", "PayloadFormatVersion", "PassthroughBehavior", "ConnectionId", "ConnectionType", "ContentHandlingStrategy", "CredentialsArn", "Description", "RequestParameters", "RequestTemplates", "ResponseParameters", "TemplateSelectionExpression", "TimeoutInMillis", "TlsConfig"},
		required: []string{"ApiId", "IntegrationType"},
		ints:     []string{"TimeoutInMillis"},
		resets:   map[string]any{"Description": "", "CredentialsArn": ""},
		dynamic:  []string{"TimeoutInMillis", "PassthroughBehavior", "PayloadFormatVersion"},
		read:     []string{"IntegrationType", "IntegrationUri", "IntegrationMethod", "IntegrationSubtype", "PayloadFormatVersion", "PassthroughBehavior", "ConnectionId", "ConnectionType", "ContentHandlingStrategy", "CredentialsArn", "Description", "RequestParameters", "RequestTemplates", "TemplateSelectionExpression", "TimeoutInMillis", "TlsConfig"},
		listWith: []string{"ApiId"},
	},
	{
		typeName: "AWS::ApiGatewayV2::Authorizer", noun: "Authorizer", leaf: "AuthorizerId",
		ids: []string{"AuthorizerId", "ApiId"}, parents: []string{"ApiId"},
		writable: []string{"Name", "AuthorizerType", "AuthorizerUri", "AuthorizerCredentialsArn", "AuthorizerPayloadFormatVersion", "AuthorizerResultTtlInSeconds", "EnableSimpleResponses", "IdentitySource", "IdentityValidationExpression", "JwtConfiguration"},
		required: []string{"ApiId", "AuthorizerType", "Name"},
		ints:     []string{"AuthorizerResultTtlInSeconds"}, bools: []string{"EnableSimpleResponses"},
		resets:   map[string]any{"AuthorizerCredentialsArn": "", "IdentityValidationExpression": "", "EnableSimpleResponses": false},
		dynamic:  []string{"AuthorizerResultTtlInSeconds"},
		read:     []string{"Name", "AuthorizerType", "AuthorizerUri", "AuthorizerCredentialsArn", "AuthorizerPayloadFormatVersion", "AuthorizerResultTtlInSeconds", "EnableSimpleResponses", "IdentitySource", "IdentityValidationExpression", "JwtConfiguration"},
		listWith: []string{"ApiId"},
	},
	{
		typeName: "AWS::ApiGatewayV2::Route", noun: "Route", leaf: "RouteId",
		ids: []string{"ApiId", "RouteId"}, parents: []string{"ApiId"},
		writable: []string{"RouteKey", "Target", "AuthorizationType", "AuthorizerId", "AuthorizationScopes", "OperationName", "ApiKeyRequired", "ModelSelectionExpression", "RequestModels", "RequestParameters", "RouteResponseSelectionExpression"},
		required: []string{"ApiId", "RouteKey"},
		bools:    []string{"ApiKeyRequired"},
		resets:   map[string]any{"Target": "", "AuthorizationType": "NONE", "AuthorizerId": "", "OperationName": "", "ApiKeyRequired": false},
		read:     []string{"RouteKey", "Target", "AuthorizationType", "AuthorizerId", "AuthorizationScopes", "OperationName", "ApiKeyRequired", "ModelSelectionExpression", "RequestModels", "RequestParameters", "RouteResponseSelectionExpression"},
		listWith: []string{"ApiId"},
	},
	{
		typeName: "AWS::ApiGatewayV2::RouteResponse", noun: "RouteResponse", leaf: "RouteResponseId",
		ids: []string{"ApiId", "RouteId", "RouteResponseId"}, parents: []string{"ApiId", "RouteId"},
		writable: []string{"RouteResponseKey", "ModelSelectionExpression", "ResponseModels", "ResponseParameters"},
		required: []string{"ApiId", "RouteId", "RouteResponseKey"},
		read:     []string{"RouteResponseKey", "ModelSelectionExpression", "ResponseModels", "ResponseParameters"},
		listWith: []string{"ApiId", "RouteId"},
	},
	{
		typeName: "AWS::ApiGatewayV2::Stage", noun: "Stage", leaf: "StageName",
		ids: []string{"ApiId", "StageName"}, parents: []string{"ApiId"},
		writable: []string{"StageName", "Description", "DeploymentId", "AutoDeploy", "AccessLogSettings", "DefaultRouteSettings", "RouteSettings", "StageVariables", "ClientCertificateId", "Tags"},
		required: []string{"ApiId", "StageName"}, createOnly: []string{"StageName"},
		local:  []string{"Tags"},
		always: []string{"StageVariables", "DefaultRouteSettings", "RouteSettings"},
		bools:  []string{"AutoDeploy"},
		resets: map[string]any{"Description": "", "AutoDeploy": false, "Tags": nil, "AccessLogSettings": nil,
			"StageVariables": nil, "DefaultRouteSettings": nil, "RouteSettings": nil},
		read:     []string{"StageName", "Description", "DeploymentId", "AutoDeploy", "AccessLogSettings", "DefaultRouteSettings", "RouteSettings", "StageVariables", "ClientCertificateId", "Tags"},
		tagged:   true,
		listWith: []string{"ApiId"},
	},
	{
		typeName: "AWS::ApiGatewayV2::Deployment", noun: "Deployment", leaf: "DeploymentId",
		ids: []string{"ApiId", "DeploymentId"}, parents: []string{"ApiId"},
		writable: []string{"Description", "StageName"},
		required: []string{"ApiId"},
		local:    []string{"StageName"},
		// A removed StageName leaves the stage on this immutable deployment.
		resets:   map[string]any{"Description": "", "StageName": nil},
		read:     []string{"Description"},
		listWith: []string{"ApiId"},
	},
}

// CloudFormationAPIGatewayV2Handlers maps every AWS::ApiGatewayV2 type with an
// implemented owner. DomainName and ApiMapping are registered separately.
func CloudFormationAPIGatewayV2Handlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	out := make(map[string]cloudformation.ResourceHandler, len(cfnGatewayV2Kinds))
	for _, kind := range cfnGatewayV2Kinds {
		out[kind.typeName] = cfnGatewayV2{commands: commands, kind: kind}
	}
	return out
}

type cfnGatewayV2 struct {
	commands StepFunctionsCommands
	kind     cfnGatewayV2Kind
}

func (h cfnGatewayV2) properties(p cloudformation.Properties) (map[string]any, error) {
	allowed := append(slices.Clone(h.kind.parents), h.kind.writable...)
	for key := range p {
		if feature, found := h.kind.unsupported[key]; found {
			return nil, fmt.Errorf("%s is not supported: the API Gateway V2 owner does not implement %s", key, feature)
		}
	}
	if err := cfnComputeProperties(p, allowed...); err != nil {
		return nil, err
	}
	if err := cfnComputeRequired(p, h.kind.required...); err != nil {
		return nil, err
	}
	if err := cfnComputeStrings(p, h.kind.parents...); err != nil {
		return nil, err
	}
	out := cfnComputeCopy(p, allowed...)
	if err := cfnGatewayV2Scalar(out, h.kind.ints, h.kind.bools); err != nil {
		return nil, err
	}
	if h.kind.tagged {
		if _, err := cfnGatewayV2Tags(out); err != nil {
			return nil, err
		}
	}
	return out, cfnGatewayV2Shape(h.kind.noun, out)
}

// cfnGatewayV2Shape converts template shapes that differ from the owner's
// generated command members.
func cfnGatewayV2Shape(noun string, p map[string]any) error {
	switch noun {
	case "Integration":
		raw, found := p["ResponseParameters"]
		if !found {
			return nil
		}
		// Template: {status: {ResponseParameters: [{Destination, Source}]}};
		// owner: {status: {destination: source}}.
		statuses, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("ResponseParameters must be an object")
		}
		converted := make(map[string]any, len(statuses))
		for status, value := range statuses {
			entry, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("ResponseParameters.%s must be an object", status)
			}
			if err := cfnComputeProperties(entry, "ResponseParameters"); err != nil {
				return err
			}
			list, _ := entry["ResponseParameters"].([]any)
			mapping := make(map[string]any, len(list))
			for _, item := range list {
				parameter, ok := item.(map[string]any)
				if !ok || cfnComputeProperties(parameter, "Destination", "Source") != nil || cfnComputeString(parameter, "Destination") == "" {
					return fmt.Errorf("ResponseParameters.%s entries require Destination and Source", status)
				}
				mapping[cfnComputeString(parameter, "Destination")] = parameter["Source"]
			}
			converted[status] = mapping
		}
		p["ResponseParameters"] = converted
	case "Stage":
		for _, key := range []string{"DefaultRouteSettings"} {
			if settings, ok := p[key].(map[string]any); ok {
				if err := cfnGatewayV2RouteSettings(settings); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			} else if p[key] != nil {
				return fmt.Errorf("%s must be an object", key)
			}
		}
		if p["RouteSettings"] != nil {
			routes, ok := p["RouteSettings"].(map[string]any)
			if !ok {
				return fmt.Errorf("RouteSettings must be an object")
			}
			for route, value := range routes {
				settings, ok := value.(map[string]any)
				if !ok {
					return fmt.Errorf("RouteSettings.%s must be an object", route)
				}
				if err := cfnGatewayV2RouteSettings(settings); err != nil {
					return fmt.Errorf("RouteSettings.%s: %w", route, err)
				}
			}
		}
	}
	return nil
}

func cfnGatewayV2RouteSettings(p map[string]any) error {
	if err := cfnComputeProperties(p, "DataTraceEnabled", "DetailedMetricsEnabled", "LoggingLevel", "ThrottlingBurstLimit", "ThrottlingRateLimit"); err != nil {
		return err
	}
	if rate, ok := p["ThrottlingRateLimit"].(string); ok {
		var parsed float64
		if _, err := fmt.Sscan(rate, &parsed); err != nil {
			return fmt.Errorf("ThrottlingRateLimit must be a number")
		}
		p["ThrottlingRateLimit"] = parsed
	}
	return cfnGatewayV2Scalar(p, []string{"ThrottlingBurstLimit"}, []string{"DataTraceEnabled", "DetailedMetricsEnabled"})
}

func (h cfnGatewayV2) Validate(p cloudformation.Properties) error {
	_, err := h.properties(p)
	return err
}

func (h cfnGatewayV2) Replacement(a, b cloudformation.Properties) (bool, error) {
	if _, err := h.properties(b); err != nil {
		return false, err
	}
	if cfnComputeChanged(a, b, append(slices.Clone(h.kind.parents), h.kind.createOnly...)...) {
		return true, nil
	}
	for key := range a {
		if _, kept := b[key]; kept || !slices.Contains(h.kind.writable, key) {
			continue
		}
		if _, reset := h.kind.resets[key]; reset || slices.Contains(h.kind.dynamic, key) {
			continue
		}
		// The owner merges omitted update members, so it cannot clear this one.
		return true, nil
	}
	return false, nil
}

func (h cfnGatewayV2) command(ids map[string]any, p map[string]any, keys []string) map[string]any {
	input := make(map[string]any, len(keys)+len(ids))
	for _, key := range keys {
		if slices.Contains(h.kind.local, key) {
			continue
		}
		if value, found := p[key]; found {
			input[key] = value
		}
	}
	for key, value := range ids {
		input[key] = value
	}
	return input
}

func (h cfnGatewayV2) result(r cloudformation.ResourceRequest, ids map[string]any, out map[string]any) cloudformation.ResourceResult {
	leaf, _ := ids[h.kind.leaf].(string)
	attrs := map[string]any{}
	switch h.kind.noun {
	case "Api":
		attrs["ApiId"] = leaf
		attrs["ApiEndpoint"] = out["ApiEndpoint"]
		attrs["ExecuteApiArn"] = cfnGatewayV2ExecuteARN(r, leaf)
	case "Stage":
	default:
		attrs[h.kind.leaf] = leaf
	}
	return cfnGatewayV2Result(h.kind.ids, ids, leaf, attrs)
}

func (h cfnGatewayV2) tagPath(ids map[string]any) string {
	path := "/apis/" + cfnComputeString(ids, "ApiId")
	if h.kind.noun == "Stage" {
		path += "/stages/" + cfnComputeString(ids, "StageName")
	}
	return path
}

func (h cfnGatewayV2) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	p, err := h.properties(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	parents := cfnComputeCopy(p, h.kind.parents...)
	input := h.command(parents, p, h.kind.writable)
	if h.kind.tagged {
		tags, err := cfnGatewayV2DesiredTags(r)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if len(tags) > 0 {
			input["Tags"] = tags
		}
	}
	if h.kind.noun == "Deployment" && p["StageName"] != nil {
		input["StageName"] = p["StageName"]
	}
	owned := cfnGatewayV2Context(ctx, r)
	out, err := cfnGatewayV2Call(owned, h.commands, "Create"+h.kind.noun, input)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ids := parents
	ids[h.kind.leaf] = out[h.kind.leaf]
	if cfnComputeString(ids, h.kind.leaf) == "" {
		return cloudformation.ResourceResult{}, fmt.Errorf("operation Create%s returned no %s", h.kind.noun, h.kind.leaf)
	}
	return h.result(r, ids, out), nil
}

// protocol reads the parent API's protocol for protocol-specific defaults.
func (h cfnGatewayV2) protocol(ctx context.Context, apiID string) (string, error) {
	out, err := cfnGatewayV2Call(ctx, h.commands, "GetApi", map[string]any{"ApiId": apiID})
	if err != nil {
		return "", err
	}
	return cfnComputeString(out, "ProtocolType"), nil
}

func cfnGatewayV2DynamicReset(noun, key, protocol string) (any, bool) {
	websocket := protocol == "WEBSOCKET"
	switch noun + "." + key {
	case "Integration.TimeoutInMillis":
		if websocket {
			return int64(29000), true
		}
		return int64(30000), true
	case "Integration.PassthroughBehavior":
		return "WHEN_NO_MATCH", websocket
	case "Integration.PayloadFormatVersion":
		return "1.0", websocket
	case "Authorizer.AuthorizerResultTtlInSeconds":
		return int64(300), !websocket
	}
	return nil, false
}

func (h cfnGatewayV2) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if r.CloudControl {
		if err := cloudformation.ValidateResourceUpdate(h.kind.typeName, r.Previous, r.Properties); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	p, err := h.properties(r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if replace, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if replace {
		return cloudformation.ResourceResult{}, fmt.Errorf("%s update requires replacement", h.kind.typeName)
	}
	ids, err := cfnGatewayV2Identifier(r, h.kind.ids...)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	previous := map[string]any(r.Previous)
	changed := []string{}
	for _, key := range h.kind.writable {
		if slices.Contains(h.kind.always, key) || !reflect.DeepEqual(previous[key], r.Properties[key]) {
			changed = append(changed, key)
		}
	}
	input := h.command(ids, p, changed)
	protocol := ""
	for _, key := range changed {
		if _, present := p[key]; present || slices.Contains(h.kind.local, key) || slices.Contains(h.kind.always, key) {
			continue
		}
		if value, found := h.kind.resets[key]; found {
			if value != nil {
				input[key] = value
			}
			continue
		}
		if protocol == "" {
			if protocol, err = h.protocol(ctx, cfnComputeString(ids, "ApiId")); err != nil {
				return cloudformation.ResourceResult{}, err
			}
		}
		if value, ok := cfnGatewayV2DynamicReset(h.kind.noun, key, protocol); ok {
			input[key] = value
		}
	}
	owned := cfnGatewayV2Context(ctx, r)
	if h.kind.noun == "Stage" {
		// The template is the complete stage model: omitted variables and
		// route settings are removed instead of merged.
		owned = apigatewayv2.WithDeclarativeStage(owned)
		if slices.Contains(changed, "AccessLogSettings") && p["AccessLogSettings"] == nil {
			if err := cfnGatewayV2Absent(cfnComputeRun(owned, h.commands, "apigatewayv2", "DeleteAccessLogSettings", ids)); err != nil {
				return cloudformation.ResourceResult{}, err
			}
		}
	}
	var out map[string]any
	if len(input) > len(ids) || h.kind.noun == "Stage" {
		if out, err = cfnGatewayV2Call(owned, h.commands, "Update"+h.kind.noun, input); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	} else if out, err = cfnGatewayV2Call(owned, h.commands, "Get"+h.kind.noun, ids); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if h.kind.tagged {
		if err := cfnGatewayV2SyncTags(owned, h.commands, r, h.tagPath(ids)); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	if h.kind.noun == "Deployment" && slices.Contains(changed, "StageName") && p["StageName"] != nil {
		// Deploying to a stage mutates that stage resource, which has its own
		// stack incarnation; the caller's authority applies, not this one's.
		if err := cfnComputeRun(ctx, h.commands, "apigatewayv2", "UpdateStage", map[string]any{"ApiId": ids["ApiId"], "StageName": p["StageName"], "DeploymentId": ids["DeploymentId"]}); err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	return h.result(r, ids, out), nil
}

func (h cfnGatewayV2) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, err := cfnGatewayV2Identifier(r, h.kind.ids...)
	if err != nil {
		return err
	}
	return cfnGatewayV2Absent(cfnComputeRun(cfnGatewayV2Context(ctx, r), h.commands, "apigatewayv2", "Delete"+h.kind.noun, ids))
}

func (h cfnGatewayV2) project(r cloudformation.ResourceRequest, ids, out map[string]any) cloudformation.Properties {
	p := cfnGatewayV2Projection(out, ids, h.kind.read...)
	if h.kind.noun == "Api" {
		p["ExecuteApiArn"] = cfnGatewayV2ExecuteARN(r, cfnComputeString(ids, "ApiId"))
	}
	if target, ok := p["Target"].(string); ok && target == "" {
		delete(p, "Target")
	}
	return p
}

func (h cfnGatewayV2) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, err := cfnGatewayV2Identifier(r, h.kind.ids...)
	if err != nil {
		return nil, err
	}
	out, err := cfnGatewayV2Call(ctx, h.commands, "Get"+h.kind.noun, ids)
	if err != nil {
		return nil, err
	}
	p := h.project(r, ids, out)
	return p, nil
}

// cfnGatewayV2ExecuteARN is the execute-api resource prefix for the API
// (https://docs.aws.amazon.com/apigateway/latest/developerguide/arn-format-reference.html).
func cfnGatewayV2ExecuteARN(r cloudformation.ResourceRequest, apiID string) string {
	return "arn:" + r.Scope.Partition + ":execute-api:" + r.Scope.Region + ":" + r.Scope.Account + ":" + apiID
}

func (h cfnGatewayV2) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	parents := map[string]any{}
	for _, key := range h.kind.listWith {
		value := cfnComputeString(r.Properties, key)
		if value == "" {
			return nil, fmt.Errorf("listing %s requires %s", h.kind.typeName, key)
		}
		parents[key] = value
	}
	input := cfnComputeCopy(parents, h.kind.listWith...)
	rows, err := cfnGatewayV2Pages(ctx, h.commands, "Get"+h.kind.noun+"s", input)
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(rows))
	for _, row := range rows {
		ids := cfnComputeCopy(parents, h.kind.listWith...)
		ids[h.kind.leaf] = row[h.kind.leaf]
		p := h.project(r, ids, row)
		out = append(out, cloudformation.ResourceDescription{Identifier: cfnGatewayV2PhysicalID(h.kind.ids, ids), Properties: p})
	}
	return out, nil
}

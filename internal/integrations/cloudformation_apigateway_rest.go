package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/services/apigateway"
	"stackd/internal/services/cloudformation"
)

// CloudFormationAPIGatewayRESTHandlers binds only resources with REST service owners.
// Property and return contracts: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_ApiGateway.html
// Wire contracts: https://docs.aws.amazon.com/apigateway/latest/api/Welcome.html
func CloudFormationAPIGatewayRESTHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::ApiGateway::RestApi":      cfnRESTGateway{commands, "RestApi"},
		"AWS::ApiGateway::Resource":     cfnRESTGateway{commands, "Resource"},
		"AWS::ApiGateway::Method":       cfnRESTGateway{commands, "Method"},
		"AWS::ApiGateway::Authorizer":   cfnRESTGateway{commands, "Authorizer"},
		"AWS::ApiGateway::Deployment":   cfnRESTGateway{commands, "Deployment"},
		"AWS::ApiGateway::Stage":        cfnRESTGateway{commands, "Stage"},
		"AWS::ApiGateway::Account":      cfnRESTGateway{commands, "Account"},
		"AWS::ApiGateway::ApiKey":       cfnRESTGateway{commands, "ApiKey"},
		"AWS::ApiGateway::UsagePlan":    cfnRESTGateway{commands, "UsagePlan"},
		"AWS::ApiGateway::UsagePlanKey": cfnRESTGateway{commands, "UsagePlanKey"},
	}
}

type cfnRESTGateway struct {
	commands StepFunctionsCommands
	kind     string
}

func cfnRESTClaim(r cloudformation.ResourceRequest) apigateway.Ownership {
	return apigateway.Ownership{StackID: r.StackID, LogicalID: r.LogicalID, Incarnation: r.Token}
}
func (h cfnRESTGateway) context(ctx context.Context, r cloudformation.ResourceRequest, enforce, release bool, rows map[string]apigateway.Ownership) context.Context {
	if r.CloudControl && enforce {
		return ctx
	}
	return apigateway.WithResourceOwnership(ctx, h.kind, cfnRESTClaim(r), enforce, release, rows)
}
func cfnRESTMissing(err error) bool {
	var wire *awswire.Error
	return errors.As(err, &wire) && wire.Code == "NotFoundException"
}
func cfnRESTAbsent(err error) error {
	if cfnRESTMissing(err) {
		return nil
	}
	return err
}
func (h cfnRESTGateway) call(ctx context.Context, action string, input map[string]any) (map[string]any, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	out, rejected := h.commands.callCloudFormation(ctx, "apigateway", action, body)
	if rejected != nil {
		return nil, rejected
	}
	data, err := json.Marshal(out.Output)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("apigateway.%s returned no object", action)
	}
	return result, nil
}
func cfnRESTWire(key string) string { return strings.ToLower(key[:1]) + key[1:] }
func cfnRESTInput(p map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, key := range keys {
		if v, ok := p[key]; ok {
			out[cfnRESTWire(key)] = v
		}
	}
	return out
}
func cfnRESTPatch(op, path string, value any) map[string]any {
	out := map[string]any{"op": op, "path": path}
	if value != nil {
		out["value"] = fmt.Sprint(value)
	}
	return out
}
func cfnRESTObject(p map[string]any, key string, allowed ...string) (map[string]any, error) {
	if p[key] == nil {
		return nil, nil
	}
	v, ok := cfnComputeObject(p[key])
	if !ok {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	if err := cfnComputeProperties(v, allowed...); err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return v, nil
}
func cfnRESTBools(p map[string]any, keys ...string) error {
	for _, key := range keys {
		if v, ok := p[key]; ok {
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", key)
			}
		}
	}
	return nil
}
func cfnRESTStringMap(p map[string]any, key string) error {
	if p[key] == nil {
		return nil
	}
	v, ok := cfnComputeObject(p[key])
	if !ok {
		return fmt.Errorf("%s must be an object", key)
	}
	for _, value := range v {
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s values must be strings", key)
		}
	}
	return nil
}
func cfnRESTStageValidation(p map[string]any) error {
	if err := cfnComputeProperties(p, "RestApiId", "DeploymentId", "StageName", "Description", "Variables", "Tags", "AccessLogSetting", "MethodSettings", "CacheClusterEnabled", "TracingEnabled"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "RestApiId", "DeploymentId", "StageName", "Description"); err != nil {
		return err
	}
	if err := cfnRESTBools(p, "CacheClusterEnabled", "TracingEnabled"); err != nil {
		return err
	}
	if p["CacheClusterEnabled"] == true || p["TracingEnabled"] == true {
		return fmt.Errorf("stage caches and tracing have no execution owner")
	}
	if err := cfnRESTStringMap(p, "Variables"); err != nil {
		return err
	}
	access, err := cfnRESTObject(p, "AccessLogSetting", "DestinationArn", "Format")
	if err != nil {
		return err
	}
	if access != nil {
		if err := cfnComputeRequired(access, "DestinationArn", "Format"); err != nil {
			return err
		}
		if err := cfnComputeStrings(access, "DestinationArn", "Format"); err != nil {
			return err
		}
	}
	if v, ok := p["MethodSettings"]; ok {
		list, ok := v.([]any)
		if !ok {
			return fmt.Errorf("MethodSettings must be a list")
		}
		for _, v := range list {
			setting, ok := cfnComputeObject(v)
			if !ok {
				return fmt.Errorf("MethodSettings entries must be objects")
			}
			if err := cfnComputeProperties(setting, "ResourcePath", "HttpMethod", "MetricsEnabled", "LoggingLevel", "DataTraceEnabled", "ThrottlingBurstLimit", "ThrottlingRateLimit"); err != nil {
				return err
			}
			if err := cfnComputeRequired(setting, "ResourcePath", "HttpMethod"); err != nil {
				return err
			}
			if err := cfnComputeStrings(setting, "ResourcePath", "HttpMethod", "LoggingLevel"); err != nil {
				return err
			}
			if err := cfnRESTBools(setting, "MetricsEnabled", "DataTraceEnabled"); err != nil {
				return err
			}
			if err := cfnRESTMethodThrottleValidation(setting); err != nil {
				return err
			}
		}
	}
	_, err = cfnComputeTags(p)
	return err
}
func (h cfnRESTGateway) Validate(p cloudformation.Properties) error {
	var allowed, required []string
	switch h.kind {
	case "RestApi":
		allowed = []string{"Name", "Description", "Version", "SecurityPolicy", "DisableExecuteApiEndpoint", "ApiKeySourceType", "EndpointConfiguration", "Tags", "Body", "BinaryMediaTypes", "Mode", "FailOnWarnings", "Parameters"}
	case "Resource":
		allowed = []string{"RestApiId", "ParentId", "PathPart"}
		required = allowed
	case "Method":
		allowed = []string{"RestApiId", "ResourceId", "HttpMethod", "AuthorizationType", "AuthorizerId", "AuthorizationScopes", "ApiKeyRequired", "OperationName", "Integration"}
		required = []string{"RestApiId", "ResourceId", "HttpMethod"}
	case "Authorizer":
		allowed = []string{"RestApiId", "Name", "Type", "AuthType", "ProviderARNs", "AuthorizerUri", "AuthorizerCredentials", "IdentitySource", "IdentityValidationExpression", "AuthorizerResultTtlInSeconds"}
		required = []string{"RestApiId", "Name", "Type"}
	case "Deployment":
		allowed = []string{"RestApiId", "Description", "StageName", "StageDescription"}
		required = []string{"RestApiId"}
	case "Stage":
		if err := cfnRESTStageValidation(p); err != nil {
			return err
		}
		return cfnComputeRequired(p, "RestApiId", "DeploymentId")
	case "Account":
		allowed = []string{"CloudWatchRoleArn"}
	case "ApiKey":
		allowed = []string{"Name", "Description", "Enabled", "CustomerId", "Value", "GenerateDistinctId", "StageKeys", "Tags"}
	case "UsagePlan":
		allowed = []string{"UsagePlanName", "Description", "ApiStages", "Throttle", "Quota", "Tags"}
	case "UsagePlanKey":
		allowed = []string{"UsagePlanId", "KeyId", "KeyType"}
		required = allowed
	default:
		return fmt.Errorf("unknown REST resource %s", h.kind)
	}
	if err := cfnComputeProperties(p, allowed...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, required...); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "Name", "UsagePlanName", "Description", "Version", "SecurityPolicy", "RestApiId", "ParentId", "PathPart", "ResourceId", "HttpMethod", "AuthorizationType", "AuthorizerId", "OperationName", "Type", "AuthType", "AuthorizerUri", "AuthorizerCredentials", "IdentitySource", "IdentityValidationExpression", "StageName", "CloudWatchRoleArn", "CustomerId", "Value", "UsagePlanId", "KeyId", "KeyType", "ApiKeySourceType"); err != nil {
		return err
	}
	for _, key := range required {
		if cfnComputeString(p, key) == "" {
			return fmt.Errorf("%s must be nonempty", key)
		}
	}
	if err := cfnRESTBools(p, "DisableExecuteApiEndpoint", "ApiKeyRequired", "Enabled", "GenerateDistinctId"); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "AuthorizationScopes"); err != nil {
		return err
	}
	if _, err := cfnComputeStringList(p, "ProviderARNs"); err != nil {
		return err
	}
	switch h.kind {
	case "RestApi":
		if err := cfnRESTImportValidation(p); err != nil {
			return err
		}
		if v, ok := p["SecurityPolicy"]; ok && v != "TLS_1_0" {
			return fmt.Errorf("only TLS_1_0 REST security policy has an owner")
		}
		endpoint, err := cfnRESTObject(p, "EndpointConfiguration", "Types", "IpAddressType")
		if err != nil {
			return err
		}
		if endpoint != nil {
			types, err := cfnComputeStringList(endpoint, "Types")
			if err != nil {
				return err
			}
			if len(types) != 1 || types[0] != "REGIONAL" {
				return fmt.Errorf("only REGIONAL REST endpoints have an owner")
			}
			if v := endpoint["IpAddressType"]; v != nil && v != "ipv4" {
				return fmt.Errorf("only ipv4 REST endpoints have an owner")
			}
		}
	case "Method":
		integration, err := cfnRESTObject(p, "Integration", "Type", "IntegrationHttpMethod", "Uri", "Credentials", "ConnectionType", "PassthroughBehavior", "TimeoutInMillis", "CacheNamespace", "ResponseTransferMode")
		if err != nil {
			return err
		}
		if integration != nil {
			if err := cfnComputeRequired(integration, "Type", "IntegrationHttpMethod", "Uri"); err != nil {
				return err
			}
			if err := cfnComputeStrings(integration, "Type", "IntegrationHttpMethod", "Uri", "Credentials", "ConnectionType", "PassthroughBehavior", "CacheNamespace", "ResponseTransferMode"); err != nil {
				return err
			}
			if integration["Type"] != "AWS_PROXY" || integration["IntegrationHttpMethod"] != "POST" {
				return fmt.Errorf("only POST Lambda AWS_PROXY integrations have an execution owner")
			}
			for key, expected := range map[string]string{"ConnectionType": "INTERNET", "PassthroughBehavior": "WHEN_NO_MATCH", "ResponseTransferMode": "BUFFERED"} {
				if v, ok := integration[key]; ok && v != expected {
					return fmt.Errorf("unsupported Integration.%s", key)
				}
			}
			if v, ok := integration["TimeoutInMillis"]; ok && fmt.Sprint(v) != "29000" {
				return fmt.Errorf("only the default integration timeout has an owner")
			}
		}
	case "Deployment":
		stage, err := cfnRESTObject(p, "StageDescription", "Description", "Variables", "Tags", "AccessLogSetting", "MethodSettings", "CacheClusterEnabled", "TracingEnabled", "MetricsEnabled", "LoggingLevel", "DataTraceEnabled", "ThrottlingBurstLimit", "ThrottlingRateLimit")
		if err != nil {
			return err
		}
		if stage != nil {
			copy := cfnComputeCopy(stage, "Description", "Variables", "Tags", "AccessLogSetting", "MethodSettings", "CacheClusterEnabled", "TracingEnabled")
			if stage["ThrottlingBurstLimit"] != nil || stage["ThrottlingRateLimit"] != nil {
				all := cfnComputeCopy(stage, "ThrottlingBurstLimit", "ThrottlingRateLimit")
				all["ResourcePath"], all["HttpMethod"] = "/*", "*"
				settings, _ := copy["MethodSettings"].([]any)
				copy["MethodSettings"] = append(settings, all)
			}
			if err := cfnRESTStageValidation(copy); err != nil {
				return err
			}
			if err := cfnRESTBools(stage, "MetricsEnabled", "DataTraceEnabled"); err != nil {
				return err
			}
			if err := cfnComputeStrings(stage, "LoggingLevel"); err != nil {
				return err
			}
			if cfnComputeString(p, "StageName") == "" {
				return fmt.Errorf("StageDescription requires StageName")
			}
		}
	case "ApiKey":
		if err := cfnRESTStages(p, "StageKeys", "RestApiId", "StageName"); err != nil {
			return err
		}
	case "UsagePlan":
		if err := cfnRESTUsageValidation(p); err != nil {
			return err
		}
	}
	_, err := cfnComputeTags(p)
	return err
}
func cfnRESTStages(p map[string]any, key string, fields ...string) error {
	if p[key] == nil {
		return nil
	}
	list, ok := p[key].([]any)
	if !ok {
		return fmt.Errorf("%s must be a list", key)
	}
	for _, v := range list {
		item, ok := cfnComputeObject(v)
		if !ok {
			return fmt.Errorf("%s entries must be objects", key)
		}
		if err := cfnComputeProperties(item, fields...); err != nil {
			return err
		}
		if err := cfnComputeRequired(item, fields...); err != nil {
			return err
		}
		if err := cfnComputeStrings(item, fields...); err != nil {
			return err
		}
	}
	return nil
}
func cfnRESTUsageValidation(p map[string]any) error {
	throttle, err := cfnRESTObject(p, "Throttle", "BurstLimit", "RateLimit")
	if err != nil {
		return err
	}
	quota, err := cfnRESTObject(p, "Quota", "Limit", "Offset", "Period")
	if err != nil {
		return err
	}
	if quota != nil {
		if err := cfnComputeRequired(quota, "Limit", "Period"); err != nil {
			return err
		}
	}
	_ = throttle
	if p["ApiStages"] != nil {
		list, ok := p["ApiStages"].([]any)
		if !ok {
			return fmt.Errorf("ApiStages must be a list")
		}
		for _, v := range list {
			item, ok := cfnComputeObject(v)
			if !ok {
				return fmt.Errorf("ApiStages entries must be objects")
			}
			if err := cfnComputeProperties(item, "ApiId", "Stage", "Throttle"); err != nil {
				return err
			}
			if err := cfnComputeRequired(item, "ApiId", "Stage"); err != nil {
				return err
			}
			if err := cfnComputeStrings(item, "ApiId", "Stage"); err != nil {
				return err
			}
			if item["Throttle"] != nil {
				settings, ok := cfnComputeObject(item["Throttle"])
				if !ok {
					return fmt.Errorf("ApiStages.Throttle must be an object")
				}
				for _, v := range settings {
					setting, ok := cfnComputeObject(v)
					if !ok {
						return fmt.Errorf("method throttle must be an object")
					}
					if err := cfnComputeProperties(setting, "BurstLimit", "RateLimit"); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
func (h cfnRESTGateway) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	switch h.kind {
	case "Resource":
		return cfnComputeChanged(a, b, "RestApiId", "ParentId", "PathPart"), nil
	case "Method":
		return cfnComputeChanged(a, b, "RestApiId", "ResourceId", "HttpMethod"), nil
	case "Authorizer":
		if cfnComputeChanged(a, b, "Type") && (a["Type"] == "COGNITO_USER_POOLS" || b["Type"] == "COGNITO_USER_POOLS") {
			return true, nil
		}
		return cfnComputeChanged(a, b, "RestApiId"), nil
	case "Deployment":
		return cfnComputeChanged(a, b, "RestApiId"), nil
	case "Stage":
		return cfnComputeChanged(a, b, "RestApiId", "StageName"), nil
	case "ApiKey":
		return cfnComputeChanged(a, b, "Name", "Value", "GenerateDistinctId"), nil
	case "UsagePlanKey":
		return cfnComputeChanged(a, b, "UsagePlanId", "KeyId", "KeyType"), nil
	default:
		return false, nil
	}
}
func cfnRESTKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

package integrations

import (
	"encoding/json"
	"fmt"
	"strings"

	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationDeveloperHandlers delegates developer-platform effects to their
// existing command owners. Generated AWS schemas define the public properties:
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/resource-type-schemas.html
func CloudFormationDeveloperHandlers(c StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::CodeBuild::Project":                 cfnCodeBuildProject{c},
		"AWS::CodeBuild::Fleet":                   cfnCodeBuildFleet{c},
		"AWS::CodeBuild::SourceCredential":        cfnCodeBuildCredential{c},
		"AWS::CodePipeline::Pipeline":             cfnCodePipeline{c},
		"AWS::AppSync::GraphQLApi":                cfnAppSyncAPI{c},
		"AWS::AppSync::GraphQLSchema":             cfnAppSyncSchema{c},
		"AWS::AppSync::ApiKey":                    cfnAppSyncKey{c},
		"AWS::AppSync::DataSource":                cfnAppSyncSource{c},
		"AWS::AppSync::FunctionConfiguration":     cfnAppSyncFunction{c},
		"AWS::AppSync::Resolver":                  cfnAppSyncResolver{c},
		"AWS::ECR::RegistryPolicy":                cfnECRRegistryPolicy{c},
		"AWS::ECR::ReplicationConfiguration":      cfnECRReplication{c},
		"AWS::ECR::RegistryScanningConfiguration": cfnECRScanning{c},
	}
}

// Translate CFN structure members, never customer-controlled map keys.
func cfnDeveloperWireName(k string) string {
	switch k {
	case "BuildSpec":
		return "buildspec"
	case "DynamoDBConfig":
		return "dynamodbConfig"
	case "OpenIDConnectConfig":
		return "openIDConnectConfig"
	case "S3Logs":
		return "s3Logs"
	case "CloudWatchLogs":
		return "cloudWatchLogs"
	}
	if k == "" {
		return k
	}
	return strings.ToLower(k[:1]) + k[1:]
}
func cfnDeveloperWire(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			_, isMap := v.(map[string]any)
			if isMap && (k == "Configuration" || k == "EnvironmentVariables" || k == "Headers") {
				out[cfnDeveloperWireName(k)] = v
			} else {
				out[cfnDeveloperWireName(k)] = cfnDeveloperWire(v)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = cfnDeveloperWire(v)
		}
		return out
	default:
		return v
	}
}
func cfnDeveloperModel(v any, allowed ...string) (cloudformation.Properties, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var wire map[string]any
	if err = json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	var upper func(any) any
	upper = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := make(map[string]any, len(x))
			for k, v := range x {
				name := strings.ToUpper(k[:1]) + k[1:]
				switch k {
				case "buildspec":
					name = "BuildSpec"
				case "dynamodbConfig":
					name = "DynamoDBConfig"
				case "openIDConnectConfig":
					name = "OpenIDConnectConfig"
				}
				dictionary, isMap := v.(map[string]any)
				if isMap && (k == "configuration" || k == "environmentVariables" || k == "headers") {
					out[name] = v
				} else if isMap && k == "artifactStores" {
					for region, store := range dictionary {
						dictionary[region] = upper(store)
					}
					out[name] = dictionary
				} else {
					out[name] = upper(v)
				}
			}
			return out
		case []any:
			for i := range x {
				x[i] = upper(x[i])
			}
			return x
		default:
			return v
		}
	}
	out := upper(wire).(map[string]any)
	if len(allowed) > 0 {
		return cfnComputeCopy(out, allowed...), nil
	}
	return out, nil
}
func cfnDeveloperInput(p cloudformation.Properties, keys ...string) map[string]any {
	return cfnDeveloperWire(cfnComputeCopy(p, keys...)).(map[string]any)
}
func cfnDeveloperNotFound(kind, id string) error {
	return &awswire.Error{Code: "ResourceNotFoundException", Message: fmt.Sprintf("%s %s does not exist", kind, id), StatusCode: 404}
}
func cfnDeveloperPageInput(token string, input map[string]any) map[string]any {
	if token != "" {
		input["nextToken"] = token
	}
	return input
}

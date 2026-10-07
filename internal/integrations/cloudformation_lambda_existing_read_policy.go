package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

func (h cfnLambdaLayerVersion) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, version, err := cfnLambdaLayerIdentity(r)
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetLayerVersionOutput](cfnLambdaLayerContext(ctx, r), h.commands, "lambda", "GetLayerVersion", map[string]any{"LayerName": name, "VersionNumber": version})
	if err != nil {
		return nil, err
	}
	// Content is write-only in the native schema. A download URL is not an S3 source.
	model, err := cfnLambdaAdditionalProperties(out)
	if err != nil {
		return nil, err
	}
	properties := cloudformation.Properties(cfnComputeCopy(model, "LayerVersionArn", "Description", "LicenseInfo", "CompatibleRuntimes", "CompatibleArchitectures"))
	properties["LayerName"] = cfnComputeValue(out.LayerArn)
	return properties, nil
}
func (h cfnLambdaLayerVersion) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	name, err := cfnLambdaRequiredListFilter(r, "LayerName")
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.ResourceDescription{}
	input := map[string]any{"LayerName": name}
	for {
		out, err := cfnComputeCall[api.ListLayerVersionsOutput](ctx, h.commands, "lambda", "ListLayerVersions", input)
		if err != nil {
			return nil, err
		}
		for _, version := range out.LayerVersions {
			request := r
			request.PhysicalID = cfnComputeValue(version.LayerVersionArn)
			properties, err := h.Read(ctx, request)
			if err != nil {
				return nil, err
			}
			rows = append(rows, cloudformation.ResourceDescription{Identifier: request.PhysicalID, Properties: properties})
		}
		if cfnComputeValue(out.NextMarker) == "" {
			return rows, nil
		}
		input["Marker"] = cfnComputeValue(out.NextMarker)
	}
}

func cfnLambdaPolicyStatements(document string) ([]map[string]any, error) {
	var policy struct{ Statement json.RawMessage }
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return nil, fmt.Errorf("lambda returned an invalid policy: %w", err)
	}
	var statements []map[string]any
	if len(policy.Statement) == 0 {
		return statements, nil
	}
	if policy.Statement[0] == '{' {
		var statement map[string]any
		if err := json.Unmarshal(policy.Statement, &statement); err != nil {
			return nil, err
		}
		return []map[string]any{statement}, nil
	}
	if err := json.Unmarshal(policy.Statement, &statements); err != nil {
		return nil, err
	}
	return statements, nil
}
func cfnLambdaPolicyScalar(value any) (string, bool) {
	if text, ok := value.(string); ok {
		return text, text != ""
	}
	if values, ok := value.([]any); ok && len(values) == 1 {
		text, ok := values[0].(string)
		return text, ok && text != ""
	}
	return "", false
}

// Only policies representable by native AddPermission/AddLayerVersionPermission
// are individual permission resources. Do not flatten arbitrary policy documents.
func cfnLambdaPermissionModel(statement map[string]any, layer bool) (cloudformation.Properties, bool) {
	id, idOK := cfnLambdaPolicyScalar(statement["Sid"])
	action, actionOK := cfnLambdaPolicyScalar(statement["Action"])
	resource, resourceOK := cfnLambdaPolicyScalar(statement["Resource"])
	if !idOK || !actionOK || !resourceOK || statement["Effect"] != "Allow" {
		return nil, false
	}
	for key := range statement {
		switch key {
		case "Sid", "Effect", "Action", "Resource", "Principal", "Condition":
		default:
			return nil, false
		}
	}
	principal, principalOK := cfnLambdaPolicyScalar(statement["Principal"])
	if !principalOK {
		object, ok := statement["Principal"].(map[string]any)
		if !ok || len(object) != 1 {
			return nil, false
		}
		for key, value := range object {
			if key != "AWS" && (layer || key != "Service") {
				return nil, false
			}
			principal, principalOK = cfnLambdaPolicyScalar(value)
		}
	}
	if !principalOK {
		return nil, false
	}
	properties := cloudformation.Properties{"Id": id, "Action": action, "Principal": principal, "FunctionName": resource}
	if layer {
		delete(properties, "FunctionName")
		properties["LayerVersionArn"] = resource
		properties["Id"] = resource + "#" + id
	}
	if value, present := statement["Condition"]; present {
		conditions, ok := value.(map[string]any)
		if !ok {
			return nil, false
		}
		for operator, value := range conditions {
			entries, ok := value.(map[string]any)
			if !ok {
				return nil, false
			}
			for key, value := range entries {
				text, ok := cfnLambdaPolicyScalar(value)
				if !ok {
					return nil, false
				}
				if layer {
					if operator != "StringEquals" || !strings.EqualFold(key, "aws:PrincipalOrgID") {
						return nil, false
					}
					properties["OrganizationId"] = text
					continue
				}
				switch {
				case operator == "ArnLike" && strings.EqualFold(key, "aws:SourceArn"):
					properties["SourceArn"] = text
				case operator == "StringEquals" && strings.EqualFold(key, "aws:SourceAccount"):
					properties["SourceAccount"] = text
				case operator == "StringEquals" && strings.EqualFold(key, "aws:PrincipalOrgID"):
					properties["PrincipalOrgID"] = text
				case operator == "StringEquals" && key == "lambda:FunctionUrlAuthType":
					properties["FunctionUrlAuthType"] = text
				case operator == "StringEquals" && key == "lambda:EventSourceToken":
					properties["EventSourceToken"] = text
				case operator == "Bool" && key == "lambda:InvokedViaFunctionUrl":
					flag, err := strconv.ParseBool(text)
					if err != nil {
						return nil, false
					}
					properties["InvokedViaFunctionUrl"] = flag
				default:
					return nil, false
				}
			}
		}
	}
	return properties, true
}
func cfnLambdaPermissionReadModel(statements []map[string]any, id string, layer bool) (cloudformation.Properties, error) {
	for _, statement := range statements {
		if statement["Sid"] != id {
			continue
		}
		properties, supported := cfnLambdaPermissionModel(statement, layer)
		if !supported {
			return nil, &awswire.Error{Code: "UnsupportedActionException", Message: "The current statement cannot be represented by the native permission resource schema.", StatusCode: 400}
		}
		return properties, nil
	}
	return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "The Lambda permission statement does not exist.", StatusCode: 404}
}

func (h cfnLambdaLayerPermission) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, version, statement, _, err := cfnLambdaLayerPermissionIdentity(r)
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetLayerVersionPolicyOutput](ctx, h.commands, "lambda", "GetLayerVersionPolicy", map[string]any{"LayerName": name, "VersionNumber": version})
	if err != nil {
		return nil, err
	}
	statements, err := cfnLambdaPolicyStatements(cfnComputeValue(out.Policy))
	if err != nil {
		return nil, err
	}
	return cfnLambdaPermissionReadModel(statements, statement, true)
}
func (h cfnLambdaLayerPermission) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	arn, err := cfnLambdaRequiredListFilter(r, "LayerVersionArn")
	if err != nil {
		return nil, err
	}
	identity := r
	identity.PhysicalID = arn
	name, version, err := cfnLambdaLayerIdentity(identity)
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetLayerVersionPolicyOutput](ctx, h.commands, "lambda", "GetLayerVersionPolicy", map[string]any{"LayerName": name, "VersionNumber": version})
	if cfnComputeMissing(err) {
		return []cloudformation.ResourceDescription{}, nil
	}
	if err != nil {
		return nil, err
	}
	statements, err := cfnLambdaPolicyStatements(cfnComputeValue(out.Policy))
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.ResourceDescription{}
	for _, statement := range statements {
		properties, supported := cfnLambdaPermissionModel(statement, true)
		if supported {
			rows = append(rows, cloudformation.ResourceDescription{Identifier: cfnComputeString(properties, "Id"), Properties: properties})
		}
	}
	return rows, nil
}

func cfnLambdaPermissionIdentity(r cloudformation.ResourceRequest) (string, string, error) {
	function := cfnComputeString(r.Properties, "FunctionName")
	if functionID, statementID, compound := strings.Cut(r.PhysicalID, "|"); compound {
		if functionID == "" || statementID == "" || strings.Contains(statementID, "|") {
			return "", "", fmt.Errorf("identifier must contain FunctionName and Id")
		}
		return functionID, statementID, nil
	}
	if function == "" {
		return "", "", fmt.Errorf("FunctionName is required when the identifier is not compound")
	}
	return function, cfnComputeName(r, "", 100), nil
}
func (h cfnLambdaPermission) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	function, statement, err := cfnLambdaPermissionIdentity(r)
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetPolicyOutput](ctx, h.commands, "lambda", "GetPolicy", map[string]any{"FunctionName": function})
	if err != nil {
		return nil, err
	}
	statements, err := cfnLambdaPolicyStatements(cfnComputeValue(out.Policy))
	if err != nil {
		return nil, err
	}
	return cfnLambdaPermissionReadModel(statements, statement, false)
}
func (h cfnLambdaPermission) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	function, err := cfnLambdaRequiredListFilter(r, "FunctionName")
	if err != nil {
		return nil, err
	}
	out, err := cfnComputeCall[api.GetPolicyOutput](ctx, h.commands, "lambda", "GetPolicy", map[string]any{"FunctionName": function})
	if cfnComputeMissing(err) {
		return []cloudformation.ResourceDescription{}, nil
	}
	if err != nil {
		return nil, err
	}
	statements, err := cfnLambdaPolicyStatements(cfnComputeValue(out.Policy))
	if err != nil {
		return nil, err
	}
	rows := []cloudformation.ResourceDescription{}
	for _, statement := range statements {
		properties, supported := cfnLambdaPermissionModel(statement, false)
		if supported {
			rows = append(rows, cloudformation.ResourceDescription{Identifier: cfnComputeString(properties, "FunctionName") + "|" + cfnComputeString(properties, "Id"), Properties: properties})
		}
	}
	return rows, nil
}

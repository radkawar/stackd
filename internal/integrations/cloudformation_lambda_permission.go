package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

type cfnLambdaPermission struct{ commands StepFunctionsCommands }

func (h cfnLambdaPermission) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "Action", "FunctionName", "Principal", "PrincipalOrgID", "SourceAccount", "SourceArn", "FunctionUrlAuthType", "InvokedViaFunctionUrl"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Action", "FunctionName", "Principal"); err != nil {
		return err
	}
	return cfnComputeStrings(p, "Action", "FunctionName", "Principal", "PrincipalOrgID", "SourceAccount", "SourceArn", "FunctionUrlAuthType")
}
func (h cfnLambdaPermission) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return !reflect.DeepEqual(a, b), nil
}
func cfnLambdaPermissionFunctionARN(r cloudformation.ResourceRequest) string {
	function := cfnComputeString(r.Properties, "FunctionName")
	if strings.HasPrefix(function, "arn:") {
		return function
	}
	if strings.Contains(function, ":function:") {
		return "arn:" + r.Scope.Partition + ":lambda:" + r.Scope.Region + ":" + function
	}
	return "arn:" + r.Scope.Partition + ":lambda:" + r.Scope.Region + ":" + r.Scope.Account + ":function:" + function
}

func cfnLambdaPermissionStatement(r cloudformation.ResourceRequest, id string) map[string]any {
	p := r.Properties
	principal := cfnComputeString(p, "Principal")
	var who any = principal
	switch {
	case principal == "*":
	case strings.HasSuffix(principal, ".amazonaws.com") || strings.HasSuffix(principal, ".amazonaws.com.cn"):
		who = map[string]any{"Service": principal}
	default:
		if len(principal) == 12 && !strings.Contains(principal, ":") {
			principal = "arn:" + r.Scope.Partition + ":iam::" + principal + ":root"
		}
		who = map[string]any{"AWS": principal}
	}
	function := cfnLambdaPermissionFunctionARN(r)
	statement := map[string]any{"Sid": id, "Effect": "Allow", "Principal": who, "Action": p["Action"], "Resource": function}
	condition := map[string]any{}
	if value, found := p["SourceArn"]; found {
		condition["ArnLike"] = map[string]any{"AWS:SourceArn": value}
	}
	equals := map[string]any{}
	for property, key := range map[string]string{"SourceAccount": "AWS:SourceAccount", "PrincipalOrgID": "aws:PrincipalOrgID", "FunctionUrlAuthType": "lambda:FunctionUrlAuthType"} {
		if value, found := p[property]; found {
			equals[key] = value
		}
	}
	if len(equals) > 0 {
		condition["StringEquals"] = equals
	}
	if value, found := p["InvokedViaFunctionUrl"]; found {
		condition["Bool"] = map[string]any{"lambda:InvokedViaFunctionUrl": fmt.Sprint(value)}
	}
	if len(condition) > 0 {
		statement["Condition"] = condition
	}
	return statement
}
func (h cfnLambdaPermission) matching(ctx context.Context, r cloudformation.ResourceRequest, id string) (bool, string, error) {
	out, err := cfnComputeCall[api.GetPolicyOutput](ctx, h.commands, "lambda", "GetPolicy", map[string]any{"FunctionName": r.Properties["FunctionName"]})
	if cfnComputeMissing(err) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	var document struct{ Statement []map[string]any }
	if err := json.Unmarshal([]byte(cfnComputeValue(out.Policy)), &document); err != nil {
		return false, "", err
	}
	for _, statement := range document.Statement {
		if statement["Sid"] == id {
			if !reflect.DeepEqual(statement, cfnLambdaPermissionStatement(r, id)) {
				return false, "", fmt.Errorf("lambda statement %s differs from the requested permission", id)
			}
			return true, cfnComputeValue(out.RevisionId), nil
		}
	}
	return false, cfnComputeValue(out.RevisionId), nil
}
func (h cfnLambdaPermission) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	function, id, err := cfnLambdaPermissionIdentity(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if function != cfnComputeString(r.Properties, "FunctionName") {
		r.Properties = maps.Clone(r.Properties)
		r.Properties["FunctionName"] = function
	}
	exists, revision, err := h.matching(ctx, r, id)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id}}
	if r.CloudControl {
		result.PhysicalID = cfnLambdaPermissionFunctionARN(r) + "|" + id
	}
	if exists {
		return result, nil
	}
	input := cfnComputeCopy(r.Properties, "Action", "FunctionName", "Principal", "PrincipalOrgID", "SourceAccount", "SourceArn", "FunctionUrlAuthType", "InvokedViaFunctionUrl")
	input["StatementId"] = id
	if revision != "" {
		input["RevisionId"] = revision
	}
	if err := cfnComputeRun(ctx, h.commands, "lambda", "AddPermission", input); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return result, nil
}
func (h cfnLambdaPermission) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if !reflect.DeepEqual(r.Previous, r.Properties) {
		return cloudformation.ResourceResult{}, fmt.Errorf("lambda permission changes require replacement")
	}
	return h.Create(ctx, r)
}
func (h cfnLambdaPermission) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	function, id, err := cfnLambdaPermissionIdentity(r)
	if err != nil {
		return err
	}
	current, err := cfnComputeCall[api.GetPolicyOutput](ctx, h.commands, "lambda", "GetPolicy", map[string]any{"FunctionName": function})
	if err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "lambda", "RemovePermission", map[string]any{"FunctionName": function, "StatementId": id, "RevisionId": cfnComputeValue(current.RevisionId)}))
}

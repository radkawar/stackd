package stackd_test

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// A statement's Sid, not its JSON or private creation receipt, is the native
// CloudFormation deletion identity. The enclosing lifecycle supplies a runtime.
func cloudFormationPermissionRecreatedStatement(t *testing.T, f *cloudFormationLambdaAliasStack, invoke func(string, string, string, bool)) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{"Grant": map[string]any{"Type": "AWS::Lambda::Permission", "Properties": map[string]any{
			"FunctionName": cloudFormationLambdaFunctionName, "Action": "lambda:InvokeFunction", "Principal": "111111111111",
		}}},
		"Outputs": map[string]any{
			"Statement":   map[string]any{"Value": map[string]string{"Ref": "Grant"}},
			"AttributeId": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Grant", "Id"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("lambda-recreated-permission"), TemplateBody: aws.String(string(body))})
	if err != nil {
		t.Fatal(err)
	}
	stack := cloudFormationWait(t, f.clients, f.source, f.cfn(), aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
	var sid, attributeID string
	for _, output := range stack.Outputs {
		if aws.ToString(output.OutputKey) == "Statement" {
			sid = aws.ToString(output.OutputValue)
		}
		if aws.ToString(output.OutputKey) == "AttributeId" {
			attributeID = aws.ToString(output.OutputValue)
		}
	}
	if sid == "" {
		t.Fatal("missing permission statement identity")
	}
	if attributeID != sid {
		t.Fatalf("Id attribute = %q, want statement identity %q", attributeID, sid)
	}
	invoke("111111111111", cloudFormationLambdaFunctionARN, "$LATEST", true)
	_, err = f.native().RemovePermission(t.Context(), &awslambda.RemovePermissionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), StatementId: &sid})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.native().AddPermission(t.Context(), &awslambda.AddPermissionInput{
		FunctionName: aws.String(cloudFormationLambdaFunctionName), StatementId: &sid,
		Action: aws.String("lambda:InvokeFunction"), Principal: aws.String("222222222222"),
	})
	if err != nil {
		t.Fatal(err)
	}
	invoke("111111111111", cloudFormationLambdaFunctionARN, "$LATEST", false)
	invoke("222222222222", cloudFormationLambdaFunctionARN, "$LATEST", true)
	_, err = f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId})
	if err != nil {
		t.Fatal(err)
	}
	cloudFormationWait(t, f.clients, f.source, f.cfn(), aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
	cloudFormationResourcePolicyAbsent(t, f, cloudFormationLambdaFunctionARN)
	invoke("222222222222", cloudFormationLambdaFunctionARN, "$LATEST", false)
}

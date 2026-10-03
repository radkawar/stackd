package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd"
	"stackd/clock"
)

func TestCloudFormationLambdaLayerPermissionSharing(t *testing.T) {
	lambdaURLDocker(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := &cloudFormationLambdaAliasStack{source: clock.NewManual(time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC))}
			f.clients, f.reopen = retainedCloud(t, backend, stackd.Config{Clock: f.source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return newLambdaDockerStack(t, config, nil)
			})
			const firstAccount, secondAccount = "111111111111", "222222222222"
			const operator = "layer-permission-operator"
			_, f.access, f.secret = f.clients.user(t, "test", operator)
			grant := func(remove bool) {
				actions := []string{"cloudformation:*", "lambda:AddLayerVersionPermission"}
				if remove {
					actions = append(actions, "lambda:GetLayerVersionPolicy", "lambda:RemoveLayerVersionPermission")
				}
				body, err := json.Marshal(map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Action": actions, "Resource": "*"}}})
				if err != nil {
					t.Fatal(err)
				}
				putUserPolicy(t, f.clients.iam("test", "test", ""), operator, string(body))
			}
			grant(false)
			layer, err := f.native().PublishLayerVersion(t.Context(), &awslambda.PublishLayerVersionInput{
				LayerName: aws.String("shared-stack-layer"), Content: &lambdatypes.LayerVersionContentInput{ZipFile: lambdaZIP(t, map[string]string{"python/shared.py": "VALUE='shared-archive'\n"})},
			})
			if err != nil {
				t.Fatal(err)
			}
			layerARN := aws.ToString(layer.LayerVersionArn)
			client := func(account string) *awslambda.Client {
				return f.lambda(cloudFormationLambdaAliasRegion, account, "test")
			}
			readLayer := func(account string, allowed bool) {
				t.Helper()
				out, err := client(account).GetLayerVersionByArn(t.Context(), &awslambda.GetLayerVersionByArnInput{Arn: &layerARN})
				if !allowed {
					assertAPIError(t, err, "AccessDeniedException")
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if aws.ToString(out.LayerVersionArn) != layerARN || out.Content == nil || aws.ToString(out.Content.CodeSha256) != aws.ToString(layer.Content.CodeSha256) {
					t.Fatalf("wrong shared layer: %+v", out)
				}
			}
			readLayer(firstAccount, false)
			created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("shared-layer-permission"), TemplateBody: aws.String(cloudFormationLayerPermissionTemplate(t, layerARN, firstAccount))})
			if err != nil {
				t.Fatal(err)
			}
			f.stackID = aws.ToString(created.StackId)
			initial := f.wait(t, cfntypes.StackStatusCreateComplete)
			firstID := cloudFormationLayerPermissionOutput(t, initial, layerARN)
			readLayer(firstAccount, true)
			readLayer(secondAccount, false)

			roles := f.clients.iam(firstAccount, "test", "")
			role, err := roles.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("shared-layer-runtime"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = roles.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("logs"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			const function = "shared-layer-consumer"
			_, err = client(firstAccount).CreateFunction(t.Context(), &awslambda.CreateFunctionInput{
				FunctionName: aws.String(function), Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("index.handler"), Layers: []string{layerARN},
				Code: &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"index.py": "from shared import VALUE\ndef handler(event,context):\n return {'value':VALUE,'arn':context.invoked_function_arn}\n"})},
			})
			if err != nil {
				t.Fatal(err)
			}
			invoke := func() {
				t.Helper()
				if err := awslambda.NewFunctionActiveWaiter(client(firstAccount), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(function)}, time.Minute); err != nil {
					t.Fatal(err)
				}
				out, err := client(firstAccount).Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: aws.String(function), Payload: []byte(`{}`)})
				if err != nil {
					t.Fatal(err)
				}
				var payload struct{ Value, ARN string }
				if err := json.Unmarshal(out.Payload, &payload); err != nil {
					t.Fatal(err)
				}
				if out.FunctionError != nil || payload.Value != "shared-archive" || payload.ARN != "arn:aws:lambda:us-east-1:"+firstAccount+":function:"+function {
					t.Fatalf("wrong cross-account layer execution: %+v %s", out, out.Payload)
				}
			}
			invoke()
			f.clients = f.reopen()
			readLayer(firstAccount, true)
			invoke()
			grant(true)
			f.update(t, cloudFormationLayerPermissionTemplate(t, layerARN, secondAccount), cfntypes.StackStatusUpdateComplete)
			secondID := cloudFormationLayerPermissionOutput(t, f.wait(t, cfntypes.StackStatusUpdateComplete), layerARN)
			if secondID == firstID {
				t.Fatal("changed grant reused the old permission identity")
			}
			readLayer(firstAccount, false)
			readLayer(secondAccount, true)
			// Revocation blocks new attachments, not bytes already retained by a function.
			_, err = client(firstAccount).UpdateFunctionConfiguration(t.Context(), &awslambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(function), Layers: []string{layerARN}})
			assertAPIError(t, err, "AccessDeniedException")
			invoke()

			grant(false)
			removeStack := func(wanted cfntypes.StackStatus) {
				t.Helper()
				_, err := f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)})
				if err != nil {
					t.Fatal(err)
				}
				f.wait(t, wanted)
			}
			removeStack(cfntypes.StackStatusDeleteFailed)
			readLayer(secondAccount, true)
			grant(true)
			_, sid, _ := strings.Cut(secondID, "#")
			_, err = f.native().RemoveLayerVersionPermission(t.Context(), &awslambda.RemoveLayerVersionPermissionInput{LayerName: aws.String("shared-stack-layer"), VersionNumber: aws.Int64(layer.Version), StatementId: &sid})
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.native().AddLayerVersionPermission(t.Context(), &awslambda.AddLayerVersionPermissionInput{LayerName: aws.String("shared-stack-layer"), VersionNumber: aws.Int64(layer.Version), StatementId: &sid, Principal: aws.String(secondAccount), Action: aws.String("lambda:GetLayerVersion")})
			if err != nil {
				t.Fatal(err)
			}
			f.clients = f.reopen()
			removeStack(cfntypes.StackStatusDeleteComplete)
			readLayer(secondAccount, false)
			invoke()
			_, err = client(firstAccount).DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: aws.String(function)})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func cloudFormationLayerPermissionTemplate(t *testing.T, layerARN, principal string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{"Permission": map[string]any{"Type": "AWS::Lambda::LayerVersionPermission", "Properties": map[string]string{"LayerVersionArn": layerARN, "Action": "lambda:GetLayerVersion", "Principal": principal}}},
		"Outputs":   map[string]any{"PermissionRef": map[string]any{"Value": map[string]string{"Ref": "Permission"}}, "PermissionId": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Permission", "Id"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func cloudFormationLayerPermissionOutput(t *testing.T, stack cfntypes.Stack, layerARN string) string {
	t.Helper()
	values := map[string]string{}
	for _, output := range stack.Outputs {
		values[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
	}
	value := values["PermissionRef"]
	layer, statement, found := strings.Cut(value, "#")
	if !found || layer != layerARN || statement == "" || value != values["PermissionId"] {
		t.Fatalf("wrong layer permission Ref/Id: %v", values)
	}
	return value
}

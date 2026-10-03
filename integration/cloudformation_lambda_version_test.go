package stackd_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd"
	"stackd/clock"
)

// This application uses all three real resource owners, not prepublished SDK
// versions. Replacement must retarget the alias before retiring its old version.
func TestCloudFormationLambdaVersionLifecycle(t *testing.T) {
	lambdaURLDocker(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, roleARN := newCloudFormationVersionStack(t, backend)
			template := func(marker string) string {
				return cloudFormationVersionTemplate(t, roleARN, marker)
			}
			created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("lambda-version-app"), TemplateBody: aws.String(template("first"))})
			if err != nil {
				t.Fatal(err)
			}
			f.stackID = aws.ToString(created.StackId)
			initial := f.wait(t, cfntypes.StackStatusCreateComplete)
			first := cloudFormationVersionOutput(t, initial)
			cloudFormationVersionInvoke(t, f, first, "first")
			f.invoke(t, first, "first", "provisioned-concurrency")
			f.assertMembers(t, f.stackQuery(t, "AWS::Lambda::Version"), map[string]string{cloudFormationLambdaFunctionARN + ":" + first: "AWS::Lambda::Version"})
			runtime, err := f.native().GetRuntimeManagementConfig(t.Context(), &awslambda.GetRuntimeManagementConfigInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), Qualifier: aws.String(first)})
			if err != nil {
				t.Fatal(err)
			}
			if string(runtime.UpdateRuntimeOn) != "FunctionUpdate" {
				t.Fatalf("version runtime mode = %+v", runtime)
			}

			// Direct Lambda repeats the last publication. A new CloudFormation
			// resource must reject it, not acquire/delete the existing version.
			direct, err := f.native().PublishVersion(t.Context(), &awslambda.PublishVersionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(direct.Version) != first {
				t.Fatalf("native repeated publication changed version: %+v", direct)
			}
			for _, rejection := range []struct{ name, properties string }{
				{"existing", `"FunctionName":"` + cloudFormationLambdaFunctionName + `"`},
				{"hash", `"FunctionName":"` + cloudFormationLambdaFunctionName + `","CodeSha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`},
			} {
				body := `{"Resources":{"Version":{"Type":"AWS::Lambda::Version","Properties":{` + rejection.properties + `}}}}`
				failed, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("lambda-version-" + rejection.name), TemplateBody: aws.String(body)})
				if err != nil {
					t.Fatal(err)
				}
				cloudFormationWait(t, f.clients, f.source, f.cfn(), aws.ToString(failed.StackId), cfntypes.StackStatusRollbackComplete)
				cloudFormationVersionInvoke(t, f, first, "first")
			}

			f.clients = f.reopen()
			cloudFormationVersionInvoke(t, f, first, "first")
			f.assertMembers(t, f.stackQuery(t, "AWS::AllSupported"), map[string]string{cloudFormationLambdaFunctionARN: "AWS::Lambda::Function", cloudFormationLambdaFunctionARN + ":" + first: "AWS::Lambda::Version", cloudFormationLambdaAliasARN: "AWS::Lambda::Alias"})
			f.update(t, template("second"), cfntypes.StackStatusUpdateComplete)
			second := cloudFormationVersionOutput(t, f.wait(t, cfntypes.StackStatusUpdateComplete))
			if second == first {
				t.Fatal("changed function deployment reused the old publication")
			}
			f.invoke(t, second, "second", "provisioned-concurrency")
			cloudFormationVersionInvoke(t, f, second, "second")
			_, err = f.native().GetFunction(t.Context(), &awslambda.GetFunctionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), Qualifier: aws.String(first)})
			assertAPIError(t, err, "ResourceNotFoundException")
			f.assertMembers(t, f.stackQuery(t, "AWS::Lambda::Version"), map[string]string{cloudFormationLambdaFunctionARN + ":" + second: "AWS::Lambda::Version"})
			_, err = f.native().CreateAlias(t.Context(), &awslambda.CreateAliasInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String("external"), FunctionVersion: aws.String(second)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)})
			if err != nil {
				t.Fatal(err)
			}
			for range 20 {
				advanceClock(t, f.source, time.Second)
				if _, err := f.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000); err != nil {
					t.Fatal(err)
				}
			}
			pending, err := f.cfn().DescribeStackResource(t.Context(), &cloudformation.DescribeStackResourceInput{StackName: aws.String(f.stackID), LogicalResourceId: aws.String("Version")})
			if err != nil {
				t.Fatal(err)
			}
			if pending.StackResourceDetail.ResourceStatus != cfntypes.ResourceStatusDeleteInProgress {
				t.Fatalf("referenced version deletion must remain pending: %+v", pending.StackResourceDetail)
			}
			cloudFormationVersionInvoke(t, f, second, "second")
			_, err = f.native().DeleteAlias(t.Context(), &awslambda.DeleteAliasInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), Name: aws.String("external")})
			if err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusDeleteComplete)
			_, err = f.native().GetFunction(t.Context(), &awslambda.GetFunctionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)})
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}

func cloudFormationVersionTemplate(t *testing.T, role, marker string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{
			"Function": map[string]any{"Type": "AWS::Lambda::Function", "Properties": map[string]any{
				"FunctionName": cloudFormationLambdaFunctionName, "Runtime": "python3.12", "Handler": "index.handler", "Role": role,
				"Code":        map[string]string{"ZipFile": "import os\ndef handler(event,context):\n return {'marker':os.environ['MARKER'],'version':context.function_version,'initialization':os.environ['AWS_LAMBDA_INITIALIZATION_TYPE']}\n"},
				"Environment": map[string]any{"Variables": map[string]string{"MARKER": marker}},
			}},
			"Version": map[string]any{"Type": "AWS::Lambda::Version", "Properties": map[string]any{
				"FunctionName": map[string]string{"Ref": "Function"}, "Description": marker,
				"ProvisionedConcurrencyConfig": map[string]int{"ProvisionedConcurrentExecutions": 1},
				"RuntimePolicy":                map[string]string{"UpdateRuntimeOn": "FunctionUpdate"},
			}},
			"Alias": map[string]any{"Type": "AWS::Lambda::Alias", "Properties": map[string]any{
				"FunctionName": map[string]string{"Ref": "Function"}, "Name": cloudFormationLambdaAliasName,
				"FunctionVersion": map[string]any{"Fn::GetAtt": []string{"Version", "Version"}},
			}},
		},
		"Outputs": map[string]any{
			"VersionRef":    map[string]any{"Value": map[string]string{"Ref": "Version"}},
			"VersionARN":    map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Version", "FunctionArn"}}},
			"VersionNumber": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Version", "Version"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func cloudFormationVersionOutput(t *testing.T, stack cfntypes.Stack) string {
	t.Helper()
	values := map[string]string{}
	for _, out := range stack.Outputs {
		values[aws.ToString(out.OutputKey)] = aws.ToString(out.OutputValue)
	}
	version := values["VersionNumber"]
	if values["VersionRef"] != cloudFormationLambdaFunctionARN+":"+version || values["VersionARN"] != values["VersionRef"] {
		t.Fatalf("wrong qualified version outputs: %v", values)
	}
	return version
}

func cloudFormationVersionInvoke(t *testing.T, f *cloudFormationLambdaAliasStack, version, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for {
		pool, err := f.native().GetProvisionedConcurrencyConfig(ctx, &awslambda.GetProvisionedConcurrencyConfigInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), Qualifier: aws.String(version)})
		if err != nil {
			t.Fatal(err)
		}
		if string(pool.Status) == "READY" {
			break
		}
		if string(pool.Status) == "FAILED" {
			t.Fatalf("provisioned version failed: %+v", pool)
		}
		advanceClock(t, f.source, time.Second)
		if _, err := f.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	out, err := f.native().Invoke(ctx, &awslambda.InvokeInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), Qualifier: aws.String(version), Payload: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct{ Marker, Version, Initialization string }
	if err := json.Unmarshal(out.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if out.FunctionError != nil || aws.ToString(out.ExecutedVersion) != version || payload.Version != version || payload.Marker != marker || payload.Initialization != "provisioned-concurrency" {
		t.Fatalf("wrong published runtime: %+v payload=%s", out, out.Payload)
	}
}

func newCloudFormationVersionStack(t *testing.T, backend string) (*cloudFormationLambdaAliasStack, string) {
	t.Helper()
	f := &cloudFormationLambdaAliasStack{source: clock.NewManual(time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC))}
	f.clients, f.reopen = retainedCloud(t, backend, stackd.Config{Clock: f.source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return newLambdaDockerStack(t, config, nil)
	})
	f.access, f.secret = "test", "test"
	roles := f.clients.iam("test", "test", "")
	role, err := roles.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("cfn-version-runtime"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = roles.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("logs"), PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	return f, aws.ToString(role.Role.Arn)
}

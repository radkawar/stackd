package stackd_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"stackd"
)

// These signed SDK calls exercise local policy ownership, IAM, and real Python
// execution. They are not evidence of native AWS cross-account behavior.
func TestCloudFormationLambdaResourcePolicyLifecycle(t *testing.T) {
	lambdaURLDocker(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, roleARN := newCloudFormationVersionStack(t, backend)
			_, err := f.native().CreateFunction(t.Context(), &awslambda.CreateFunctionInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), Role: &roleARN,
				Runtime: lambdatypes.RuntimePython312, Handler: aws.String("index.handler"),
				Code: &lambdatypes.FunctionCode{ZipFile: lambdaZIP(t, map[string]string{"index.py": "def handler(event,context):\n return {'marker':'resource-policy','version':context.function_version,'arn':context.invoked_function_arn}\n"})},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(f.native(), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)}, time.Minute); err != nil {
				t.Fatal(err)
			}
			published, err := f.native().PublishVersion(t.Context(), &awslambda.PublishVersionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)})
			if err != nil {
				t.Fatal(err)
			}
			version := aws.ToString(published.Version)
			qualifiedARN := cloudFormationLambdaFunctionARN + ":" + version
			const firstAccount, secondAccount = "111111111111", "222222222222"
			invoke := func(account, target, wantedVersion string, allowed bool) {
				t.Helper()
				client := f.lambda(cloudFormationLambdaAliasRegion, account, "test")
				out, err := client.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: &target, Payload: []byte(`{}`)})
				if !allowed {
					assertAPIError(t, err, "AccessDeniedException")
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var payload struct{ Marker, Version, ARN string }
				if err := json.Unmarshal(out.Payload, &payload); err != nil {
					t.Fatal(err)
				}
				if out.FunctionError != nil || aws.ToString(out.ExecutedVersion) != wantedVersion || payload.Marker != "resource-policy" || payload.Version != wantedVersion || payload.ARN != target {
					t.Fatalf("wrong shared function execution: %+v payload=%s", out, out.Payload)
				}
			}
			invoke(firstAccount, cloudFormationLambdaFunctionARN, "$LATEST", false)
			invoke(secondAccount, cloudFormationLambdaFunctionARN, "$LATEST", false)
			cloudFormationPermissionRecreatedStatement(t, f, invoke)
			// Creation must not acquire an existing policy installed by AddPermission.
			_, err = f.native().AddPermission(t.Context(), &awslambda.AddPermissionInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), StatementId: aws.String("NativeBeforeStack"),
				Action: aws.String("lambda:InvokeFunction"), Principal: aws.String(secondAccount),
			})
			if err != nil {
				t.Fatal(err)
			}
			invoke(secondAccount, cloudFormationLambdaFunctionARN, "$LATEST", true)
			initialPolicy := cloudFormationResourcePolicyDocument(cloudFormationLambdaFunctionARN, []string{firstAccount}, "")
			previous, err := f.native().GetResourcePolicy(t.Context(), &awslambda.GetResourcePolicyInput{ResourceArn: aws.String(cloudFormationLambdaFunctionARN)})
			if err != nil {
				t.Fatal(err)
			}
			var previousPolicy map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(previous.Policy)), &previousPolicy); err != nil {
				t.Fatal(err)
			}
			rejected, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
				StackName: aws.String("lambda-resource-policy-conflict"), TemplateBody: aws.String(cloudFormationResourcePolicyTemplate(t, cloudFormationLambdaFunctionARN, initialPolicy)),
			})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationResourcePolicyReject(t, f, aws.ToString(rejected.StackId))
			if revision := cloudFormationResourcePolicyRead(t, f, cloudFormationLambdaFunctionARN, previousPolicy); revision != aws.ToString(previous.RevisionId) {
				t.Fatalf("rejected create changed existing policy revision: got %q want %q", revision, aws.ToString(previous.RevisionId))
			}
			invoke(firstAccount, cloudFormationLambdaFunctionARN, "$LATEST", false)
			invoke(secondAccount, cloudFormationLambdaFunctionARN, "$LATEST", true)
			_, err = f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: rejected.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, f.clients, f.source, f.cfn(), aws.ToString(rejected.StackId), cfntypes.StackStatusDeleteComplete)
			if revision := cloudFormationResourcePolicyRead(t, f, cloudFormationLambdaFunctionARN, previousPolicy); revision != aws.ToString(previous.RevisionId) {
				t.Fatal("failed stack cleanup changed the existing policy")
			}
			_, err = f.native().RemovePermission(t.Context(), &awslambda.RemovePermissionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName), StatementId: aws.String("NativeBeforeStack")})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationResourcePolicyAbsent(t, f, cloudFormationLambdaFunctionARN)
			created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
				StackName: aws.String("lambda-resource-policy"), TemplateBody: aws.String(cloudFormationResourcePolicyTemplate(t, cloudFormationLambdaFunctionARN, initialPolicy)),
			})
			if err != nil {
				t.Fatal(err)
			}
			f.stackID = aws.ToString(created.StackId)
			cloudFormationResourcePolicyOutput(t, f.wait(t, cfntypes.StackStatusCreateComplete), cloudFormationLambdaFunctionARN)
			initialRevision := cloudFormationResourcePolicyRead(t, f, cloudFormationLambdaFunctionARN, initialPolicy)
			invoke(firstAccount, cloudFormationLambdaFunctionARN, "$LATEST", true)
			invoke(secondAccount, cloudFormationLambdaFunctionARN, "$LATEST", false)
			invoke(firstAccount, qualifiedARN, version, false)
			// Updating a managed full policy replaces any additional native grants.
			_, err = f.native().AddPermission(t.Context(), &awslambda.AddPermissionInput{
				FunctionName: aws.String(cloudFormationLambdaFunctionName), StatementId: aws.String("NativeBeforeUpdate"),
				Action: aws.String("lambda:InvokeFunction"), Principal: aws.String(secondAccount),
			})
			if err != nil {
				t.Fatal(err)
			}
			invoke(secondAccount, cloudFormationLambdaFunctionARN, "$LATEST", true)

			// A's allow remains present: only the explicit deny revokes its access.
			swappedPolicy := cloudFormationResourcePolicyDocument(cloudFormationLambdaFunctionARN, []string{firstAccount, secondAccount}, firstAccount)
			f.update(t, cloudFormationResourcePolicyTemplate(t, cloudFormationLambdaFunctionARN, swappedPolicy), cfntypes.StackStatusUpdateComplete)
			swappedRevision := cloudFormationResourcePolicyRead(t, f, cloudFormationLambdaFunctionARN, swappedPolicy)
			if swappedRevision == initialRevision {
				t.Fatal("policy update retained the previous revision")
			}
			invoke(firstAccount, cloudFormationLambdaFunctionARN, "$LATEST", false)
			invoke(secondAccount, cloudFormationLambdaFunctionARN, "$LATEST", true)
			cloudFormationResourcePolicyOutput(t, f.wait(t, cfntypes.StackStatusUpdateComplete), cloudFormationLambdaFunctionARN)
			f.clients = f.reopen()
			if revision := cloudFormationResourcePolicyRead(t, f, cloudFormationLambdaFunctionARN, swappedPolicy); revision != swappedRevision {
				t.Fatalf("restart changed policy revision: got %q want %q", revision, swappedRevision)
			}
			invoke(firstAccount, cloudFormationLambdaFunctionARN, "$LATEST", false)
			invoke(secondAccount, cloudFormationLambdaFunctionARN, "$LATEST", true)

			// Changing the target replaces the resource and retires the old policy,
			// without deleting either the SDK-owned function or its publication.
			qualifiedPolicy := cloudFormationResourcePolicyDocument(qualifiedARN, []string{firstAccount}, "")
			f.update(t, cloudFormationResourcePolicyTemplate(t, qualifiedARN, qualifiedPolicy), cfntypes.StackStatusUpdateComplete)
			cloudFormationResourcePolicyOutput(t, f.wait(t, cfntypes.StackStatusUpdateComplete), qualifiedARN)
			qualifiedRevision := cloudFormationResourcePolicyRead(t, f, qualifiedARN, qualifiedPolicy)
			cloudFormationResourcePolicyAbsent(t, f, cloudFormationLambdaFunctionARN)
			invoke(firstAccount, cloudFormationLambdaFunctionARN, "$LATEST", false)
			invoke(secondAccount, cloudFormationLambdaFunctionARN, "$LATEST", false)
			invoke(firstAccount, qualifiedARN, version, true)
			invoke(secondAccount, qualifiedARN, version, false)
			f.clients = f.reopen()
			if revision := cloudFormationResourcePolicyRead(t, f, qualifiedARN, qualifiedPolicy); revision != qualifiedRevision {
				t.Fatalf("restart changed qualified policy revision: got %q want %q", revision, qualifiedRevision)
			}
			cloudFormationResourcePolicyAbsent(t, f, cloudFormationLambdaFunctionARN)
			invoke(firstAccount, qualifiedARN, version, true)
			invoke(secondAccount, qualifiedARN, version, false)

			// Native overwrite does not protect the same policy ARN from the
			// existing CloudFormation resource's subsequent deletion.
			foreignPolicy := cloudFormationResourcePolicyDocument(qualifiedARN, []string{secondAccount}, "")
			foreignDocument, err := json.Marshal(foreignPolicy)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.native().PutResourcePolicy(t.Context(), &awslambda.PutResourcePolicyInput{ResourceArn: &qualifiedARN, Policy: aws.String(string(foreignDocument))})
			if err != nil {
				t.Fatal(err)
			}
			invoke(firstAccount, qualifiedARN, version, false)
			invoke(secondAccount, qualifiedARN, version, true)

			_, err = f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)})
			if err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusDeleteComplete)
			cloudFormationResourcePolicyAbsent(t, f, qualifiedARN)
			invoke(firstAccount, qualifiedARN, version, false)
			invoke(secondAccount, qualifiedARN, version, false)
			invoke("test", qualifiedARN, version, true)
			invoke("test", cloudFormationLambdaFunctionARN, "$LATEST", true)
			if _, err := f.native().DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func cloudFormationResourcePolicyDocument(target string, allowed []string, denied string) map[string]any {
	statements := make([]any, 0, len(allowed)+1)
	for _, account := range allowed {
		statements = append(statements, map[string]any{
			"Sid": "Allow" + account, "Effect": "Allow", "Principal": map[string]string{"AWS": "arn:aws:iam::" + account + ":root"},
			"Action": "lambda:InvokeFunction", "Resource": target,
		})
	}
	if denied != "" {
		statements = append(statements, map[string]any{
			"Sid": "Deny" + denied, "Effect": "Deny", "Principal": map[string]string{"AWS": "arn:aws:iam::" + denied + ":root"},
			"Action": "lambda:InvokeFunction", "Resource": target,
		})
	}
	return map[string]any{"Version": "2012-10-17", "Statement": statements}
}

func cloudFormationResourcePolicyTemplate(t *testing.T, target string, policy map[string]any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{"Policy": map[string]any{
			"Type": "AWS::Lambda::ResourcePolicy", "Properties": map[string]any{"ResourceArn": target, "PolicyDocument": policy},
		}},
		"Outputs": map[string]any{"PolicyRef": map[string]any{"Value": map[string]string{"Ref": "Policy"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func cloudFormationResourcePolicyOutput(t *testing.T, stack cfntypes.Stack, target string) {
	t.Helper()
	for _, output := range stack.Outputs {
		if aws.ToString(output.OutputKey) == "PolicyRef" {
			if aws.ToString(output.OutputValue) != target {
				t.Fatalf("resource policy Ref = %q, want target ARN %q", aws.ToString(output.OutputValue), target)
			}
			return
		}
	}
	t.Fatal("resource policy Ref output is missing")
}

func cloudFormationResourcePolicyRead(t *testing.T, f *cloudFormationLambdaAliasStack, target string, expected map[string]any) string {
	t.Helper()
	current, err := f.native().GetResourcePolicy(t.Context(), &awslambda.GetResourcePolicyInput{ResourceArn: &target})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := f.native().GetPolicy(t.Context(), &awslambda.GetPolicyInput{FunctionName: &target})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(current.RevisionId) == "" || aws.ToString(current.RevisionId) != aws.ToString(legacy.RevisionId) {
		t.Fatalf("policy APIs disagree on revision: resource=%+v legacy=%+v", current, legacy)
	}
	wanted, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	// Compare statements by Sid, not serialization or statement ordering.
	normalize := func(raw string) (string, map[string]map[string]any) {
		t.Helper()
		var document struct {
			Version   string
			Statement []map[string]any
		}
		if err := json.Unmarshal([]byte(raw), &document); err != nil {
			t.Fatal(err)
		}
		statements := make(map[string]map[string]any, len(document.Statement))
		for _, statement := range document.Statement {
			sid, ok := statement["Sid"].(string)
			if !ok || sid == "" || statements[sid] != nil {
				t.Fatalf("missing or duplicate statement identity in policy: %s", raw)
			}
			statements[sid] = statement
		}
		return document.Version, statements
	}
	wantedVersion, wantedStatements := normalize(string(wanted))
	for _, raw := range []string{aws.ToString(current.Policy), aws.ToString(legacy.Policy)} {
		version, statements := normalize(raw)
		if version != wantedVersion || !reflect.DeepEqual(statements, wantedStatements) {
			t.Fatalf("wrong full resource policy: got %s want %s", raw, wanted)
		}
	}
	return aws.ToString(current.RevisionId)
}

func cloudFormationResourcePolicyAbsent(t *testing.T, f *cloudFormationLambdaAliasStack, target string) {
	t.Helper()
	_, err := f.native().GetResourcePolicy(t.Context(), &awslambda.GetResourcePolicyInput{ResourceArn: &target})
	assertAPIError(t, err, "ResourceNotFoundException")
	_, err = f.native().GetPolicy(t.Context(), &awslambda.GetPolicyInput{FunctionName: &target})
	assertAPIError(t, err, "ResourceNotFoundException")
}

func cloudFormationResourcePolicyReject(t *testing.T, f *cloudFormationLambdaAliasStack, stackID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	for {
		out, err := f.cfn().DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &stackID})
		if err != nil {
			t.Fatal(err)
		}
		status := out.Stacks[0].StackStatus
		if status == cfntypes.StackStatusCreateComplete {
			t.Fatal("resource policy creation acquired an existing native policy")
		}
		// Native early validation and local provider rollback need not reject
		// at the same stage; both must preserve the original policy.
		if status == cfntypes.StackStatusReviewInProgress || !cloudFormationTransient(map[string]any{"Stacks": []any{map[string]any{"StackStatus": string(status)}}}) {
			return
		}
		advanceClock(t, f.source, time.Second)
		if _, err := f.clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 1000); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("conflicting resource policy stack did not settle", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

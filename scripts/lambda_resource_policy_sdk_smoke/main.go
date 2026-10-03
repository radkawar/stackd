// Exercise replacement policies through signed SDK requests and real Lambda execution.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func failure(err error, code string) {
	var api smithy.APIError
	require(errors.As(err, &api) && api.ErrorCode() == code, fmt.Sprintf("expected %s, got %v", code, err))
}
func encode(value any) string {
	data, err := json.Marshal(value)
	must(err)
	return string(data)
}

func main() {
	endpoint := flag.String("endpoint", "", "actual stackd endpoint")
	flag.Parse()
	require(*endpoint != "", "endpoint required")
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	config := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), "")}
	lam := lambda.NewFromConfig(config, func(o *lambda.Options) { o.BaseEndpoint = endpoint })
	users := iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = endpoint })
	identity := sts.NewFromConfig(config, func(o *sts.Options) { o.BaseEndpoint = endpoint })
	who, err := identity.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	must(err)
	account := aws.ToString(who.Account)
	name := fmt.Sprintf("stackd-next-resource-policy-%x", time.Now().UnixNano())
	arn := "arn:aws:lambda:us-east-1:" + account + ":function:" + name
	_, err = lam.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{ResourceArn: &arn})
	must(err)
	role, err := users.CreateRole(ctx, &iam.CreateRoleInput{RoleName: &name, AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
	must(err)
	defer func() {
		_, err := users.DeleteRole(context.Background(), &iam.DeleteRoleInput{RoleName: &name})
		must(err)
	}()
	var code bytes.Buffer
	writer := zip.NewWriter(&code)
	file, err := writer.Create("handler.py")
	must(err)
	_, err = file.Write([]byte("def handler(event, context):\n return {'resource_policy': True}\n"))
	must(err)
	must(writer.Close())
	_, err = lam.CreateFunction(ctx, &lambda.CreateFunctionInput{FunctionName: &name, Runtime: types.RuntimePython312, Handler: aws.String("handler.handler"), Role: role.Role.Arn, Code: &types.FunctionCode{ZipFile: code.Bytes()}, Publish: true})
	must(err)
	defer func() {
		_, err := lam.DeleteFunction(context.Background(), &lambda.DeleteFunctionInput{FunctionName: &name})
		must(err)
	}()
	must(lambda.NewFunctionActiveV2Waiter(lam).Wait(ctx, &lambda.GetFunctionInput{FunctionName: &name}, 90*time.Second))
	user, err := users.CreateUser(ctx, &iam.CreateUserInput{UserName: &name})
	must(err)
	defer func() {
		_, err := users.DeleteUser(context.Background(), &iam.DeleteUserInput{UserName: &name})
		must(err)
	}()
	key, err := users.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: &name})
	must(err)
	defer func() {
		_, err := users.DeleteAccessKey(context.Background(), &iam.DeleteAccessKeyInput{UserName: &name, AccessKeyId: key.AccessKey.AccessKeyId})
		must(err)
	}()
	limitedConfig := config
	limitedConfig.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), "")
	limited := lambda.NewFromConfig(limitedConfig, func(o *lambda.Options) { o.BaseEndpoint = endpoint })
	invoke := func(target string, allowed bool) {
		out, err := limited.Invoke(ctx, &lambda.InvokeInput{FunctionName: &target, Payload: []byte(`{}`)})
		if !allowed {
			failure(err, "AccessDeniedException")
			return
		}
		must(err)
		var body struct {
			ResourcePolicy bool `json:"resource_policy"`
		}
		must(json.Unmarshal(out.Payload, &body))
		require(out.FunctionError == nil && body.ResourcePolicy, "resource policy did not authorize real runtime execution")
	}
	policy := func(target, sid string, principal any, condition any) string {
		statement := map[string]any{"Sid": sid, "Effect": "Allow", "Principal": principal, "Action": "lambda:InvokeFunction", "Resource": target}
		if condition != nil {
			statement["Condition"] = condition
		}
		return encode(map[string]any{"Version": "2012-10-17", "Statement": []any{statement}})
	}
	put := func(target, document string, revision *string) *lambda.PutResourcePolicyOutput {
		out, err := lam.PutResourcePolicy(ctx, &lambda.PutResourcePolicyInput{ResourceArn: &target, Policy: &document, RevisionId: revision})
		must(err)
		return out
	}
	invoke(name, false)
	public := put(arn, policy(arn, "public", "*", nil), nil)
	invoke(name, true)
	sourceBound := policy(arn, "source", "*", map[string]any{"StringEquals": map[string]string{"aws:SourceAccount": account}, "ArnLike": map[string]string{"aws:SourceArn": "arn:aws:s3:::" + name + "/*"}})
	bound := put(arn, sourceBound, public.RevisionId)
	invoke(name, false)
	_, err = lam.PutResourcePolicy(ctx, &lambda.PutResourcePolicyInput{ResourceArn: &arn, Policy: public.Policy, RevisionId: public.RevisionId})
	failure(err, "PreconditionFailedException")
	_, err = lam.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{ResourceArn: &arn, RevisionId: public.RevisionId})
	failure(err, "PreconditionFailedException")
	retained, err := lam.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: &name})
	must(err)
	require(aws.ToString(retained.RevisionId) == aws.ToString(bound.RevisionId), "legacy GetPolicy sees a different policy revision")
	arrayPolicy := encode(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Sid": "array", "Effect": "Allow", "Principal": map[string]any{"AWS": []string{aws.ToString(user.User.Arn), "arn:aws:iam::" + account + ":root"}}, "Action": []string{"lambda:InvokeFunction", "lambda:GetFunction"}, "Resource": []string{arn}, "Condition": map[string]any{"StringEquals": map[string]any{"aws:PrincipalAccount": []string{account, "111111111111"}}}}}})
	put(arn, arrayPolicy, bound.RevisionId)
	_, err = lam.AddPermission(ctx, &lambda.AddPermissionInput{FunctionName: &name, StatementId: aws.String("service"), Action: aws.String("lambda:InvokeFunction"), Principal: aws.String("s3.amazonaws.com"), SourceArn: aws.String("arn:aws:s3:::" + name), SourceAccount: &account})
	must(err)
	invoke(name, true)
	_, err = lam.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("array")})
	must(err)
	invoke(name, false)
	setRemovalCondition := func(operator string, principal any) {
		document := encode(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": "lambda:RemovePermission", "Resource": arn, "Condition": map[string]any{operator: map[string]any{"lambda:Principal": principal}}}}})
		_, err := users.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: &name, PolicyName: aws.String("owned-remove"), PolicyDocument: &document})
		must(err)
	}
	put(arn, policy(arn, "account", map[string]string{"AWS": account}, nil), nil)
	setRemovalCondition("StringEquals", account)
	defer func() {
		_, err := users.DeleteUserPolicy(context.Background(), &iam.DeleteUserPolicyInput{UserName: &name, PolicyName: aws.String("owned-remove")})
		must(err)
	}()
	_, err = limited.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("account")})
	failure(err, "AccessDeniedException")
	setRemovalCondition("StringEquals", "arn:aws:iam::"+account+":root")
	_, err = limited.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("account")})
	must(err)
	put(arn, arrayPolicy, nil)
	_, err = limited.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("array")})
	failure(err, "AccessDeniedException")
	setRemovalCondition("StringEquals", "")
	_, err = limited.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("array")})
	must(err)
	put(arn, policy(arn, "federated", map[string]string{"Federated": "cognito-identity.amazonaws.com"}, nil), nil)
	_, err = lam.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("federated")})
	failure(err, "ServiceException")
	_, err = lam.GetResourcePolicy(ctx, &lambda.GetResourcePolicyInput{ResourceArn: &arn})
	must(err)
	_, err = lam.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{ResourceArn: &arn})
	must(err)
	for _, reference := range []string{"not a principal", "*", ""} {
		put(arn, policy(arn, "federated-opaque", map[string]string{"Federated": reference}, nil), nil)
		invoke(name, false)
	}
	_, err = lam.AddPermission(ctx, &lambda.AddPermissionInput{FunctionName: &name, StatementId: aws.String("beside-federated"), Action: aws.String("lambda:InvokeFunction"), Principal: user.User.Arn})
	must(err)
	invoke(name, true)
	_, err = lam.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("beside-federated")})
	must(err)
	invoke(name, false)
	_, err = lam.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{ResourceArn: &arn})
	must(err)
	put(arn, policy(arn, "mixed", map[string]string{"AWS": "arn:aws:iam::" + account + ":root", "Service": "s3.amazonaws.com"}, nil), nil)
	setRemovalCondition("Null", "true")
	_, err = limited.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("mixed")})
	failure(err, "AccessDeniedException")
	setRemovalCondition("ForAnyValue:StringEquals", "s3.amazonaws.com")
	_, err = limited.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("mixed")})
	failure(err, "AccessDeniedException")
	setRemovalCondition("ForAllValues:StringEquals", []string{"arn:aws:iam::" + account + ":root", "s3.amazonaws.com"})
	_, err = limited.RemovePermission(ctx, &lambda.RemovePermissionInput{FunctionName: &name, StatementId: aws.String("mixed")})
	must(err)
	for _, qualifier := range []string{"$LATEST", "1"} {
		target := arn + ":" + qualifier
		put(target, policy(target, "qualified", map[string]string{"AWS": aws.ToString(user.User.Arn)}, nil), nil)
		invoke(target, true)
		_, err = lam.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{ResourceArn: &target})
		must(err)
		_, err = lam.GetResourcePolicy(ctx, &lambda.GetResourcePolicyInput{ResourceArn: &target})
		failure(err, "ResourceNotFoundException")
	}
	_, err = lam.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{ResourceArn: &arn})
	must(err)
	_, err = lam.DeleteResourcePolicy(ctx, &lambda.DeleteResourcePolicyInput{ResourceArn: &arn})
	must(err)
	invoke(name, false)
	fmt.Println(encode(map[string]any{"sdk": "aws-sdk-go-v2", "public_and_source_bound_authorization": true, "replacement_and_revision_cas": true, "array_policy_legacy_add_remove": true, "scoped_principal_iam_denial_recovery": true, "federated_literals_not_wildcard_grants": true, "latest_and_version_runtime": true, "idempotent_delete": true}))
}

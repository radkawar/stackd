// Run against the actual retained stackd executable; all requests use SDK v2 SigV4.
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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	lambda "github.com/aws/aws-sdk-go-v2/service/lambda"
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
func denied(err error) {
	var api smithy.APIError
	require(errors.As(err, &api) && api.ErrorCode() == "AccessDeniedException", fmt.Sprintf("expected IAM denial, got %v", err))
}

func main() {
	endpoint := flag.String("endpoint", "", "stackd HTTP endpoint")
	flag.Parse()
	require(*endpoint != "", "endpoint required")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	config := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), "")}
	client := lambda.NewFromConfig(config, func(o *lambda.Options) { o.BaseEndpoint = endpoint })
	identity := sts.NewFromConfig(config, func(o *sts.Options) { o.BaseEndpoint = endpoint })
	users := iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = endpoint })
	who, err := identity.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	must(err)
	name := fmt.Sprintf("stackd-next-csc-sdk-%x", time.Now().UnixNano())
	profile := "arn:aws:signer:us-east-1:" + aws.ToString(who.Account) + ":/signing-profiles/sdk_probe/0123456789"
	var configs []string
	defer func() {
		for _, arn := range configs {
			_, err := client.DeleteCodeSigningConfig(context.Background(), &lambda.DeleteCodeSigningConfigInput{CodeSigningConfigArn: aws.String(arn)})
			must(err)
		}
	}()
	for range 2 {
		out, err := client.CreateCodeSigningConfig(ctx, &lambda.CreateCodeSigningConfigInput{AllowedPublishers: &types.AllowedPublishers{SigningProfileVersionArns: []string{profile}}, CodeSigningPolicies: &types.CodeSigningPolicies{UntrustedArtifactOnDeployment: types.CodeSigningPolicyEnforce}, Tags: map[string]string{"owner": name}})
		must(err)
		require(out.CodeSigningConfig != nil && strings.HasPrefix(aws.ToString(out.CodeSigningConfig.CodeSigningConfigId), "csc-"), "missing modeled configuration")
		configs = append(configs, aws.ToString(out.CodeSigningConfig.CodeSigningConfigArn))
	}
	arn := configs[0]
	updated, err := client.UpdateCodeSigningConfig(ctx, &lambda.UpdateCodeSigningConfigInput{CodeSigningConfigArn: &arn, Description: aws.String("SDK v2 retained policy"), CodeSigningPolicies: &types.CodeSigningPolicies{UntrustedArtifactOnDeployment: types.CodeSigningPolicyWarn}})
	must(err)
	require(updated.CodeSigningConfig.CodeSigningPolicies.UntrustedArtifactOnDeployment == types.CodeSigningPolicyWarn, "update did not change admission policy")
	seen := map[string]bool{}
	pages := lambda.NewListCodeSigningConfigsPaginator(client, &lambda.ListCodeSigningConfigsInput{MaxItems: aws.Int32(1)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		must(err)
		for _, item := range page.CodeSigningConfigs {
			seen[aws.ToString(item.CodeSigningConfigArn)] = true
		}
	}
	require(seen[configs[0]] && seen[configs[1]], "pagination omitted owned configs")
	_, err = client.ListCodeSigningConfigs(ctx, &lambda.ListCodeSigningConfigsInput{Marker: aws.String("invalid")})
	var invalid *types.InvalidParameterValueException
	require(errors.As(err, &invalid), fmt.Sprintf("invalid cursor not modeled: %v", err))
	_, err = client.TagResource(ctx, &lambda.TagResourceInput{Resource: &arn, Tags: map[string]string{"temporary": "remove"}})
	must(err)
	_, err = client.UntagResource(ctx, &lambda.UntagResourceInput{Resource: &arn, TagKeys: []string{"temporary"}})
	must(err)
	tags, err := client.ListTags(ctx, &lambda.ListTagsInput{Resource: &arn})
	must(err)
	require(tags.Tags["owner"] == name && tags.Tags["temporary"] == "", "tag roundtrip differs")
	_, err = users.CreateUser(ctx, &iam.CreateUserInput{UserName: &name})
	must(err)
	defer func() {
		_, err := users.DeleteUser(context.Background(), &iam.DeleteUserInput{UserName: &name})
		must(err)
	}()
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":"*"},{"Effect":"Deny","Action":"lambda:GetCodeSigningConfig","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/owner":"` + name + `"}}},{"Effect":"Deny","Action":"lambda:CreateFunction","Resource":"*","Condition":{"StringEquals":{"lambda:CodeSigningConfigArn":"` + configs[1] + `"}}}]}`
	_, err = users.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: &name, PolicyName: aws.String("scope"), PolicyDocument: &policy})
	must(err)
	defer func() {
		_, err := users.DeleteUserPolicy(context.Background(), &iam.DeleteUserPolicyInput{UserName: &name, PolicyName: aws.String("scope")})
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
	_, err = limited.GetCodeSigningConfig(ctx, &lambda.GetCodeSigningConfigInput{CodeSigningConfigArn: &arn})
	denied(err)
	_, err = client.GetCodeSigningConfig(ctx, &lambda.GetCodeSigningConfigInput{CodeSigningConfigArn: &arn})
	must(err)
	var code bytes.Buffer
	archive := zip.NewWriter(&code)
	handler, err := archive.Create("lambda_function.py")
	must(err)
	_, err = handler.Write([]byte("def handler(event, context):\n return {'signed': False}\n"))
	must(err)
	must(archive.Close())
	// Denial must precede unsigned-code rejection, including its metric effect.
	_, err = limited.CreateFunction(ctx, &lambda.CreateFunctionInput{
		FunctionName: &name, Runtime: types.RuntimePython312, Handler: aws.String("lambda_function.handler"),
		Role: aws.String("arn:aws:iam::" + aws.ToString(who.Account) + ":role/unused-denied-role"),
		Code: &types.FunctionCode{ZipFile: code.Bytes()}, CodeSigningConfigArn: &configs[1],
	})
	denied(err)
	out, _ := json.Marshal(map[string]any{"sdk": "aws-sdk-go-v2", "signed": true, "create_update_get_delete": true, "pagination": true, "tags": true, "invalid_marker": "InvalidParameterValueException", "resource_tag_iam_deny": "AccessDeniedException", "code_signing_arn_iam_deny": "AccessDeniedException"})
	fmt.Println(string(out))
}

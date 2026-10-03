package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func authority(ctx context.Context, endpoint string, roles *iam.Client, features []gt.DetectorFeatureConfiguration) {
	name := aws.String("guardduty-smoke-caller")
	_, err := roles.CreateUser(ctx, &iam.CreateUserInput{UserName: name})
	must(err)
	defer func() { _, e := roles.DeleteUser(ctx, &iam.DeleteUserInput{UserName: name}); must(e) }()
	key, err := roles.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: name})
	must(err)
	defer func() {
		_, e := roles.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: name, AccessKeyId: key.AccessKey.AccessKeyId})
		must(e)
	}()
	policy := aws.String("guardduty-access")
	set := func(document string) {
		_, e := roles.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: name, PolicyName: policy, PolicyDocument: &document})
		must(e)
	}
	set(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"guardduty:*","Resource":"*"}]}`)
	defer func() {
		_, e := roles.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{UserName: name, PolicyName: policy})
		must(e)
	}()
	cfg := config("123456789012", "us-east-1")
	cfg.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), "")
	caller := gd.NewFromConfig(cfg, func(o *gd.Options) { o.BaseEndpoint = &endpoint })
	_, err = caller.CreateDetector(ctx, &gd.CreateDetectorInput{Enable: aws.Bool(false), Features: features})
	code(err, "AccessDenied")
	_, err = roles.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String("AWSServiceRoleForAmazonGuardDuty")})
	code(err, "NoSuchEntity")
	root := client(endpoint, "123456789012", "us-east-1")
	empty, err := root.ListDetectors(ctx, &gd.ListDetectorsInput{})
	must(err)
	check(len(empty.DetectorIds) == 0, "denied role creation orphaned a detector")
	set(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"guardduty:*","Resource":"*"},{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"*","Condition":{"StringEquals":{"iam:AWSServiceName":"guardduty.amazonaws.com"}}}]}`)
	created, err := caller.CreateDetector(ctx, &gd.CreateDetectorInput{Enable: aws.Bool(false), Features: features, Tags: map[string]string{"owner": "reader"}})
	must(err)
	set(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"guardduty:GetDetector","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/owner":"reader"}}}]}`)
	_, err = caller.GetDetector(ctx, &gd.GetDetectorInput{DetectorId: created.DetectorId})
	must(err)
	arn := "arn:aws:guardduty:us-east-1:123456789012:detector/" + aws.ToString(created.DetectorId)
	_, err = root.TagResource(ctx, &gd.TagResourceInput{ResourceArn: &arn, Tags: map[string]string{"owner": "revoked"}})
	must(err)
	_, err = caller.GetDetector(ctx, &gd.GetDetectorInput{DetectorId: created.DetectorId})
	code(err, "AccessDenied")
	_, err = root.DeleteDetector(ctx, &gd.DeleteDetectorInput{DetectorId: created.DetectorId})
	must(err)
	// Keep the protected role for the main workflow, proving existing-role reuse.
	fmt.Println("GuardDuty current IAM role admission, rollback/no orphan, and resource-tag revocation: PASS")
}

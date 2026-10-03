package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	st "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	ct "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
)

func s3PublicAccessDetection(ctx context.Context, endpoint string, detectorClient *gd.Client, detector *string) {
	const account = "123456789012"
	bucket := "guardduty-public-access"
	client := s3.NewFromConfig(config(account, "us-east-1"), func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	localURL, err := url.Parse(endpoint)
	must(err)
	control := s3control.NewFromConfig(config(account, "us-east-1"), func(o *s3control.Options) {
		o.EndpointResolverV2 = localS3ControlEndpoint{URI: *localURL}
	})
	_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	must(err)
	findings := func(scope, operation string) []gt.Finding {
		page, err := detectorClient.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector, FindingCriteria: &gt.FindingCriteria{Criterion: map[string]gt.Condition{
			"type":                                {Equals: []string{"Policy:S3/" + scope + "BlockPublicAccessDisabled"}},
			"service.action.awsApiCallAction.api": {Equals: []string{operation + scope + "PublicAccessBlock"}},
		}}})
		must(err)
		if len(page.FindingIds) == 0 {
			return nil
		}
		out, err := detectorClient.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: page.FindingIds})
		must(err)
		return out.Findings
	}
	checkFinding := func(scope, operation, resourceType, resourceName string) {
		got := findings(scope, operation)
		check(len(got) == 1 && aws.ToInt32(got[0].Service.Count) == 1 && got[0].Service.Action.AwsApiCallAction.AffectedResources[resourceType] == resourceName && aws.ToString(got[0].Resource.ResourceType) == "AccessKey", "public access change did not identify actual caller/target: "+scope+operation)
	}
	bucketConfig := &st.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true)}
	_, err = client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{Bucket: &bucket, PublicAccessBlockConfiguration: bucketConfig})
	must(err)
	check(len(findings("Bucket", "Put")) == 0, "fully enabled bucket settings produced finding")
	bucketConfig.BlockPublicPolicy = aws.Bool(false)
	_, err = client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{Bucket: &bucket, ExpectedBucketOwner: aws.String("222222222222"), PublicAccessBlockConfiguration: bucketConfig})
	code(err, "AccessDenied")
	_, err = client.DeletePublicAccessBlock(ctx, &s3.DeletePublicAccessBlockInput{Bucket: &bucket, ExpectedBucketOwner: aws.String("222222222222")})
	code(err, "AccessDenied")
	check(len(findings("Bucket", "Put")) == 0 && len(findings("Bucket", "Delete")) == 0, "denied bucket changes produced findings")
	_, err = client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{Bucket: &bucket, PublicAccessBlockConfiguration: bucketConfig})
	must(err)
	bucketState, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &bucket})
	must(err)
	check(!aws.ToBool(bucketState.PublicAccessBlockConfiguration.BlockPublicPolicy) && aws.ToBool(bucketState.PublicAccessBlockConfiguration.BlockPublicAcls), "bucket setting change was not retained")
	checkFinding("Bucket", "Put", "AWS::S3::Bucket", bucket)
	_, err = client.DeletePublicAccessBlock(ctx, &s3.DeletePublicAccessBlockInput{Bucket: &bucket})
	must(err)
	checkFinding("Bucket", "Delete", "AWS::S3::Bucket", bucket)
	_, err = client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: &bucket})
	code(err, "NoSuchPublicAccessBlockConfiguration")
	accountConfig := &ct.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), BlockPublicPolicy: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true)}
	_, err = control.PutPublicAccessBlock(ctx, &s3control.PutPublicAccessBlockInput{AccountId: aws.String(account), PublicAccessBlockConfiguration: accountConfig})
	must(err)
	check(len(findings("Account", "Put")) == 0, "fully enabled account settings produced finding")
	accountConfig.RestrictPublicBuckets = aws.Bool(false)
	_, err = control.PutPublicAccessBlock(ctx, &s3control.PutPublicAccessBlockInput{AccountId: aws.String("222222222222"), PublicAccessBlockConfiguration: accountConfig})
	code(err, "AccessDenied")
	_, err = control.DeletePublicAccessBlock(ctx, &s3control.DeletePublicAccessBlockInput{AccountId: aws.String("222222222222")})
	code(err, "AccessDenied")
	check(len(findings("Account", "Put")) == 0 && len(findings("Account", "Delete")) == 0, "denied account changes produced findings")
	_, err = control.PutPublicAccessBlock(ctx, &s3control.PutPublicAccessBlockInput{AccountId: aws.String(account), PublicAccessBlockConfiguration: accountConfig})
	must(err)
	accountState, err := control.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{AccountId: aws.String(account)})
	must(err)
	check(!aws.ToBool(accountState.PublicAccessBlockConfiguration.RestrictPublicBuckets) && aws.ToBool(accountState.PublicAccessBlockConfiguration.BlockPublicPolicy), "account setting change was not retained")
	checkFinding("Account", "Put", "AWS::Account", account)
	_, err = control.PutPublicAccessBlock(ctx, &s3control.PutPublicAccessBlockInput{AccountId: aws.String(account), PublicAccessBlockConfiguration: &ct.PublicAccessBlockConfiguration{}})
	must(err)
	accountState, err = control.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{AccountId: aws.String(account)})
	must(err)
	check(!aws.ToBool(accountState.PublicAccessBlockConfiguration.BlockPublicAcls) && !aws.ToBool(accountState.PublicAccessBlockConfiguration.IgnorePublicAcls) && !aws.ToBool(accountState.PublicAccessBlockConfiguration.BlockPublicPolicy) && !aws.ToBool(accountState.PublicAccessBlockConfiguration.RestrictPublicBuckets), "omitted account settings did not reset")
	resetFindings := findings("Account", "Put")
	check(len(resetFindings) == 1 && aws.ToInt32(resetFindings[0].Service.Count) == 2, "empty account configuration was not detected and aggregated")
	_, err = control.DeletePublicAccessBlock(ctx, &s3control.DeletePublicAccessBlockInput{AccountId: aws.String(account)})
	must(err)
	checkFinding("Account", "Delete", "AWS::Account", account)
	_, err = control.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{AccountId: aws.String(account)})
	code(err, "NoSuchPublicAccessBlockConfiguration")
	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &bucket})
	must(err)
	fmt.Println("GuardDuty S3 bucket/account public access: enabled and denied changes excluded; successful partial disable and delete identify actual targets: PASS")
}

// S3 Control's default resolver prefixes the account onto the host. The smoke
// uses an IP listener; keep the target account in the signed request header.
type localS3ControlEndpoint struct {
	URI url.URL
}

func (e localS3ControlEndpoint) ResolveEndpoint(context.Context, s3control.EndpointParameters) (smithyendpoints.Endpoint, error) {
	return smithyendpoints.Endpoint{URI: e.URI}, nil
}

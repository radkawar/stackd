package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	st "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func s3LoggingDetection(ctx context.Context, endpoint string, detectorClient *gd.Client, detector *string) {
	client := s3.NewFromConfig(config("123456789012", "us-east-1"), func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	source, destination := "guardduty-access-log-source", "guardduty-access-log-destination"
	for _, name := range []string{source, destination} {
		_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &name})
		must(err)
	}
	findings := func() []gt.Finding {
		page, err := detectorClient.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector, FindingCriteria: &gt.FindingCriteria{Criterion: map[string]gt.Condition{
			"type":                                {Equals: []string{"Stealth:S3/ServerAccessLoggingDisabled"}},
			"service.action.awsApiCallAction.api": {Equals: []string{"PutBucketLogging"}},
		}}})
		must(err)
		if len(page.FindingIds) == 0 {
			return nil
		}
		out, err := detectorClient.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: page.FindingIds})
		must(err)
		return out.Findings
	}
	_, err := client.PutBucketLogging(ctx, &s3.PutBucketLoggingInput{Bucket: &source, BucketLoggingStatus: &st.BucketLoggingStatus{LoggingEnabled: &st.LoggingEnabled{TargetBucket: &destination, TargetPrefix: aws.String("access/")}}})
	must(err)
	enabled, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &source})
	must(err)
	check(enabled.LoggingEnabled != nil && aws.ToString(enabled.LoggingEnabled.TargetBucket) == destination, "logging enable did not persist")
	check(len(findings()) == 0, "enabling access logging produced disabled finding")
	_, err = client.PutBucketLogging(ctx, &s3.PutBucketLoggingInput{Bucket: &source, ExpectedBucketOwner: aws.String("222222222222"), BucketLoggingStatus: &st.BucketLoggingStatus{}})
	code(err, "AccessDenied")
	check(len(findings()) == 0, "rejected logging disable produced finding")
	_, err = client.PutBucketLogging(ctx, &s3.PutBucketLoggingInput{Bucket: &source, BucketLoggingStatus: &st.BucketLoggingStatus{}})
	must(err)
	disabled, err := client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: &source})
	must(err)
	check(disabled.LoggingEnabled == nil, "logging disable did not persist")
	got := findings()
	check(len(got) == 1 && got[0].Service.Action.AwsApiCallAction.AffectedResources["AWS::S3::Bucket"] == source && aws.ToString(got[0].Resource.ResourceType) == "AccessKey" && aws.ToInt32(got[0].Service.Count) == 1, "successful access logging disable did not identify actual bucket/caller")
	for _, name := range []string{source, destination} {
		pages := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{Bucket: &name})
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			must(err)
			for _, object := range page.Contents {
				_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &name, Key: object.Key})
				must(err)
			}
		}
		_, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &name})
		must(err)
	}
	fmt.Println("GuardDuty S3 access logging: enable and denied disable excluded; successful disable identifies actual bucket: PASS")
}

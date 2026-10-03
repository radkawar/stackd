package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gt "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func detections(ctx context.Context, endpoint string, c *gd.Client, roles *iam.Client, detector *string) func() {
	const rootType = "Policy:IAMUser/RootCredentialUsage"
	const loggingType = "Stealth:IAMUser/CloudTrailLoggingDisabled"
	verifyEvent, cleanupEvents := findingEvents(ctx, endpoint, rootType, "ListUsers")
	defer cleanupEvents()
	_, err := c.UpdateDetector(ctx, &gd.UpdateDetectorInput{DetectorId: detector, Enable: aws.Bool(true)})
	must(err)
	lookup := func(kind, action string) []gt.Finding {
		page, e := c.ListFindings(ctx, &gd.ListFindingsInput{DetectorId: detector, FindingCriteria: &gt.FindingCriteria{Criterion: map[string]gt.Condition{
			"type": {Equals: []string{kind}}, "service.action.awsApiCallAction.api": {Equals: []string{action}},
		}}})
		must(e)
		if len(page.FindingIds) == 0 {
			return nil
		}
		out, e := c.GetFindings(ctx, &gd.GetFindingsInput{DetectorId: detector, FindingIds: page.FindingIds})
		must(e)
		return out.Findings
	}
	_, err = roles.ListUsers(ctx, &iam.ListUsersInput{})
	must(err)
	verifyEvent()
	first := lookup(rootType, "ListUsers")
	check(len(first) == 1 && aws.ToInt32(first[0].Service.Count) == 1, "actual root call did not create one finding")
	check(aws.ToString(first[0].Resource.AccessKeyDetails.UserType) == "Root", "observed caller is not root")
	check(aws.ToString(first[0].Service.Action.AwsApiCallAction.ServiceName) == "iam.amazonaws.com", "observed API source lost")
	findingID := aws.ToString(first[0].Id)
	_, err = roles.ListUsers(ctx, &iam.ListUsersInput{})
	must(err)
	check(aws.ToInt32(lookup(rootType, "ListUsers")[0].Service.Count) == 2, "repeated activity did not aggregate")
	sessions := sts.NewFromConfig(config("123456789012", "us-east-1"), func(o *sts.Options) { o.BaseEndpoint = &endpoint })
	session, err := sessions.GetSessionToken(ctx, &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	must(err)
	temporaryConfig := config("123456789012", "us-east-1")
	temporaryConfig.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
	temporaryRoot := iam.NewFromConfig(temporaryConfig, func(o *iam.Options) { o.BaseEndpoint = &endpoint })
	_, err = temporaryRoot.ListUsers(ctx, &iam.ListUsersInput{})
	// Non-MFA GetSessionToken credentials cannot call IAM; the denied root
	// request must still be detected with its actual outcome.
	code(err, "AccessDenied")
	shortRoot := lookup("Policy:IAMUser/ShortTermRootCredentialUsage", "ListUsers")
	check(len(shortRoot) == 1 && aws.ToString(shortRoot[0].Resource.AccessKeyDetails.AccessKeyId) == aws.ToString(session.Credentials.AccessKeyId), "temporary root session was not detected separately")
	check(aws.ToString(shortRoot[0].Service.Action.AwsApiCallAction.ErrorCode) == "AccessDenied", "temporary root denial was lost")
	check(aws.ToInt32(lookup(rootType, "ListUsers")[0].Service.Count) == 2, "temporary root session was counted as a long-term root credential")

	trail := cloudtrail.NewFromConfig(config("123456789012", "us-east-1"), func(o *cloudtrail.Options) { o.BaseEndpoint = &endpoint })
	_, err = trail.StopLogging(ctx, &cloudtrail.StopLoggingInput{Name: aws.String("missing-detection-trail")})
	code(err, "TrailNotFoundException")
	check(len(lookup(loggingType, "StopLogging")) == 0, "failed stop generated a logging-disabled finding")
	bucket := s3.NewFromConfig(config("123456789012", "us-east-1"), func(o *s3.Options) { o.BaseEndpoint = &endpoint; o.UsePathStyle = true })
	name := "guardduty-detection-trail"
	_, err = bucket.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &name})
	must(err)
	trailARN := "arn:aws:cloudtrail:us-east-1:123456789012:trail/" + name
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%s","Condition":{"StringEquals":{"aws:SourceArn":%q}}},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/AWSLogs/123456789012/*","Condition":{"StringEquals":{"aws:SourceArn":%q,"s3:x-amz-acl":"bucket-owner-full-control"}}}]}`, name, trailARN, name, trailARN)
	_, err = bucket.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: &name, Policy: &policy})
	must(err)
	_, err = trail.CreateTrail(ctx, &cloudtrail.CreateTrailInput{Name: &name, S3BucketName: &name})
	must(err)
	_, err = trail.StopLogging(ctx, &cloudtrail.StopLoggingInput{Name: &name})
	must(err)
	stopped := lookup(loggingType, "StopLogging")
	check(len(stopped) == 1 && stopped[0].Service.Action.AwsApiCallAction.AffectedResources["AWS::CloudTrail::Trail"] == name, "successful named stop did not produce its actual trail")
	_, err = trail.UpdateTrail(ctx, &cloudtrail.UpdateTrailInput{Name: &name, IncludeGlobalServiceEvents: aws.Bool(false)})
	must(err)
	check(len(lookup(loggingType, "UpdateTrail")) == 1, "successful trail update was not detected")
	// CloudTrail destination validation can leave owned check objects.
	objects := s3.NewListObjectsV2Paginator(bucket, &s3.ListObjectsV2Input{Bucket: &name})
	for objects.HasMorePages() {
		page, err := objects.NextPage(ctx)
		must(err)
		for _, object := range page.Contents {
			_, err = bucket.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &name, Key: object.Key})
			must(err)
		}
	}
	_, err = bucket.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: &name})
	must(err)
	deleted := lookup(loggingType, "DeleteBucket")
	check(len(deleted) == 1 && deleted[0].Service.Action.AwsApiCallAction.AffectedResources["AWS::S3::Bucket"] == name, "associated trail bucket deletion was not detected")
	_, err = trail.DeleteTrail(ctx, &cloudtrail.DeleteTrailInput{Name: &name})
	must(err)
	check(len(lookup(loggingType, "DeleteTrail")) == 1, "successful trail deletion was not detected")
	s3LoggingDetection(ctx, endpoint, c, detector)
	s3PublicAccessDetection(ctx, endpoint, c, detector)
	verifyS3Grants := s3GrantDetection(ctx, endpoint, c, detector)
	verifyS3PolicyGrants := s3PolicyGrantDetection(ctx, endpoint, c, roles, detector)
	passwordPolicyDetection(ctx, c, roles, temporaryRoot, detector)
	verifyS3Data := s3DataDetection(ctx, endpoint, c, detector)
	_, err = c.UpdateDetector(ctx, &gd.UpdateDetectorInput{DetectorId: detector, Enable: aws.Bool(false)})
	must(err)
	_, err = roles.ListUsers(ctx, &iam.ListUsersInput{})
	must(err)
	check(aws.ToInt32(lookup(rootType, "ListUsers")[0].Service.Count) == 2, "disabled detector consumed activity")
	fmt.Println("GuardDuty structured root/trail/bucket rules, real EventBridge delivery, aggregation and disabled-source gate: PASS")
	return func() {
		before := lookup(rootType, "ListUsers")
		check(len(before) == 1 && aws.ToString(before[0].Id) == findingID && aws.ToInt32(before[0].Service.Count) == 2, "restart lost or replayed observation")
		_, err := c.UpdateDetector(ctx, &gd.UpdateDetectorInput{DetectorId: detector, Enable: aws.Bool(true)})
		must(err)
		_, err = roles.ListUsers(ctx, &iam.ListUsersInput{})
		must(err)
		after := lookup(rootType, "ListUsers")
		check(len(after) == 1 && aws.ToString(after[0].Id) == findingID && aws.ToInt32(after[0].Service.Count) == 3, "restart lost aggregate identity or replayed disabled events")
		fmt.Println("GuardDuty observed finding identity/count and detector source gate survive SQLite restart: PASS")
		verifyS3Data()
		verifyS3Grants()
		verifyS3PolicyGrants()
	}
}

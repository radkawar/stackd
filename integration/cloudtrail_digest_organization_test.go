package stackd_test

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"stackd"
	"stackd/clock"
)

func TestCloudTrailDigestOrganizationAccountsAndEncryption(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			ctx := t.Context()
			orgs := c.organizations(eventDeliveryAccount, "test")
			org, err := orgs.CreateOrganization(ctx, &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll})
			if err != nil {
				t.Fatal(err)
			}
			roots, err := orgs.ListRoots(ctx, &organizations.ListRootsInput{})
			if err != nil {
				t.Fatal(err)
			}
			fixture := organizationReportFixture{cloud: c, clock: source, org: orgs, rootID: aws.ToString(roots.Roots[0].Id)}
			member := fixture.account(t, fixture.rootID, "digest-member")
			if _, err := orgs.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			const name, bucket = "digest-organization", "digest-organization-bucket"
			arn := "arn:aws:cloudtrail:us-east-1:" + eventDeliveryAccount + ":trail/" + name
			objects := s3NativeClient(c, eventDeliveryAccount, "test")
			if _, err := objects.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
				t.Fatal(err)
			}
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%s","Condition":{"StringEquals":{"aws:SourceArn":"%s"}}},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/AWSLogs/%s/*","Condition":{"StringEquals":{"aws:SourceArn":"%s","s3:x-amz-acl":"bucket-owner-full-control"}}}]}`, bucket, arn, bucket, aws.ToString(org.Organization.Id), arn)
			if _, err := objects.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: &policy}); err != nil {
				t.Fatal(err)
			}
			keyPolicy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":["kms:GenerateDataKey*","kms:DescribeKey"],"Resource":"*","Condition":{"StringEquals":{"aws:SourceArn":"%s"}}}]}`, eventDeliveryAccount, arn)
			key, err := c.kms(eventDeliveryAccount, "test", "").CreateKey(ctx, &kms.CreateKeyInput{Policy: &keyPolicy})
			if err != nil {
				t.Fatal(err)
			}
			trails := trailNativeClient(c)
			_, err = trails.CreateTrail(ctx, &cloudtrail.CreateTrailInput{Name: aws.String(name), S3BucketName: aws.String(bucket), KmsKeyId: key.KeyMetadata.Arn, IsOrganizationTrail: aws.Bool(true), IsMultiRegionTrail: aws.Bool(true), EnableLogFileValidation: aws.Bool(true), RecursiveLogging: aws.Bool(false)})
			if err != nil {
				t.Fatal(err)
			}
			// No matching records: member and owner must still receive separate empty digests.
			_, err = trails.PutEventSelectors(ctx, &cloudtrail.PutEventSelectorsInput{TrailName: aws.String(name), AdvancedEventSelectors: []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Data"}}, {Field: aws.String("resources.type"), Equals: []string{"AWS::S3::Object"}}, {Field: aws.String("resources.ARN"), StartsWith: []string{"arn:aws:s3:::never-matches/"}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := trails.StartLogging(ctx, &cloudtrail.StartLoggingInput{Name: aws.String(name)}); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			for _, account := range []string{eventDeliveryAccount, member} {
				for _, region := range []string{"us-east-1", "eu-west-1"} {
					prefix := "AWSLogs/" + aws.ToString(org.Organization.Id) + "/" + account + "/CloudTrail-Digest/" + region + "/"
					files := digestObjects(t, c, bucket, prefix)
					if len(files) != 2 {
						t.Fatalf("empty account chain %s: %v", account, files)
					}
					doc, _, _ := verifyTrailDigest(t, c, bucket, files[0], region)
					if !strings.Contains(doc.Object, "_CloudTrail-Digest_"+region+"_"+name+"_us-east-1_") {
						t.Fatalf("source/home region filename: %s", doc.Object)
					}
					if doc.Account != account || len(doc.Logs) != 0 || doc.PreviousObject != nil {
						t.Fatalf("account chain isolation: %+v", doc)
					}
					next, _, _ := verifyTrailDigest(t, c, bucket, files[1], region)
					if next.Account != account || len(next.Logs) != 0 || aws.ToString(next.PreviousObject) != files[0] {
						t.Fatalf("regional hourly chain crossed an account or region: %+v", next)
					}
					head, err := s3NativeClient(c, eventDeliveryAccount, "test").HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: &files[0]})
					if err != nil || head.ServerSideEncryption != "aws:kms" || aws.ToString(head.SSEKMSKeyId) != aws.ToString(key.KeyMetadata.Arn) {
						t.Fatalf("digest bypassed actual KMS destination: %+v %v", head, err)
					}
				}
			}
			// An owner-only policy failure must not contaminate member status.
			ownerPrefix := "AWSLogs/" + aws.ToString(org.Organization.Id) + "/" + eventDeliveryAccount + "/CloudTrail-Digest/us-east-1/"
			denied := strings.TrimSuffix(policy, "]}") + fmt.Sprintf(`,{"Effect":"Deny","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/%s*"}]}`, bucket, ownerPrefix)
			if _, err := s3NativeClient(c, eventDeliveryAccount, "test").PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: &denied}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			ownerStatus, err := trailNativeClient(c).GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: &arn})
			if err != nil || aws.ToString(ownerStatus.LatestDigestDeliveryError) == "" {
				t.Fatalf("owner failure not surfaced: %+v %v", ownerStatus, err)
			}
			memberStatus, err := organizationTrailClient(c, member, "us-east-1").GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: &arn})
			if err != nil || memberStatus.LatestDigestDeliveryTime == nil || aws.ToString(memberStatus.LatestDigestDeliveryError) != "" {
				t.Fatalf("member inherited owner failure: %+v %v", memberStatus, err)
			}
			regionalStatus, err := organizationTrailClient(c, eventDeliveryAccount, "eu-west-1").GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: &arn})
			if err != nil || regionalStatus.LatestDigestDeliveryTime == nil || aws.ToString(regionalStatus.LatestDigestDeliveryError) != "" {
				t.Fatalf("region inherited home-region failure: %+v %v", regionalStatus, err)
			}
		})
	}
}

package stackd_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

// This scenario exercises primary-document region/conversion boundaries, not
// native delivery timing. The local manual clock makes retained batches finite.
func TestCloudTrailOrganizationRegionAndConversionBoundaries(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source})
			ctx := t.Context()
			f := organizationFixture(t, c, source)
			member := f.account(t, f.rootID, "scope-member")
			if _, err := f.org.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			buckets := s3NativeClient(c, eventDeliveryAccount, "test")
			const bucket, name = "organization-scope-logs", "organization-scope"
			if _, err := buckets.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
				t.Fatal(err)
			}
			policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%s"},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/*"}]}`, bucket, bucket)
			if _, err := buckets.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: &policy}); err != nil {
				t.Fatal(err)
			}
			owner := organizationTrailClient(c, eventDeliveryAccount, "us-east-1")
			trail, err := owner.CreateTrail(ctx, &cloudtrail.CreateTrailInput{Name: aws.String(name), S3BucketName: aws.String(bucket), S3KeyPrefix: aws.String("single"), IncludeGlobalServiceEvents: aws.Bool(false), RecursiveLogging: aws.Bool(false)})
			if err != nil {
				t.Fatal(err)
			}
			arn := trail.TrailARN
			_, err = organizationTrailClient(c, member, "us-east-1").GetTrail(ctx, &cloudtrail.GetTrailInput{Name: arn})
			assertAPIError(t, err, "TrailNotFoundException")
			changed, err := owner.UpdateTrail(ctx, &cloudtrail.UpdateTrailInput{Name: arn, IsOrganizationTrail: aws.Bool(true)})
			if err != nil || !aws.ToBool(changed.IsOrganizationTrail) {
				t.Fatalf("management conversion failed: %+v %v", changed, err)
			}
			selection := []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}}}
			if _, err = owner.PutEventSelectors(ctx, &cloudtrail.PutEventSelectorsInput{TrailName: arn, AdvancedEventSelectors: selection}); err != nil {
				t.Fatal(err)
			}
			if _, err = owner.StartLogging(ctx, &cloudtrail.StartLoggingInput{Name: arn}); err != nil {
				t.Fatal(err)
			}
			createQueue := func(region, name string) string {
				client := sqs.New(sqs.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(member, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				out, err := client.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: &name})
				if err != nil {
					t.Fatal(err)
				}
				return nativeAuditRequestID(t, out, nil)
			}
			createRole := func(name string) string {
				out, err := c.iam(member, "test", "").CreateRole(ctx, &iam.CreateRoleInput{RoleName: &name, AssumeRolePolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
				if err != nil {
					t.Fatal(err)
				}
				return nativeAuditRequestID(t, out, nil)
			}
			accepted := []string{createQueue("us-east-1", "single-home-event")}
			rejected := []string{createQueue("eu-west-1", "single-foreign-region"), createRole("global-suppressed")}
			_, err = organizationTrailClient(c, member, "eu-west-1").GetTrail(ctx, &cloudtrail.GetTrailInput{Name: arn})
			assertAPIError(t, err, "TrailNotFoundException")
			_, err = organizationTrailClient(c, eventDeliveryAccount, "eu-west-1").StopLogging(ctx, &cloudtrail.StopLoggingInput{Name: arn})
			assertAPIError(t, err, "InvalidHomeRegionException")
			if _, err = owner.UpdateTrail(ctx, &cloudtrail.UpdateTrailInput{Name: arn, IncludeGlobalServiceEvents: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			accepted = append(accepted, createRole("global-included"))
			// Opt-in home Region gates all regions of a multi-region org trail.
			if _, err = c.account(eventDeliveryAccount, "test", "").EnableRegion(ctx, &account.EnableRegionInput{RegionName: aws.String("af-south-1")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 2*time.Minute)
			optOwner := organizationTrailClient(c, eventDeliveryAccount, "af-south-1")
			opt, err := optOwner.CreateTrail(ctx, &cloudtrail.CreateTrailInput{Name: aws.String("organization-opt-in"), S3BucketName: aws.String(bucket), S3KeyPrefix: aws.String("opt-in"), IsOrganizationTrail: aws.Bool(true), IsMultiRegionTrail: aws.Bool(true), RecursiveLogging: aws.Bool(false)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = optOwner.PutEventSelectors(ctx, &cloudtrail.PutEventSelectorsInput{TrailName: opt.TrailARN, AdvancedEventSelectors: selection}); err != nil {
				t.Fatal(err)
			}
			if _, err = optOwner.StartLogging(ctx, &cloudtrail.StartLoggingInput{Name: opt.TrailARN}); err != nil {
				t.Fatal(err)
			}
			beforeOptIn := createQueue("us-east-1", "before-member-home-opt-in")
			_, err = organizationTrailClient(c, member, "us-east-1").GetTrail(ctx, &cloudtrail.GetTrailInput{Name: opt.TrailARN})
			assertAPIError(t, err, "TrailNotFoundException")
			if _, err = c.account(member, "test", "").EnableRegion(ctx, &account.EnableRegionInput{RegionName: aws.String("af-south-1")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 2*time.Minute)
			afterOptIn := createQueue("us-east-1", "after-member-home-opt-in")
			if _, err = organizationTrailClient(c, member, "us-east-1").GetTrail(ctx, &cloudtrail.GetTrailInput{Name: opt.TrailARN}); err != nil {
				t.Fatal(err)
			}
			// Scope conversion seals old organization batches instead of mixing
			// pre-conversion org hierarchy and later account-level records.
			if _, err = owner.UpdateTrail(ctx, &cloudtrail.UpdateTrailInput{Name: arn, IsOrganizationTrail: aws.Bool(false)}); err != nil {
				t.Fatal(err)
			}
			rejected = append(rejected, createQueue("us-east-1", "after-account-conversion"))
			c = reopen()
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			buckets = s3NativeClient(c, eventDeliveryAccount, "test")
			requests := func(prefix string) map[string]bool {
				out := map[string]bool{}
				for _, record := range trailNativeRecords(t, trailNativeObjects(t, buckets, bucket, prefix)) {
					if id, ok := record["requestID"].(string); ok {
						out[id] = true
					}
				}
				return out
			}
			single := requests("single/AWSLogs/")
			for _, id := range accepted {
				if !single[id] {
					t.Fatalf("lost selected home/global event %s", id)
				}
			}
			for _, id := range rejected {
				if single[id] {
					t.Fatalf("admitted excluded region/global/account event %s", id)
				}
			}
			optIn := requests("opt-in/AWSLogs/")
			if optIn[beforeOptIn] || !optIn[afterOptIn] {
				t.Fatalf("home region opt-in did not control aggregation: %+v", optIn)
			}
			if _, err = organizationTrailClient(c, eventDeliveryAccount, "af-south-1").DeleteTrail(ctx, &cloudtrail.DeleteTrailInput{Name: opt.TrailARN}); err != nil {
				t.Fatal(err)
			}
			_, err = organizationTrailClient(c, member, "us-east-1").GetTrail(ctx, &cloudtrail.GetTrailInput{Name: opt.TrailARN})
			assertAPIError(t, err, "TrailNotFoundException")
		})
	}
}

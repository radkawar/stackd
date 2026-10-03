package stackd_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
)

func organizationTrailClient(c cloudClients, account, region string) *cloudtrail.Client {
	return cloudtrail.New(cloudtrail.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

// Successful organization behavior here is derived from the AWS organization
// trail/delegated-administrator contracts, not claimed as a native capture.
// organization_admission.json separately records safe missing-bucket admission.
func TestCloudTrailOrganizationMembershipDeliveryAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			ctx := t.Context()
			orgs := c.organizations(eventDeliveryAccount, "test")
			createdOrg, err := orgs.CreateOrganization(ctx, &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll})
			if err != nil {
				t.Fatal(err)
			}
			orgID := aws.ToString(createdOrg.Organization.Id)
			roots, err := orgs.ListRoots(ctx, &organizations.ListRootsInput{})
			if err != nil {
				t.Fatal(err)
			}
			f := organizationReportFixture{cloud: c, clock: source, org: orgs, rootID: aws.ToString(roots.Roots[0].Id)}
			member := f.account(t, f.rootID, "trail-member")
			delegate := f.account(t, f.rootID, "trail-delegate")
			owner := organizationTrailClient(c, eventDeliveryAccount, "us-east-1")
			const name, bucket, group, roleName = "organization-owned", "organization-trail-logs", "/organization/cloudtrail", "organization-trail-logs"
			arn := "arn:aws:cloudtrail:us-east-1:" + eventDeliveryAccount + ":trail/" + name
			input := &cloudtrail.CreateTrailInput{Name: aws.String(name), S3BucketName: aws.String(bucket), IsOrganizationTrail: aws.Bool(true), IsMultiRegionTrail: aws.Bool(true), RecursiveLogging: aws.Bool(false)}
			_, err = owner.CreateTrail(ctx, input)
			assertAPIError(t, err, "CloudTrailAccessNotEnabledException")
			if _, err = orgs.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			// Native missing-bucket admission reaches S3 without committing a trail.
			_, err = owner.CreateTrail(ctx, input)
			assertAPIError(t, err, "S3BucketDoesNotExistException")
			_, err = owner.GetTrail(ctx, &cloudtrail.GetTrailInput{Name: &arn})
			assertAPIError(t, err, "TrailNotFoundException")
			if _, err = orgs.RegisterDelegatedAdministrator(ctx, &organizations.RegisterDelegatedAdministratorInput{AccountId: &delegate, ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			if _, err = c.iam(eventDeliveryAccount, "test", "").CreateServiceLinkedRole(ctx, &iam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("cloudtrail.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			buckets := s3NativeClient(c, eventDeliveryAccount, "test")
			if _, err = buckets.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
				t.Fatal(err)
			}
			bucketPolicy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%s","Condition":{"StringEquals":{"aws:SourceArn":"%s"}}},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/AWSLogs/%s/*","Condition":{"StringEquals":{"aws:SourceArn":"%s","s3:x-amz-acl":"bucket-owner-full-control"}}}]}`, bucket, arn, bucket, orgID, arn)
			if _, err = buckets.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: &bucketPolicy}); err != nil {
				t.Fatal(err)
			}
			keys := c.kms(eventDeliveryAccount, "test", "")
			keyPolicy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":["kms:GenerateDataKey*","kms:DescribeKey"],"Resource":"*","Condition":{"StringEquals":{"aws:SourceArn":"%s"}}}]}`, eventDeliveryAccount, arn)
			key, err := keys.CreateKey(ctx, &kms.CreateKeyInput{Policy: &keyPolicy})
			if err != nil {
				t.Fatal(err)
			}
			input.KmsKeyId = key.KeyMetadata.Arn
			// Delegated administrator destinations remain in the caller account,
			// while the trail and KMS source ARN belong to management.
			logs := logsClient(c, delegate)
			if _, err = logs.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{LogGroupName: aws.String(group)}); err != nil {
				t.Fatal(err)
			}
			roles := c.iam(delegate, "test", "")
			role, err := roles.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String(roleName), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = roles.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: aws.String(roleName), PolicyName: aws.String("delivery"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}`)}); err != nil {
				t.Fatal(err)
			}
			input.CloudWatchLogsRoleArn = role.Role.Arn
			input.CloudWatchLogsLogGroupArn = aws.String("arn:aws:logs:us-east-1:" + delegate + ":log-group:" + group + ":*")
			topics := sns.New(sns.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			topic, err := topics.CreateTopic(ctx, &sns.CreateTopicInput{Name: aws.String("organization-log-notifications")})
			if err != nil {
				t.Fatal(err)
			}
			topicPolicy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sns:Publish","Resource":"%s","Condition":{"StringEquals":{"aws:SourceArn":"%s"}}}]}`, aws.ToString(topic.TopicArn), arn)
			if _, err = topics.SetTopicAttributes(ctx, &sns.SetTopicAttributesInput{TopicArn: topic.TopicArn, AttributeName: aws.String("Policy"), AttributeValue: &topicPolicy}); err != nil {
				t.Fatal(err)
			}
			queues := c.sqs(eventDeliveryAccount, "test", "")
			notifications, err := queues.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("organization-notifications")})
			if err != nil {
				t.Fatal(err)
			}
			queueARN := "arn:aws:sqs:us-east-1:" + eventDeliveryAccount + ":organization-notifications"
			queuePolicy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"%s","Condition":{"ArnEquals":{"aws:SourceArn":"%s"}}}]}`, queueARN, aws.ToString(topic.TopicArn))
			if _, err = queues.SetQueueAttributes(ctx, &sqs.SetQueueAttributesInput{QueueUrl: notifications.QueueUrl, Attributes: map[string]string{"Policy": queuePolicy}}); err != nil {
				t.Fatal(err)
			}
			if _, err = topics.Subscribe(ctx, &sns.SubscribeInput{TopicArn: topic.TopicArn, Protocol: aws.String("sqs"), Endpoint: &queueARN}); err != nil {
				t.Fatal(err)
			}
			input.SnsTopicName = topic.TopicArn
			admin := organizationTrailClient(c, delegate, "us-east-1")
			trail, err := admin.CreateTrail(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(trail.TrailARN) != arn || !aws.ToBool(trail.IsOrganizationTrail) {
				t.Fatalf("delegate did not create management-owned organization trail: %+v", trail)
			}
			selectors := []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Management"}}}}}
			if _, err = admin.PutEventSelectors(ctx, &cloudtrail.PutEventSelectorsInput{TrailName: &arn, AdvancedEventSelectors: selectors}); err != nil {
				t.Fatal(err)
			}
			if _, err = admin.StartLogging(ctx, &cloudtrail.StartLoggingInput{Name: &arn}); err != nil {
				t.Fatal(err)
			}
			shadow := organizationTrailClient(c, member, "us-east-1")
			got, err := shadow.GetTrail(ctx, &cloudtrail.GetTrailInput{Name: &arn})
			if err != nil || got == nil || !aws.ToBool(got.Trail.IsOrganizationTrail) {
				t.Fatalf("missing member shadow: %+v %v", got, err)
			}
			_, err = shadow.StopLogging(ctx, &cloudtrail.StopLoggingInput{Name: &arn})
			assertAPIError(t, err, "OperationNotPermittedException")
			_, err = shadow.DeleteTrail(ctx, &cloudtrail.DeleteTrailInput{Name: &arn})
			assertAPIError(t, err, "OperationNotPermittedException")
			_, err = admin.UpdateTrail(ctx, &cloudtrail.UpdateTrailInput{Name: &arn, IsOrganizationTrail: aws.Bool(false)})
			assertAPIError(t, err, "NotOrganizationMasterAccountException")
			withoutShadows, err := shadow.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(false)})
			if err != nil || len(withoutShadows.TrailList) != 0 {
				t.Fatalf("member shadow escaped IncludeShadowTrails: %+v %v", withoutShadows, err)
			}
			accepted := map[string]string{}
			createQueue := func(account, region, queue string) string {
				client := sqs.New(sqs.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				out, err := client.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: &queue})
				if err != nil {
					t.Fatal(err)
				}
				return nativeAuditRequestID(t, out, nil)
			}
			accepted[createQueue(member, "us-east-1", "member-before-leave")] = member
			accepted[createQueue(eventDeliveryAccount, "us-east-1", "management-event")] = eventDeliveryAccount
			accepted[createQueue(member, "eu-west-1", "member-other-region")] = member
			late := f.account(t, f.rootID, "trail-late-member")
			if _, err = c.iam(late, "test", "").GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String("AWSServiceRoleForCloudTrail")}); err != nil {
				t.Fatalf("new member lacks service-owned role: %v", err)
			}
			accepted[createQueue(late, "us-east-1", "joined-event")] = late
			if _, err = orgs.RemoveAccountFromOrganization(ctx, &organizations.RemoveAccountFromOrganizationInput{AccountId: &member}); err != nil {
				t.Fatal(err)
			}
			_, err = c.iam(member, "test", "").GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String("AWSServiceRoleForCloudTrail")})
			assertAPIError(t, err, "NoSuchEntity")
			rejected := []string{createQueue(member, "us-east-1", "departed-event"), createQueue("999999999999", "us-east-1", "outsider-event")}
			_, err = shadow.GetTrail(ctx, &cloudtrail.GetTrailInput{Name: &arn})
			assertAPIError(t, err, "TrailNotFoundException")
			// Block only S3/KMS, preserving independently completed Logs work.
			if _, err = keys.DisableKey(ctx, &kms.DisableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			status, err := owner.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: &arn})
			if err != nil || status.LatestDeliveryTime != nil || aws.ToString(status.LatestDeliveryError) == "" || status.LatestCloudWatchLogsDeliveryTime == nil {
				t.Fatalf("destinations failed to retain independent outcomes: %+v %v", status, err)
			}
			c = reopen()
			keys = c.kms(eventDeliveryAccount, "test", "")
			if _, err = keys.EnableKey(ctx, &kms.EnableKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 2*time.Minute)
			cloud := c.server.Config.Handler.(*stackd.Stack)
			trailNativeDrain(t, cloud)
			buckets = s3NativeClient(c, eventDeliveryAccount, "test")
			listing, err := buckets.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String("AWSLogs/" + orgID + "/")})
			if err != nil {
				t.Fatal(err)
			}
			delivered := map[string]string{}
			objectKeys := map[string]bool{}
			for _, object := range listing.Contents {
				keyName := aws.ToString(object.Key)
				if !strings.HasSuffix(keyName, ".json.gz") {
					continue
				}
				objectKeys[keyName] = true
				body, err := buckets.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: object.Key})
				if err != nil {
					t.Fatal(err)
				}
				data, readErr := io.ReadAll(body.Body)
				body.Body.Close()
				if readErr != nil || body.ServerSideEncryption != "aws:kms" || aws.ToString(body.SSEKMSKeyId) != aws.ToString(key.KeyMetadata.Arn) {
					t.Fatalf("retained organization object lost encryption: %+v %v", body, readErr)
				}
				for _, record := range trailNativeRecords(t, map[string][]byte{keyName: data}) {
					request, _ := record["requestID"].(string)
					account, _ := record["recipientAccountId"].(string)
					if !strings.Contains(keyName, "/"+account+"/CloudTrail/") {
						t.Fatalf("cross-account records mixed in one batch: %s %+v", keyName, record)
					}
					delivered[request] = account
				}
			}
			for id, account := range accepted {
				if delivered[id] != account {
					t.Fatalf("lost member/management event %s after leave/restart: %+v", id, delivered)
				}
			}
			for _, id := range rejected {
				if delivered[id] != "" {
					t.Fatalf("logged departed or foreign account event %s", id)
				}
			}
			logEvents := trailLogsEvents(t, logsClient(c, delegate), group, `{ $.eventName = "CreateQueue" }`)
			for id := range accepted {
				found := false
				for _, event := range logEvents {
					var record map[string]any
					if err := json.Unmarshal([]byte(aws.ToString(event.Message)), &record); err != nil {
						t.Fatal(err)
					}
					if record["requestID"] == id {
						found = true
						if !strings.HasPrefix(aws.ToString(event.LogStreamName), orgID+"_") {
							t.Fatalf("organization Logs stream lost hierarchy: %+v", event)
						}
					}
				}
				if !found {
					t.Fatalf("organization Logs delivery lost %s", id)
				}
			}
			queues = c.sqs(eventDeliveryAccount, "test", "")
			for _, message := range snsAdmissionReceive(t, cloud, queues, notifications.QueueUrl) {
				var envelope struct{ Message string }
				if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &envelope); err != nil {
					t.Fatal(err)
				}
				var notice struct {
					Keys []string `json:"s3ObjectKey"`
				}
				if json.Unmarshal([]byte(envelope.Message), &notice) == nil {
					for _, key := range notice.Keys {
						delete(objectKeys, key)
					}
				}
			}
			if len(objectKeys) != 0 {
				t.Fatalf("missing SNS notifications for delivered organization objects: %+v", objectKeys)
			}
			// Delegation revocation changes authority, not trail ownership/lifetime.
			orgs = c.organizations(eventDeliveryAccount, "test")
			if _, err = orgs.DeregisterDelegatedAdministrator(ctx, &organizations.DeregisterDelegatedAdministratorInput{AccountId: &delegate, ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			_, err = organizationTrailClient(c, delegate, "us-east-1").StopLogging(ctx, &cloudtrail.StopLoggingInput{Name: &arn})
			assertAPIError(t, err, "OperationNotPermittedException")
			if _, err = orgs.DisableAWSServiceAccess(ctx, &organizations.DisableAWSServiceAccessInput{ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			if _, err = orgs.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("cloudtrail.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			got, err = organizationTrailClient(c, eventDeliveryAccount, "us-east-1").GetTrail(ctx, &cloudtrail.GetTrailInput{Name: &arn})
			if err != nil || aws.ToBool(got.Trail.IsOrganizationTrail) {
				t.Fatalf("trust re-enable resurrected organization scope: %+v %v", got, err)
			}
			_, err = organizationTrailClient(c, late, "us-east-1").GetTrail(ctx, &cloudtrail.GetTrailInput{Name: &arn})
			assertAPIError(t, err, "TrailNotFoundException")
		})
	}
}

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
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"stackd"
	"stackd/clock"
)

func cloudFormationStorageJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func cloudFormationStorageS3(c cloudClients) *s3.Client {
	return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), UsePathStyle: true, RetryMaxAttempts: 1})
}

func cloudFormationStorageOutput(t *testing.T, stack cfntypes.Stack, key string) string {
	t.Helper()
	for _, output := range stack.Outputs {
		if aws.ToString(output.OutputKey) == key {
			return aws.ToString(output.OutputValue)
		}
	}
	t.Fatalf("stack output %s is missing", key)
	return ""
}

// The Guard data bucket and FIFO worker queues deploy through the existing S3
// and SQS owners: CORS is readable by S3 clients, the tag-filtered expiry and
// KMS default encryption apply to real objects, and high-throughput FIFO
// deduplication and redrive keep native SQS semantics.
func TestCloudFormationStorageGuardProperties(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			bucket := map[string]any{"BucketName": "cfn-guard-data",
				"CorsConfiguration": map[string]any{"CorsRules": []any{map[string]any{
					"Id": "ui", "AllowedOrigins": []string{"http://localhost:3000"}, "AllowedMethods": []string{"GET", "PUT"},
					"AllowedHeaders": []string{"*"}, "ExposedHeaders": []string{"ETag"}, "MaxAge": 300}}},
				"BucketEncryption": map[string]any{"ServerSideEncryptionConfiguration": []any{map[string]any{
					"ServerSideEncryptionByDefault": map[string]any{"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": map[string]any{"Fn::GetAtt": []string{"Key", "Arn"}}}}}},
				"LifecycleConfiguration": map[string]any{"Rules": []any{map[string]any{
					"Id": "expire-tagged", "Status": "Enabled", "Prefix": "tmp/", "ExpirationInDays": 1,
					"TagFilters": []any{map[string]any{"Key": "expire", "Value": "true"}}}}},
			}
			template := func(bucket map[string]any) string {
				return cloudFormationStorageJSON(t, map[string]any{
					"Resources": map[string]any{
						"Key":  map[string]any{"Type": "AWS::KMS::Key", "Properties": map[string]any{}},
						"Data": map[string]any{"Type": "AWS::S3::Bucket", "Properties": bucket},
						"DeadLetters": map[string]any{"Type": "AWS::SQS::Queue", "Properties": map[string]any{
							"QueueName": "cfn-guard-dlq.fifo", "FifoQueue": true,
							// Registry Json properties also accept JSON text.
							"RedriveAllowPolicy": map[string]any{"Fn::Sub": `{"redrivePermission":"byQueue","sourceQueueArns":["arn:${AWS::Partition}:sqs:${AWS::Region}:${AWS::AccountId}:cfn-guard-work.fifo"]}`},
						}},
						"Work": map[string]any{"Type": "AWS::SQS::Queue", "Properties": map[string]any{
							"QueueName": "cfn-guard-work.fifo", "FifoQueue": true, "ContentBasedDeduplication": true,
							"DeduplicationScope": "messageGroup", "FifoThroughputLimit": "perMessageGroupId",
							"VisibilityTimeout": 120, "MessageRetentionPeriod": 3600,
							"RedrivePolicy": map[string]any{"deadLetterTargetArn": map[string]any{"Fn::GetAtt": []string{"DeadLetters", "Arn"}}, "maxReceiveCount": 1},
						}},
					},
					"Outputs": map[string]any{
						"KeyArn": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Key", "Arn"}}},
						"Work":   map[string]any{"Value": map[string]any{"Ref": "Work"}},
						"Dead":   map[string]any{"Value": map[string]any{"Ref": "DeadLetters"}},
					},
				})
			}
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("guard-storage"), TemplateBody: aws.String(template(bucket))})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			buckets := cloudFormationStorageS3(c)
			cors, err := buckets.GetBucketCors(t.Context(), &s3.GetBucketCorsInput{Bucket: aws.String("cfn-guard-data")})
			if err != nil {
				t.Fatal(err)
			}
			if len(cors.CORSRules) != 1 || aws.ToString(cors.CORSRules[0].ID) != "ui" || aws.ToInt32(cors.CORSRules[0].MaxAgeSeconds) != 300 ||
				strings.Join(cors.CORSRules[0].AllowedMethods, ",") != "GET,PUT" || strings.Join(cors.CORSRules[0].AllowedOrigins, ",") != "http://localhost:3000" ||
				strings.Join(cors.CORSRules[0].ExposeHeaders, ",") != "ETag" || strings.Join(cors.CORSRules[0].AllowedHeaders, ",") != "*" {
				t.Fatalf("CloudFormation CORS was not applied: %+v", cors.CORSRules)
			}
			lifecycle, err := buckets.GetBucketLifecycleConfiguration(t.Context(), &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String("cfn-guard-data")})
			if err != nil {
				t.Fatal(err)
			}
			if len(lifecycle.Rules) != 1 || lifecycle.Rules[0].Filter == nil || lifecycle.Rules[0].Filter.And == nil ||
				aws.ToString(lifecycle.Rules[0].Filter.And.Prefix) != "tmp/" || len(lifecycle.Rules[0].Filter.And.Tags) != 1 ||
				lifecycle.Rules[0].Expiration == nil || aws.ToInt32(lifecycle.Rules[0].Expiration.Days) != 1 {
				t.Fatalf("tag-filtered expiry was not translated to a lifecycle And filter: %+v", lifecycle.Rules)
			}
			for key, tagging := range map[string]string{"tmp/expiring": "expire=true", "tmp/untagged": "", "keep/tagged": "expire=true"} {
				in := &s3.PutObjectInput{Bucket: aws.String("cfn-guard-data"), Key: aws.String(key), Body: strings.NewReader(key)}
				if tagging != "" {
					in.Tagging = aws.String(tagging)
				}
				if _, err := buckets.PutObject(t.Context(), in); err != nil {
					t.Fatal(err)
				}
			}
			head, err := buckets.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: aws.String("cfn-guard-data"), Key: aws.String("tmp/untagged")})
			if err != nil {
				t.Fatal(err)
			}
			if head.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms || aws.ToString(head.SSEKMSKeyId) != cloudFormationStorageOutput(t, stack, "KeyArn") {
				t.Fatalf("bucket default KMS encryption was not effective: %s %s", head.ServerSideEncryption, aws.ToString(head.SSEKMSKeyId))
			}
			advanceClock(t, source, 72*time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			_, err = buckets.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: aws.String("cfn-guard-data"), Key: aws.String("tmp/expiring")})
			assertAPIError(t, err, "NotFound")
			for _, key := range []string{"tmp/untagged", "keep/tagged"} {
				if _, err := buckets.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: aws.String("cfn-guard-data"), Key: aws.String(key)}); err != nil {
					t.Fatalf("lifecycle expired %s outside its prefix and tag filter: %v", key, err)
				}
			}

			queues := c.sqs("test", "test", "")
			work, dead := cloudFormationStorageOutput(t, stack, "Work"), cloudFormationStorageOutput(t, stack, "Dead")
			attributes, err := queues.GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: aws.String(work), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameAll}})
			if err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true", "DeduplicationScope": "messageGroup",
				"FifoThroughputLimit": "perMessageGroupId", "VisibilityTimeout": "120", "MessageRetentionPeriod": "3600"} {
				if attributes.Attributes[key] != want {
					t.Fatalf("queue attribute %s = %q, want %q", key, attributes.Attributes[key], want)
				}
			}
			if !strings.Contains(attributes.Attributes["RedrivePolicy"], "cfn-guard-dlq.fifo") {
				t.Fatalf("redrive policy was not applied: %q", attributes.Attributes["RedrivePolicy"])
			}
			// Message-group deduplication drops the repeated body only within its group.
			for _, group := range []string{"g1", "g1", "g2"} {
				if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: aws.String(work), MessageBody: aws.String("job"), MessageGroupId: aws.String(group)}); err != nil {
					t.Fatal(err)
				}
			}
			received, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(work), MaxNumberOfMessages: 10})
			if err != nil {
				t.Fatal(err)
			}
			if len(received.Messages) != 2 {
				t.Fatalf("messageGroup deduplication delivered %d messages, want 2", len(received.Messages))
			}
			advanceClock(t, source, 121*time.Second)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			again, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(work), MaxNumberOfMessages: 10})
			if err != nil {
				t.Fatal(err)
			}
			moved, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(dead), MaxNumberOfMessages: 10})
			if err != nil {
				t.Fatal(err)
			}
			if len(again.Messages) != 0 || len(moved.Messages) != 2 {
				t.Fatalf("maxReceiveCount=1 redrive: source=%d dead-letter=%d", len(again.Messages), len(moved.Messages))
			}

			// Removing the properties removes the owner configuration.
			delete(bucket, "CorsConfiguration")
			delete(bucket, "LifecycleConfiguration")
			if _, err := root.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(template(bucket))}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			_, err = buckets.GetBucketCors(t.Context(), &s3.GetBucketCorsInput{Bucket: aws.String("cfn-guard-data")})
			assertAPIError(t, err, "NoSuchCORSConfiguration")
			_, err = buckets.GetBucketLifecycleConfiguration(t.Context(), &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String("cfn-guard-data")})
			assertAPIError(t, err, "NoSuchLifecycleConfiguration")
			for _, key := range []string{"tmp/untagged", "keep/tagged"} {
				if _, err := buckets.DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: aws.String("cfn-guard-data"), Key: aws.String(key)}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := root.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
			_, err = buckets.GetBucketLocation(t.Context(), &s3.GetBucketLocationInput{Bucket: aws.String("cfn-guard-data")})
			assertAPIError(t, err, "NoSuchBucket")
		})
	}
}

// Access points, inline queue policies, SSM documents, parameter resource
// policies and service settings are deployed only through their owners.
func TestCloudFormationStorageOwnerResources(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const consumer = "444455556666"
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, _ := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			userARN, userKey, userSecret := c.user(t, consumer, "storage-consumer")
			putUserPolicy(t, c.iam(consumer, "test", ""), "storage-consumer", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:SendMessage","ssm:GetParameter"],"Resource":"*"}]}`)
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			template := func(documentVersion, parameterActions string, method string) string {
				document := map[string]any{"Name": "cfn-command", "DocumentType": "Command", "DocumentFormat": "JSON", "Content": shellDocument(documentVersion),
					"Tags": []map[string]string{{"Key": "team", "Value": "storage"}}}
				if method != "" {
					document["UpdateMethod"] = method
				}
				return cloudFormationStorageJSON(t, map[string]any{
					"Resources": map[string]any{
						"Bucket": map[string]any{"Type": "AWS::S3::Bucket", "Properties": map[string]any{"BucketName": "cfn-storage-points"}},
						"Point":  map[string]any{"Type": "AWS::S3::AccessPoint", "Properties": map[string]any{"Bucket": map[string]any{"Ref": "Bucket"}, "Name": "cfn-point"}},
						"Queue":  map[string]any{"Type": "AWS::SQS::Queue", "Properties": map[string]any{"QueueName": "cfn-inline"}},
						"QueuePolicy": map[string]any{"Type": "AWS::SQS::QueueInlinePolicy", "Properties": map[string]any{
							"Queue": map[string]any{"Ref": "Queue"},
							"PolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
								"Effect": "Allow", "Principal": map[string]any{"AWS": userARN}, "Action": "sqs:SendMessage",
								"Resource": map[string]any{"Fn::GetAtt": []string{"Queue", "Arn"}}}}},
						}},
						"Document": map[string]any{"Type": "AWS::SSM::Document", "Properties": document},
						"Parameter": map[string]any{"Type": "AWS::SSM::Parameter", "Properties": map[string]any{
							"Name": "/cfn/shared", "Type": "String", "Value": "v1", "Tier": "Advanced"}},
						"ParameterPolicy": map[string]any{"Type": "AWS::SSM::ResourcePolicy", "DependsOn": "Parameter", "Properties": map[string]any{
							"ResourceArn": map[string]any{"Fn::Sub": "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/cfn/shared"},
							"Policy":      fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":%s,"Resource":"arn:aws:ssm:us-east-1:000000000000:parameter/cfn/shared"}]}`, userARN, parameterActions),
						}},
						"Setting": map[string]any{"Type": "AWS::SSM::ServiceSetting", "Properties": map[string]any{
							"SettingId": "/ssm/parameter-store/default-parameter-tier", "SettingValue": "Advanced"}},
					},
					"Outputs": map[string]any{
						"Alias":    map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Point", "Alias"}}},
						"PointArn": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Point", "Arn"}}},
						"Queue":    map[string]any{"Value": map[string]any{"Ref": "Queue"}},
						"PolicyId": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"ParameterPolicy", "PolicyId"}}},
					},
				})
			}
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("storage-owners"), TemplateBody: aws.String(template("v1", `"ssm:GetParameter"`, ""))})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)

			if got := cloudFormationStorageOutput(t, stack, "PointArn"); got != "arn:aws:s3:us-east-1:000000000000:accesspoint/cfn-point" {
				t.Fatalf("access point ARN %s", got)
			}
			alias := cloudFormationStorageOutput(t, stack, "Alias")
			buckets := cloudFormationStorageS3(c)
			if _, err := buckets.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String("cfn-storage-points"), Key: aws.String("object"), Body: strings.NewReader("through-point")}); err != nil {
				t.Fatal(err)
			}
			object, err := buckets.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(alias), Key: aws.String("object")})
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(object.Body)
			_ = object.Body.Close()
			if string(body) != "through-point" {
				t.Fatalf("access point alias read %q", body)
			}

			remoteQueue := c.sqs(userKey, userSecret, "")
			if _, err := remoteQueue.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: aws.String(cloudFormationStorageOutput(t, stack, "Queue")), MessageBody: aws.String("cross-account")}); err != nil {
				t.Fatalf("inline queue policy did not grant the consumer: %v", err)
			}

			documents := c.ssm("us-east-1", "test", "test")
			described, err := documents.DescribeDocument(t.Context(), &ssm.DescribeDocumentInput{Name: aws.String("cfn-command")})
			if err != nil {
				t.Fatal(err)
			}
			if string(described.Document.DocumentType) != "Command" || aws.ToString(described.Document.DefaultVersion) != "1" {
				t.Fatalf("document %+v", described.Document)
			}
			remoteParameters := c.ssm("us-east-1", userKey, userSecret)
			arn := "arn:aws:ssm:us-east-1:000000000000:parameter/cfn/shared"
			shared, err := remoteParameters.GetParameter(t.Context(), &ssm.GetParameterInput{Name: aws.String(arn)})
			if err != nil || aws.ToString(shared.Parameter.Value) != "v1" {
				t.Fatalf("parameter resource policy did not share: %+v %v", shared, err)
			}
			setting, err := documents.GetServiceSetting(t.Context(), &ssm.GetServiceSettingInput{SettingId: aws.String("/ssm/parameter-store/default-parameter-tier")})
			if err != nil || aws.ToString(setting.ServiceSetting.SettingValue) != "Advanced" {
				t.Fatalf("service setting %+v %v", setting, err)
			}

			// NewVersion keeps the document identity and promotes the new default.
			if _, err := root.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId,
				TemplateBody: aws.String(template("v2", `["ssm:GetParameter","ssm:GetParameters"]`, "NewVersion"))}); err != nil {
				t.Fatal(err)
			}
			updated := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
			described, err = documents.DescribeDocument(t.Context(), &ssm.DescribeDocumentInput{Name: aws.String("cfn-command")})
			if err != nil || aws.ToString(described.Document.DefaultVersion) != "2" {
				t.Fatalf("document new version %+v %v", described, err)
			}
			policies, err := documents.GetResourcePolicies(t.Context(), &ssm.GetResourcePoliciesInput{ResourceArn: aws.String(arn)})
			if err != nil {
				t.Fatal(err)
			}
			if len(policies.Policies) != 1 || aws.ToString(policies.Policies[0].PolicyId) != cloudFormationStorageOutput(t, updated, "PolicyId") ||
				!strings.Contains(aws.ToString(policies.Policies[0].Policy), "ssm:GetParameters") {
				t.Fatalf("policy update must keep one policy identity: %+v", policies.Policies)
			}

			if _, err := buckets.DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: aws.String("cfn-storage-points"), Key: aws.String("object")}); err != nil {
				t.Fatal(err)
			}
			if _, err := root.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
			_, err = documents.DescribeDocument(t.Context(), &ssm.DescribeDocumentInput{Name: aws.String("cfn-command")})
			assertAPIError(t, err, "InvalidDocument")
			setting, err = documents.GetServiceSetting(t.Context(), &ssm.GetServiceSettingInput{SettingId: aws.String("/ssm/parameter-store/default-parameter-tier")})
			if err != nil || aws.ToString(setting.ServiceSetting.SettingValue) != "Standard" {
				t.Fatalf("deleting the setting resource must reset it: %+v %v", setting, err)
			}
			_, err = buckets.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(alias), Key: aws.String("object")})
			if err == nil {
				t.Fatal("deleted access point alias still resolved")
			}
		})
	}
}

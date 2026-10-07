package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"stackd"
	"stackd/clock"
)

func nestedStackCC(c cloudClients, region string) *cloudcontrol.Client {
	return cloudcontrol.New(cloudcontrol.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), HTTPClient: c.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")})
}

func nestedStackCCWait(t *testing.T, c cloudClients, source *clock.Manual, token *string, wanted cctypes.OperationStatus) cctypes.ProgressEvent {
	t.Helper()
	for range 100 {
		out, err := nestedStackCC(c, "us-east-1").GetResourceRequestStatus(t.Context(), &cloudcontrol.GetResourceRequestStatusInput{RequestToken: token})
		if err != nil {
			t.Fatal(err)
		}
		if out.ProgressEvent.OperationStatus == wanted {
			return *out.ProgressEvent
		}
		if out.ProgressEvent.OperationStatus != cctypes.OperationStatusInProgress {
			t.Fatalf("stack resource reached unexpected progress: %+v", out.ProgressEvent)
		}
		advanceClock(t, source, time.Second)
		if _, err := c.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("actual stack source job did not settle")
	return cctypes.ProgressEvent{}
}

func nestedStackChildTemplate(t *testing.T, queue, bucket string) string {
	t.Helper()
	return cloudFormationStorageJSON(t, map[string]any{
		"Parameters": map[string]any{"Visibility": map[string]any{"Type": "String"}},
		"Resources": map[string]any{
			"Queue":  map[string]any{"Type": "AWS::SQS::Queue", "Properties": map[string]any{"QueueName": queue, "VisibilityTimeout": map[string]any{"Ref": "Visibility"}}},
			"Bucket": map[string]any{"Type": "AWS::S3::Bucket", "Properties": map[string]any{"BucketName": bucket, "CorsConfiguration": map[string]any{"CorsRules": []any{map[string]any{"AllowedOrigins": []string{"https://nested.example"}, "AllowedMethods": []string{"GET"}, "MaxAge": 123}}}}},
		},
		"Outputs": map[string]any{
			"Queue":      map[string]any{"Value": map[string]any{"Ref": "Queue"}},
			"Bucket":     map[string]any{"Value": map[string]any{"Ref": "Bucket"}},
			"Visibility": map[string]any{"Value": map[string]any{"Ref": "Visibility"}},
		},
	})
}

func nestedStackParentTemplate(t *testing.T, url, visibility string) string {
	t.Helper()
	return cloudFormationStorageJSON(t, map[string]any{
		"Resources": map[string]any{
			"Child":  map[string]any{"Type": "AWS::CloudFormation::Stack", "Properties": map[string]any{"TemplateURL": url, "Parameters": map[string]any{"Visibility": visibility}, "Tags": []any{map[string]any{"Key": "child", "Value": "native"}}}},
			"Mirror": map[string]any{"Type": "AWS::SQS::Queue", "Properties": map[string]any{"QueueName": "nested-mirror", "VisibilityTimeout": map[string]any{"Fn::GetAtt": []string{"Child", "Outputs.Visibility"}}}},
		},
		"Outputs": map[string]any{
			"Child":  map[string]any{"Value": map[string]any{"Ref": "Child"}},
			"Queue":  map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Child", "Outputs.Queue"}}},
			"Bucket": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Child", "Outputs.Bucket"}}},
			"Mirror": map[string]any{"Value": map[string]any{"Ref": "Mirror"}},
		},
	})
}

// Both layers enter native CreateStack and own real SQS/S3 resources. The parent
// waits for the child job rather than declaring completion at admission.
func TestCloudFormationNestedStackActualOwnersUpdateDeleteAndReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			roles := c.iam("test", "test", "")
			role, err := roles.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("nested-execution"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudformation.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := roles.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: aws.String("nested-execution"), PolicyName: aws.String("native-owners"), PolicyDocument: aws.String(allow(`["cloudformation:*","sqs:*","s3:*"]`, "*"))}); err != nil {
				t.Fatal(err)
			}
			buckets := cloudFormationStorageS3(c)
			if _, err := buckets.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String("nested-template-source")}); err != nil {
				t.Fatal(err)
			}
			childBody := nestedStackChildTemplate(t, "nested-work", "nested-data")
			if _, err := buckets.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String("nested-template-source"), Key: aws.String("child.json"), Body: strings.NewReader(childBody)}); err != nil {
				t.Fatal(err)
			}
			url := "https://nested-template-source.s3.us-east-1.amazonaws.com/child.json"
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			input := &cloudformation.CreateStackInput{StackName: aws.String("nested-parent"), TemplateBody: aws.String(nestedStackParentTemplate(t, url, "10")), ClientRequestToken: aws.String("parent-create"), Tags: []cfntypes.Tag{{Key: aws.String("parent"), Value: aws.String("retained")}}}
			input.RoleARN = role.Role.Arn
			created, err := root.CreateStack(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = c.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			buckets = cloudFormationStorageS3(c)
			replayed, err := root.CreateStack(t.Context(), input)
			if err != nil || aws.ToString(replayed.StackId) != aws.ToString(created.StackId) {
				t.Fatalf("parent replay changed retained identity: %v %v", replayed, err)
			}
			parent := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			childID := cloudFormationStorageOutput(t, parent, "Child")
			queue, mirror := cloudFormationStorageOutput(t, parent, "Queue"), cloudFormationStorageOutput(t, parent, "Mirror")
			child, err := root.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: aws.String(childID)})
			if err != nil || len(child.Stacks) != 1 || aws.ToString(child.Stacks[0].ParentId) != aws.ToString(created.StackId) || aws.ToString(child.Stacks[0].RootId) != aws.ToString(created.StackId) {
				t.Fatalf("native child lost authentic parent/root metadata: %v %v", child, err)
			}
			if aws.ToString(child.Stacks[0].RoleARN) != aws.ToString(role.Role.Arn) {
				t.Fatal("nested native owner did not inherit the real parent execution role")
			}
			tagged := map[string]string{}
			for _, tag := range child.Stacks[0].Tags {
				tagged[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			if tagged["parent"] != "retained" || tagged["child"] != "native" {
				t.Fatalf("child did not inherit real stack tags: %v", tagged)
			}
			queues := c.sqs("test", "test", "")
			cloudFormationQueueVisibility(t, queues, queue, "10")
			cloudFormationQueueVisibility(t, queues, mirror, "10")
			if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: aws.String(queue), MessageBody: aws.String("actual nested queue")}); err != nil {
				t.Fatal(err)
			}
			messages, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: aws.String(queue)})
			if err != nil || len(messages.Messages) != 1 || aws.ToString(messages.Messages[0].Body) != "actual nested queue" {
				t.Fatalf("nested stack did not own a real queue: %v %v", messages, err)
			}
			bucket := cloudFormationStorageOutput(t, parent, "Bucket")
			cors, err := buckets.GetBucketCors(t.Context(), &s3.GetBucketCorsInput{Bucket: aws.String(bucket)})
			if err != nil || len(cors.CORSRules) != 1 || aws.ToInt32(cors.CORSRules[0].MaxAgeSeconds) != 123 {
				t.Fatalf("child did not configure the actual S3 owner: %v %v", cors, err)
			}
			// Returning to the original value must be a new native operation, not
			// an accidental replay of the first update on this incarnation.
			for _, visibility := range []string{"30", "10"} {
				if _, err := root.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(nestedStackParentTemplate(t, url, visibility))}); err != nil {
					t.Fatal(err)
				}
				parent = cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
				if cloudFormationStorageOutput(t, parent, "Child") != childID {
					t.Fatal("nested update replaced its physical stack identity")
				}
				cloudFormationQueueVisibility(t, queues, queue, visibility)
				cloudFormationQueueVisibility(t, queues, mirror, visibility)
			}
			if _, err := root.UpdateTerminationProtection(t.Context(), &cloudformation.UpdateTerminationProtectionInput{StackName: created.StackId, EnableTerminationProtection: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			protected, err := root.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: aws.String(childID)})
			if err != nil || !aws.ToBool(protected.Stacks[0].EnableTerminationProtection) {
				t.Fatalf("nested stack did not inherit root termination protection: %v %v", protected, err)
			}
			_, err = root.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(childID)})
			assertAPIError(t, err, "ValidationError")
			_, err = root.UpdateTerminationProtection(t.Context(), &cloudformation.UpdateTerminationProtectionInput{StackName: aws.String(childID), EnableTerminationProtection: aws.Bool(false)})
			assertAPIError(t, err, "ValidationError")
			if _, err := root.UpdateTerminationProtection(t.Context(), &cloudformation.UpdateTerminationProtectionInput{StackName: created.StackId, EnableTerminationProtection: aws.Bool(false)}); err != nil {
				t.Fatal(err)
			}
			// A native busy child must postpone parent deletion, not fail or
			// report a fake-complete delete before its source job can run.
			if _, err := root.UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: aws.String(childID), TemplateBody: aws.String(childBody), Parameters: []cfntypes.Parameter{{ParameterKey: aws.String("Visibility"), ParameterValue: aws.String("40")}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := root.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
			cloudFormationWait(t, c, source, root, childID, cfntypes.StackStatusDeleteComplete)
			_, err = c.sqs("test", "test", "").GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: aws.String(queue), AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
			assertAPIError(t, err, "AWS.SimpleQueueService.NonExistentQueue")
			_, err = cloudFormationStorageS3(c).GetBucketCors(t.Context(), &s3.GetBucketCorsInput{Bucket: aws.String(bucket)})
			assertAPIError(t, err, "NoSuchBucket")
		})
	}
}

func TestCloudFormationNestedStackChildFailureRollsBackExactOwnedChild(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			queues := c.sqs("test", "test", "")
			control, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("nested-existing-control"), Attributes: map[string]string{"VisibilityTimeout": "71"}})
			if err != nil {
				t.Fatal(err)
			}
			childBody := cloudFormationQueueTemplate(t, "nested-existing-control", 10, 0)
			body := cloudFormationStorageJSON(t, map[string]any{"Resources": map[string]any{"Child": map[string]any{"Type": "AWS::CloudFormation::Stack", "Properties": map[string]any{"TemplateBody": childBody}}}})
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			created, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("nested-failure"), TemplateBody: aws.String(body)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			root = cloudFormationClient(c, "us-east-1", "test", "test")
			failed := cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusRollbackComplete)
			if !strings.Contains(aws.ToString(failed.StackStatusReason), "child stack") {
				t.Fatalf("parent hid actual child failure: %s", aws.ToString(failed.StackStatusReason))
			}
			resources, err := root.DescribeStackResources(t.Context(), &cloudformation.DescribeStackResourcesInput{StackName: created.StackId})
			if err != nil || len(resources.StackResources) != 1 || aws.ToString(resources.StackResources[0].PhysicalResourceId) == "" {
				t.Fatalf("parent lost exact failed child identity: %v %v", resources, err)
			}
			childID := aws.ToString(resources.StackResources[0].PhysicalResourceId)
			child := cloudFormationWait(t, c, source, root, childID, cfntypes.StackStatusDeleteComplete)
			if aws.ToString(child.ParentId) != aws.ToString(created.StackId) || aws.ToString(child.RootId) != aws.ToString(created.StackId) {
				t.Fatal("rollback deleted a stack without retained parent ownership")
			}
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), aws.ToString(control.QueueUrl), "71")
			if _, err := root.DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, c, source, root, aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
		})
	}
}

func TestCloudControlStackUsesNativeRootAndExistingStackOwner(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			c, reopen := retainedCloud(t, backend, stackd.Config{Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			typ := aws.String("AWS::CloudFormation::Stack")
			body := cloudFormationQueueTemplate(t, "cc-native-stack-queue", 12, 0)
			desired := cloudFormationStorageJSON(t, map[string]any{"StackName": "cc-native-stack", "TemplateBody": body})
			input := &cloudcontrol.CreateResourceInput{TypeName: typ, DesiredState: aws.String(desired), ClientToken: aws.String("cc-stack-create")}
			created, err := nestedStackCC(c, "us-east-1").CreateResource(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			c = reopen()
			progress := nestedStackCCWait(t, c, source, created.ProgressEvent.RequestToken, cctypes.OperationStatusSuccess)
			id := progress.Identifier
			replay, err := nestedStackCC(c, "us-east-1").CreateResource(t.Context(), input)
			if err != nil || aws.ToString(replay.ProgressEvent.RequestToken) != aws.ToString(created.ProgressEvent.RequestToken) {
				t.Fatalf("CC stack replay changed source intent: %v %v", replay, err)
			}
			root := cloudFormationClient(c, "us-east-1", "test", "test")
			native, err := root.DescribeStacks(t.Context(), &cloudformation.DescribeStacksInput{StackName: id})
			if err != nil || len(native.Stacks) != 1 || native.Stacks[0].ParentId != nil || native.Stacks[0].RootId != nil {
				t.Fatalf("direct CC stack was not a native root: %v %v", native, err)
			}
			queue := cloudFormationQueueURL(t, native.Stacks[0])
			for _, visibility := range []int{33, 12} {
				patch := cloudFormationStorageJSON(t, []any{map[string]any{"op": "replace", "path": "/TemplateBody", "value": cloudFormationQueueTemplate(t, "cc-native-stack-queue", visibility, 0)}})
				updated, err := nestedStackCC(c, "us-east-1").UpdateResource(t.Context(), &cloudcontrol.UpdateResourceInput{TypeName: typ, Identifier: id, PatchDocument: aws.String(patch)})
				if err != nil {
					t.Fatal(err)
				}
				nestedStackCCWait(t, c, source, updated.ProgressEvent.RequestToken, cctypes.OperationStatusSuccess)
				cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), queue, strconv.Itoa(visibility))
			}
			get, err := nestedStackCC(c, "us-east-1").GetResource(t.Context(), &cloudcontrol.GetResourceInput{TypeName: typ, Identifier: id})
			if err != nil {
				t.Fatal(err)
			}
			var model map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(get.ResourceDescription.Properties)), &model); err != nil {
				t.Fatal(err)
			}
			if model["StackId"] != aws.ToString(id) || model["ParentId"] != nil || model["RootId"] != nil || model["TemplateBody"] == nil {
				t.Fatalf("CC read was not authoritative native stack state: %v", model)
			}
			_, err = nestedStackCC(c, "us-west-2").GetResource(t.Context(), &cloudcontrol.GetResourceInput{TypeName: typ, Identifier: id})
			assertAPIError(t, err, "ResourceNotFoundException")
			// Direct CC may discover/update an ordinary SDK-created native root;
			// creation cannot adopt it by name or matching template.
			existing, err := root.CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("ordinary-native-root"), TemplateBody: aws.String(cloudFormationQueueTemplate(t, "ordinary-native-control", 55, 0))})
			if err != nil {
				t.Fatal(err)
			}
			ordinary := cloudFormationWait(t, c, source, root, aws.ToString(existing.StackId), cfntypes.StackStatusCreateComplete)
			duplicate, err := nestedStackCC(c, "us-east-1").CreateResource(t.Context(), &cloudcontrol.CreateResourceInput{TypeName: typ, DesiredState: aws.String(cloudFormationStorageJSON(t, map[string]any{"StackName": "ordinary-native-root", "TemplateBody": cloudFormationQueueTemplate(t, "ordinary-native-control", 55, 0)}))})
			if err != nil {
				t.Fatal(err)
			}
			if failed := nestedStackCCWait(t, c, source, duplicate.ProgressEvent.RequestToken, cctypes.OperationStatusFailed); failed.ErrorCode != cctypes.HandlerErrorCodeAlreadyExists {
				t.Fatalf("CC create adopted an unrelated native stack: %+v", failed)
			}
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), cloudFormationQueueURL(t, ordinary), "55")
			patch := cloudFormationStorageJSON(t, []any{map[string]any{"op": "replace", "path": "/TemplateBody", "value": cloudFormationQueueTemplate(t, "ordinary-native-control", 71, 0)}})
			mutated, err := nestedStackCC(c, "us-east-1").UpdateResource(t.Context(), &cloudcontrol.UpdateResourceInput{TypeName: typ, Identifier: existing.StackId, PatchDocument: aws.String(patch)})
			if err != nil {
				t.Fatal(err)
			}
			nestedStackCCWait(t, c, source, mutated.ProgressEvent.RequestToken, cctypes.OperationStatusSuccess)
			cloudFormationQueueVisibility(t, c.sqs("test", "test", ""), cloudFormationQueueURL(t, ordinary), "71")
			listed, err := nestedStackCC(c, "us-east-1").ListResources(t.Context(), &cloudcontrol.ListResourcesInput{TypeName: typ})
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]bool{}
			for _, resource := range listed.ResourceDescriptions {
				found[aws.ToString(resource.Identifier)] = true
			}
			if !found[aws.ToString(existing.StackId)] || !found[aws.ToString(id)] {
				t.Fatalf("CC discovery omitted actual native stack owners: %v", found)
			}
			for _, stackID := range []*string{id, existing.StackId} {
				deleted, err := nestedStackCC(c, "us-east-1").DeleteResource(t.Context(), &cloudcontrol.DeleteResourceInput{TypeName: typ, Identifier: stackID})
				if err != nil {
					t.Fatal(err)
				}
				nestedStackCCWait(t, c, source, deleted.ProgressEvent.RequestToken, cctypes.OperationStatusSuccess)
				cloudFormationWait(t, c, source, root, aws.ToString(stackID), cfntypes.StackStatusDeleteComplete)
			}
		})
	}
}

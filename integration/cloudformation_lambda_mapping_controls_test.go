package stackd_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd"
	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// Native captures calibrate the control plane, not encrypted stream delivery.
// This workflow uses signed SDK calls, DynamoDB Local and the captured Python
// handler in Docker to exercise the CloudFormation/Lambda/KMS/SQS boundary.
func TestCloudFormationLambdaDynamoDBMappingControls(t *testing.T) {
	lambdaDynamoDBDocker(t)
	fixture := lambdaFixture[lambdaDynamoDBFixture](t, "dynamodb_source")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.StartedAt)
			// This helper owns teardown of every retained stack, Lambda executor
			// and observed DynamoDB engine, including failures before deletion.
			clients, reopen := lambdaDynamoDBCloud(t, backend, source)
			account := fixture.row(t, "identity_before_writes").Result.Output["Account"].(string)
			replace := strings.NewReplacer(account, "000000000000")
			for _, label := range []string{"create_log_group", "create_role", "create_table"} {
				lambdaDynamoDBCall(t, clients, fixture.row(t, label), replace)
			}
			table := lambdaStreamingInput[dynamodb.CreateTableInput](t, fixture.row(t, "create_table").Input, replace)
			streamARN := cloudFormationDynamoDBStream(t, clients, aws.ToString(table.TableName))
			nativeStream := fixture.row(t, "create_table").Result.Output["TableDescription"].(map[string]any)["LatestStreamArn"].(string)
			replace = strings.NewReplacer(nativeStream, streamARN, account, "000000000000")
			for _, label := range []string{"policy_owned-logs", "policy_owned-source", "create_function_0"} {
				lambdaDynamoDBCall(t, clients, fixture.row(t, label), replace)
			}
			if err := awslambda.NewFunctionActiveWaiter(lambdaDynamoDBClient(clients), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &fixture.Prefix}, time.Minute); err != nil {
				t.Fatal(err)
			}
			for _, label := range []string{"publish_handler", "images_alias"} {
				lambdaDynamoDBCall(t, clients, fixture.row(t, label), replace)
			}
			targetARN := replace.Replace(fixture.row(t, "images_alias").Result.Output["AliasArn"].(string))
			version := fixture.row(t, "publish_handler").Result.Output["Version"].(string)
			role := lambdaStreamingInput[iam.CreateRoleInput](t, fixture.row(t, "create_role").Input, replace)
			queueURLs, queueARNs := []string{}, []string{}
			for _, suffix := range []string{"first", "second"} {
				queue, err := clients.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String(fixture.Prefix + "-controls-" + suffix)})
				if err != nil {
					t.Fatal(err)
				}
				attributes, err := clients.sqs("test", "test", "").GetQueueAttributes(t.Context(), &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameQueueArn}})
				if err != nil {
					t.Fatal(err)
				}
				queueURLs = append(queueURLs, aws.ToString(queue.QueueUrl))
				queueARNs = append(queueARNs, attributes.Attributes["QueueArn"])
			}
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
				RoleName: role.RoleName, PolicyName: aws.String("controls-destinations"),
				PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":[%q,%q]}}`, queueARNs[0], queueARNs[1])),
			}); err != nil {
				t.Fatal(err)
			}
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Allow","Principal":{"Service":"lambda.us-east-1.amazonaws.com"},"Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:EncryptionContext:aws:lambda:FunctionArn":%q,"kms:EncryptionContext:aws:lambda:EventSourceArn":%q}}}]}`, targetARN, streamARN)
			key, err := clients.kms("test", "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{Policy: &policy})
			if err != nil {
				t.Fatal(err)
			}
			filter := cloudFormationDynamoDBFilter("accepted")
			properties := map[string]any{
				"FunctionName": fixture.Prefix + ":images", "EventSourceArn": streamARN,
				"StartingPosition": "TRIM_HORIZON", "Enabled": true, "BatchSize": 1,
				"MaximumRetryAttempts": 0, "FilterCriteria": filter, "KmsKeyArn": aws.ToString(key.KeyMetadata.Arn),
				"DestinationConfig": map[string]any{"OnFailure": map[string]any{"Destination": queueARNs[0]}},
			}
			cfn := func() *cloudformation.Client { return cloudFormationClient(clients, "us-east-1", "test", "test") }
			created, err := cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("dynamodb-mapping-controls"), TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties))})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			id := cloudFormationKinesisMappingIdentity(t, clients, stack)
			lambdaKinesisMappingState(t, clients, source, id, "Enabled")
			update := func() {
				t.Helper()
				if _, err := cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties))}); err != nil {
					t.Fatal(err)
				}
				stack = cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
				if got := cloudFormationKinesisMappingIdentity(t, clients, stack); got != id {
					t.Fatalf("mutable controls replaced mapping: before=%s after=%s", id, got)
				}
				lambdaKinesisMappingState(t, clients, source, id, "Enabled")
			}
			mapping := func() *awslambda.GetEventSourceMappingOutput {
				t.Helper()
				out, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			assertEncryptedFilter := func() {
				t.Helper()
				out := mapping()
				want := lambdaStreamingInput[lambdatypes.FilterCriteria](t, lambdaQualifiedJSON(t, filter), strings.NewReplacer())
				if aws.ToString(out.KMSKeyArn) != aws.ToString(key.KeyMetadata.Arn) || out.FilterCriteriaError != nil || !reflect.DeepEqual(out.FilterCriteria, &want) {
					t.Fatalf("key/filter changed: %+v", out)
				}
				listed, err := lambdaDynamoDBClient(clients).ListEventSourceMappings(t.Context(), &awslambda.ListEventSourceMappingsInput{FunctionName: &targetARN, EventSourceArn: &streamARN})
				if err != nil {
					t.Fatal(err)
				}
				if len(listed.EventSourceMappings) != 1 || aws.ToString(listed.EventSourceMappings[0].UUID) != id {
					t.Fatalf("list lost owned mapping: %+v", listed)
				}
				listedFilter := listed.EventSourceMappings[0].FilterCriteria
				if listedFilter != nil {
					t.Fatalf("list exposed encrypted filter criteria: %+v", listedFilter)
				}
			}
			settle := func() {
				t.Helper()
				advanceClock(t, source, 2*time.Second)
				if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 256); err != nil {
					t.Fatal(err)
				}
			}
			want := map[string]cloudFormationDynamoDBDelivery{}
			committed := map[string]int{}
			var previous map[string]any
			put := func(label, phase string, poison, deliver bool) {
				t.Helper()
				item := map[string]ddbtypes.AttributeValue{}
				image := map[string]any{}
				for name, value := range map[string]string{"pk": "ordered", "id": label, "phase": phase, "mode": "raise"} {
					item[name] = &ddbtypes.AttributeValueMemberS{Value: value}
					image[name] = map[string]any{"S": value}
				}
				item["bad"] = &ddbtypes.AttributeValueMemberBOOL{Value: poison}
				image["bad"] = map[string]any{"BOOL": poison}
				if _, err := dynamoClient(clients, "test", "test", clients.server.Client()).PutItem(t.Context(), &dynamodb.PutItemInput{TableName: table.TableName, Item: item}); err != nil {
					t.Fatal(err)
				}
				if deliver {
					want[label] = cloudFormationDynamoDBDelivery{sourceARN: streamARN, newImage: image, oldImage: previous}
				}
				previous = image
			}
			observe := func() map[string]int {
				t.Helper()
				seen := cloudFormationDynamoDBObserved(t, clients, fixture.Prefix, targetARN, want)
				for label, count := range committed {
					if seen[label] != count {
						t.Fatalf("checkpointed %s replayed or disappeared: before=%d after=%d", label, count, seen[label])
					}
				}
				return seen
			}
			await := func(label string) {
				t.Helper()
				deadline := time.Now().Add(90 * time.Second)
				for time.Now().Before(deadline) {
					advanceClock(t, source, 250*time.Millisecond)
					if observe()[label] > 0 {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Fatalf("real Python handler did not receive %s", label)
			}
			checkpoint := func(label string) {
				t.Helper()
				marker := "checkpoint-" + label
				put(marker, "accepted", false, true)
				await(marker)
				// BatchSize=1 and the same key order each marker after its business
				// records. Freeze observed counts only after commit, not at first log.
				for record, count := range observe() {
					if !strings.HasPrefix(record, "checkpoint-") {
						committed[record] = count
					}
				}
			}
			assertEncryptedFilter()
			for _, property := range []string{"KmsKeyArn", "DestinationConfig"} {
				previous := properties[property]
				if property == "KmsKeyArn" {
					properties[property] = ""
				} else {
					properties[property] = map[string]any{"OnFailure": map[string]any{"Destination": ""}}
				}
				if _, err := cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{StackName: created.StackId, TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties))}); err != nil {
					t.Fatal(err)
				}
				rolledBack := cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackComplete)
				if got := cloudFormationKinesisMappingIdentity(t, clients, rolledBack); got != id {
					t.Fatalf("invalid %s replaced mapping: %s", property, got)
				}
				assertEncryptedFilter()
				out := mapping()
				if out.DestinationConfig == nil || out.DestinationConfig.OnFailure == nil || aws.ToString(out.DestinationConfig.OnFailure.Destination) != queueARNs[0] {
					t.Fatalf("invalid %s changed destination: %+v", property, out.DestinationConfig)
				}
				properties[property] = previous
			}
			put("encrypted-rejected", "rejected", true, false)
			put("encrypted-accepted", "accepted", false, true)
			await("encrypted-accepted")
			checkpoint("encrypted")

			if _, err := clients.kms("test", "test", "").DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.Arn}); err != nil {
				t.Fatal(err)
			}
			// Observe rejection before writing new work: an already-authorized
			// poll or in-flight invocation is deliberately not a revocation claim.
			lambdaKinesisAwaitDenied(t, clients, source, id, "disabled")
			put("key-blocked", "accepted", false, true)
			put("key-blocked-filtered", "rejected", true, false)
			clients = reopen()
			lambdaKinesisAwaitDenied(t, clients, source, id, "disabled")
			out := mapping()
			if out.FilterCriteria != nil || out.FilterCriteriaError == nil || aws.ToString(out.FilterCriteriaError.ErrorCode) != "DisabledException" || aws.ToString(out.KMSKeyArn) != aws.ToString(key.KeyMetadata.Arn) {
				t.Fatalf("disabled key leaked or lost encrypted criteria: %+v", out)
			}
			if observe()["key-blocked"] != 0 {
				t.Fatal("disabled key admitted new work across reopen")
			}
			if _, err := clients.kms("test", "test", "").EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: key.KeyMetadata.Arn}); err != nil {
				t.Fatal(err)
			}
			await("key-blocked")
			checkpoint("key-recovered")
			assertEncryptedFilter()

			deny := "controls-current-source-denial"
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: role.RoleName, PolicyName: &deny, PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"dynamodb:GetRecords","Resource":%q}}`, streamARN))}); err != nil {
				t.Fatal(err)
			}
			lambdaKinesisAwaitDenied(t, clients, source, id, "dynamodb:GetRecords")
			put("role-blocked", "accepted", false, true)
			clients = reopen()
			lambdaKinesisAwaitDenied(t, clients, source, id, "dynamodb:GetRecords")
			if observe()["role-blocked"] != 0 {
				t.Fatal("encrypted mapping bypassed current execution-role denial")
			}
			if _, err := clients.iam("test", "test", "").DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: role.RoleName, PolicyName: &deny}); err != nil {
				t.Fatal(err)
			}
			await("role-blocked")
			checkpoint("role-recovered")

			allowedFailures := map[string]int{"failure-first": 0, "failure-second": 1}
			deliveredFailures := map[string]int{}
			receiveFailures := func() {
				t.Helper()
				invocations := lambdaDynamoDBLogInvocations(t, clients, fixture.Prefix, "DDB_PROBE ")
				for index, queue := range queueURLs {
					cloudFormationMappingFailureMessages(t, clients, queue, index, streamARN, targetARN, version, invocations, allowedFailures, deliveredFailures)
				}
			}
			fail := func(label string) {
				t.Helper()
				put(label, "accepted", true, true)
				await(label)
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					advanceClock(t, source, time.Second)
					receiveFailures()
					if deliveredFailures[label] > 0 {
						checkpoint(label)
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Fatalf("real Python failure %s did not reach its configured SQS destination", label)
			}
			fail("failure-first")
			properties["DestinationConfig"] = map[string]any{"OnFailure": map[string]any{"Destination": queueARNs[1]}}
			update()
			clients = reopen()
			fail("failure-second")
			for index, empty := range []map[string]any{{}, {"OnFailure": map[string]any{}}} {
				properties["DestinationConfig"] = empty
				update()
				out := mapping()
				if out.DestinationConfig != nil && out.DestinationConfig.OnFailure != nil && aws.ToString(out.DestinationConfig.OnFailure.Destination) != "" {
					t.Fatalf("empty destination object retained target: %+v", out.DestinationConfig)
				}
				label := fmt.Sprintf("empty-destination-%d", index)
				put(label, "accepted", true, true)
				await(label)
				checkpoint(label)
				receiveFailures()
				properties["DestinationConfig"] = map[string]any{"OnFailure": map[string]any{"Destination": queueARNs[1]}}
				update()
			}

			// lambda_mapping_controls.json calibrates the surprising distinction:
			// omitting KmsKeyArn retains encryption when FilterCriteria remains.
			delete(properties, "KmsKeyArn")
			update()
			assertEncryptedFilter()
			if _, err := clients.kms("test", "test", "").DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.Arn}); err != nil {
				t.Fatal(err)
			}
			lambdaKinesisAwaitDenied(t, clients, source, id, "disabled")
			put("omitted-key-blocked", "accepted", false, true)
			put("omitted-key-rejected", "rejected", true, false)
			clients = reopen()
			lambdaKinesisAwaitDenied(t, clients, source, id, "disabled")
			out = mapping()
			if out.FilterCriteria != nil || out.FilterCriteriaError == nil || aws.ToString(out.FilterCriteriaError.ErrorCode) != "DisabledException" || aws.ToString(out.KMSKeyArn) != aws.ToString(key.KeyMetadata.Arn) {
				t.Fatalf("key omission lost native retained encryption: %+v", out)
			}
			if observe()["omitted-key-blocked"] != 0 {
				t.Fatal("omitting KmsKeyArn bypassed the retained disabled key")
			}
			if _, err := clients.kms("test", "test", "").EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: key.KeyMetadata.Arn}); err != nil {
				t.Fatal(err)
			}
			await("omitted-key-blocked")
			checkpoint("omitted-key")
			assertEncryptedFilter()

			// Clearing the criteria, unlike omitting the key, removes encryption.
			properties["KmsKeyArn"] = aws.ToString(key.KeyMetadata.Arn)
			delete(properties, "FilterCriteria")
			update()
			if _, err := clients.kms("test", "test", "").DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: key.KeyMetadata.Arn}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			out = mapping()
			if out.FilterCriteria != nil || out.FilterCriteriaError != nil || aws.ToString(out.KMSKeyArn) != "" {
				t.Fatalf("removed criteria retained encryption: %+v", out)
			}
			put("removed-filter-nonmatching", "rejected", false, true)
			await("removed-filter-nonmatching")
			checkpoint("removed-filter")

			delete(properties, "DestinationConfig")
			update()
			out = mapping()
			if out.DestinationConfig != nil && out.DestinationConfig.OnFailure != nil && aws.ToString(out.DestinationConfig.OnFailure.Destination) != "" {
				t.Fatalf("omitted destination retained failure target: %+v", out.DestinationConfig)
			}
			put("failure-discarded", "accepted", true, true)
			await("failure-discarded")
			checkpoint("discarded")
			clients = reopen()
			checkpoint("discarded-reopen")
			for range 5 {
				settle()
				receiveFailures()
				time.Sleep(50 * time.Millisecond)
			}
			observe()
			if _, err := cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: created.StackId}); err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusDeleteComplete)
			clients = reopen()
			_, err = lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}

// SQS contains stream failure metadata, not the original record payload. Bind
// every envelope back to the actual Python invocation and DynamoDB sequence;
// accept duplicate delivery but never a stale/wrong/removed destination.
func cloudFormationMappingFailureMessages(t *testing.T, clients cloudClients, queue string, queueIndex int, streamARN, targetARN, version string, invocations []lambdaDynamoDBInvocation, allowed map[string]int, delivered map[string]int) {
	t.Helper()
	for range 16 {
		output, err := clients.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: &queue, MaxNumberOfMessages: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(output.Messages) == 0 {
			return
		}
		for _, message := range output.Messages {
			var document struct {
				Version        string
				RequestContext struct {
					RequestID, FunctionArn, Condition string
					ApproximateInvokeCount            int
				}
				ResponseContext struct {
					StatusCode                     int
					ExecutedVersion, FunctionError string
				}
				DDBStreamBatchInfo struct {
					StreamArn, StartSequenceNumber, EndSequenceNumber string
					BatchSize                                         int
				}
			}
			if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &document); err != nil {
				t.Fatal(err)
			}
			request, response, batch := document.RequestContext, document.ResponseContext, document.DDBStreamBatchInfo
			if document.Version != "1.0" || request.FunctionArn != targetARN || request.Condition != "RetryAttemptsExhausted" || request.ApproximateInvokeCount < 1 || response.StatusCode != 200 || response.ExecutedVersion != version || response.FunctionError != "Unhandled" || batch.StreamArn != streamARN || batch.BatchSize != 1 || batch.StartSequenceNumber != batch.EndSequenceNumber {
				t.Fatalf("wrong real-runtime failure envelope: %s", aws.ToString(message.Body))
			}
			label := ""
			for _, invocation := range invocations {
				if invocation.RequestID != request.RequestID {
					continue
				}
				data := invocation.Event["Records"].([]any)[0].(map[string]any)["dynamodb"].(map[string]any)
				if data["SequenceNumber"] == batch.StartSequenceNumber {
					label, _ = data["NewImage"].(map[string]any)["id"].(map[string]any)["S"].(string)
					break
				}
			}
			wantedQueue, ok := allowed[label]
			if !ok || wantedQueue != queueIndex {
				t.Fatalf("unexpected record %q reached failure queue %d: %s", label, queueIndex, aws.ToString(message.Body))
			}
			delivered[label]++
			if _, err := clients.sqs("test", "test", "").DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: &queue, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Fatal("failure destination did not drain within the bounded receive limit")
}

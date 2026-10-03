package stackd_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"stackd/clock"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// Only the mapping belongs to CloudFormation. Its source, execution role and
// published Python handler are created through the native signed SDK fixture;
// delivery below traverses the real Kafka-backed stream and Docker runtime.
func TestCloudFormationLambdaKinesisMappingLifecycle(t *testing.T) {
	lambdaURLDocker(t)
	fixture := lambdaFixture[lambdaKinesisFixture](t, "kinesis_source")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.StartedAt)
			clients, reopen := lambdaKinesisCloud(t, backend, source)
			replace, streamARN := lambdaKinesisNativeSetup(t, fixture, clients, source)
			for _, label := range []string{"partial_off_alias", "partial_on_alias"} {
				lambdaKinesisCall(t, clients, fixture.row(t, label), replace)
			}
			targetARN := replace.Replace(fixture.row(t, "partial_off_alias").Result.Output["AliasArn"].(string))
			role := lambdaStreamingInput[iam.CreateRoleInput](t, fixture.row(t, "create_role").Input, replace)
			properties := map[string]any{
				"FunctionName": fixture.Prefix + ":partial_off", "EventSourceArn": streamARN,
				"StartingPosition": "TRIM_HORIZON", "Enabled": false, "BatchSize": 1,
				"MaximumBatchingWindowInSeconds": 0,
				"FilterCriteria":                 cloudFormationKinesisFilter("first"),
			}
			cfn := func() *cloudformation.Client { return cloudFormationClient(clients, "us-east-1", "test", "test") }
			created, err := cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
				StackName: aws.String("kinesis-mapping"), TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties)),
			})
			if err != nil {
				t.Fatal(err)
			}
			stack := cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			id := cloudFormationKinesisMappingIdentity(t, clients, stack)
			lambdaKinesisMappingState(t, clients, source, id, "Disabled")
			update := func(replacement bool) {
				t.Helper()
				if _, err := cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{
					StackName: created.StackId, TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties)),
				}); err != nil {
					t.Fatal(err)
				}
				stack = cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusUpdateComplete)
				next := cloudFormationKinesisMappingIdentity(t, clients, stack)
				if (next != id) != replacement {
					t.Fatalf("mapping replacement=%v: before=%s after=%s", replacement, id, next)
				}
				if replacement {
					_, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
					assertAPIError(t, err, "ResourceNotFoundException")
				}
				id = next
				state := "Disabled"
				if properties["Enabled"] == true {
					state = "Enabled"
				}
				lambdaKinesisMappingState(t, clients, source, id, state)
			}

			want := map[string]cloudFormationKinesisDelivery{}
			put := func(label, phase, arn string, deliver bool) {
				t.Helper()
				out, err := clients.kinesis("test", "test", "").PutRecord(t.Context(), &kinesis.PutRecordInput{
					StreamARN: &arn, PartitionKey: aws.String("ordered"), ExplicitHashKey: aws.String("0"),
					Data: lambdaQualifiedJSON(t, map[string]any{"id": label, "phase": phase}),
				})
				if err != nil {
					t.Fatal(err)
				}
				if deliver {
					want[label] = cloudFormationKinesisDelivery{sourceARN: arn, targetARN: targetARN, phase: phase, record: out}
				}
			}
			await := func(label string) {
				t.Helper()
				deadline := time.Now().Add(90 * time.Second)
				for time.Now().Before(deadline) {
					advanceClock(t, source, 250*time.Millisecond)
					if cloudFormationKinesisObserved(t, clients, fixture.Prefix, want)[label] > 0 {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
				t.Fatalf("real handler did not receive %s", label)
			}
			checkpoint := func(label, phase, arn string) {
				t.Helper()
				marker := "checkpoint-" + label
				put(marker, phase, arn, true)
				await(marker)
			}

			put("disabled-backlog", "first", streamARN, true)
			put("initial-filtered", "other", streamARN, false)
			clients = reopen()
			lambdaKinesisMappingState(t, clients, source, id, "Disabled")
			if got := cloudFormationKinesisObserved(t, clients, fixture.Prefix, want); len(got) != 0 {
				t.Fatalf("initially disabled mapping invoked its retained backlog: %v", got)
			}
			properties["Enabled"] = true
			update(false)
			await("disabled-backlog")
			checkpoint("initial", "first", streamARN)

			properties["FilterCriteria"] = cloudFormationKinesisFilter("second")
			update(false)
			put("old-filter-rejected", "first", streamARN, false)
			put("new-filter-accepted", "second", streamARN, true)
			await("new-filter-accepted")
			checkpoint("filter", "second", streamARN)

			// Native CloudFormation clears FilterCriteria when it is omitted.
			// Prove the removal admits a previously unmatched payload.
			delete(properties, "FilterCriteria")
			update(false)
			put("cleared-filter", "neither", streamARN, true)
			await("cleared-filter")
			checkpoint("clear", "neither", streamARN)

			// A later invocation on the same shard proves all preceding business
			// records were checkpointed. Only the final marker may be in flight.
			denyName := "cfn-live-source-denial"
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
				RoleName: role.RoleName, PolicyName: &denyName,
				PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"kinesis:GetRecords","Resource":"*"}}`),
			}); err != nil {
				t.Fatal(err)
			}
			lambdaKinesisAwaitDenied(t, clients, source, id, "kinesis:GetRecords")
			put("denied-until-reopen", "neither", streamARN, true)
			lambdaKinesisAwaitDenied(t, clients, source, id, "kinesis:GetRecords")
			clients = reopen()
			lambdaKinesisAwaitDenied(t, clients, source, id, "kinesis:GetRecords")
			if cloudFormationKinesisObserved(t, clients, fixture.Prefix, want)["denied-until-reopen"] != 0 {
				t.Fatal("revoked execution-role source permission still delivered a record")
			}
			if _, err := clients.iam("test", "test", "").DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: role.RoleName, PolicyName: &denyName}); err != nil {
				t.Fatal(err)
			}
			await("denied-until-reopen")
			checkpoint("recovered", "neither", streamARN)

			// FunctionName is mutable. Retargeting changes the actual invoked ARN
			// without replacing the mapping or replaying its committed records.
			properties["FunctionName"] = fixture.Prefix + ":partial_on"
			targetARN = replace.Replace(fixture.row(t, "partial_on_alias").Result.Output["AliasArn"].(string))
			update(false)
			put("retargeted", "neither", streamARN, true)
			await("retargeted")
			checkpoint("retargeted", "neither", streamARN)

			// Changing only the starting position requires replacement, but
			// native Lambda rejects a duplicate source/qualified-function pair.
			properties["StartingPosition"] = "LATEST"
			if _, err := cfn().UpdateStack(t.Context(), &cloudformation.UpdateStackInput{
				StackName: created.StackId, TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties)),
			}); err != nil {
				t.Fatal(err)
			}
			rolledBack := cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusUpdateRollbackComplete)
			if cloudFormationKinesisMappingIdentity(t, clients, rolledBack) != id {
				t.Fatal("failed same-source replacement retired the original mapping")
			}
			properties["StartingPosition"] = "TRIM_HORIZON"
			put("after-replacement-rollback", "neither", streamARN, true)
			await("after-replacement-rollback")
			checkpoint("rollback", "neither", streamARN)

			newStream := fixture.Prefix + "-replacement"
			if _, err := clients.kinesis("test", "test", "").CreateStream(t.Context(), &kinesis.CreateStreamInput{StreamName: &newStream, ShardCount: aws.Int32(1)}); err != nil {
				t.Fatal(err)
			}
			newARN := aws.ToString(awaitKinesisActive(t, source, clients.kinesis("test", "test", ""), newStream).StreamDescriptionSummary.StreamARN)
			put("before-starting-timestamp", "neither", newARN, false)
			advanceClock(t, source, 2*time.Second)
			extraPolicy := "cfn-replacement-source"
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
				RoleName: role.RoleName, PolicyName: &extraPolicy,
				PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["kinesis:DescribeStream","kinesis:DescribeStreamSummary","kinesis:ListShards","kinesis:GetShardIterator","kinesis:GetRecords","kinesis:ListStreams"],"Resource":%q}}`, newARN)),
			}); err != nil {
				t.Fatal(err)
			}
			properties["EventSourceArn"] = newARN
			properties["StartingPosition"] = "AT_TIMESTAMP"
			properties["StartingPositionTimestamp"] = source.Now().Unix()
			update(true)
			put("old-source-after-replacement", "neither", streamARN, false)
			put("replacement-source", "neither", newARN, true)
			await("replacement-source")
			checkpoint("replacement", "neither", newARN)

			deleteStack := func(stackID *string, mappingID string) {
				t.Helper()
				if _, err := cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: stackID}); err != nil {
					t.Fatal(err)
				}
				cloudFormationWait(t, clients, source, cfn(), aws.ToString(stackID), cfntypes.StackStatusDeleteComplete)
				_, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &mappingID})
				assertAPIError(t, err, "ResourceNotFoundException")
			}
			deleteStack(created.StackId, id)
			put("after-mapping-deletion", "neither", newARN, false)

			// Positive progress through a second, initially enabled CFN mapping
			// exercises admission and gives removed pollers time to reveal leaks.
			// Its filter excludes the old stream's already-observed history.
			properties["EventSourceArn"] = streamARN
			properties["StartingPosition"] = "TRIM_HORIZON"
			delete(properties, "StartingPositionTimestamp")
			properties["FilterCriteria"] = cloudFormationKinesisFilter("fresh")
			fresh, err := cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
				StackName: aws.String("initially-enabled-mapping"), TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties)),
			})
			if err != nil {
				t.Fatal(err)
			}
			freshStack := cloudFormationWait(t, clients, source, cfn(), aws.ToString(fresh.StackId), cfntypes.StackStatusCreateComplete)
			freshID := cloudFormationKinesisMappingIdentity(t, clients, freshStack)
			lambdaKinesisMappingState(t, clients, source, freshID, "Enabled")
			put("initially-enabled", "fresh", streamARN, true)
			await("initially-enabled")
			checkpoint("enabled", "fresh", streamARN)
			deleteStack(fresh.StackId, freshID)

			observed := cloudFormationKinesisObserved(t, clients, fixture.Prefix, want)
			for label := range want {
				if observed[label] == 0 {
					t.Fatalf("handler lost accepted record %s: %v", label, observed)
				}
			}
			if _, err := lambdaDynamoDBClient(clients).GetFunction(t.Context(), &awslambda.GetFunctionInput{FunctionName: &fixture.Prefix}); err != nil {
				t.Fatal("mapping lifecycle removed its native-owned function", err)
			}
			for _, arn := range []string{streamARN, newARN} {
				if _, err := clients.kinesis("test", "test", "").DescribeStreamSummary(t.Context(), &kinesis.DescribeStreamSummaryInput{StreamARN: &arn}); err != nil {
					t.Fatal("mapping lifecycle removed its native-owned stream", err)
				}
			}
			// Application deletion is explicit, before retainedCloud tears down
			// the reopened HTTP server; the fixture owns runtime cleanup on failure.
			if _, err := lambdaDynamoDBClient(clients).DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: &fixture.Prefix}); err != nil {
				t.Fatal(err)
			}
			for _, arn := range []string{streamARN, newARN} {
				if _, err := clients.kinesis("test", "test", "").DeleteStream(t.Context(), &kinesis.DeleteStreamInput{StreamARN: &arn, EnforceConsumerDeletion: aws.Bool(true)}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func cloudFormationKinesisFilter(phase string) map[string]any {
	return map[string]any{"Filters": []any{map[string]any{"Pattern": fmt.Sprintf(`{"data":{"phase":[%q]}}`, phase)}}}
}

func cloudFormationKinesisTemplate(t *testing.T, properties map[string]any) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"Resources": map[string]any{"Mapping": map[string]any{"Type": "AWS::Lambda::EventSourceMapping", "Properties": properties}},
		"Outputs": map[string]any{
			"Ref": map[string]any{"Value": map[string]any{"Ref": "Mapping"}},
			"Id":  map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Mapping", "Id"}}},
			"Arn": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Mapping", "EventSourceMappingArn"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func cloudFormationKinesisMappingIdentity(t *testing.T, clients cloudClients, stack cfntypes.Stack) string {
	t.Helper()
	values := map[string]string{}
	for _, output := range stack.Outputs {
		values[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
	}
	id := values["Ref"]
	mapping, err := lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || id != aws.ToString(mapping.UUID) || values["Id"] != id || values["Arn"] != aws.ToString(mapping.EventSourceMappingArn) {
		t.Fatalf("CloudFormation Ref/Id/ARN disagree with Lambda owner: outputs=%v mapping=%+v", values, mapping)
	}
	return id
}

type cloudFormationKinesisDelivery struct {
	sourceARN, targetARN, phase string
	record                      *kinesis.PutRecordOutput
}

func cloudFormationKinesisObserved(t *testing.T, clients cloudClients, name string, want map[string]cloudFormationKinesisDelivery) map[string]int {
	t.Helper()
	seen := map[string]int{}
	for _, invocation := range lambdaDynamoDBLogInvocations(t, clients, name, "KINESIS_PROBE ") {
		records := invocation.Event["Records"].([]any)
		if len(records) != 1 {
			t.Fatalf("BatchSize=1 produced unexpected records: %+v", invocation.Event)
		}
		record := records[0].(map[string]any)
		payload := lambdaKinesisRecordData(t, record)
		label, _ := payload["id"].(string)
		expected, ok := want[label]
		if !ok {
			t.Fatalf("filtered, detached, or deleted source delivered %q: %+v", label, record)
		}
		seen[label]++
		if seen[label] > 1 && !strings.HasPrefix(label, "checkpoint-") {
			t.Fatalf("committed business record %q replayed after update/reopen", label)
		}
		data := record["kinesis"].(map[string]any)
		if !reflect.DeepEqual(payload, map[string]any{"id": label, "phase": expected.phase}) ||
			record["eventSourceARN"] != expected.sourceARN || invocation.InvokedARN != expected.targetARN ||
			record["eventID"] != aws.ToString(expected.record.ShardId)+":"+aws.ToString(expected.record.SequenceNumber) ||
			data["sequenceNumber"] != aws.ToString(expected.record.SequenceNumber) || data["partitionKey"] != "ordered" {
			t.Fatalf("handler received wrong payload, target or Kinesis identity for %q: %+v", label, invocation)
		}
	}
	return seen
}

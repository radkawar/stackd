package stackd_test

import (
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
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
)

// The native fixture supplies the Python handler and SDK prerequisites, not the
// CloudFormation results. Only the mapping belongs to the stack; delivery uses
// DynamoDB Local's actual stream and the ordinary Docker Lambda executor.
func TestCloudFormationLambdaDynamoDBMappingLifecycle(t *testing.T) {
	lambdaDynamoDBDocker(t)
	fixture := lambdaFixture[lambdaDynamoDBFixture](t, "dynamodb_source")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.StartedAt)
			clients, reopen := lambdaDynamoDBCloud(t, backend, source)
			replace := strings.NewReplacer(fixture.row(t, "identity_before_writes").Result.Output["Account"].(string), "000000000000")
			for _, label := range []string{"create_log_group", "create_role", "create_table"} {
				lambdaDynamoDBCall(t, clients, fixture.row(t, label), replace)
			}
			tableInput := lambdaStreamingInput[dynamodb.CreateTableInput](t, fixture.row(t, "create_table").Input, replace)
			tableName := aws.ToString(tableInput.TableName)
			streamARN := cloudFormationDynamoDBStream(t, clients, tableName)
			nativeStream := fixture.row(t, "create_table").Result.Output["TableDescription"].(map[string]any)["LatestStreamArn"].(string)
			replace = strings.NewReplacer(nativeStream, streamARN, fixture.row(t, "identity_before_writes").Result.Output["Account"].(string), "000000000000")
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
			role := lambdaStreamingInput[iam.CreateRoleInput](t, fixture.row(t, "create_role").Input, replace)
			// Native mapping admission does not require account-wide discovery.
			// Keep it denied through actual delivery and retained recovery.
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
				RoleName: role.RoleName, PolicyName: aws.String("deny-unused-stream-discovery"),
				PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"dynamodb:ListStreams","Resource":"*"}}`),
			}); err != nil {
				t.Fatal(err)
			}
			properties := map[string]any{
				"FunctionName": fixture.Prefix + ":images", "EventSourceArn": streamARN,
				"StartingPosition": "TRIM_HORIZON", "Enabled": false, "BatchSize": 1,
				"FilterCriteria": cloudFormationDynamoDBFilter("first"),
			}
			cfn := func() *cloudformation.Client { return cloudFormationClient(clients, "us-east-1", "test", "test") }
			ddb := func() *dynamodb.Client { return dynamoClient(clients, "test", "test", clients.server.Client()) }
			created, err := cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
				StackName: aws.String("dynamodb-mapping"), TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties)),
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
				lambdaKinesisMappingState(t, clients, source, id, "Enabled")
			}

			want := map[string]cloudFormationDynamoDBDelivery{}
			previous := map[string]map[string]any{}
			committed := map[string]int{}
			observe := func() map[string]int {
				t.Helper()
				seen := cloudFormationDynamoDBObserved(t, clients, fixture.Prefix, targetARN, want)
				for label, count := range committed {
					if seen[label] != count {
						t.Fatalf("checkpointed record %s replayed or disappeared after update/reopen: before=%d after=%d", label, count, seen[label])
					}
				}
				return seen
			}
			put := func(label, phase, table, arn string, deliver bool) {
				t.Helper()
				image := map[string]any{}
				item := map[string]ddbtypes.AttributeValue{}
				// Rewriting the same key keeps every business record and its later
				// checkpoint on the same shard, even when the table has many shards.
				for key, value := range map[string]string{"pk": "ordered", "id": label, "phase": phase} {
					item[key] = &ddbtypes.AttributeValueMemberS{Value: value}
					image[key] = map[string]any{"S": value}
				}
				if _, err := ddb().PutItem(t.Context(), &dynamodb.PutItemInput{TableName: &table, Item: item}); err != nil {
					t.Fatal(err)
				}
				if deliver {
					want[label] = cloudFormationDynamoDBDelivery{sourceARN: arn, newImage: image, oldImage: previous[table]}
				}
				previous[table] = image
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
			checkpoint := func(label, phase, table, arn string) {
				t.Helper()
				marker := "checkpoint-" + label
				put(marker, phase, table, arn, true)
				await(marker)
				// Logging alone does not commit a source batch. A later BatchSize=1
				// invocation for this key proves its earlier batches were committed.
				// Retain observed counts, not an exactly-once delivery assumption;
				// the final marker itself is allowed to remain in flight and retry.
				for record, count := range observe() {
					if want[record].sourceARN == arn && !strings.HasPrefix(record, "checkpoint-") {
						committed[record] = count
					}
				}
			}
			settle := func() {
				t.Helper()
				advanceClock(t, source, 2*time.Second)
				if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 256); err != nil {
					t.Fatal(err)
				}
			}

			put("disabled-backlog", "first", tableName, streamARN, true)
			put("initial-filtered", "other", tableName, streamARN, false)
			clients = reopen()
			stack = cloudFormationWait(t, clients, source, cfn(), aws.ToString(created.StackId), cfntypes.StackStatusCreateComplete)
			if cloudFormationKinesisMappingIdentity(t, clients, stack) != id {
				t.Fatal("reopen changed the CloudFormation-owned mapping identity")
			}
			lambdaKinesisMappingState(t, clients, source, id, "Disabled")
			settle()
			if got := observe(); len(got) != 0 {
				t.Fatalf("disabled mapping invoked its retained backlog: %v", got)
			}
			properties["Enabled"] = true
			update(false)
			await("disabled-backlog")
			checkpoint("initial", "first", tableName, streamARN)

			properties["FilterCriteria"] = cloudFormationDynamoDBFilter("second")
			update(false)
			put("old-filter-rejected", "first", tableName, streamARN, false)
			put("new-filter-accepted", "second", tableName, streamARN, true)
			await("new-filter-accepted")
			checkpoint("filter", "second", tableName, streamARN)

			delete(properties, "FilterCriteria")
			update(false)
			put("cleared-filter", "neither", tableName, streamARN, true)
			await("cleared-filter")
			checkpoint("clear", "neither", tableName, streamARN)

			denyName := "cfn-live-source-denial"
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
				RoleName: role.RoleName, PolicyName: &denyName,
				PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"dynamodb:GetRecords","Resource":%q}}`, streamARN)),
			}); err != nil {
				t.Fatal(err)
			}
			lambdaKinesisAwaitDenied(t, clients, source, id, "dynamodb:GetRecords")
			put("denied-until-reopen", "neither", tableName, streamARN, true)
			clients = reopen()
			settle()
			lambdaKinesisAwaitDenied(t, clients, source, id, "dynamodb:GetRecords")
			if observe()["denied-until-reopen"] != 0 {
				t.Fatal("current execution-role denial did not retain the source record across reopen")
			}
			if _, err := clients.iam("test", "test", "").DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: role.RoleName, PolicyName: &denyName}); err != nil {
				t.Fatal(err)
			}
			await("denied-until-reopen")
			checkpoint("recovered", "neither", tableName, streamARN)

			// StartingPosition replacement is create-before-delete. The same
			// source/qualified-function pair conflicts; rollback must retain it.
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
			put("after-replacement-rollback", "neither", tableName, streamARN, true)
			await("after-replacement-rollback")
			checkpoint("rollback", "neither", tableName, streamARN)

			newTable := tableName + "-replacement"
			tableInput.TableName = &newTable
			if _, err := ddb().CreateTable(t.Context(), &tableInput); err != nil {
				t.Fatal(err)
			}
			newARN := cloudFormationDynamoDBStream(t, clients, newTable)
			extraPolicy := "cfn-replacement-source"
			if _, err := clients.iam("test", "test", "").PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
				RoleName: role.RoleName, PolicyName: &extraPolicy,
				PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["dynamodb:DescribeStream","dynamodb:GetShardIterator","dynamodb:GetRecords"],"Resource":%q}}`, newARN)),
			}); err != nil {
				t.Fatal(err)
			}
			put("replacement-backlog", "neither", newTable, newARN, true)
			properties["EventSourceArn"] = newARN
			update(true)
			put("old-source-after-replacement", "neither", tableName, streamARN, false)
			await("replacement-backlog")
			checkpoint("replacement", "neither", newTable, newARN)

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
			clients = reopen()
			_, err = lambdaDynamoDBClient(clients).GetEventSourceMapping(t.Context(), &awslambda.GetEventSourceMappingInput{UUID: &id})
			assertAPIError(t, err, "ResourceNotFoundException")
			put("after-mapping-deletion", "neither", newTable, newARN, false)

			// Progress on the old stream proves prerequisites remain usable and
			// exposes any deleted/replaced poller still consuming either stream.
			// The fresh filter excludes that stream's already-processed history.
			properties["EventSourceArn"] = streamARN
			properties["FilterCriteria"] = cloudFormationDynamoDBFilter("fresh")
			fresh, err := cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{
				StackName: aws.String("dynamodb-mapping-after-delete"), TemplateBody: aws.String(cloudFormationKinesisTemplate(t, properties)),
			})
			if err != nil {
				t.Fatal(err)
			}
			freshStack := cloudFormationWait(t, clients, source, cfn(), aws.ToString(fresh.StackId), cfntypes.StackStatusCreateComplete)
			freshID := cloudFormationKinesisMappingIdentity(t, clients, freshStack)
			put("native-prerequisites-survive", "fresh", tableName, streamARN, true)
			await("native-prerequisites-survive")
			checkpoint("surviving", "fresh", tableName, streamARN)
			deleteStack(fresh.StackId, freshID)
			observed := observe()
			for label := range want {
				if observed[label] == 0 {
					t.Fatalf("handler lost accepted record %s", label)
				}
			}
			if _, err := clients.iam("test", "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: role.RoleName}); err != nil {
				t.Fatal("mapping lifecycle removed its native-owned role", err)
			}
			if _, err := lambdaDynamoDBClient(clients).GetFunction(t.Context(), &awslambda.GetFunctionInput{FunctionName: &targetARN}); err != nil {
				t.Fatal("mapping lifecycle removed its native-owned qualified function", err)
			}
			for table, arn := range map[string]string{tableName: streamARN, newTable: newARN} {
				if got := cloudFormationDynamoDBStream(t, clients, table); got != arn {
					t.Fatalf("mapping lifecycle replaced native-owned stream: got %s want %s", got, arn)
				}
			}
			// Native prerequisite cleanup is explicit and outside CloudFormation.
			// The fixture also owns container cleanup when an assertion fails.
			if _, err := lambdaDynamoDBClient(clients).DeleteFunction(t.Context(), &awslambda.DeleteFunctionInput{FunctionName: &fixture.Prefix}); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{tableName, newTable} {
				if _, err := ddb().DeleteTable(t.Context(), &dynamodb.DeleteTableInput{TableName: &table}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func cloudFormationDynamoDBStream(t *testing.T, clients cloudClients, table string) string {
	t.Helper()
	client := dynamoClient(clients, "test", "test", clients.server.Client())
	if err := dynamoWaitActive(t.Context(), client, table); err != nil {
		t.Fatal(err)
	}
	out, err := client.DescribeTable(t.Context(), &dynamodb.DescribeTableInput{TableName: &table})
	if err != nil {
		t.Fatal(err)
	}
	if out.Table == nil || aws.ToString(out.Table.LatestStreamArn) == "" {
		t.Fatalf("table %s has no native stream: %+v", table, out)
	}
	return aws.ToString(out.Table.LatestStreamArn)
}

func cloudFormationDynamoDBFilter(phase string) map[string]any {
	return map[string]any{"Filters": []any{map[string]any{"Pattern": fmt.Sprintf(`{"dynamodb":{"NewImage":{"phase":{"S":[%q]}}}}`, phase)}}}
}

type cloudFormationDynamoDBDelivery struct {
	sourceARN          string
	newImage, oldImage map[string]any
}

func cloudFormationDynamoDBObserved(t *testing.T, clients cloudClients, name, targetARN string, want map[string]cloudFormationDynamoDBDelivery) map[string]int {
	t.Helper()
	seen := map[string]int{}
	for _, invocation := range lambdaDynamoDBLogInvocations(t, clients, name, "DDB_PROBE ") {
		records, ok := invocation.Event["Records"].([]any)
		if !ok || len(records) != 1 {
			t.Fatalf("BatchSize=1 produced unexpected records: %+v", invocation.Event)
		}
		record := records[0].(map[string]any)
		data := record["dynamodb"].(map[string]any)
		image := data["NewImage"].(map[string]any)
		label, _ := image["id"].(map[string]any)["S"].(string)
		expected, ok := want[label]
		if !ok {
			t.Fatalf("filtered, detached, or deleted source delivered %q: %+v", label, invocation)
		}
		seen[label]++
		eventName := "INSERT"
		var oldImage any
		if expected.oldImage != nil {
			eventName = "MODIFY"
			oldImage = expected.oldImage
		}
		if !reflect.DeepEqual(data["Keys"], map[string]any{"pk": map[string]any{"S": "ordered"}}) ||
			!reflect.DeepEqual(image, expected.newImage) || !reflect.DeepEqual(data["OldImage"], oldImage) ||
			record["eventName"] != eventName || record["eventSource"] != "aws:dynamodb" ||
			record["eventSourceARN"] != expected.sourceARN || record["awsRegion"] != "us-east-1" ||
			data["StreamViewType"] != "NEW_AND_OLD_IMAGES" || invocation.InvokedARN != targetARN {
			t.Fatalf("handler received wrong DynamoDB record or qualified target for %q: %+v", label, invocation)
		}
	}
	return seen
}

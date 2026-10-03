package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"
)

type dynamoNativeRow struct {
	Sequence                         int
	Label, Service, Operation, Actor string
	Code                             string
	Input, Output, Error             json.RawMessage
	HTTPStatus                       int `json:"http_status"`
	Exit                             int
}

type dynamoReplaySegment struct {
	Source, Actor  string
	Rows           []int
	Reopen         bool
	UnorderedItems bool
}

type dynamoReplayWorkflow struct {
	Name            string
	Segments        []dynamoReplaySegment
	CompareCapacity bool
}

func dynamoReadJSON(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/dynamodb/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func dynamoClient(c cloudClients, key, secret string, transport aws.HTTPClient, options ...func(*dynamodb.Options)) *dynamodb.Client {
	return dynamodb.New(dynamodb.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: transport, RetryMaxAttempts: 1}, options...)
}

// The manifest is an explicit selection, not a rewrite of native outcomes. It
// records contaminated rows, asynchronous observations and untested contracts.
// No row expecting native success is accepted as an unsupported local operation.
func TestDynamoDBNativeReplay(t *testing.T) {
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	var manifest struct{ Workflows []dynamoReplayWorkflow }
	dynamoReadJSON(t, "replay", &manifest)
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: engine})
	if err != nil {
		t.Fatal(err)
	}
	for _, workflow := range manifest.Workflows {
		t.Run(workflow.Name, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					dynamoReplay(t, runtime, backend, workflow)
				})
			}
		})
	}
}

func dynamoReplay(t *testing.T, runtime dynamoengine.Runtime, backend string, workflow dynamoReplayWorkflow) {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC))
	observedRuntime := &dynamoReplayRuntime{Runtime: runtime}
	// Runs after retainedCloud's cleanup, with no controller still using the
	// native database. Remove is idempotent if asynchronous retirement finished.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		for _, spec := range observedRuntime.specifications() {
			if err := runtime.Remove(ctx, spec); err != nil {
				t.Errorf("remove owned native database %s: %v", spec.ID, err)
			}
		}
	})
	clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "000000000000", Clock: source, DynamoDBRuntime: observedRuntime})
	_, key, secret := clients.user(t, "test", "Delegated")
	putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"*"`, "*"))
	actors := map[string][2]string{"Delegated": {key, secret}}
	bindings := map[string]string{}
	tables := map[string]bool{}
	var unordered dynamoUnorderedPages
	// Defer public deletion until this replay returns, before any t.Cleanup
	// callbacks close SQLite handles opened by a later reopen.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		client := dynamoClient(clients, "test", "test", clients.server.Client())
		for table := range tables {
			if err := dynamoWaitActive(ctx, client, table); err != nil {
				t.Errorf("await native table %s before deletion: %v", table, err)
			}
			_, err := client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(table)})
			var absent *types.ResourceNotFoundException
			if err != nil && !errors.As(err, &absent) {
				t.Errorf("delete native table %s before store teardown: %v", table, err)
			}
			if err := dynamoWaitAbsent(ctx, client, table); err != nil {
				t.Errorf("await native table %s deletion: %v", table, err)
			}
		}
	}()
	for _, segment := range workflow.Segments {
		var fixture struct{ Calls []dynamoNativeRow }
		dynamoReadJSON(t, segment.Source, &fixture)
		for _, number := range segment.Rows {
			if number < 1 || number > len(fixture.Calls) {
				t.Fatalf("%s has no call %d", segment.Source, number)
			}
			row := fixture.Calls[number-1]
			if row.Sequence != 0 && row.Sequence != number {
				t.Fatalf("%s call %d moved to sequence %d", segment.Source, number, row.Sequence)
			}
			if segment.Actor != "" {
				row.Actor = segment.Actor
			}
			if row.Actor == "" {
				row.Actor = "Delegated"
			}
			if row.Service == "" {
				row.Service = "dynamodb"
				if strings.HasSuffix(row.Operation, "user-policy") || row.Operation == "create-access-key" {
					row.Service = "iam"
				}
			}
			if row.Code == "" {
				row.Code = "Success"
				if row.Exit != 0 {
					row.Code, _ = ecsControlBody(t, row.Output)["Code"].(string)
					if row.Code == "" {
						t.Fatalf("%s/%d lacks a native API error code", segment.Source, number)
					}
				}
			}
			if !t.Run(fmt.Sprintf("%s_%03d_%s", segment.Source, number, row.Label), func(t *testing.T) {
				credential, ok := actors[row.Actor]
				if !ok {
					t.Fatalf("no issued credentials for native actor %q", row.Actor)
				}
				input := json.RawMessage(aasReplace(string(row.Input), bindings))
				if row.Service == "iam" {
					// The original PartiQL capture redacted this request, but retained
					// the key owner's name. No native secret is stored or replayed.
					if row.Operation == "create-access-key" && len(input) == 0 {
						native := ecsControlBody(t, row.Output)["AccessKey"].(map[string]any)
						input, _ = json.Marshal(map[string]any{"UserName": native["UserName"]})
					}
					if row.Operation == "delete-access-key" {
						value := ecsControlBody(t, input)
						value["AccessKeyId"] = actors[value["UserName"].(string)][0]
						input, _ = json.Marshal(value)
					}
					out, err := awstest.CallSDK(t.Context(), clients.iam(credential[0], credential[1], ""), row.Operation, input)
					if row.Code != "Success" {
						assertAPIError(t, err, row.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					switch out := out.(type) {
					case *iam.CreateUserOutput:
						native := ecsControlBody(t, row.Output)["User"].(map[string]any)
						aasBind(t, bindings, native["UserId"].(string), aws.ToString(out.User.UserId))
						if aws.ToString(out.User.Arn) != native["Arn"] {
							t.Fatalf("user ARN %s want %s", aws.ToString(out.User.Arn), native["Arn"])
						}
					case *iam.CreateAccessKeyOutput:
						actors[aws.ToString(out.AccessKey.UserName)] = [2]string{aws.ToString(out.AccessKey.AccessKeyId), aws.ToString(out.AccessKey.SecretAccessKey)}
					}
					return
				}
				if row.Service != "dynamodb" {
					t.Fatalf("unselected prerequisite service %s", row.Service)
				}
				wire := &awstest.WireClient{Client: clients.server.Client()}
				client := dynamoClient(clients, credential[0], credential[1], wire)
				out, err := awstest.CallSDK(t.Context(), client, row.Operation, json.RawMessage(`{}`), func(target any) { dynamoSDKInput(t, target, input) })
				if created, ok := out.(*dynamodb.CreateTableOutput); ok && created != nil && created.TableDescription != nil {
					tables[aws.ToString(created.TableDescription.TableName)] = true
				}
				if row.Code == "Success" {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					assertAPIError(t, err, row.Code)
				}
				status := row.HTTPStatus
				if status == 0 {
					status = 200
					if row.Code != "Success" {
						status = 400
					}
				}
				if wire.Status != status {
					t.Fatalf("HTTP status %d want %d", wire.Status, status)
				}
				expectedRaw := row.Output
				if len(row.Error) != 0 {
					expectedRaw = row.Error
				}
				actual := ecsControlBody(t, wire.Body)
				expected := ecsControlBody(t, expectedRaw)
				if row.Operation == "execute-statement" {
					dynamoTerminalPage(t, client, input, expected, actual)
					if segment.UnorderedItems {
						unordered.comparePage(t, expected, actual)
					}
				}
				dynamoCompare(t, row.Operation, expected, actual, bindings, workflow.CompareCapacity)
				if row.Code == "Success" && (row.Operation == "create-table" || row.Operation == "update-table") {
					table := ecsControlBody(t, input)["TableName"].(string)
					if err := dynamoWaitActive(t.Context(), client, table); err != nil {
						t.Fatal(err)
					}
				}
			}) {
				return // Subsequent rows depend on this state; never replay on corruption.
			}
		}
		if segment.Reopen {
			clients = reopen()
		}
	}
	if len(unordered.expected) != 0 || len(unordered.actual) != 0 {
		t.Fatal("unordered native page chain did not terminate")
	}
}

// AWS permits a nonempty LastEvaluatedKey even when no data remains. Native
// captures include both direct exhaustion and a final empty page. Verify the
// extra continuation terminates without data; do not pin exporter pagination
// choices that ExecuteStatement's documented contract does not guarantee.
func dynamoTerminalPage(t *testing.T, client *dynamodb.Client, input json.RawMessage, expected, actual map[string]any) {
	t.Helper()
	if expected["LastEvaluatedKey"] == nil && expected["NextToken"] != nil {
		// AWS may omit a key at an exhausted range while returning a token
		// for later ranges. An additional key is legal only if it identifies
		// the actual last item, not an invented or out-of-page position.
		key, hasKey := actual["LastEvaluatedKey"].(map[string]any)
		items, hasItems := actual["Items"].([]any)
		if hasKey && hasItems && len(items) != 0 {
			last := items[len(items)-1].(map[string]any)
			for name, attribute := range key {
				if !reflect.DeepEqual(last[name], attribute) {
					t.Fatalf("evaluated key %v does not identify the last item %v", key, last)
				}
			}
			delete(actual, "LastEvaluatedKey")
		}
	}
	if expected["NextToken"] != nil || expected["LastEvaluatedKey"] != nil {
		return
	}
	token, ok := actual["NextToken"].(string)
	if !ok {
		return
	}
	var request dynamodb.ExecuteStatementInput
	dynamoSDKInput(t, &request, input)
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(aws.ToString(request.Statement))), "SELECT ") {
		t.Fatalf("write returned a continuation: %v", actual)
	}
	seen := make(map[string]bool)
	for token != "" {
		if seen[token] {
			t.Fatal("terminal continuation did not progress")
		}
		seen[token] = true
		request.NextToken = &token
		out, err := client.ExecuteStatement(t.Context(), &request)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Items) != 0 {
			t.Fatalf("continuation returned uncaptured data: %v", out.Items)
		}
		token = aws.ToString(out.NextToken)
	}
	delete(actual, "NextToken")
	delete(actual, "LastEvaluatedKey")
}

// Hash-only index queries and full-table scans have no ordering guarantee.
// Compare the complete page chain as a multiset, retaining counts, charges,
// continuation presence and each returned key's correspondence to its last item.
type dynamoUnorderedPages struct{ expected, actual []any }

func (pages *dynamoUnorderedPages) comparePage(t *testing.T, expected, actual map[string]any) {
	t.Helper()
	want, ok := expected["Items"].([]any)
	if !ok {
		return
	}
	got, ok := actual["Items"].([]any)
	if !ok || len(got) != len(want) {
		t.Fatalf("unordered page has %d items, native has %d", len(got), len(want))
	}
	if len(want) != 0 {
		wantLast := want[len(want)-1].(map[string]any)
		gotLast := got[len(got)-1].(map[string]any)
		wantKey, _ := expected["LastEvaluatedKey"].(map[string]any)
		gotKey, _ := actual["LastEvaluatedKey"].(map[string]any)
		for name, value := range wantKey {
			if projected, ok := wantLast[name]; ok && reflect.DeepEqual(projected, value) {
				if !reflect.DeepEqual(gotLast[name], gotKey[name]) {
					t.Fatalf("unordered continuation key %s does not match its last item", name)
				}
				wantKey[name] = gotLast[name]
			}
		}
	}
	pages.expected = append(pages.expected, want...)
	pages.actual = append(pages.actual, got...)
	if expected["NextToken"] != nil {
		delete(expected, "Items")
		delete(actual, "Items")
		return
	}
	if len(pages.expected) != 0 {
		dynamoSort(pages.expected)
		dynamoSort(pages.actual)
		expected["Items"], actual["Items"] = pages.expected, pages.actual
	}
	pages.expected, pages.actual = nil, nil
}

func dynamoCompare(t *testing.T, operation string, expected, actual map[string]any, bindings map[string]string, compareCapacity bool) {
	t.Helper()
	if operation == "create-table" || operation == "update-table" || operation == "describe-table" {
		field := "TableDescription"
		if operation == "describe-table" {
			field = "Table"
		}
		if table, ok := expected[field].(map[string]any); ok {
			got, ok := actual[field].(map[string]any)
			if !ok {
				t.Fatalf("missing %s in %v", field, actual)
			}
			if id, ok := table["TableId"].(string); ok {
				actualID, ok := got["TableId"].(string)
				if !ok || actualID == "" {
					t.Fatalf("missing table identity: %v", got)
				}
				aasBind(t, bindings, id, actualID)
			}
			// Native Create/Update descriptions are asynchronous. Compare accepted
			// schema/identity here, and capacity/status at selected ACTIVE reads.
			expected = dynamoTableContract(table, operation)
			actual = dynamoTableContract(got, operation)
		}
	}
	for _, field := range []string{"RevisionId", "NextToken"} {
		if native, ok := expected[field].(string); ok {
			local, ok := actual[field].(string)
			if !ok || local == "" {
				t.Fatalf("missing %s in %v", field, actual)
			}
			if field == "NextToken" {
				bindings[native] = local // Opaque cursor bytes, not resource identities.
			} else {
				aasBind(t, bindings, native, local)
			}
		}
	}
	for _, body := range []map[string]any{expected, actual} {
		// CLI captures carry Code/Message while AWS JSON carries __type/message.
		// The SDK error code is asserted separately; old Item and ordered reasons
		// are compared in full. The manifest selects capacity-metering workflows.
		if !compareCapacity {
			delete(body, "ConsumedCapacity")
		}
		for _, key := range []string{"Code", "Message", "message", "__type"} {
			delete(body, key)
		}
		if reasons, ok := body["CancellationReasons"].([]any); ok {
			for _, reason := range reasons {
				delete(reason.(map[string]any), "Message")
			}
		}
		if responses, ok := body["Responses"].([]any); ok {
			for _, response := range responses {
				if failure, ok := response.(map[string]any)["Error"].(map[string]any); ok {
					delete(failure, "Message")
				}
			}
		}
		if text, ok := body["Policy"].(string); ok {
			body["Policy"] = ecsControlBody(t, []byte(aasReplace(text, bindings)))
		}
		dynamoUnordered(body)
	}
	encoded, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	expected = ecsControlBody(t, []byte(aasReplace(string(encoded), bindings)))
	if !reflect.DeepEqual(expected, actual) {
		got, _ := json.Marshal(actual)
		want, _ := json.Marshal(expected)
		t.Fatalf("native semantic response mismatch\n got %s\nwant %s", got, want)
	}
}

func dynamoTableContract(table map[string]any, operation string) map[string]any {
	out := map[string]any{}
	fields := []string{"TableName", "TableArn", "TableId", "AttributeDefinitions", "KeySchema", "LocalSecondaryIndexes", "GlobalSecondaryIndexes", "DeletionProtectionEnabled"}
	if operation != "update-table" {
		fields = append(fields, "ProvisionedThroughput", "BillingModeSummary", "TableClassSummary")
	}
	if operation == "describe-table" {
		fields = append(fields, "TableStatus")
	}
	for _, field := range fields {
		if value, ok := table[field]; ok {
			out[field] = value
		}
	}
	var prune func(any)
	prune = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for _, field := range []string{"LastIncreaseDateTime", "LastDecreaseDateTime", "LastUpdateToPayPerRequestDateTime", "LastUpdateDateTime", "NumberOfDecreasesToday", "IndexStatus", "IndexSizeBytes", "ItemCount", "WarmThroughput", "Backfilling"} {
				delete(value, field)
			}
			if operation == "update-table" {
				delete(value, "ProvisionedThroughput")
			}
			for _, child := range value {
				prune(child)
			}
		case []any:
			for _, child := range value {
				prune(child)
			}
		}
	}
	prune(out)
	return out
}

func dynamoUnordered(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			dynamoUnordered(child)
			// DynamoDB sets, schema declarations, tags and BatchGetItems results
			// are unordered. Query items, lists, transaction responses and
			// cancellation reasons retain native ordering, including empty slots.
			// Fixture selections may name a dotted response field.
			field := key[strings.LastIndex(key, ".")+1:]
			if values, ok := child.([]any); ok && slices.Contains([]string{"SS", "NS", "BS", "AttributeDefinitions", "Tags", "NonKeyAttributes", "GlobalSecondaryIndexes", "LocalSecondaryIndexes"}, field) {
				dynamoSort(values)
			}
			if key == "Responses" {
				if tables, ok := child.(map[string]any); ok {
					for _, items := range tables {
						dynamoSort(items.([]any))
					}
				}
			}
		}
	case []any:
		for _, child := range value {
			dynamoUnordered(child)
		}
	}
}

func dynamoSort(values []any) {
	slices.SortFunc(values, func(a, b any) int {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return strings.Compare(string(left), string(right))
	})
}

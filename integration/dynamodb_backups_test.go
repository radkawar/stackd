package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodbstreams"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	dynamoengine "stackd/engine/dynamodb"
	"stackd/internal/awstest"
)

type dynamoBackupStep struct {
	Name, Operation, Code, Advance string
	Region                         string
	Audit                          string
	Input                          json.RawMessage
	UserPolicy                     json.RawMessage
	Want                           map[string]any
	Bind                           map[string]string
	Backups                        []string
	Reopen, WaitBackup             bool
	EnginePaused                   *bool
	RestorePaused                  *bool
	WaitRestoreBarrier             bool
	CommitFailureOperation         string
	WaitItemAbsent                 bool
	WaitTableAbsent                bool
	WaitWant                       bool
	Async                          bool
}

// The native capture supplies schema, typed items, errors and lifecycle fields.
// Local extensions retain those contracts across source expiry and both store
// reopens. Recovery replay can suspend native readiness without faking results.
func TestDynamoDBBackupContracts(t *testing.T) {
	replayDynamoBackupContracts(t, "../testdata/dynamodb/backups.json")
}

func TestDynamoDBRecoveryContracts(t *testing.T) {
	for _, name := range []string{"dynamodb_recovery", "dynamodb_recovery_mutations", "dynamodb_recovery_system", "dynamodb_recovery_audit", "dynamodb_recovery_tokens", "dynamodb_recovery_readiness"} {
		t.Run(name, func(t *testing.T) {
			replayDynamoBackupContracts(t, "../testdata/integration/"+name+".json")
		})
	}
}

func TestDynamoDBReplicationContracts(t *testing.T) {
	for _, name := range []string{"dynamodb_replication", "dynamodb_replication_mutations", "dynamodb_replication_recovery", "dynamodb_replication_authorization", "dynamodb_replication_conflicts", "dynamodb_replication_transitions", "dynamodb_replication_ttl", "dynamodb_replication_stream_views", "dynamodb_replication_scaling", "dynamodb_replication_billing", "dynamodb_replication_combined", "dynamodb_replication_autoscaling", "dynamodb_replication_legacy"} {
		t.Run(name, func(t *testing.T) {
			replayDynamoBackupContracts(t, "../testdata/integration/"+name+".json")
		})
	}
}

func replayDynamoBackupContracts(t *testing.T, fixturePath string) {
	t.Helper()
	if os.Getenv("STACKD_DYNAMODB_DOCKER") != "1" {
		t.Skip("set STACKD_DYNAMODB_DOCKER=1 to exercise pinned DynamoDB Local")
	}
	var fixture struct {
		Account       string
		Start         time.Time
		Steps         []dynamoBackupStep
		AuditBindings map[string]string
		AuditFixture  string
	}
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	runtime, err := dynamoengine.NewDocker(t.Context(), dynamoengine.DockerConfig{Client: engine})
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Start)
			owned := &dynamoReplayRuntime{Runtime: runtime}
			restoreRuntime := &dynamoRestoreBarrierRuntime{Runtime: owned}
			// Registered before retainedCloud: services and repositories close
			// before fallback native removal, including retained backup databases.
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				for _, spec := range owned.specifications() {
					if err := runtime.Remove(ctx, spec); err != nil {
						t.Errorf("remove owned native database %s: %v", spec.ID, err)
					}
				}
			})
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source, DynamoDBRuntime: restoreRuntime})
			_, key, secret := clients.user(t, fixture.Account, "Delegated")
			putUserPolicy(t, clients.iam(fixture.Account, "test", ""), "Delegated", allow(`"*"`, "*"))
			expectedAudit := map[string]string{}
			bindings := map[string]json.RawMessage{}
			type regionalResource struct{ region, name string }
			tables, backups := map[regionalResource]bool{}, map[regionalResource]bool{}
			// Use the latest server before retainedCloud closes its SQLite handle.
			defer func() {
				restoreRuntime.setPaused(false)
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				if err := owned.setPaused(ctx, engine, false); err != nil {
					t.Errorf("resume owned native engines: %v", err)
				}
				// A failed fixture may leave its source protected for 24 hours.
				// Advance only the fixture clock before removing owned resources.
				if len(tables) != 0 {
					if err := source.Advance(25 * time.Hour); err != nil {
						t.Errorf("advance owned-resource cleanup clock: %v", err)
					}
				}
				regionalClient := func(region string) *dynamodb.Client {
					return dynamoClient(clients, "test", "test", clients.server.Client(), func(options *dynamodb.Options) {
						options.Region = region
					})
				}
				for backup := range backups {
					client := regionalClient(backup.region)
					_, err := client.DeleteBackup(ctx, &dynamodb.DeleteBackupInput{BackupArn: aws.String(backup.name)})
					var absent *types.BackupNotFoundException
					if err != nil && !errors.As(err, &absent) {
						t.Errorf("delete owned backup %s in %s: %v", backup.name, backup.region, err)
					}
				}
				for table := range tables {
					client := regionalClient(table.region)
					_, err := client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(table.name)})
					var absent *types.ResourceNotFoundException
					if err != nil && !errors.As(err, &absent) {
						t.Errorf("delete owned table %s in %s: %v", table.name, table.region, err)
					}
					if err := dynamoWaitAbsent(ctx, client, table.name); err != nil {
						t.Errorf("await owned table deletion %s in %s: %v", table.name, table.region, err)
					}
				}
			}()
			for _, step := range fixture.Steps {
				if !t.Run(step.Name, func(t *testing.T) {
					if step.UserPolicy != nil {
						putUserPolicy(t, clients.iam(fixture.Account, "test", ""), "Delegated", string(step.UserPolicy))
					}
					if step.RestorePaused != nil {
						restoreRuntime.setPaused(*step.RestorePaused)
					}
					if step.EnginePaused != nil {
						if err := owned.setPaused(t.Context(), engine, *step.EnginePaused); err != nil {
							t.Fatal(err)
						}
					}
					advance := time.Second
					if step.Advance != "" {
						var err error
						advance, err = time.ParseDuration(step.Advance)
						if err != nil {
							t.Fatal(err)
						}
					}
					advanceClock(t, source, advance)
					// Do not await external work while its real engine is suspended.
					if len(owned.paused) == 0 && restoreRuntime.pending() == nil {
						trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
					}
					if step.Reopen {
						clients = reopen()
					}
					if step.Operation == "" {
						return
					}
					input := dynamoBackupBound(t, step.Input, bindings)
					wire := &awstest.WireClient{Client: clients.server.Client()}
					region := step.Region
					if region == "" {
						region = "us-east-1"
					}
					client := dynamoClient(clients, key, secret, wire, func(options *dynamodb.Options) {
						options.Region = region
					})
					if step.WaitItemAbsent {
						var request dynamodb.GetItemInput
						dynamoBackupInput(t, &request, input)
						ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
						defer cancel()
						for {
							result, err := client.GetItem(ctx, &request)
							if err != nil {
								t.Fatal(err)
							}
							if len(result.Item) == 0 {
								break
							}
							select {
							case <-ctx.Done():
								t.Fatal(ctx.Err())
							case <-time.After(20 * time.Millisecond):
							}
						}
					}
					if step.WaitTableAbsent {
						if err := dynamoWaitAbsent(t.Context(), client, ecsControlBody(t, input)["TableName"].(string)); err != nil {
							t.Fatal(err)
						}
					}
					if !step.WaitWant && step.Operation == "DescribeTable" && step.Want["Table.TableStatus"] == "ACTIVE" {
						if err := dynamoWaitActive(t.Context(), client, ecsControlBody(t, input)["TableName"].(string)); err != nil {
							t.Fatal(err)
						}
					}
					if step.WaitBackup {
						arn := ecsControlBody(t, input)["BackupArn"].(string)
						dynamoBackupWait(t, source, client, arn)
					}
					var sdkClient any = client
					switch step.Operation {
					case "DescribeStream", "GetShardIterator", "GetRecords", "ListStreams":
						sdkClient = dynamodbstreams.New(dynamodbstreams.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: wire, RetryMaxAttempts: 1})
					case "RegisterScalableTarget", "DeregisterScalableTarget", "DescribeScalableTargets", "PutScalingPolicy", "DeleteScalingPolicy", "DescribeScalingPolicies", "DescribeScalingActivities":
						sdkClient = applicationautoscaling.New(applicationautoscaling.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: wire, RetryMaxAttempts: 1})
					}
					var commitFailure <-chan struct{}
					if step.CommitFailureOperation != "" {
						commitFailure = owned.failAfterCommit(step.CommitFailureOperation)
					}
					wantRaw, err := json.Marshal(step.Want)
					if err != nil {
						t.Fatal(err)
					}
					var want map[string]any
					if step.WaitWant {
						want = ecsControlBody(t, dynamoBackupBound(t, wantRaw, bindings))
					}
					callCtx := t.Context()
					if step.WaitWant {
						switch step.Operation {
						case "GetItem", "DescribeTable", "DescribeTableReplicaAutoScaling", "DescribeTimeToLive", "DescribeContinuousBackups", "DescribeStream", "GetRecords", "DescribeScalableTargets", "DescribeScalingPolicies", "DescribeScalingActivities":
						default:
							t.Fatalf("WaitWant is restricted to read-only state observations, got %s", step.Operation)
						}
						if len(want) == 0 || step.Code != "" {
							t.Fatal("WaitWant requires selected successful response fields")
						}
						var cancel context.CancelFunc
						callCtx, cancel = context.WithTimeout(callCtx, 60*time.Second)
						defer cancel()
					}
					var out any
					for {
						out, err = awstest.CallSDK(callCtx, sdkClient, step.Operation, json.RawMessage(`{}`), func(target any) {
							dynamoBackupInput(t, target, input)
						})
						if !step.WaitWant {
							break
						}
						var absent *types.ResourceNotFoundException
						if err != nil && !errors.As(err, &absent) {
							t.Fatal(err)
						}
						matches := err == nil
						if matches {
							actual := ecsControlBody(t, wire.Body)
							for field, value := range want {
								if !reflect.DeepEqual(dynamoAdmissionField(t, actual, field), value) {
									matches = false
									break
								}
							}
						}
						if matches {
							break
						}
						select {
						case <-callCtx.Done():
							t.Fatalf("await %s in %s: want %v, last response %s, error %v", step.Operation, region, want, wire.Body, err)
						case <-time.After(100 * time.Millisecond):
							advanceClock(t, source, 100*time.Millisecond)
							trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
						}
					}
					if commitFailure != nil {
						// DeleteTable commits asynchronously in the controller. Even
						// failed SDK calls must not pass until native commit was real.
						ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
						defer cancel()
						select {
						case <-commitFailure:
						case <-ctx.Done():
							t.Fatalf("%s did not reach its native post-commit failure boundary: %v", step.CommitFailureOperation, err)
						}
					}
					if step.Audit != "" {
						expectedAudit[nativeAuditRequestID(t, out, err)] = step.Audit
					}
					if step.Code != "" {
						assertAPIError(t, err, step.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if step.WaitRestoreBarrier {
						barrier := restoreRuntime.pending()
						if barrier == nil {
							t.Fatal("restore readiness barrier is not armed")
						}
						ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
						defer cancel()
						select {
						case <-barrier.reached:
						case <-ctx.Done():
							t.Fatal("restore did not reach native readiness barrier")
						}
					}
					actual := ecsControlBody(t, wire.Body)
					for token, field := range step.Bind {
						value := dynamoAdmissionField(t, actual, field)
						if value == nil || value == "" {
							t.Fatalf("missing generated %s: %v", field, actual)
						}
						encoded, err := json.Marshal(value)
						if err != nil {
							t.Fatal(err)
						}
						bindings[token] = encoded
					}
					if !step.WaitWant {
						want = ecsControlBody(t, dynamoBackupBound(t, wantRaw, bindings))
					}
					switch result := out.(type) {
					case *dynamodb.CreateTableOutput:
						tables[regionalResource{region, aws.ToString(result.TableDescription.TableName)}] = true
					case *dynamodb.RestoreTableFromBackupOutput:
						tables[regionalResource{region, aws.ToString(result.TableDescription.TableName)}] = true
					case *dynamodb.RestoreTableToPointInTimeOutput:
						tables[regionalResource{region, aws.ToString(result.TableDescription.TableName)}] = true
					case *dynamodb.UpdateTableOutput:
						for _, replica := range result.TableDescription.Replicas {
							tables[regionalResource{aws.ToString(replica.RegionName), aws.ToString(result.TableDescription.TableName)}] = true
						}
					case *dynamodb.CreateBackupOutput:
						backups[regionalResource{region, aws.ToString(result.BackupDetails.BackupArn)}] = true
					case *dynamodb.ListBackupsOutput:
						if len(result.BackupSummaries) != len(step.Backups) {
							t.Fatalf("listed %d backups, want %d", len(result.BackupSummaries), len(step.Backups))
						}
						for i, backup := range result.BackupSummaries {
							want, _ := json.Marshal(step.Backups[i])
							got, _ := json.Marshal(aws.ToString(backup.BackupArn))
							if string(got) != string(dynamoBackupBound(t, want, bindings)) {
								t.Fatalf("backup page entry %d: %s want %s", i, got, want)
							}
						}
					}
					if len(want) != 0 {
						selected := make(map[string]any, len(want))
						for field := range want {
							selected[field] = dynamoAdmissionField(t, actual, field)
						}
						if step.Operation == "Scan" {
							for _, body := range []map[string]any{want, selected} {
								if items, ok := body["Items"].([]any); ok {
									dynamoUnordered(items)
									dynamoSort(items)
								}
							}
						}
						dynamoCompare(t, step.Operation, want, selected, nil, true)
					}
					request := ecsControlBody(t, input)
					switch step.Operation {
					case "CreateTable", "RestoreTableFromBackup", "RestoreTableToPointInTime":
						if step.Async || len(owned.paused) != 0 || restoreRuntime.pending() != nil {
							break
						}
						field := "TableName"
						if step.Operation != "CreateTable" {
							field = "TargetTableName"
						}
						if err := dynamoWaitActive(t.Context(), client, request[field].(string)); err != nil {
							t.Fatal(err)
						}
					case "DeleteTable":
						if step.Async || commitFailure != nil || restoreRuntime.pending() != nil {
							break
						}
						if err := dynamoWaitAbsent(t.Context(), client, request["TableName"].(string)); err != nil {
							t.Fatal(err)
						}
						delete(tables, regionalResource{region, request["TableName"].(string)})
					}
				}) {
					return
				}
			}
			if len(expectedAudit) != 0 {
				dynamoBackupAudit(t, clients, expectedAudit, fixture.AuditFixture, fixture.AuditBindings, bindings, key, fixture.Account)
			}
		})
	}
}

// Replace complete JSON values, not substrings: generated timestamps remain
// numbers, and absent, null and explicitly empty index overrides stay distinct.
func dynamoBackupBound(t *testing.T, raw json.RawMessage, bindings map[string]json.RawMessage) json.RawMessage {
	t.Helper()
	text := string(raw)
	for token, value := range bindings {
		quoted, _ := json.Marshal(token)
		text = strings.ReplaceAll(text, string(quoted), string(value))
	}
	return json.RawMessage(text)
}

// dynamoSDKInput handles AttributeValue and nil/empty slices. Backup list bounds
// and point-in-time restore selections also accept numeric AWS-JSON timestamps.
func dynamoBackupInput(t *testing.T, target any, raw json.RawMessage) {
	t.Helper()
	var times map[string]**time.Time
	switch input := target.(type) {
	case *dynamodb.ListBackupsInput:
		times = map[string]**time.Time{"TimeRangeLowerBound": &input.TimeRangeLowerBound, "TimeRangeUpperBound": &input.TimeRangeUpperBound}
	case *dynamodb.RestoreTableToPointInTimeInput:
		times = map[string]**time.Time{"RestoreDateTime": &input.RestoreDateTime}
	default:
		dynamoSDKInput(t, target, raw)
		return
	}
	body := ecsControlBody(t, raw)
	for field, target := range times {
		if value, exists := body[field]; exists {
			seconds, ok := value.(float64)
			if !ok {
				t.Fatalf("%s must be bound to epoch seconds, got %v", field, value)
			}
			*target = aws.Time(time.UnixMilli(int64(seconds * 1000)).UTC())
			delete(body, field)
		}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	dynamoSDKInput(t, target, encoded)
}

func dynamoBackupWait(t *testing.T, source *clock.Manual, client *dynamodb.Client, arn string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	for {
		out, err := client.DescribeBackup(ctx, &dynamodb.DescribeBackupInput{BackupArn: aws.String(arn)})
		if err != nil {
			t.Fatal(err)
		}
		if out.BackupDescription != nil && out.BackupDescription.BackupDetails != nil && out.BackupDescription.BackupDetails.BackupStatus == types.BackupStatusAvailable {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
			advanceClock(t, source, 100*time.Millisecond)
		}
	}
}

// Compare public Event History documents and its independently projected lookup
// aliases against native records. Polling and nonselected setup calls are not
// reconstructed into artificial expected events.
func dynamoBackupAudit(t *testing.T, clients cloudClients, expected map[string]string, fixture string, identities map[string]string, bindings map[string]json.RawMessage, key, account string) {
	t.Helper()
	var capture struct {
		Selected []struct {
			Role                  string
			CloudTrailEvent       json.RawMessage
			LookupEventsResources json.RawMessage
		}
	}
	if fixture == "" {
		fixture = "backup_audit"
	}
	dynamoReadJSON(t, fixture, &capture)
	documents, aliases := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	for _, event := range capture.Selected {
		documents[event.Role], aliases[event.Role] = event.CloudTrailEvent, event.LookupEventsResources
	}
	seen := map[string]bool{}
	pages := cloudtrail.NewLookupEventsPaginator(organizationsAuditClient(clients, account, "us-east-1"), &cloudtrail.LookupEventsInput{MaxResults: aws.Int32(50), LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventSource, AttributeValue: aws.String("dynamodb.amazonaws.com")}}})
	for pages.HasMorePages() {
		page, err := pages.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range page.Events {
			actual := ecsControlBody(t, []byte(aws.ToString(event.CloudTrailEvent)))
			id, _ := actual["requestID"].(string)
			role, selected := expected[id]
			if !selected {
				continue
			}
			wanted := dynamoBackupBound(t, []byte(aasReplace(string(documents[role]), identities)), bindings)
			dynamoAuditCompare(t, actual, ecsControlBody(t, wanted), nil, key, account)
			var resources []trailtypes.Resource
			if err := json.Unmarshal(dynamoBackupBound(t, []byte(aasReplace(string(aliases[role]), identities)), bindings), &resources); err != nil {
				t.Fatal(err)
			}
			if len(event.Resources) != len(resources) {
				t.Fatalf("%s lookup aliases: got %v, native %v", role, event.Resources, resources)
			}
			for i, resource := range event.Resources {
				if aws.ToString(resource.ResourceType) != aws.ToString(resources[i].ResourceType) || aws.ToString(resource.ResourceName) != aws.ToString(resources[i].ResourceName) {
					t.Fatalf("%s lookup alias %d: got %v, native %v", role, i, resource, resources[i])
				}
			}
			seen[id] = true
		}
	}
	if len(seen) != len(expected) {
		t.Fatalf("Event History returned %d of %d selected backup outcomes", len(seen), len(expected))
	}
}

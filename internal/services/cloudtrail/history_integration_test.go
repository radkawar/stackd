package cloudtrail_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdktrail "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cloudtrail"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscatalog"
	"stackd/internal/awstest"
	"stackd/internal/gateway"
	"stackd/internal/identity"
	"stackd/internal/services/cloudtrail"
	"stackd/internal/services/iam"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqliteiam "stackd/storage/sqlite/iam"
	sqlitejournal "stackd/storage/sqlite/journal"
)

type deployment struct {
	journal journal.Storage
	iam     *sdkiam.Client
	trail   *sdktrail.Client
	server  *httptest.Server
	close   func()
}

func deploy(t *testing.T, repo iam.Repository, events journal.Storage, source clock.Clock) deployment {
	t.Helper()
	creds := identity.NewWithConfig(identity.Config{Repository: iam.NewCredentialRepository(repo, events), Clock: source})
	identityService := iam.NewWithConfig(iam.Config{Repository: repo, Credentials: creds, CredentialEvents: events, APICallEvents: apievents.New(events), Clock: source})
	authorizer := authorization.NewWithClock(identityService, nil, source)
	identityService.SetAuthorizer(authorizer)
	provider := cloudtrail.New(cloudtrail.Config{Journal: events, Clock: source, Authorizer: authorizer})
	registry := &gateway.Registry{}
	iamModel, _ := awscatalog.LookupService("iam")
	if err := registry.Register(gateway.Service{Name: "iam", SigningName: "iam", Protocol: gateway.Query, QueryVersion: iamModel.Version, Namespace: iamModel.XMLNamespace, Provider: identityService, Model: &iamModel, Decode: iamapi.DecodeRequest}); err != nil {
		t.Fatal(err)
	}
	trailModel, _ := awscatalog.LookupService("cloudtrail")
	if err := registry.Register(gateway.Service{Name: "cloudtrail", SigningName: "cloudtrail", Protocol: gateway.JSON11, TargetPrefix: trailModel.TargetPrefix, Provider: provider, Model: &trailModel, Decode: api.DecodeRequest}); err != nil {
		t.Fatal(err)
	}
	handler, err := gateway.New(registry, gateway.Config{Credentials: creds, Clock: source, Activity: identityService})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	iamClient := sdkiam.New(sdkiam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	d := deployment{journal: events, iam: iamClient, server: server, close: func() { server.Close(); _ = identityService.Close() }}
	d.trail = d.client("test", "test", "us-east-1")
	t.Cleanup(d.close)
	return d
}
func (d deployment) client(key, secret, region string) *sdktrail.Client {
	return sdktrail.New(sdktrail.Options{Region: region, BaseEndpoint: aws.String(d.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: d.server.Client(), RetryMaxAttempts: 1})
}
func lookup(t *testing.T, client *sdktrail.Client, key trailtypes.LookupAttributeKey, value string) []trailtypes.Event {
	t.Helper()
	out, err := client.LookupEvents(t.Context(), &sdktrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: key, AttributeValue: aws.String(value)}}})
	if err != nil {
		t.Fatal(err)
	}
	return out.Events
}
func apiError(t *testing.T, err error, code string) {
	t.Helper()
	var e smithy.APIError
	if !errors.As(err, &e) || e.ErrorCode() != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestIAMHistorySDKNativeFieldsAndRecovery(t *testing.T) {
	var fixture struct {
		Replay []struct {
			Operation string
			Input     json.RawMessage
			ErrorCode string
		}
		Observations []struct {
			EventName         string
			ReadOnly          bool
			EventCategory     string
			ManagementEvent   bool
			ErrorCode         *string
			ResourceTypes     []string
			HasEventResources bool
			ResponseFields    map[string][]string
		}
	}
	readFixture(t, "iam_history.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
			source := clock.NewManual(epoch)
			domain := memory.NewDomain()
			var repo iam.Repository = iam.NewMemoryRepository(domain)
			events := journal.NewMemory(domain)
			path := filepath.Join(t.TempDir(), "state.sqlite")
			closeDB := func() {}
			open := func() {
				if backend == "sqlite" {
					db, err := sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					repo = sqliteiam.New(db)
					events = sqlitejournal.New(db)
					closeDB = func() { _ = db.Close() }
				}
			}
			open()
			t.Cleanup(func() { closeDB() })
			d := deploy(t, repo, events, source)
			var created *sdkiam.CreateUserOutput
			var key *sdkiam.CreateAccessKeyOutput
			keyID := ""
			for _, step := range fixture.Replay {
				input := json.RawMessage(strings.ReplaceAll(string(step.Input), "CAPTURED_KEY", keyID))
				out, err := awstest.CallSDK(t.Context(), d.iam, step.Operation, input)
				if step.ErrorCode != "" {
					apiError(t, err, step.ErrorCode)
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", step.Operation, err)
				}
				switch out := out.(type) {
				case *sdkiam.CreateUserOutput:
					created = out
				case *sdkiam.CreateAccessKeyOutput:
					key = out
					keyID = *out.AccessKey.AccessKeyId
				}
			}
			for _, observation := range fixture.Observations {
				rows := lookup(t, d.trail, trailtypes.LookupAttributeKeyEventName, observation.EventName)
				if len(rows) != 1 {
					t.Fatalf("%s: %d rows", observation.EventName, len(rows))
				}
				row := rows[0]
				if aws.ToString(row.ReadOnly) != map[bool]string{true: "true", false: "false"}[observation.ReadOnly] || !row.EventTime.Equal(epoch) {
					t.Fatalf("classification/time: %+v", row)
				}
				var doc map[string]json.RawMessage
				if err := json.Unmarshal([]byte(*row.CloudTrailEvent), &doc); err != nil {
					t.Fatal(err)
				}
				var category string
				var management bool
				_ = json.Unmarshal(doc["eventCategory"], &category)
				_ = json.Unmarshal(doc["managementEvent"], &management)
				if category != observation.EventCategory || management != observation.ManagementEvent {
					t.Fatalf("%s category=%q management=%t", observation.EventName, category, management)
				}
				var code *string
				_ = json.Unmarshal(doc["errorCode"], &code)
				if !reflect.DeepEqual(code, observation.ErrorCode) {
					t.Fatalf("%s error=%v want %v", observation.EventName, code, observation.ErrorCode)
				}
				types := []string{}
				for _, r := range row.Resources {
					types = append(types, aws.ToString(r.ResourceType))
				}
				if !reflect.DeepEqual(types, observation.ResourceTypes) {
					t.Fatalf("%s resource types=%v want %v", observation.EventName, types, observation.ResourceTypes)
				}
				_, hasResources := doc["resources"]
				if hasResources != observation.HasEventResources {
					t.Fatalf("%s event resource presence", observation.EventName)
				}
				var response map[string]map[string]json.RawMessage
				_ = json.Unmarshal(doc["responseElements"], &response)
				var fields map[string][]string
				if response != nil {
					fields = map[string][]string{}
					for k, v := range response {
						for name := range v {
							fields[k] = append(fields[k], name)
						}
						slices.Sort(fields[k])
					}
				}
				if !reflect.DeepEqual(fields, observation.ResponseFields) {
					t.Fatalf("%s response fields=%v want %v", observation.EventName, fields, observation.ResponseFields)
				}
				if strings.Contains(*row.CloudTrailEvent, *key.AccessKey.SecretAccessKey) {
					t.Fatal("secret appeared in CloudTrail")
				}
			}
			for _, name := range []string{*created.User.Arn, *created.User.UserName, *created.User.UserId} {
				if got := lookup(t, d.trail, trailtypes.LookupAttributeKeyResourceName, name); len(got) == 0 {
					t.Fatalf("missing resource alias %s", name)
				}
			}
			all := lookup(t, d.trail, trailtypes.LookupAttributeKeyEventSource, "iam.amazonaws.com")
			if len(all) != 9 {
				t.Fatalf("management event count %d", len(all))
			}
			detached, err := events.Read(t.Context(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range detached {
				if event.APICallCompleted != nil && len(event.APICallCompleted.Resources) > 0 {
					call := event.APICallCompleted
					id := call.EventID
					call.EventID = "mutated"
					call.Resources[0].Name = "mutated"
					call.RequestParameters[0] = '!'
					retained := lookup(t, d.trail, trailtypes.LookupAttributeKeyEventId, id)
					if len(retained) != 1 || strings.Contains(*retained[0].CloudTrailEvent, "mutated") || *retained[0].Resources[0].ResourceName == "mutated" {
						t.Fatal("history read exposed mutable stored data")
					}
					break
				}
			}
			for key, value := range map[trailtypes.LookupAttributeKey]string{trailtypes.LookupAttributeKeyEventId: *all[0].EventId, trailtypes.LookupAttributeKeyReadOnly: "true", trailtypes.LookupAttributeKeyUsername: "root", trailtypes.LookupAttributeKeyAccessKeyId: "test", trailtypes.LookupAttributeKeyResourceType: "AWS::IAM::AccessKey"} {
				if len(lookup(t, d.trail, key, value)) == 0 {
					t.Fatalf("empty filter %s", key)
				}
			}
			d.close()
			closeDB()
			open()
			d = deploy(t, repo, events, source)
			retained := lookup(t, d.trail, trailtypes.LookupAttributeKeyEventSource, "iam.amazonaws.com")
			if len(retained) != len(all) || *retained[0].EventId != *all[0].EventId {
				t.Fatal("history changed after reopening")
			}
			if len(lookup(t, d.client("111111111111", "test", "us-east-1"), trailtypes.LookupAttributeKeyEventSource, "iam.amazonaws.com")) != 0 {
				t.Fatal("cross-account history exposed")
			}
			if len(lookup(t, d.client("test", "test", "us-west-2"), trailtypes.LookupAttributeKeyEventSource, "iam.amazonaws.com")) != 0 {
				t.Fatal("cross-region history exposed")
			}
		})
	}
}

// A source failure after the audit insert must abort both the user and its event.
type failedAudit struct{ journal.Storage }

func (s failedAudit) AppendAPICallCompleted(ctx context.Context, e journal.Envelope, event journal.APICallCompleted) error {
	if err := s.Storage.AppendAPICallCompleted(ctx, e, event); err != nil {
		return err
	}
	return errors.New("injected failure after audit insert")
}
func TestAuditAppendFailureRollsBackIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			domain := memory.NewDomain()
			var repo iam.Repository = iam.NewMemoryRepository(domain)
			events := journal.NewMemory(domain)
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = sqliteiam.New(db)
				events = sqlitejournal.New(db)
			}
			d := deploy(t, repo, failedAudit{events}, clock.NewManual(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)))
			_, err := d.iam.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("rolledback")})
			apiError(t, err, "ServiceFailure")
			err = repo.View(t.Context(), func(tx iam.ReadTx) error {
				users, err := tx.Users(iam.Scope{Partition: "aws", AccountID: "000000000000"})
				if len(users) != 0 {
					t.Fatal("user survived audit failure")
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			rows, err := events.Read(t.Context(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			// The failed outcome append occurs outside the rejected resource transaction;
			// a failing sink owns its own rollback, just as it does for ordinary events.
			for _, row := range rows {
				if row.APICallCompleted != nil && row.APICallCompleted.ErrorCode == "" {
					t.Fatal("successful event survived rollback")
				}
			}
		})
	}
}

func TestHistorySDKPaginationTimeBoundsAndDenials(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			domain := memory.NewDomain()
			var repo iam.Repository = iam.NewMemoryRepository(domain)
			events := journal.NewMemory(domain)
			if backend == "sqlite" {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				repo = sqliteiam.New(db)
				events = sqlitejournal.New(db)
			}
			epoch := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			source := clock.NewManual(epoch)
			d := deploy(t, repo, events, source)
			for _, name := range []string{"first", "second", "third"} {
				if _, err := d.iam.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
					t.Fatal(err)
				}
			}
			selectCreates := func() *sdktrail.LookupEventsInput {
				return &sdktrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("CreateUser")}}, MaxResults: aws.Int32(1)}
			}
			first, err := d.trail.LookupEvents(t.Context(), selectCreates())
			if err != nil {
				t.Fatal(err)
			}
			if len(first.Events) != 1 || first.NextToken == nil {
				t.Fatalf("first page %+v", first)
			}
			if !strings.Contains(*first.Events[0].CloudTrailEvent, `"userName":"third"`) {
				t.Fatal("equal-time sequence order changed")
			}
			if _, err := d.iam.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("after-page")}); err != nil {
				t.Fatal(err)
			}
			next := selectCreates()
			next.NextToken = first.NextToken
			second, err := d.trail.LookupEvents(t.Context(), next)
			if err != nil {
				t.Fatal(err)
			}
			if len(second.Events) != 1 || !strings.Contains(*second.Events[0].CloudTrailEvent, `"userName":"second"`) {
				t.Fatalf("second page shifted %+v", second)
			}
			next.NextToken = second.NextToken
			third, err := d.trail.LookupEvents(t.Context(), next)
			if err != nil {
				t.Fatal(err)
			}
			if len(third.Events) != 1 || third.NextToken != nil || !strings.Contains(*third.Events[0].CloudTrailEvent, `"userName":"first"`) {
				t.Fatal("third page shifted")
			}
			altered := selectCreates()
			altered.NextToken = first.NextToken
			altered.MaxResults = aws.Int32(2)
			_, err = d.trail.LookupEvents(t.Context(), altered)
			apiError(t, err, "InvalidNextTokenException")
			altered = selectCreates()
			altered.NextToken = first.NextToken
			_, err = d.client("111111111111", "test", "us-east-1").LookupEvents(t.Context(), altered)
			apiError(t, err, "InvalidNextTokenException")
			if err := source.Advance(100 * time.Millisecond); err != nil {
				t.Fatal(err)
			}
			if _, err := d.iam.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("fractional")}); err != nil {
				t.Fatal(err)
			}
			for _, instant := range []time.Time{epoch, epoch.Add(100 * time.Millisecond)} {
				out, err := d.trail.LookupEvents(t.Context(), &sdktrail.LookupEventsInput{StartTime: &instant, EndTime: &instant})
				if err != nil {
					t.Fatal(err)
				}
				expected := 4
				if instant.After(epoch) {
					expected = 1
				}
				if len(out.Events) != expected {
					t.Fatalf("inclusive instant %v got %d want %d", instant, len(out.Events), expected)
				}
			}
			all := lookup(t, d.trail, trailtypes.LookupAttributeKeyEventName, "CreateUser")
			if !strings.Contains(*all[0].CloudTrailEvent, `"userName":"fractional"`) {
				t.Fatal("fractional time ordering")
			}
			key, err := d.iam.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: aws.String("first")})
			if err != nil {
				t.Fatal(err)
			}
			unprivileged := sdkiam.New(sdkiam.Options{Region: "us-east-1", BaseEndpoint: aws.String(d.server.URL), Credentials: credentials.NewStaticCredentialsProvider(*key.AccessKey.AccessKeyId, *key.AccessKey.SecretAccessKey, ""), HTTPClient: d.server.Client(), RetryMaxAttempts: 1})
			_, err = unprivileged.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("denied")})
			apiError(t, err, "AccessDenied")
			denied := lookup(t, d.trail, trailtypes.LookupAttributeKeyUsername, "first")
			if len(denied) != 1 || !strings.Contains(*denied[0].CloudTrailEvent, `"errorCode":"AccessDenied"`) {
				t.Fatalf("denied call missing %+v", denied)
			}
			if !strings.Contains(*denied[0].CloudTrailEvent, `"type":"IAMUser"`) {
				t.Fatal("caller identity lost")
			}
			_, err = d.client(*key.AccessKey.AccessKeyId, *key.AccessKey.SecretAccessKey, "us-east-1").LookupEvents(t.Context(), &sdktrail.LookupEventsInput{})
			apiError(t, err, "AccessDenied")
			var validation struct {
				Observations []struct {
					Name, Code string
					Input      json.RawMessage
				}
			}
			readFixture(t, "lookup_validation.json", &validation)
			for _, row := range validation.Observations {
				_, err := awstest.CallSDK(t.Context(), d.trail, "LookupEvents", row.Input)
				apiError(t, err, row.Code)
			}
			if err := source.Advance(90 * 24 * time.Hour); err != nil {
				t.Fatal(err)
			}
			retained := lookup(t, d.trail, trailtypes.LookupAttributeKeyEventName, "CreateUser")
			if len(retained) != 2 {
				t.Fatalf("retention boundary got %d want fractional success and denial", len(retained))
			}
			if err := source.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if len(lookup(t, d.trail, trailtypes.LookupAttributeKeyEventName, "CreateUser")) != 0 {
				t.Fatal("expired management events exposed")
			}
			internal, err := events.Read(t.Context(), 0, 100)
			if err != nil || len(internal) == 0 {
				t.Fatal("CloudTrail retention deleted shared journal", err)
			}
		})
	}
}

func TestLookupInputsAWS(t *testing.T) {
	var fixture struct {
		Observations []struct {
			Name   string
			Input  json.RawMessage
			Result struct {
				ErrorCode  string
				EventCount int
			}
		}
	}
	readFixture(t, "lookup_inputs.json", &fixture)
	domain := memory.NewDomain()
	events := journal.NewMemory(domain)
	d := deploy(t, iam.NewMemoryRepository(domain), events, clock.NewManual(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)))
	_, err := d.iam.GetUser(t.Context(), &sdkiam.GetUserInput{UserName: aws.String("absent")})
	apiError(t, err, "NoSuchEntity")
	for _, observation := range fixture.Observations {
		t.Run(observation.Name, func(t *testing.T) {
			// Convert captured wire timestamps into the SDK's Go JSON representation.
			decoded, err := api.DecodeRequest("LookupEvents", awsapi.Request{JSON: observation.Input})
			if err != nil {
				t.Fatal(err)
			}
			input, err := json.Marshal(decoded.Input)
			if err != nil {
				t.Fatal(err)
			}
			result, err := awstest.CallSDK(t.Context(), d.trail, "LookupEvents", input)
			if observation.Result.ErrorCode != "" {
				apiError(t, err, observation.Result.ErrorCode)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			out := result.(*sdktrail.LookupEventsOutput)
			if len(out.Events) != observation.Result.EventCount {
				t.Fatalf("event count %d want %d", len(out.Events), observation.Result.EventCount)
			}
		})
	}
}

func readFixture(t *testing.T, name string, target any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../../testdata/aws/cloudtrail", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

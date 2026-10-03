package athena

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

type nativeAthenaFixture struct {
	Observations []struct {
		Label  string
		Input  json.RawMessage
		Result struct {
			Code   string
			Output json.RawMessage
		}
	}
	Consumers map[string]struct {
		Body string `json:"body_utf8"`
	}
}

func loadAthenaFixture(t *testing.T) nativeAthenaFixture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/athena/application_verified.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture nativeAthenaFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// These commands replay the native duplicate/rollback, workgroup isolation and
// partial-update transitions, not stored copies of local implementation defaults.
func TestNativePreparedStatementTransitions(t *testing.T) {
	fixture := loadAthenaFixture(t)
	source := clock.NewManual(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	s := New(Config{Clock: source})
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	model, _ := awscatalog.LookupService("athena")
	actions := map[string]string{
		"create-workgroup":             "CreateWorkGroup",
		"create-other-workgroup":       "CreateWorkGroup",
		"create-prepared":              "CreatePreparedStatement",
		"duplicate-prepared":           "CreatePreparedStatement",
		"get-prepared-after-duplicate": "GetPreparedStatement",
		"update-prepared-missing":      "UpdatePreparedStatement",
		"get-prepared-other-workgroup": "GetPreparedStatement",
		"update-prepared":              "UpdatePreparedStatement",
		"get-prepared-updated":         "GetPreparedStatement",
	}
	observed := map[string]bool{}
	for _, entry := range fixture.Observations {
		action, ok := actions[entry.Label]
		if !ok {
			continue
		}
		observed[entry.Label] = true
		t.Run(entry.Label, func(t *testing.T) {
			in, err := api.NewInput(action)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(entry.Input, in); err != nil {
				t.Fatal(err)
			}
			operation, _ := model.Operation(action)
			out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: awscatalog.AWSJSON11, Input: in})
			if entry.Result.Code != "Success" {
				if rejected == nil || rejected.Code != entry.Result.Code {
					t.Fatalf("error = %v; native %s", rejected, entry.Result.Code)
				}
				return
			}
			if rejected != nil {
				t.Fatal(rejected)
			}
			if action == "GetPreparedStatement" {
				var expected api.GetPreparedStatementOutput
				if err := json.Unmarshal(entry.Result.Output, &expected); err != nil {
					t.Fatal(err)
				}
				actual := out.(*api.GetPreparedStatementOutput).PreparedStatement
				want := expected.PreparedStatement
				if actual == nil || want == nil {
					t.Fatal("prepared statement missing")
				}
				if value(actual.QueryStatement) != value(want.QueryStatement) || value(actual.Description) != value(want.Description) || value(actual.WorkGroupName) != value(want.WorkGroupName) {
					t.Fatalf("prepared statement = %#v; native %#v", actual, want)
				}
			}
		})
		if err := source.Advance(time.Second); err != nil {
			t.Fatal(err)
		}
	}
	for label := range actions {
		if !observed[label] {
			t.Fatalf("native observation %q missing", label)
		}
	}
}

func TestNativeResultObjectMatchesPaginatedAPIRows(t *testing.T) {
	fixture := loadAthenaFixture(t)
	body := fixture.Consumers["consume-query-csv"].Body
	if body == "" {
		t.Fatal("native S3 result object missing")
	}
	var expected api.GetQueryResultsOutput
	for _, entry := range fixture.Observations {
		if entry.Label == "aggregate-results" {
			if err := json.Unmarshal(entry.Result.Output, &expected); err != nil {
				t.Fatal(err)
			}
		}
	}
	if expected.ResultSet == nil {
		t.Fatal("native GetQueryResults observation missing")
	}
	var all api.RowList
	offset := 0
	data := []byte(body)
	for {
		rows, more, err := resultRows(data, offset, 1)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, rows...)
		offset += len(rows)
		if !more {
			break
		}
	}
	if !reflect.DeepEqual(all, expected.ResultSet.Rows) {
		t.Fatalf("decoded S3 rows = %#v; native API %#v", all, expected.ResultSet.Rows)
	}
}

func TestNativeWorkgroupRemovalChangesResultSelection(t *testing.T) {
	fixture := loadAthenaFixture(t)
	source := clock.NewManual(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	s := New(Config{Clock: source})
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	model, _ := awscatalog.LookupService("athena")
	actions := map[string]string{"create-other-workgroup": "CreateWorkGroup", "update-other-result": "UpdateWorkGroup", "remove-other-result": "UpdateWorkGroup"}
	client := &api.ResultConfiguration{OutputLocation: new(api.ResultOutputLocation("s3://client-results/result/"))}
	selected := map[string]string{}
	var configuredLocation *api.ResultOutputLocation
	for _, entry := range fixture.Observations {
		action, ok := actions[entry.Label]
		if !ok {
			continue
		}
		in, err := api.NewInput(action)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(entry.Input, in); err != nil {
			t.Fatal(err)
		}
		if entry.Label == "update-other-result" {
			configuredLocation = in.(*api.UpdateWorkGroupInput).ConfigurationUpdates.ResultConfigurationUpdates.OutputLocation
		}
		operation, _ := model.Operation(action)
		if _, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: awscatalog.AWSJSON11, Input: in}); rejected != nil {
			t.Fatal(rejected)
		}
		if err := s.repository.View(ctx, func(r Reader) error {
			v, err := r.WorkGroup(resourceFor(ctx, "stackd-analytics-owned-other"))
			if err != nil {
				return err
			}
			result := effectiveResults(v.Data.Configuration, client)
			selected[entry.Label] = value(result.OutputLocation)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if selected["create-other-workgroup"] != value(client.OutputLocation) || selected["remove-other-result"] != value(client.OutputLocation) {
		t.Fatalf("unset/removed workgroup location blocked client configuration: %#v", selected)
	}
	if configuredLocation == nil {
		t.Fatal("native workgroup update location missing")
	}
	if selected["update-other-result"] != value(configuredLocation) {
		t.Fatalf("enforced location = %q; native configured %q", selected["update-other-result"], value(configuredLocation))
	}
}

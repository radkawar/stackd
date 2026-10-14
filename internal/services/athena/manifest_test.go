package athena_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/athena"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/athena"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/athena"
)

type manifestResultOwner struct {
	bodies              map[string][]byte
	denied              bool
	location, principal string
}

func (r *manifestResultOwner) Write(context.Context, service.QueryRecord, []byte) *awswire.Error {
	panic("unexpected result write")
}
func (r *manifestResultOwner) Read(ctx context.Context, query service.QueryRecord) ([]byte, *awswire.Error) {
	r.location = string(*query.Data.ResultConfiguration.OutputLocation)
	r.principal = awsctx.FromContext(ctx).PrincipalARN
	if r.denied {
		return nil, &awswire.Error{Code: "AccessDenied", StatusCode: 403}
	}
	body, ok := r.bodies[r.location]
	if !ok {
		return nil, &awswire.Error{Code: "NoSuchKey", StatusCode: 404}
	}
	return body, nil
}

func TestNativeManifestResultsAndByteTokensAcrossSQLiteRestart(t *testing.T) {
	body, err := os.ReadFile("../../../testdata/aws/athena/manifest_verified.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		QueryTerminal map[string]api.QueryExecution `json:"query_terminal"`
		Consumers     map[string]struct {
			Body string `json:"body_utf8"`
		}
		Observations []struct {
			Label  string
			Result struct {
				Code   string
				Output json.RawMessage
				Error  struct{ Message, Code, AthenaErrorCode string }
			}
		}
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	outputs := map[string]api.GetQueryResultsOutput{}
	errors := map[string]*awswire.Error{}
	for _, observation := range fixture.Observations {
		if observation.Result.Code == "Success" && (strings.Contains(observation.Label, "manifest") || strings.Contains(observation.Label, "rows")) {
			var out api.GetQueryResultsOutput
			if json.Unmarshal(observation.Result.Output, &out) == nil && out.ResultSet != nil {
				outputs[observation.Label] = out
			}
		}
		if observation.Result.Code != "Success" {
			native := observation.Result.Error
			encoded, _ := json.Marshal(native.AthenaErrorCode)
			errors[observation.Label] = &awswire.Error{Code: native.Code, Message: native.Message, Details: map[string]json.RawMessage{"AthenaErrorCode": encoded}}
		}
	}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	path := filepath.Join(t.TempDir(), "manifest.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	repo := backend.New(db)
	owner := &manifestResultOwner{bodies: map[string][]byte{}}
	keys := map[string]service.ResourceKey{}
	for _, name := range []string{"ctas", "insert", "select", "failed"} {
		execution, ok := fixture.QueryTerminal[name]
		if !ok || execution.QueryExecutionId == nil {
			t.Fatalf("native terminal execution %s missing", name)
		}
		key := service.ResourceKey{Scope: service.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: string(*execution.QueryExecutionId)}
		keys[name] = key
		var columns api.ColumnInfoList
		var count int64
		if name == "ctas" || name == "insert" {
			rows := outputs[name+"-rows-full"]
			columns, count = rows.ResultSet.ResultSetMetadata.ColumnInfo, int64(*rows.UpdateCount)
			owner.bodies[string(*execution.Statistics.DataManifestLocation)] = []byte(fixture.Consumers["consume-"+name+"-manifest"].Body)
		}
		if name == "select" {
			columns = outputs["select-rows"].ResultSet.ResultSetMetadata.ColumnInfo
			owner.bodies[string(*execution.ResultConfiguration.OutputLocation)] = []byte("\"id\",\"p\"\n\"1\",\"a\"\n\"2\",\"b\"\n\"3\",\"c\"\n\"4\",\"d\"\n")
		}
		if err := repo.Update(ctx, func(tx service.Transaction) error {
			if name == "ctas" {
				group := service.ResourceKey{Scope: key.Scope, Name: string(*execution.WorkGroup)}
				if err := tx.PutWorkGroup(service.WorkGroupRecord{Key: group, Data: api.WorkGroup{Name: execution.WorkGroup, State: new(api.WorkGroupState("ENABLED"))}}); err != nil {
					return err
				}
			}
			return tx.PutQuery(service.QueryRecord{Key: key, Version: 1, Data: execution, Columns: columns, UpdateCount: count})
		}); err != nil {
			t.Fatal(err)
		}
	}
	s := service.New(service.Config{Repository: repo, Results: owner})
	model, _ := awscatalog.LookupService("athena")
	op, _ := model.Operation("GetQueryResults")
	get := func(name, kind string, limit int32, token *api.Token) (*api.GetQueryResultsOutput, *awswire.Error) {
		t.Helper()
		out, rejected := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: awscatalog.AWSJSON11, Input: &api.GetQueryResultsInput{QueryExecutionId: new(api.QueryExecutionId(keys[name].Name)), QueryResultType: new(api.QueryResultType(kind)), MaxResults: new(api.MaxQueryResults(limit)), NextToken: token}})
		if rejected != nil {
			return nil, rejected
		}
		return out.(*api.GetQueryResultsOutput), nil
	}
	compare := func(actual *api.GetQueryResultsOutput, label string) {
		t.Helper()
		expected, ok := outputs[label]
		if !ok {
			t.Fatalf("native output %s missing", label)
		}
		if !reflect.DeepEqual(actual.ResultSet, expected.ResultSet) || !reflect.DeepEqual(actual.UpdateCount, expected.UpdateCount) || (actual.NextToken != nil) != (expected.NextToken != nil) {
			t.Fatalf("%s: local %#v; native %#v", label, actual, expected)
		}
	}
	compareError := func(actual *awswire.Error, label string) {
		t.Helper()
		expected := errors[label]
		if expected == nil || actual == nil || actual.Code != expected.Code || actual.Message != expected.Message || !reflect.DeepEqual(actual.Details, expected.Details) {
			t.Fatalf("%s: local %#v; native %#v", label, actual, expected)
		}
	}
	var retainedToken *api.Token
	for _, name := range []string{"ctas", "insert"} {
		for _, limit := range []int32{2, 3} {
			out, rejected := get(name, "DATA_MANIFEST", limit, nil)
			if rejected != nil {
				t.Fatal(rejected)
			}
			label := name + "-manifest-limit-2"
			if limit == 3 {
				label = name + "-manifest-limit-3"
			}
			compare(out, label)
		}
		var token *api.Token
		for _, page := range []string{"1", "2", "3"} {
			out, rejected := get(name, "DATA_MANIFEST", 1, token)
			if rejected != nil {
				t.Fatal(rejected)
			}
			compare(out, name+"-manifest-page-"+page)
			token = out.NextToken
			if name == "ctas" && page == "1" {
				retainedToken = token
			}
		}
		rows, rejected := get(name, "DATA_ROWS", 1, retainedToken)
		if rejected != nil {
			t.Fatal(rejected)
		}
		compare(rows, name+"-manifest-token-as-rows")
	}
	selectPage, rejected := get("select", "DATA_ROWS", 1, nil)
	if rejected != nil {
		t.Fatal(rejected)
	}
	for _, name := range []string{"ctas", "insert"} {
		out, rejected := get(name, "DATA_MANIFEST", 1, selectPage.NextToken)
		if rejected != nil {
			t.Fatal(rejected)
		}
		compare(out, name+"-select-rows-token-as-manifest")
	}
	_, rejected = get("select", "DATA_MANIFEST", 1, nil)
	compareError(rejected, "select-manifest")
	_, rejected = get("failed", "DATA_MANIFEST", 1, nil)
	compareError(rejected, "failed-manifest")
	_, rejected = get("failed", "DATA_ROWS", 1, nil)
	compareError(rejected, "failed-rows")
	owner.denied = true
	_, rejected = get("ctas", "DATA_MANIFEST", 1, retainedToken)
	compareError(rejected, "reader-manifest-current-s3-deny")
	owner.denied = false
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s = service.New(service.Config{Repository: backend.New(db), Results: owner})
	defer s.Close()
	location := string(*fixture.QueryTerminal["ctas"].Statistics.DataManifestLocation)
	original := owner.bodies[location]
	firstEnd := strings.IndexByte(string(original), '\n') + 1
	owner.bodies[location] = append(append([]byte{}, original[:firstEnd]...), []byte("s3://data/current-second\n")...)
	second, rejected := get("ctas", "DATA_MANIFEST", 1, retainedToken)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if second.NextToken == nil || second.UpdateCount != nil || len(second.ResultSet.ResultSetMetadata.ColumnInfo) != 0 || *second.ResultSet.Rows[0].Data[0].VarCharValue != "s3://data/current-second" || owner.location != location || owner.principal != awsctx.FromContext(ctx).PrincipalARN {
		t.Fatalf("restarted current manifest = %#v; owner %#v", second, owner)
	}
	last, rejected := get("ctas", "DATA_MANIFEST", 1, second.NextToken)
	if rejected != nil {
		t.Fatal(rejected)
	}
	if last.NextToken != nil || len(last.ResultSet.Rows) != 0 {
		t.Fatalf("exact-boundary final page = %#v", last)
	}
}

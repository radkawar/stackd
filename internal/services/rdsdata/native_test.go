package rdsdata

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/rdsdata"
	"github.com/aws/aws-sdk-go-v2/service/rdsdata/types"
	"github.com/aws/smithy-go"
	"stackd/clock"
	engine "stackd/engine/rds"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/rdsdata"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

const testCluster = "arn:aws:rds:us-east-1:123456789012:cluster:data"
const testSecret = "arn:aws:secretsmanager:us-east-1:123456789012:secret:database-abc123"

type nativeFixture struct {
	mu                   sync.Mutex
	cluster              Cluster
	username, password   string
	denied, secretDenied bool
	lookupErr            error
	events               []journal.APICallCompleted
}

func (f *nativeFixture) ResolveDataCluster(_ context.Context, arn string) (Cluster, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.cluster
	c.ARN = arn
	return c, f.lookupErr
}
func (f *nativeFixture) Credentials(context.Context, string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.secretDenied {
		return "", "", failure("AccessDeniedException", "Secret access denied.", 403)
	}
	return f.username, f.password, nil
}
func (f *nativeFixture) Authorize(ctx context.Context, r authorization.Request) *awswire.Error {
	f.mu.Lock()
	denied := f.denied
	f.mu.Unlock()
	if denied {
		return failure("AccessDeniedException", "Data access denied.", 403)
	}
	return authorization.New(nil, nil).Authorize(ctx, r)
}
func (f *nativeFixture) Record(_ context.Context, _ journal.Envelope, call journal.APICallCompleted) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, call)
	return nil
}
func sdkServer(t *testing.T, s *Service) *sdk.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := strings.TrimPrefix(r.URL.Path, "/")
		switch operation {
		case "Execute":
			operation = "ExecuteStatement"
		case "BatchExecute":
			operation = "BatchExecuteStatement"
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		decoded, err := api.DecodeRequest(operation, awsapi.Request{Body: body, JSON: body, Header: r.Header})
		if err != nil {
			awswire.JSONError(w, r, s.RequestError(operation, err))
			return
		}
		ctx := awsctx.WithMetadata(r.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
		s.ServeHTTP(w, r.WithContext(awsapi.WithDecodedRequest(ctx, decoded)))
	}))
	t.Cleanup(server.Close)
	return sdk.New(sdk.Options{Region: "us-east-1", BaseEndpoint: new(server.URL), Credentials: credentials.NewStaticCredentialsProvider("local", "local", ""), RetryMaxAttempts: 1})
}

// This opt-in test owns native containers/volumes under an isolated random
// namespace. It uses the official SDK, generated frontend and actual native SQL;
// it never provisions AWS resources. The default unit gate requires no Docker.
func TestNativeDataAPI(t *testing.T) {
	if os.Getenv("STACKD_RDSDATA_NATIVE") != "1" {
		t.Skip("set STACKD_RDSDATA_NATIVE=1 for exact-owned PostgreSQL/MySQL SDK regressions")
	}
	for _, family := range []string{"aurora-postgresql", "aurora-mysql"} {
		t.Run(family, func(t *testing.T) {
			ctx := context.Background()
			var random [12]byte
			if _, err := rand.Read(random[:]); err != nil {
				t.Fatal(err)
			}
			id := hex.EncodeToString(random[:])
			runtime, err := engine.NewDocker(engine.DockerConfig{Namespace: "rdsdata-regression-" + id})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := runtime.Close(); err != nil {
					t.Error(err)
				}
			})
			spec := engine.Specification{ID: id, Engine: family, Database: "app", Username: "appuser", Password: "LocalRegressionPassword42"}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := runtime.Delete(cleanup, id); err != nil {
					t.Error(err)
				}
			})
			endpoint, err := runtime.Ensure(ctx, spec)
			if err != nil {
				t.Fatal(err)
			}
			source := &nativeFixture{cluster: Cluster{ARN: testCluster, Engine: family, Database: "app", Status: "available", Endpoint: endpoint, HTTPEnabled: true}, username: spec.Username, password: spec.Password}
			manual := clock.NewManual(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			service := New(Config{Clusters: source, Secrets: source, Authorizer: source, Recorder: source, Clock: manual})
			t.Cleanup(func() {
				if err := service.Close(); err != nil {
					t.Error(err)
				}
			})
			client := sdkServer(t, service)
			statement := func(sql string, tx *string, parameters ...types.SqlParameter) (*sdk.ExecuteStatementOutput, error) {
				return client.ExecuteStatement(ctx, &sdk.ExecuteStatementInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), Database: new("app"), Sql: new(sql), TransactionId: tx, Parameters: parameters, IncludeResultMetadata: true})
			}
			must := func(sql string, tx *string, parameters ...types.SqlParameter) *sdk.ExecuteStatementOutput {
				t.Helper()
				out, err := statement(sql, tx, parameters...)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			assertCode := func(err error, code string) {
				t.Helper()
				var apiError smithy.APIError
				if !errors.As(err, &apiError) || apiError.ErrorCode() != code {
					t.Fatalf("error=%v; want %s", err, code)
				}
			}
			begin := func() *string {
				t.Helper()
				out, err := client.BeginTransaction(ctx, &sdk.BeginTransactionInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), Database: new("app")})
				if err != nil {
					t.Fatal(err)
				}
				return out.TransactionId
			}
			count := func() int64 {
				t.Helper()
				out := must("SELECT count(*) AS n FROM items", nil)
				return out.Records[0][0].(*types.FieldMemberLongValue).Value
			}
			blobType := "bytea"
			if family == "aurora-mysql" {
				blobType = "blob"
			}
			must("CREATE TABLE items (id bigint PRIMARY KEY, note text, amount decimal(30,10), payload "+blobType+")", nil)
			payload := []byte{0, 1, 255, 39}
			parameters := []types.SqlParameter{{Name: new("id"), Value: &types.FieldMemberLongValue{Value: 1}}, {Name: new("note"), Value: &types.FieldMemberStringValue{Value: "'; DROP TABLE items; --"}}, {Name: new("amount"), TypeHint: types.TypeHintDecimal, Value: &types.FieldMemberStringValue{Value: "12345678901234567890.1234567890"}}, {Name: new("payload"), Value: &types.FieldMemberBlobValue{Value: payload}}}
			out := must("INSERT INTO items VALUES (:id,:note,:amount,:payload)", nil, parameters...)
			if out.NumberOfRecordsUpdated != 1 {
				t.Fatalf("insert affected %d rows", out.NumberOfRecordsUpdated)
			}
			out = must("SELECT note, amount, payload, NULL AS absent FROM items WHERE id=:id", nil, parameters[0])
			if out.Records[0][0].(*types.FieldMemberStringValue).Value != "'; DROP TABLE items; --" || out.Records[0][1].(*types.FieldMemberStringValue).Value != "12345678901234567890.1234567890" || string(out.Records[0][2].(*types.FieldMemberBlobValue).Value) != string(payload) || !out.Records[0][3].(*types.FieldMemberIsNull).Value {
				t.Fatalf("bound result changed: %#v", out.Records)
			}
			if *out.ColumnMetadata[1].TypeName != "numeric" && *out.ColumnMetadata[1].TypeName != "decimal" {
				t.Fatalf("native decimal metadata: %#v", out.ColumnMetadata[1])
			}
			hints := []types.SqlParameter{
				{Name: new("d"), TypeHint: types.TypeHint("DATE"), Value: &types.FieldMemberStringValue{Value: "2026-01-02"}},
				{Name: new("t"), TypeHint: types.TypeHint("TIME"), Value: &types.FieldMemberStringValue{Value: "12:34:56.123456"}},
				{Name: new("ts"), TypeHint: types.TypeHint("TIMESTAMP"), Value: &types.FieldMemberStringValue{Value: "2026-01-02 12:34:56.123456"}},
				{Name: new("j"), TypeHint: types.TypeHint("JSON"), Value: &types.FieldMemberStringValue{Value: `{"bound":true}`}},
			}
			typed := must("SELECT :d AS d, :t AS t, :ts AS ts, :j AS j", nil, hints...)
			for i, want := range []string{"2026-01-02", "12:34:56.123456", "2026-01-02 12:34:56.123456"} {
				if typed.Records[0][i].(*types.FieldMemberStringValue).Value != want {
					t.Fatalf("native temporal parameter %d lost its value: %#v", i, typed.Records[0][i])
				}
			}
			var jsonValue map[string]bool
			if err := json.Unmarshal([]byte(typed.Records[0][3].(*types.FieldMemberStringValue).Value), &jsonValue); err != nil || !jsonValue["bound"] {
				t.Fatalf("native JSON hint: %#v %v", jsonValue, err)
			}
			if family == "aurora-postgresql" {
				uuid := "00112233-4455-6677-8899-aabbccddeeff"
				typed := must("SELECT :u AS u", nil, types.SqlParameter{Name: new("u"), TypeHint: types.TypeHint("UUID"), Value: &types.FieldMemberStringValue{Value: uuid}})
				if typed.Records[0][0].(*types.FieldMemberStringValue).Value != uuid {
					t.Fatal("native UUID parameter changed")
				}
			}
			jsonOut, err := client.ExecuteStatement(ctx, &sdk.ExecuteStatementInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), Database: new("app"), Sql: new("SELECT id, amount, payload, NULL AS absent FROM items"), FormatRecordsAs: types.RecordsFormatTypeJson, ResultSetOptions: &types.ResultSetOptions{LongReturnType: types.LongReturnTypeString}})
			if err != nil {
				t.Fatal(err)
			}
			var formatted []map[string]any
			if err := json.Unmarshal([]byte(*jsonOut.FormattedRecords), &formatted); err != nil {
				t.Fatal(err)
			}
			if formatted[0]["id"] != "1" || formatted[0]["amount"] != "12345678901234567890.1234567890" || formatted[0]["payload"] != "AAH/Jw==" || formatted[0]["absent"] != nil || len(jsonOut.Records) != 0 || len(jsonOut.ColumnMetadata) != 0 {
				t.Fatalf("JSON result: %#v", formatted)
			}
			_, err = statement("SELECT id AS duplicate,id AS duplicate FROM items", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ExecuteStatement(ctx, &sdk.ExecuteStatementInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), Database: new("app"), Sql: new("SELECT id AS duplicate,id AS duplicate FROM items"), FormatRecordsAs: types.RecordsFormatTypeJson})
			assertCode(err, "BadRequestException")
			_, err = statement("SELECT nonexistent_column FROM items", nil)
			assertCode(err, "DatabaseErrorException")
			if !strings.Contains(err.Error(), "nonexistent_column") {
				t.Fatalf("native SQL error suppressed: %v", err)
			}
			if family == "aurora-postgresql" {
				tx := begin()
				must("SET standard_conforming_strings=off", tx)
				// The server's string mode can differ from the lexical binder.
				// Native preparation must still reject a second statement.
				_, err = statement(`UPDATE items SET note='\' '; INSERT INTO items(id) VALUES (999); -- '`, tx)
				assertCode(err, "DatabaseErrorException")
				if _, err := client.RollbackTransaction(ctx, &sdk.RollbackTransactionInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), TransactionId: tx}); err != nil {
					t.Fatal(err)
				}
				if count() != 1 {
					t.Fatal("SQL string-mode change admitted multiple native statements")
				}
			}
			tx := begin()
			must("INSERT INTO items(id) VALUES (2)", tx)
			_, err = client.RollbackTransaction(ctx, &sdk.RollbackTransactionInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), TransactionId: tx})
			if err != nil {
				t.Fatal(err)
			}
			if count() != 1 {
				t.Fatal("rollback did not undo native insert")
			}
			_, err = statement("SELECT 1", tx)
			assertCode(err, "TransactionNotFoundException")
			tx = begin()
			must("INSERT INTO items(id) VALUES (2)", tx)
			_, err = client.CommitTransaction(ctx, &sdk.CommitTransactionInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), TransactionId: tx})
			if err != nil {
				t.Fatal(err)
			}
			if count() != 2 {
				t.Fatal("commit did not persist native insert")
			}
			tx = begin()
			for _, change := range []func(*sdk.ExecuteStatementInput){func(in *sdk.ExecuteStatementInput) { in.ResourceArn = new(testCluster + "-other") }, func(in *sdk.ExecuteStatementInput) { in.SecretArn = new(testSecret + "-other") }, func(in *sdk.ExecuteStatementInput) { in.Database = new("other") }} {
				in := &sdk.ExecuteStatementInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), Database: new("app"), TransactionId: tx, Sql: new("INSERT INTO items(id) VALUES (99)")}
				change(in)
				_, err = client.ExecuteStatement(ctx, in)
				assertCode(err, "TransactionNotFoundException")
			}
			source.mu.Lock()
			source.denied = true
			source.mu.Unlock()
			_, err = statement("INSERT INTO items(id) VALUES (99)", tx)
			assertCode(err, "AccessDeniedException")
			source.mu.Lock()
			source.denied = false
			source.secretDenied = true
			source.mu.Unlock()
			_, err = statement("INSERT INTO items(id) VALUES (99)", tx)
			assertCode(err, "AccessDeniedException")
			source.mu.Lock()
			source.secretDenied = false
			source.cluster.HTTPEnabled = false
			source.mu.Unlock()
			_, err = statement("SELECT 1", nil)
			assertCode(err, "HttpEndpointNotEnabledException")
			source.mu.Lock()
			source.cluster.HTTPEnabled = true
			source.cluster.Status = "stopped"
			source.mu.Unlock()
			_, err = statement("SELECT 1", nil)
			assertCode(err, "DatabaseUnavailableException")
			source.mu.Lock()
			source.cluster.Status = "available"
			source.mu.Unlock()
			must("INSERT INTO items(id) VALUES (3)", tx)
			if err := manual.Advance(idleTimeout); err != nil {
				t.Fatal(err)
			}
			if _, err := service.JobDriver().RunDue(ctx, 10); err != nil {
				t.Fatal(err)
			}
			_, err = statement("SELECT 1", tx)
			assertCode(err, "TransactionNotFoundException")
			if count() != 2 {
				t.Fatal("expiry or denied request changed committed data")
			}
			batch, err := client.BatchExecuteStatement(ctx, &sdk.BatchExecuteStatementInput{ResourceArn: new(testCluster), SecretArn: new(testSecret), Database: new("app"), Sql: new("INSERT INTO items(id) VALUES (:id)"), ParameterSets: [][]types.SqlParameter{{{Name: new("id"), Value: &types.FieldMemberLongValue{Value: 3}}}, {{Name: new("id"), Value: &types.FieldMemberLongValue{Value: 4}}}}})
			if err != nil || len(batch.UpdateResults) != 2 || count() != 4 {
				t.Fatalf("native batch: %#v %v", batch, err)
			}
			tx = begin()
			must("INSERT INTO items(id) VALUES (5)", tx)
			sleepSQL := "SELECT pg_sleep(10)"
			if family == "aurora-mysql" {
				sleepSQL = "SELECT SLEEP(10)"
			}
			finished := make(chan error, 1)
			go func() { _, err := statement(sleepSQL, tx); finished <- err }()
			deadline := time.Now().Add(5 * time.Second)
			for {
				service.mu.Lock()
				lease := service.transactions[*tx]
				busy := lease != nil && lease.busy
				service.mu.Unlock()
				if busy {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("native statement did not acquire its transaction")
				}
				time.Sleep(time.Millisecond)
			}
			if err := manual.Advance(hardTimeout); err != nil {
				t.Fatal(err)
			}
			if _, err := service.JobDriver().RunDue(ctx, 10); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("hard transaction deadline did not cancel native I/O")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("hard transaction deadline left native I/O running")
			}
			if count() != 4 {
				t.Fatal("hard expiry did not roll back the native transaction")
			}
			_, err = statement("SELECT 1", tx)
			assertCode(err, "TransactionNotFoundException")
			tx = begin()
			must("INSERT INTO items(id) VALUES (5)", tx)
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			service = New(Config{Clusters: source, Secrets: source, Authorizer: source, Recorder: source, Clock: manual})
			client = sdkServer(t, service)
			if count() != 4 {
				t.Fatal("shutdown did not roll back the native session")
			}
			_, err = statement("SELECT 1", tx)
			assertCode(err, "TransactionNotFoundException")
			source.mu.Lock()
			defer source.mu.Unlock()
			for _, event := range source.events {
				if event.Category != journal.CategoryData || event.EventType != journal.EventTypeRDSData || event.EventSource != "rdsdataapi.amazonaws.com" {
					t.Fatalf("wrong Data API audit classification: %#v", event)
				}
				raw := string(event.RequestParameters) + string(event.ResponseElements) + event.ErrorMessage
				for _, secret := range []string{"DROP TABLE items", "12345678901234567890.1234567890", "nonexistent_column", spec.Password, "AAH/Jw=="} {
					if strings.Contains(raw, secret) {
						t.Fatal("Data API audit leaked SQL, credential, parameter or result material")
					}
				}
			}
		})
	}
}

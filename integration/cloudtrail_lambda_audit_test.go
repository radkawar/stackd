package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage"
)

type lambdaAuditFailure struct {
	journal.Storage
	fail atomic.Bool
}

func (f *lambdaAuditFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "lambda.amazonaws.com" && call.EventName == "Invoke" && call.ErrorCode == "" && f.fail.Swap(false) {
		return errors.New("injected failure after Lambda API audit append")
	}
	return nil
}

func lambdaAuditRows(t *testing.T, store journal.Storage) []journal.Event {
	t.Helper()
	rows, err := store.Read(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var result []journal.Event
	for _, row := range rows {
		if row.APICallCompleted != nil && row.APICallCompleted.EventSource == "lambda.amazonaws.com" {
			result = append(result, row)
		}
	}
	return result
}

func lambdaAuditDocument(t *testing.T, row journal.Event) map[string]any {
	t.Helper()
	data, err := apievents.CloudTrailRecord(row)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func lambdaAuditNative(t *testing.T, name, kind string) map[string]any {
	t.Helper()
	for _, record := range auditNativeRecords(t, "service_data_events") {
		if record["eventSource"] != "lambda.amazonaws.com" || record["eventName"] != name {
			continue
		}
		parameters, _ := record["requestParameters"].(map[string]any)
		if name == "InvokeExecution" || (kind == "invalid" && parameters == nil) || parameters["invocationType"] == kind {
			return record
		}
	}
	t.Fatalf("native Lambda record missing: %s %s", name, kind)
	return nil
}

func lambdaAuditConforms(t *testing.T, row journal.Event, native map[string]any, arn string) {
	t.Helper()
	encoded, err := json.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	encoded = []byte(strings.ReplaceAll(string(encoded), "arn:aws:lambda:us-east-1:111111111111:function:stackd-ctdata-e346cb00c6ee-fn", arn))
	encoded = []byte(strings.ReplaceAll(string(encoded), "111111111111", "000000000000"))
	var want map[string]any
	if err := json.Unmarshal(encoded, &want); err != nil {
		t.Fatal(err)
	}
	got := lambdaAuditDocument(t, row)
	for _, key := range []string{"apiVersion", "eventName", "eventSource", "readOnly", "eventCategory", "managementEvent", "eventType", "requestParameters", "responseElements", "resources", "additionalEventData", "errorCode", "errorMessage"} {
		actual, actualPresent := got[key]
		expected, expectedPresent := want[key]
		if actualPresent != expectedPresent || !reflect.DeepEqual(actual, expected) {
			t.Fatalf("%s %s = %#v (present %v), native %#v (present %v)", row.APICallCompleted.EventName, key, actual, actualPresent, expected, expectedPresent)
		}
	}
	if native["eventName"] == "InvokeExecution" {
		for _, key := range []string{"userIdentity", "sourceIPAddress", "userAgent"} {
			if !reflect.DeepEqual(got[key], want[key]) {
				t.Fatalf("service execution %s = %#v, native %#v", key, got[key], want[key])
			}
		}
		if got["sharedEventID"] == nil || got["sharedEventID"] == got["eventID"] {
			t.Fatal("execution lacks a distinct shared event identity")
		}
	} else if _, present := got["sharedEventID"]; present {
		t.Fatal("acceptance incorrectly acquired execution sharedEventID")
	}
}

func TestCloudTrailLambdaDockerNativeOutcomes(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaFixture[lambdaEventsFixture](t, "event_invocation")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "lambda-audit.sqlite"))
			}
			failing := &lambdaAuditFailure{Storage: backends.Journal}
			backends.Journal = failing
			source := clock.NewManual(time.Date(2026, 9, 13, 19, 11, 0, 0, time.UTC))
			c := lambdaEventsConnect(t, backends, source)
			lambdaEventsProvision(t, c, fixture)
			var nativeCreate map[string]any
			for _, native := range auditNativeRecords(t, "service_management_events") {
				if native["eventSource"] == "lambda.amazonaws.com" && native["eventName"] == "CreateFunction20150331" && native["responseElements"] != nil {
					nativeCreate = native
					break
				}
			}
			if nativeCreate == nil {
				t.Fatal("native creation record missing")
			}
			created := false
			for _, row := range lambdaAuditRows(t, failing) {
				if row.APICallCompleted.EventName != "CreateFunction20150331" {
					continue
				}
				document := lambdaAuditDocument(t, row)
				for _, key := range []string{"eventName", "eventCategory", "managementEvent", "readOnly"} {
					if !reflect.DeepEqual(document[key], nativeCreate[key]) {
						t.Fatalf("creation %s differs from native", key)
					}
				}
				if _, ok := document["resources"]; ok {
					t.Fatal("management Lookup aliases leaked into native resources")
				}
				request := document["requestParameters"].(map[string]any)
				nativeRequest := nativeCreate["requestParameters"].(map[string]any)
				for _, key := range []string{"code", "environment"} {
					if !reflect.DeepEqual(request[key], nativeRequest[key]) {
						t.Fatalf("creation %s leaked contents or lost native empty container: %#v", key, request[key])
					}
				}
				response := document["responseElements"].(map[string]any)
				if !reflect.DeepEqual(response["environment"], nativeCreate["responseElements"].(map[string]any)["environment"]) {
					t.Fatal("creation response leaked environment")
				}
				created = true
			}
			if !created {
				t.Fatal("committed creation audit missing")
			}
			// Generated SDK transport, real source transaction and real container.
			for _, kind := range []string{"RequestResponse", "Event", "DryRun"} {
				input, _ := json.Marshal(map[string]any{"FunctionName": aws.ToString(c.functionName), "InvocationType": kind})
				result, err := awstest.CallSDK(t.Context(), c.lambda, "Invoke", input, func(input any) { input.(*awslambda.InvokeInput).Payload = []byte(`{"case":"audit-success"}`) })
				if err != nil {
					t.Fatal(err)
				}
				out := result.(*awslambda.InvokeOutput)
				requestID, _ := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
				if kind != "DryRun" {
					lambdaEventsReceive(t, c, c.outputURL, 1)
				}
				var acceptance, execution *journal.Event
				for _, row := range lambdaAuditRows(t, failing) {
					if row.RequestID != requestID {
						continue
					}
					switch row.APICallCompleted.EventName {
					case "Invoke":
						if acceptance != nil {
							t.Fatal("duplicate invocation acceptance audit")
						}
						acceptance = new(row)
					case "InvokeExecution":
						execution = new(row)
					}
				}
				if acceptance == nil {
					t.Fatal("SDK invocation missing its request-correlated audit")
				}
				lambdaAuditConforms(t, *acceptance, lambdaAuditNative(t, "Invoke", kind), c.functionARN)
				if kind == "Event" {
					if execution == nil {
						t.Fatal("retained event invocation missing execution audit")
					}
					lambdaAuditConforms(t, *execution, lambdaAuditNative(t, "InvokeExecution", ""), c.functionARN)
					if execution.APICallCompleted.EventID == acceptance.APICallCompleted.EventID || execution.APICallCompleted.SharedEventID == acceptance.APICallCompleted.EventID {
						t.Fatal("execution reused acceptance event identity")
					}
				} else if execution != nil {
					t.Fatal("non-event invocation emitted asynchronous execution record")
				}
			}
			response, _ := lambdaRawInvoke(t, c.server, aws.ToString(c.functionName), "RequestResponse", []byte(`{`))
			if response.StatusCode != 400 {
				t.Fatalf("invalid JSON status %d", response.StatusCode)
			}
			invalidID := response.Header.Get("X-Amzn-Requestid")
			found := false
			for _, row := range lambdaAuditRows(t, failing) {
				if row.RequestID == invalidID {
					lambdaAuditConforms(t, row, lambdaAuditNative(t, "Invoke", "invalid"), c.functionARN)
					found = true
				}
			}
			if !found {
				t.Fatal("invalid JSON invocation audit missing")
			}
			// Audit append failure must roll back the retained work AND acceptance fact.
			beforeRollback, err := failing.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			var cursor int64
			if len(beforeRollback) != 0 {
				cursor = beforeRollback[len(beforeRollback)-1].Sequence
			}
			failing.fail.Store(true)
			_, err = c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: c.functionName, InvocationType: lambdatypes.InvocationTypeEvent, Payload: []byte(`{"case":"rollback"}`)})
			assertAPIError(t, err, "ServiceException")
			lambdaEventsQuiet(t, c, c.outputURL)
			afterRollback, err := failing.Read(t.Context(), cursor, 1000)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range afterRollback {
				if row.LambdaInvocationAccepted.InvocationID != "" {
					t.Fatal("rolled-back audit published retained acceptance")
				}
				if call := row.APICallCompleted; call != nil && call.EventSource == "lambda.amazonaws.com" && call.EventName == "Invoke" && call.ErrorCode == "" {
					t.Fatal("rolled-back audit published success")
				}
			}
			// Exercise actual EventBridge internal delivery, including its rejection.
			lambdaEventsPipeline(t, c, fixture, source)
			functionError, err := c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: c.functionName, Payload: []byte(`{"case":"function-error-default-retry"}`)})
			if err != nil || functionError.FunctionError == nil {
				t.Fatalf("expected native function-error HTTP 200: %+v, %v", functionError, err)
			}
			lambdaEventsReceive(t, c, c.outputURL, 1)
			functionErrorID, _ := awsmiddleware.GetRequestIDMetadata(functionError.ResultMetadata)
			functionErrorFound := false
			for _, row := range lambdaAuditRows(t, failing) {
				if row.RequestID == functionErrorID {
					lambdaAuditConforms(t, row, lambdaAuditNative(t, "Invoke", "RequestResponse"), c.functionARN)
					functionErrorFound = true
				}
			}
			if !functionErrorFound {
				t.Fatal("FunctionError HTTP 200 outcome was omitted")
			}
			acceptedInternal, rejectedInternal := false, false
			for _, row := range lambdaAuditRows(t, failing) {
				if row.APICallCompleted.EventName != "Invoke" || row.ActorService != "events.amazonaws.com" {
					continue
				}
				if row.ParentEventID == "" || row.RequestID == "" {
					t.Fatal("internal invocation lost request or parent identity")
				}
				if row.APICallCompleted.ErrorCode == "" {
					acceptedInternal = true
					lambdaAuditConforms(t, row, lambdaAuditNative(t, "Invoke", "Event"), c.functionARN)
				} else {
					rejectedInternal = true
				}
			}
			if !acceptedInternal || !rejectedInternal {
				t.Fatal("internal accepted/rejected Lambda API outcomes missing")
			}
		})
	}
}

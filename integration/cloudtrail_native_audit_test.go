package stackd_test

import (
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"sort"
	"testing"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/smithy-go/middleware"
)

// nativeControlAuditCapture is the shared output of cloudtrail_service_probe.py.
// Inputs drive signed SDK calls; request IDs select the native audit outcome.
type nativeControlAuditCapture struct {
	Account  string `json:"account"`
	Region   string `json:"region"`
	Identity struct {
		UserID string `json:"UserId"`
	} `json:"identity"`
	Calls []struct {
		Label            string          `json:"label"`
		Service          string          `json:"service"`
		Operation        string          `json:"operation"`
		Caller           string          `json:"caller"`
		Input            json.RawMessage `json:"input"`
		Output           json.RawMessage `json:"output"`
		Code             string          `json:"code"`
		RequestID        string          `json:"request_id"`
		ExpectedCategory string          `json:"expected_category"`
	} `json:"calls"`
	History struct {
		Events []nativeAuditObservation `json:"events"`
	} `json:"history"`
}

type nativeAuditObservation struct {
	Label          string         `json:"call_label"`
	Event          map[string]any `json:"event"`
	LookupMetadata struct {
		Resources []struct {
			Name string `json:"ResourceName"`
			Type string `json:"ResourceType"`
		} `json:"Resources"`
	} `json:"lookup_metadata"`
}

// Preserve native field presence and values, but not diagnostic wording.
// CloudTrail may report a different diagnostic from the SDK wire rejection.
func assertNativeAuditEvent(t *testing.T, got, want map[string]any, errorMessage string) {
	t.Helper()
	for _, field := range []string{"eventVersion", "eventTime", "eventSource", "eventName", "awsRegion", "readOnly", "eventCategory", "managementEvent", "eventType", "recipientAccountId", "resources", "requestParameters", "responseElements", "errorCode"} {
		actual, present := got[field]
		value, nativePresent := want[field]
		if field == "requestParameters" && want["eventSource"] == "xray.amazonaws.com" && want["eventName"] == "PutTraceSegments" {
			// Native audit reduces accepted documents to an unordered trace-ID
			// collection. Preserve the original event for S3/SQS equality.
			normalize := func(value any) any {
				request, ok := value.(map[string]any)
				if !ok {
					return value
				}
				ids, ok := request["traceSegmentDocuments"].([]any)
				if !ok {
					return value
				}
				request = maps.Clone(request)
				ids = slices.Clone(ids)
				sort.Slice(ids, func(i, j int) bool { return ids[i].(string) < ids[j].(string) })
				request["traceSegmentDocuments"] = ids
				return request
			}
			actual, value = normalize(actual), normalize(value)
		}
		if present != nativePresent || !reflect.DeepEqual(actual, value) {
			actualJSON, _ := json.MarshalIndent(actual, "", "  ")
			nativeJSON, _ := json.MarshalIndent(value, "", "  ")
			t.Fatalf("%s field %s: got (present %t):\n%s\nnative (present %t):\n%s", want["eventName"], field, present, actualJSON, nativePresent, nativeJSON)
		}
	}
	nativeMessage, nativeError := want["errorMessage"]
	message, present := got["errorMessage"]
	if present != nativeError || reflect.TypeOf(message) != reflect.TypeOf(nativeMessage) {
		t.Fatalf("%s audit diagnostic differs from native (SDK rejection %q): %#v", got["requestID"], errorMessage, got)
	}
}

func nativeAuditRequestID(t *testing.T, output any, callErr error) string {
	t.Helper()
	var id string
	if callErr != nil {
		var response interface{ ServiceRequestID() string }
		if !errors.As(callErr, &response) {
			t.Fatalf("SDK error has no request correlation: %v", callErr)
		}
		id = response.ServiceRequestID()
	} else {
		metadata := reflect.ValueOf(output).Elem().FieldByName("ResultMetadata").Interface().(middleware.Metadata)
		id, _ = awsmiddleware.GetRequestIDMetadata(metadata)
	}
	if id == "" {
		t.Fatal("SDK response has no request ID")
	}
	return id
}

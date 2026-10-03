package stackd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type s3NativeObservation struct {
	Label, Operation string
	Input            json.RawMessage
	Result           struct {
		Code       string
		Output     map[string]any
		HTTPStatus int `json:"http_status"`
	}
}

type s3NativeFixture struct {
	Observations  []s3NativeObservation
	Identity      map[string]string `json:"identity_relationships"`
	Payload       struct{ Base64 string }
	DeliveredLogs []struct {
		Records []map[string]any `json:"Records"`
	} `json:"delivered_logs"`
	Correlations []struct {
		EventID string `json:"eventID"`
		Label   string `json:"observation_label"`
	} `json:"request_correlations"`
}

func s3NativeLoad(t *testing.T, service, name string) s3NativeFixture {
	t.Helper()
	var f s3NativeFixture
	awsReadFixture(t, service+"/"+name+".json", &f)
	return f
}

func (f s3NativeFixture) row(t *testing.T, label string) s3NativeObservation {
	t.Helper()
	for _, row := range f.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("native fixture missing %s", label)
	return s3NativeObservation{}
}

func (f s3NativeFixture) payload(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(f.Payload.Base64)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func s3NativeClient(c cloudClients, key, secret string) *s3.Client {
	return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL),
		Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(),
		UsePathStyle: true, RetryMaxAttempts: 1, RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenSupported})
}

// Invoke the real SDK operation named by the native observation. CLI file-body
// placeholders are transport annotations, not bytes to upload or JSON readers.
func s3NativeInvoke(t *testing.T, client any, row s3NativeObservation, payload []byte) (map[string]any, string, error) {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(row.Input, &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "Body")
	// The CLI's botocore listing handler injects encoding-type=url. The Go SDK
	// does not; replay that observed transport option rather than changing S3's
	// behavior for requests that genuinely omit it.
	if (row.Operation == "ListObjects" || row.Operation == "ListObjectsV2") && raw["EncodingType"] == nil && row.Result.Output["EncodingType"] == "url" {
		raw["EncodingType"] = json.RawMessage(`"url"`)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	result, err := awstest.CallSDK(t.Context(), client, row.Operation, b, func(input any) {
		if input, ok := input.(*s3.PutObjectInput); ok {
			input.Body = bytes.NewReader(payload)
		}
	})
	if err != nil {
		var response interface{ ServiceRequestID() string }
		if errors.As(err, &response) {
			return nil, response.ServiceRequestID(), err
		}
		return nil, "", err
	}
	output := reflect.ValueOf(result).Elem()
	metadata := output.FieldByName("ResultMetadata").Interface().(middleware.Metadata)
	requestID, ok := awsmiddleware.GetRequestIDMetadata(metadata)
	if !ok || requestID == "" {
		t.Fatalf("%s omitted SDK request correlation", row.Label)
	}
	response, ok := awsmiddleware.GetRawResponse(metadata).(*smithyhttp.Response)
	if !ok || row.Result.HTTPStatus != 0 && response.StatusCode != row.Result.HTTPStatus {
		t.Fatalf("%s HTTP response: %+v; native %d", row.Label, response, row.Result.HTTPStatus)
	}
	var body []byte
	if field := output.FieldByName("Body"); field.IsValid() && !field.IsNil() {
		reader := field.Interface().(io.ReadCloser)
		body, err = io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("%s body: %v %v", row.Label, err, closeErr)
		}
	}
	b, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if body != nil {
		got["captured_body"] = map[string]any{"base64": base64.StdEncoding.EncodeToString(body), "bytes": float64(len(body)), "equals_uploaded_payload": bytes.Equal(body, payload)}
	}
	return got, requestID, nil
}

func s3NativeReplay(t *testing.T, client any, f s3NativeFixture, label string) (map[string]any, string) {
	t.Helper()
	row := f.row(t, label)
	got, id, err := s3NativeInvoke(t, client, row, f.payload(t))
	if row.Result.Code != "Success" {
		var response *smithyhttp.ResponseError
		if !errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
			t.Fatalf("%s HTTP error: %v; native %d", label, err, row.Result.HTTPStatus)
		}
		// HEAD's empty error body is an HTTP distinction, not a modeled XML code.
		if row.Result.Code != "404" {
			var api smithy.APIError
			if !errors.As(err, &api) || api.ErrorCode() != row.Result.Code {
				t.Fatalf("%s: %v; native code %s", label, err, row.Result.Code)
			}
		}
		return nil, response.Response.Header.Get("x-amz-request-id")
	}
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	s3NativeProjection(t, label, row.Result.Output, got)
	return got, id
}

// ACL order is not stable. Match captured fields one-to-one without turning
// omitted provider identities into asserted empty strings.
func assertS3NativeGrantSet(t *testing.T, path string, want []any, got any) {
	t.Helper()
	array, ok := got.([]any)
	if !ok || len(array) != len(want) {
		t.Fatalf("%s grants: got %#v; native %#v", path, got, want)
	}
	var matches func(any, any) bool
	matches = func(expected, actual any) bool {
		fields, object := expected.(map[string]any)
		if !object {
			return reflect.DeepEqual(expected, actual)
		}
		values, object := actual.(map[string]any)
		if !object {
			return false
		}
		for key, value := range fields {
			current, exists := values[key]
			if !exists || !matches(value, current) {
				return false
			}
		}
		return true
	}
	// Reassign an earlier match when a more specific captured grant needs it.
	matched := make([]int, len(array))
	for i := range matched {
		matched[i] = -1
	}
	seen := make([]bool, len(array))
	var assign func(int) bool
	assign = func(expected int) bool {
		for i, actual := range array {
			if seen[i] || !matches(want[expected], actual) {
				continue
			}
			seen[i] = true
			if matched[i] < 0 || assign(matched[i]) {
				matched[i] = expected
				return true
			}
		}
		return false
	}
	for i := range want {
		clear(seen)
		if !assign(i) {
			t.Fatalf("%s grants: got %#v; native %#v", path, got, want)
		}
	}
}

// Compare captured fields, preserving array order except for tags and ACL grants.
// Only provider timestamps and locally derived body digests differ.
func s3NativeProjection(t *testing.T, path string, want, got any) {
	t.Helper()
	var native any
	if bound, ok := want.(s3NativeBoundOutput); ok {
		native, want = bound.native, bound.rebound
	}
	switch want := want.(type) {
	case map[string]any:
		object, ok := got.(map[string]any)
		if len(want) == 0 && got == nil {
			return
		}
		if !ok {
			t.Fatalf("%s object: got %#v", path, got)
		}
		nativeObject, _ := native.(map[string]any)
		for key, value := range want {
			if key == "LastModified" {
				if object[key] == nil {
					t.Fatalf("%s missing timestamp", path)
				}
				if expected, ok := nativeObject[key].(string); !ok || !strings.Contains(expected, "${") {
					continue
				}
			}
			if key == "sha256" {
				continue
			} // Exact decoded body bytes are compared instead.
			actual, exists := object[key]
			// SDK output fields are exported Go identifiers; the CLI preserves modeled
			// lower-case members such as DescribeTrails.trailList.
			if !exists && key != "" {
				actual, exists = object[strings.ToUpper(key[:1])+key[1:]]
			}
			if !exists {
				t.Fatalf("%s missing native field %s", path, key)
			}
			if values, set := value.([]any); set {
				if key == "Tags" || key == "TagSet" {
					assertS3NativeTagSet(t, path+"."+key, value, actual)
					continue
				}
				// S3 ACL grants, unlike KMS grants, carry a modeled Grantee.
				if key == "Grants" && len(values) != 0 {
					if grant, ok := values[0].(map[string]any); ok && grant["Grantee"] != nil {
						assertS3NativeGrantSet(t, path+"."+key, values, actual)
						continue
					}
				}
			}
			if text, document := actual.(string); key == "Policy" && document {
				// S3 policy text is a document; IAM's Policy is a typed resource
				// and follows the ordinary field projection below.
				if expected, ok := value.(string); ok {
					if err := json.Unmarshal([]byte(expected), &value); err != nil {
						t.Fatalf("%s: invalid native policy: %v", path, err)
					}
				}
				if err := json.Unmarshal([]byte(text), &actual); err != nil {
					t.Fatalf("%s: invalid returned policy: %v", path, err)
				}
				if !reflect.DeepEqual(value, actual) {
					t.Fatalf("%s.Policy: got %#v want native %#v", path, actual, value)
				}
				continue
			}
			if key == "ObjectLockRetainUntilDate" || key == "RetainUntilDate" {
				expectedTime, expectedErr := time.Parse(time.RFC3339Nano, fmt.Sprint(value))
				actualTime, actualErr := time.Parse(time.RFC3339Nano, fmt.Sprint(actual))
				if expectedErr != nil || actualErr != nil || !actualTime.Equal(expectedTime) {
					t.Fatalf("%s.%s: got %#v want native %#v", path, key, actual, value)
				}
				continue
			}
			if nativeObject != nil {
				value = s3NativeBoundOutput{native: nativeObject[key], rebound: value}
			}
			s3NativeProjection(t, path+"."+key, value, actual)
		}
	case []any:
		array, ok := got.([]any)
		if len(want) == 0 && got == nil {
			return
		}
		if !ok || len(array) != len(want) {
			t.Fatalf("%s array: got %#v want %#v", path, got, want)
		}
		nativeArray, _ := native.([]any)
		for i := range want {
			value := want[i]
			if nativeArray != nil {
				value = s3NativeBoundOutput{native: nativeArray[i], rebound: value}
			}
			s3NativeProjection(t, path, value, array[i])
		}
	default:
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: got %#v want native %#v", path, got, want)
		}
	}
}

type s3ObjectCall struct {
	s3KMSCall
	At            time.Time
	Raw           *s3MultipartEventCall
	Drain         bool
	Headers       map[string]string
	AbsentHeaders []string
	Deadline      *struct {
		At              time.Time
		FromSequence    int
		ThroughSequence int
		Days, Years     int
	}
	Batch *s3LockBatch
}

type s3LockDeleted struct {
	Key, VersionId, DeleteMarkerVersionId string
	DeleteMarker                          bool
}

type s3LockDeleteError struct {
	Key, VersionId, Code string
}

type s3LockBatch struct {
	Deleted []s3LockDeleted
	Errors  []s3LockDeleteError `xml:"Error"`
}

// The transport is part of the replay: TLS must reach the actual stack so IAM
// SecureTransport conditions and SSE-C see the connection, not a proxy header.
func retainedS3ReplayCloud(t *testing.T, backend string, config stackd.Config, useTLS bool) (cloudClients, func() cloudClients) {
	t.Helper()
	return retainedCloud(t, backend, config, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		if !useTLS {
			return startPublicCloud(t, config)
		}
		server := httptest.NewUnstartedServer(nil)
		config.PublicEndpoint = "https://" + server.Listener.Addr().String()
		cloud, err := stackd.New(config)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		server.Config.Handler = cloud
		// StartTLS supplies server.Client with a transport trusting this server's
		// certificate. Both SDK and raw replay use that client without bypasses.
		server.StartTLS()
		return cloud, server
	})
}

func runS3ObjectCalls(t *testing.T, backend string, setup []s3KMSCall, calls []s3ObjectCall, useTLS bool) {
	t.Helper()
	source := clock.NewManual(calls[0].At)
	clients, reopen := retainedS3ReplayCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, useTLS)
	replay := newS3KMSReplay(clients)
	for _, row := range setup {
		replay.call(t, row)
	}
	times := make(map[int]time.Time, len(calls))
	for _, row := range calls {
		if row.Reopen {
			replay.clients = reopen()
		}
		advanceClock(t, source, row.At.Sub(source.Now()))
		if row.Drain {
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
		}
		times[row.Sequence] = source.Now()
		if !t.Run(fmt.Sprintf("%03d-%s", row.Sequence, row.Label), func(t *testing.T) {
			wire := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
			replay.httpClient = wire
			if row.Raw != nil {
				raw := *row.Raw
				raw.Sequence, raw.Label, raw.Operation = row.Sequence, row.Label, row.Operation
				raw.Status = row.Status
				// HEAD errors have no XML code on the wire.
				if row.Code != "Success" && row.Operation != "HeadObject" {
					raw.Code = row.Code
				}
				actor := row.Actor
				if actor == "" {
					actor = "caller"
				}
				credentials, ok := replay.sessions[actor]
				if !ok {
					t.Fatalf("missing native actor %s", actor)
				}
				s3MultipartEventRequest(t, replay, credentials, raw, source.Now())
			} else {
				replay.call(t, row.s3KMSCall)
				var details map[string]string
				if err := json.Unmarshal(replay.rebind(t, row.ErrorDetails), &details); err != nil {
					t.Fatal(err)
				}
				assertS3ErrorDetails(t, wire.body, details)
			}
			var headers map[string]string
			if err := json.Unmarshal(replay.rebind(t, row.Headers), &headers); err != nil {
				t.Fatal(err)
			}
			for name, want := range headers {
				if got := wire.header.Get(name); got != want {
					t.Fatalf("%s = %q; native %q", name, got, want)
				}
			}
			for _, name := range row.AbsentHeaders {
				if _, exists := wire.header[http.CanonicalHeaderKey(name)]; exists {
					t.Fatalf("exposed %s omitted by native response", name)
				}
			}
			if row.Deadline != nil {
				want := row.Deadline.At
				if row.Deadline.FromSequence != 0 {
					base, exists := times[row.Deadline.FromSequence]
					if !exists {
						t.Fatalf("missing native deadline origin %d", row.Deadline.FromSequence)
					}
					want = base.AddDate(row.Deadline.Years, 0, row.Deadline.Days)
				}
				latest := want
				if row.Deadline.ThroughSequence != 0 {
					base, exists := times[row.Deadline.ThroughSequence]
					if !exists {
						t.Fatalf("missing native deadline upper bound %d", row.Deadline.ThroughSequence)
					}
					latest = base.AddDate(row.Deadline.Years, 0, row.Deadline.Days)
				}
				value := wire.header.Get("x-amz-object-lock-retain-until-date")
				if row.Operation == "GetObjectRetention" {
					var retention struct{ RetainUntilDate string }
					if err := xml.Unmarshal(wire.body, &retention); err != nil {
						t.Fatal(err)
					}
					value = retention.RetainUntilDate
				}
				got, err := time.Parse(time.RFC3339Nano, value)
				if err != nil || got.Before(want) || got.After(latest) {
					t.Fatalf("retention deadline = %q (%v); native interval [%s, %s]", value, err, want.Format(time.RFC3339Nano), latest.Format(time.RFC3339Nano))
				}
			}
			if row.Batch != nil {
				var got, want s3LockBatch
				if err := xml.Unmarshal(wire.body, &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(replay.rebind(t, row.Batch), &want); err != nil {
					t.Fatal(err)
				}
				// DeleteObjects response order is not contractual. Marker IDs
				// are generated, but their presence and per-entry outcome are.
				for i := range got.Deleted {
					if got.Deleted[i].DeleteMarkerVersionId != "" {
						got.Deleted[i].DeleteMarkerVersionId = "generated"
					}
				}
				for _, batch := range []*s3LockBatch{&got, &want} {
					sort.Slice(batch.Deleted, func(i, j int) bool { return batch.Deleted[i].Key < batch.Deleted[j].Key })
					sort.Slice(batch.Errors, func(i, j int) bool { return batch.Errors[i].Key < batch.Errors[j].Key })
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("batch deletion = %#v; native %#v", got, want)
				}
			}
		}) {
			return
		}
	}
}
func assertS3ErrorDetails(t *testing.T, body []byte, want map[string]string) {
	t.Helper()
	if len(want) == 0 {
		return
	}
	type xmlDetails struct {
		Fields []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
		Error *xmlDetails `xml:"Error"`
	}
	var detail xmlDetails
	if err := xml.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Error != nil {
		detail = *detail.Error
	}
	got := make(map[string]string, len(detail.Fields))
	for _, field := range detail.Fields {
		got[field.XMLName.Local] = field.Value
	}
	for name, expected := range want {
		if value, exists := got[name]; !exists || value != expected {
			t.Fatalf("error %s = %q (present %t); native %q", name, value, exists, expected)
		}
	}
}

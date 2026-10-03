package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type s3MultipartCall struct {
	s3KMSCall
	Payload string
	Digest  *struct {
		Length int
		SHA256 string
	}
	Headers map[string]string
}

type s3MultipartPayload struct {
	Base64 string
	Repeat int
}

// Expectations are compact projections of the referenced native observation,
// not values calculated from the emulator. Only issued upload/version identities
// are rebound; ETags, checksum bytes, selected part order and body digests remain
// literal native values. Payload recipes keep the 5 MiB boundary inexpensive on disk.
func TestS3NativeMultipartReplay(t *testing.T) {
	for _, name := range []string{"controls", "readers", "completion", "checksums", "read_bounds"} {
		var fixture struct {
			Payloads  map[string][]s3MultipartPayload
			Scenarios []struct {
				Name  string
				Calls []s3MultipartCall
			}
		}
		awsReadFixture(t, "s3/multipart_"+name+"_replay.json", &fixture)
		for _, backend := range []string{"memory", "sqlite"} {
			for _, scenario := range fixture.Scenarios {
				t.Run(name+"/"+backend+"/"+scenario.Name, func(t *testing.T) {
					source := clock.NewManual(time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC))
					clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
					replay := newS3KMSReplay(clients)
					for _, row := range scenario.Calls {
						if row.Reopen {
							replay.clients = reopen()
						}
						if !t.Run(row.Label, func(t *testing.T) {
							s3MultipartReplayCall(t, replay, fixture.Payloads, row)
						}) {
							return // Dependent calls must not run with missing issued identities.
						}
						advanceClock(t, source, time.Second)
					}
				})
			}
		}
	}
}

func s3MultipartReplayCall(t *testing.T, replay *s3KMSReplay, payloads map[string][]s3MultipartPayload, row s3MultipartCall) {
	t.Helper()
	var payload []byte
	if row.Payload != "" {
		segments, ok := payloads[row.Payload]
		if !ok {
			t.Fatalf("%s: missing native payload %s", row.Label, row.Payload)
		}
		for _, segment := range segments {
			payload = append(payload, bytes.Repeat(s3KMSDecode(t, segment.Base64), segment.Repeat)...)
		}
	}
	actor := row.Actor
	if actor == "" {
		actor = "caller"
	}
	region := row.Region
	if region == "" {
		region = "us-east-1"
	}
	out, err := awstest.CallSDK(t.Context(), replay.s3RegionClient(actor, region), row.Operation, replay.rebind(t, row.Input), func(input any) {
		switch input := input.(type) {
		case *s3.UploadPartInput:
			input.Body = bytes.NewReader(payload)
		case *s3.PutObjectInput:
			input.Body = bytes.NewReader(payload)
			if input.ContentType == nil {
				input.ContentType = aws.String("binary/octet-stream")
			}
		case *s3.CreateMultipartUploadInput:
			if input.ContentType == nil {
				input.ContentType = aws.String("binary/octet-stream")
			}
		}
	})
	var header http.Header
	if row.Code != "Success" {
		if _, numeric := strconv.Atoi(row.Code); numeric != nil {
			assertAPIError(t, err, row.Code)
		}
		var response *smithyhttp.ResponseError
		// S3 may begin a completion's 200 response before a final failure.
		// The Go SDK's S3:ProcessResponseFor200Error middleware rewrites that
		// embedded error to status 500; the signed raw replay checks wire status.
		// Zero means the capture established the error code, not the wire status.
		if !errors.As(err, &response) || (row.Status != 0 && response.HTTPStatusCode() != row.Status && !(row.Operation == "CompleteMultipartUpload" && response.HTTPStatusCode() == 500)) {
			t.Fatalf("%s (%s:%d): native HTTP %d, got %v", row.Label, row.Source, row.Sequence, row.Status, err)
		}
		header = response.Response.Header
	} else {
		if err != nil {
			t.Fatalf("%s (%s:%d): %v", row.Label, row.Source, row.Sequence, err)
		}
		metadata := reflect.ValueOf(out).Elem().FieldByName("ResultMetadata").Interface().(middleware.Metadata)
		response, ok := awsmiddleware.GetRawResponse(metadata).(*smithyhttp.Response)
		if !ok || response.StatusCode != row.Status {
			t.Fatalf("%s: native HTTP %d, got %+v", row.Label, row.Status, response)
		}
		header = response.Header
		if object, ok := out.(*s3.GetObjectOutput); ok {
			body, readErr := io.ReadAll(object.Body)
			closeErr := object.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatalf("%s: reading object: %v %v", row.Label, readErr, closeErr)
			}
			if row.Digest == nil {
				t.Fatalf("%s: missing native consumer-body expectation", row.Label)
			}
			if len(body) != row.Digest.Length || fmt.Sprintf("%x", sha256.Sum256(body)) != row.Digest.SHA256 {
				t.Fatalf("%s: object bytes differ from native length/digest", row.Label)
			}
		}
		data, marshalErr := awstest.MarshalSDK(out)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var got map[string]any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		for name, path := range row.Bind {
			value := awsFixtureField(got, path)
			text, ok := value.(string)
			if !ok || text == "" {
				t.Fatalf("%s: missing issued identity %s", row.Label, path)
			}
			replay.values[name] = text
		}
		var want map[string]any
		if err := json.Unmarshal(replay.rebind(t, row.Output), &want); err != nil {
			t.Fatal(err)
		}
		s3NativeProjection(t, row.Label, s3NativeBoundOutput{native: row.Output, rebound: want}, got)
		for _, path := range row.Absent {
			if value := awsFixtureField(got, path); value != nil && value != "" {
				t.Fatalf("%s: %s exposed %#v but native omitted it", row.Label, path, value)
			}
		}
	}
	for name, want := range row.Headers {
		if got := header.Get(name); got != want {
			t.Fatalf("%s: native header %s=%q, got %q", row.Label, name, want, got)
		}
	}
}

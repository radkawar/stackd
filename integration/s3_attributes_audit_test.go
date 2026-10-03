package stackd_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"stackd"
	"stackd/clock"
)

// Capture the public serialization before the SDK consumes it or rewrites a
// CompleteMultipartUpload HTTP200 Error into a modeled HTTP500 failure.
type s3AttributesAuditWire struct {
	*http.Client
	header  http.Header
	body    []byte
	host    string
	status  int
	bytesIn int64
}

func (w *s3AttributesAuditWire) Do(request *http.Request) (*http.Response, error) {
	var body []byte
	response, err := w.Client.Do(request)
	if err != nil {
		return response, err
	}
	body, err = io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err == nil {
		err = closeErr
	}
	w.capture(request, response, body)
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, err
}

func (w *s3AttributesAuditWire) capture(request *http.Request, response *http.Response, body []byte) {
	w.host, w.bytesIn = request.URL.Host, request.ContentLength
	if request.Host != "" {
		w.host = request.Host
	}
	w.header, w.status, w.body = response.Header.Clone(), response.StatusCode, body
}

// Only request-correlated outcomes actually delivered in the two native bounded
// captures are asserted. In particular, InvalidArgument for BogusAttribute is
// excluded, not asserted permanently absent from CloudTrail.
func TestS3AttributesNativeAuditDelivery(t *testing.T) {
	var fixture struct {
		AuditBucket, AuditPrefix string
		Payloads                 map[string][]s3MultipartPayload
		Setup, Trail             []s3KMSCall
		Objects, Verify          []s3MultipartCall
		Calls                    []struct {
			s3MultipartCall
			Record map[string]any
		}
	}
	awsReadFixture(t, "s3/multipart_attributes_audit_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
			replay := newS3KMSReplay(clients)
			for _, row := range fixture.Setup {
				replay.call(t, row)
			}
			arn, key, secret := clients.user(t, "test", "Delegated")
			putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"s3:*"`, "*"))
			replay.sessions["audit-user"] = aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			for _, row := range fixture.Objects {
				s3MultipartReplayCall(t, replay, fixture.Payloads, row)
			}
			for _, row := range fixture.Trail {
				replay.call(t, row)
			}
			wires := map[string]*s3AttributesAuditWire{}
			ids := map[int]string{}
			times := map[int]string{}
			for _, row := range fixture.Calls {
				wire := &s3AttributesAuditWire{Client: replay.clients.server.Client()}
				replay.httpClient = wire
				s3MultipartReplayCall(t, replay, fixture.Payloads, row.s3MultipartCall)
				id := wire.header.Get("x-amz-request-id")
				if id == "" || wires[id] != nil || wire.header.Get("x-amz-id-2") == "" {
					t.Fatalf("%s lost unique public request correlation", row.Label)
				}
				wires[id], ids[row.Sequence] = wire, id
				times[row.Sequence] = source.Now().UTC().Format(time.RFC3339)
				advanceClock(t, source, time.Second)
			}
			// Accepted audit work and retained failed-upload parts survive reopen.
			replay.clients = reopen()
			replay.httpClient = nil
			for _, row := range fixture.Verify {
				s3MultipartReplayCall(t, replay, fixture.Payloads, row)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			delivered := map[string]map[string]any{}
			objects := trailNativeObjects(t, replay.s3Client("caller"), fixture.AuditBucket, fixture.AuditPrefix)
			for _, record := range trailNativeRecords(t, objects) {
				id, _ := record["requestID"].(string)
				if wires[id] == nil {
					// Native selectors also include management operations. Setup,
					// retention controls and trail reads are not primary cases.
					continue
				}
				if prior := delivered[id]; prior != nil && !reflect.DeepEqual(prior, record) {
					t.Fatalf("redelivery changed request %s", id)
				}
				delivered[id] = record
			}
			for _, row := range fixture.Calls {
				id := ids[row.Sequence]
				got, wire := delivered[id], wires[id]
				if got == nil {
					t.Fatalf("%s: missing delivered gzip record from %s", row.Label, row.Source)
				}
				if row.Operation == "CompleteMultipartUpload" {
					response, _ := got["responseElements"].(map[string]any)
					version, _ := response["x-amz-version-id"].(string)
					if version == "" || wire.header.Get("x-amz-version-id") != "" {
						t.Fatalf("InvalidPart lost audit-only unpublished version: %#v", response)
					}
					for _, name := range []string{"ordinaryVersion", "multipartVersion", "predecessorVersion", "markerVersion"} {
						if version == replay.values[name] {
							t.Fatal("InvalidPart audit version aliases a published version")
						}
					}
					replay.values["unpublishedVersion"] = version
				}
				var want map[string]any
				if err := json.Unmarshal(replay.rebind(t, row.Record), &want); err != nil {
					t.Fatal(err)
				}
				want["eventTime"] = times[row.Sequence]
				want["requestParameters"].(map[string]any)["Host"] = wire.host
				var failure struct{ Message string }
				if err := xml.Unmarshal(wire.body, &failure); err != nil {
					t.Fatal(err)
				}
				assertNativeAuditEvent(t, got, want, failure.Message)
				identity, _ := got["userIdentity"].(map[string]any)
				nativeIdentity := want["userIdentity"].(map[string]any)
				for _, field := range []string{"type", "userName", "accountId", "arn", "invokedBy"} {
					if identity[field] != nativeIdentity[field] {
						t.Fatalf("%s changed caller %s: %#v", row.Label, field, identity)
					}
				}
				if identity["arn"] != arn || identity["accessKeyId"] != key || identity["principalId"] == nil || identity["principalId"] == "" || got["eventID"] == nil || got["eventID"] == "" {
					t.Fatalf("%s lost caller/event correlation: %#v", row.Label, got)
				}
				additional, _ := got["additionalEventData"].(map[string]any)
				nativeAdditional := want["additionalEventData"].(map[string]any)
				for _, field := range []string{"AuthenticationMethod", "SignatureVersion", "objectSize"} {
					value, present := additional[field]
					native, nativePresent := nativeAdditional[field]
					if present != nativePresent || !reflect.DeepEqual(value, native) {
						t.Fatalf("%s changed native %s presence/value: %#v", row.Label, field, additional)
					}
				}
				// Native605/raw567 is retained in JSON, not generalized into a
				// serializer offset. Compare each local serialized body directly.
				if additional["bytesTransferredIn"] != float64(wire.bytesIn) || additional["bytesTransferredOut"] != float64(len(wire.body)) || additional["httpStatusCode"] != float64(wire.status) || additional["x-amz-id-2"] != wire.header.Get("x-amz-id-2") {
					t.Fatalf("%s lost local wire accounting/correlation: %#v; HTTP%d in%d out%d", row.Label, additional, wire.status, wire.bytesIn, len(wire.body))
				}
			}
		})
	}
}

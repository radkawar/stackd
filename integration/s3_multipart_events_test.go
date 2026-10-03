package stackd_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"stackd"
	"stackd/clock"
)

type s3MultipartEventCall struct {
	Sequence                                           int
	Label, Operation, Method, Target, Body, Code, ETag string
	Headers                                            map[string]string
	AfterSigningHeaders                                map[string]string
	Bind                                               map[string]string
	Presign                                            bool
	RequestHost, ResponseFormat, Region                string
	ResponseHeaders                                    map[string]string
	AbsentHeaders, BodyContains                        []string
	ResponseBody                                       *string
	ErrorDetails                                       map[string]string
	AbsentErrorDetails                                 []string
	Payload                                            []s3MultipartPayload
	Status                                             int
	Reopen                                             bool
	ResponseDigest                                     *struct {
		Length int
		SHA256 string
	}
	Notifications []s3NotifyDelivery
}

type s3MultipartEventWire struct {
	id, extended, eventTime, message string
	status, bytesIn, bytesOut        int
	target                           *url.URL
}

// The primary capture used raw signed HTTP, including the literal completion
// XML. Replay it through the public listener, not an internal S3 dispatcher.
// Native data projections come from delivered gzip logs; native management
// projections come from LookupEvents, with a read-only management selector
// explicitly added to deliver those same records through the real trail sink.
func TestS3MultipartNativeEventsAndAuditDelivery(t *testing.T) {
	var fixture struct {
		Source, Bucket, AuditBucket, AuditPrefix string
		Setup                                    []s3KMSCall
		Calls                                    []s3MultipartEventCall
		NoPrivateValues                          []string
		Records                                  []struct {
			Sequence      int
			ErrorBodyFrom int
			Source        string
			Internal      bool
			Record        map[string]any
		}
	}
	awsReadFixture(t, "s3/multipart_events_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 20, 7, 44, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source})
			replay := newS3KMSReplay(clients)
			for _, row := range fixture.Setup {
				replay.call(t, row)
			}
			arn, key, secret := clients.user(t, "test", "Delegated")
			putUserPolicy(t, clients.iam("test", "test", ""), "Delegated", allow(`"s3:*"`, "*"))
			credentials := aws.Credentials{AccessKeyID: key, SecretAccessKey: secret}
			receipts := map[string][]s3NotifyReceipt{}
			sequencers := map[string]string{}
			// Stabilize configuration using service time, then consume only the
			// native setup TestEvent. No primary mutation has run yet.
			advanceClock(t, source, time.Minute)
			for _, channel := range []string{"classic", "eventbridge"} {
				queue := replay.values["queue_"+channel]
				s3NotifyCollect(t, replay, queue, receipts)
				for _, receipt := range receipts[queue] {
					if channel != "classic" || receipt.payload["Event"] != "s3:TestEvent" {
						t.Fatalf("unexpected setup delivery: %#v", receipt.payload)
					}
				}
				receipts[queue] = nil
			}
			wires := map[int]s3MultipartEventWire{}
			byRequest := map[string]int{}
			byExtended := map[string]int{}
			for _, row := range fixture.Calls {
				if row.Reopen {
					replay.clients = reopen()
				}
				if !t.Run(fmt.Sprintf("%d-%s", row.Sequence, row.Label), func(t *testing.T) {
					wire := s3MultipartEventRequest(t, replay, credentials, row, source.Now())
					if wire.id == "" || byRequest[wire.id] != 0 || wire.extended == "" {
						t.Fatalf("lost unique public request correlation: %+v", wire)
					}
					wires[row.Sequence], byRequest[wire.id] = wire, row.Sequence
					if row.Operation == "UploadPartCopy" {
						if byExtended[wire.extended] != 0 {
							t.Fatal("CopyPart reused an extended request ID")
						}
						byExtended[wire.extended] = row.Sequence
					}
					replay.values[fmt.Sprintf("request%d", row.Sequence)] = wire.id
					// Retain accepted publication and audit work before draining it;
					// this also precedes the exact successful completion retry.
					if row.Operation == "CompleteMultipartUpload" && row.Code == "" {
						replay.clients = reopen()
					}
					advanceClock(t, source, time.Second)
					trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
					var expected []s3NotifyDelivery
					if err := json.Unmarshal(replay.rebind(t, row.Notifications), &expected); err != nil {
						t.Fatal(err)
					}
					for _, channel := range []string{"classic", "eventbridge"} {
						queue := replay.values["queue_"+channel]
						s3NotifyCollect(t, replay, queue, receipts)
						for _, want := range expected {
							if want.Queue != queue {
								continue
							}
							found := -1
							for i, receipt := range receipts[queue] {
								if s3NotifyIdentity(receipt.payload) == s3NotifyIdentity(want.Payload) {
									found = i
									break
								}
							}
							if found < 0 {
								t.Fatalf("missing native %s delivery from %s after bounded service-time drain: %#v", channel, want.Source, receipts[queue])
							}
							s3NotifyCompare(t, row.Label, want, receipts[queue][found], sequencers)
							receipts[queue] = append(receipts[queue][:found], receipts[queue][found+1:]...)
						}
						// The native primary sequence has a positive control for each
						// channel and explicit TagAPI publication. No initiation tags,
						// part writes, failed completions, aborts or exact retry publish.
						if len(receipts[queue]) != 0 {
							t.Fatalf("unexpected %s publication for %s: %#v", channel, row.Label, receipts[queue])
						}
					}
				}) {
					return
				}
			}
			replay.clients = reopen()
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
			objects := trailNativeObjects(t, replay.s3Client("caller"), fixture.AuditBucket, fixture.AuditPrefix)
			delivered := map[int]map[string]any{}
			internal := map[int]map[string]any{}
			seen := map[string]map[string]any{}
			for _, got := range trailNativeRecords(t, objects) {
				id, _ := got["requestID"].(string)
				if id == "" {
					t.Fatal("delivered gzip record omitted request ID")
				}
				if prior := seen[id]; prior != nil {
					if !reflect.DeepEqual(prior, got) {
						t.Fatalf("redelivery changed record %s", id)
					}
					continue
				}
				seen[id] = got
				identity, _ := got["userIdentity"].(map[string]any)
				sequence := byRequest[id]
				if identity["invokedBy"] == "AWS Internal" {
					additional, _ := got["additionalEventData"].(map[string]any)
					extended, _ := additional["x-amz-id-2"].(string)
					sequence = byExtended[extended]
					if sequence == 0 || byRequest[id] != 0 || internal[sequence] != nil || got["eventName"] != "GetObject" {
						t.Fatalf("uncorrelated internal CopyPart read: %#v", got)
					}
					internal[sequence] = got
				} else {
					if sequence == 0 {
						// Management trail selectors cannot filter by eventName;
						// setup and delivery reads are outside the captured sequence.
						if got["eventCategory"] == "Management" {
							continue
						}
						t.Fatalf("scoped selectors delivered an unrelated request: %#v", got)
					}
					delivered[sequence] = got
				}
				for _, field := range []string{"requestParameters", "responseElements"} {
					projection, err := json.Marshal(got[field])
					if err != nil {
						t.Fatal(err)
					}
					for _, value := range fixture.NoPrivateValues {
						if strings.Contains(string(projection), value) {
							t.Fatalf("sequence %d leaked private tagging/metadata through %s", sequence, field)
						}
					}
				}
			}
			for _, expected := range fixture.Records {
				got := delivered[expected.Sequence]
				if expected.Internal {
					got = internal[expected.Sequence]
				}
				if got == nil {
					t.Fatalf("missing sequence %d from %s", expected.Sequence, expected.Source)
				}
				wire := wires[expected.Sequence]
				var want map[string]any
				if err := json.Unmarshal(replay.rebind(t, expected.Record), &want); err != nil {
					t.Fatal(err)
				}
				want["eventTime"] = wire.eventTime
				if !expected.Internal {
					// Reopen may change the listener port; bind the host recorded
					// for the request itself, rather than the delivery endpoint.
					want["requestParameters"].(map[string]any)["Host"] = replay.values[fmt.Sprintf("host%d", expected.Sequence)]
				}
				message := wire.message
				if want["eventName"] == "HeadObject" && want["errorCode"] != nil {
					// HEAD deliberately carries no error document. Its audit
					// diagnostic must be present, but its wording is not a wire
					// contract; error code/status remain native comparisons.
					message, _ = got["errorMessage"].(string)
					if message == "" {
						t.Fatalf("HEAD sequence %d omitted audit diagnostic", expected.Sequence)
					}
				}
				assertNativeAuditEvent(t, got, want, message)
				identity, _ := got["userIdentity"].(map[string]any)
				nativeIdentity := want["userIdentity"].(map[string]any)
				for _, field := range []string{"type", "userName", "accountId", "arn", "invokedBy"} {
					if identity[field] != nativeIdentity[field] {
						t.Fatalf("sequence %d changed native caller %s: %#v", expected.Sequence, field, identity)
					}
				}
				if identity["arn"] != arn || identity["accessKeyId"] != key || identity["principalId"] == nil || identity["principalId"] == "" || got["eventID"] == nil || got["eventID"] == "" {
					t.Fatalf("sequence %d lost caller/event context: %#v", expected.Sequence, got)
				}
				additional, _ := got["additionalEventData"].(map[string]any)
				nativeAdditional := want["additionalEventData"].(map[string]any)
				// Keep the fixture's native transfer lengths intact. XML wire
				// lengths depend on issued IDs/serialization; objectSize does not.
				for field, value := range nativeAdditional {
					if field == "bytesTransferredIn" || field == "bytesTransferredOut" {
						continue
					}
					if field == "httpStatusCode" && !expected.Internal && want["eventName"] == "CompleteMultipartUpload" && wire.status == 200 && want["errorCode"] != nil {
						value = float64(wire.status)
					}
					if !reflect.DeepEqual(additional[field], value) {
						t.Fatalf("sequence %d native additional field %s: got %#v, want %#v", expected.Sequence, field, additional[field], value)
					}
				}
				if _, present := nativeAdditional["objectSize"]; !present {
					if _, exposed := additional["objectSize"]; exposed {
						t.Fatalf("sequence %d invented objectSize", expected.Sequence)
					}
				}
				in := nativeAdditional["bytesTransferredIn"]
				if want["eventName"] == "CompleteMultipartUpload" {
					in = float64(wire.bytesIn)
				}
				out := float64(wire.bytesOut)
				checkOut := want["eventName"] != "HeadObject" || nativeAdditional["bytesTransferredOut"] == float64(0) || expected.ErrorBodyFrom != 0
				if expected.ErrorBodyFrom != 0 {
					// Native HEAD audit counts the logical XML document despite
					// an empty HTTP body. Compare the same public GET failure,
					// rebinding only the request/host identifier lengths.
					paired := wires[expected.ErrorBodyFrom]
					if wire.bytesOut != 0 || paired.status != wire.status {
						t.Fatalf("sequence %d changed the paired HEAD/GET failure", expected.Sequence)
					}
					out = float64(paired.bytesOut + len(wire.id) - len(paired.id) + len(wire.extended) - len(paired.extended))
				}
				if expected.Internal {
					in, out = float64(0), float64(0)
					for _, field := range []string{"sourceIPAddress", "userAgent"} {
						if got[field] != want[field] {
							t.Fatalf("internal sequence %d lost %s", expected.Sequence, field)
						}
					}
				}
				if additional["bytesTransferredIn"] != in || checkOut && additional["bytesTransferredOut"] != out || additional["x-amz-id-2"] != wire.extended {
					t.Fatalf("sequence %d lost actual wire byte/extended-ID correlation: %#v; wire %+v", expected.Sequence, additional, wire)
				}
				if expected.Internal {
					delete(internal, expected.Sequence)
				} else {
					delete(delivered, expected.Sequence)
				}
			}
			if len(delivered) != 0 || len(internal) != 0 {
				t.Fatalf("unobserved selected audit records: external %#v, internal %#v", delivered, internal)
			}
			// Check the entire final drain too, not merely per-call snapshots.
			for _, channel := range []string{"classic", "eventbridge"} {
				queue := replay.values["queue_"+channel]
				s3NotifyCollect(t, replay, queue, receipts)
				if len(receipts[queue]) != 0 {
					t.Fatalf("unexpected late publication: %#v", receipts[queue])
				}
			}
		})
	}
}

func s3MultipartEventRequest(t *testing.T, replay *s3KMSReplay, credentials aws.Credentials, row s3MultipartEventCall, now time.Time) s3MultipartEventWire {
	t.Helper()
	var target, body string
	if err := json.Unmarshal(replay.rebind(t, row.Target), &target); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(replay.rebind(t, row.Body), &body); err != nil {
		t.Fatal(err)
	}
	payload := []byte(body)
	for _, segment := range row.Payload {
		payload = append(payload, bytes.Repeat(s3KMSDecode(t, segment.Base64), segment.Repeat)...)
	}
	request, err := http.NewRequestWithContext(t.Context(), row.Method, replay.clients.server.URL+target, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if row.RequestHost != "" {
		if err := json.Unmarshal(replay.rebind(t, row.RequestHost), &request.Host); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range row.Headers {
		if value == "${bodyMD5}" {
			sum := md5.Sum(payload)
			request.Header.Set(name, base64.StdEncoding.EncodeToString(sum[:]))
			continue
		}
		var rebound string
		if err := json.Unmarshal(replay.rebind(t, value), &rebound); err != nil {
			t.Fatal(err)
		}
		request.Header.Set(name, rebound)
	}
	if credentials.AccessKeyID != "" {
		region := row.Region
		if region == "" {
			region = "us-east-1"
		}
		signer := v4.NewSigner(func(o *v4.SignerOptions) {
			o.DisableURIPathEscaping = true
			o.DisableHeaderHoisting = true
		})
		if row.Presign {
			query := request.URL.Query()
			query.Set("X-Amz-Expires", "120")
			request.URL.RawQuery = query.Encode()
			target, headers, err := signer.PresignHTTP(t.Context(), credentials, request, "UNSIGNED-PAYLOAD", "s3", region, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			request.URL, err = url.Parse(target)
			if err != nil {
				t.Fatal(err)
			}
			for name, values := range headers {
				request.Header[name] = values
			}
		} else {
			digest := sha256.Sum256(payload)
			if request.Header.Get("X-Amz-Content-Sha256") == "" {
				request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(digest[:]))
			}
			query := request.URL.RawQuery
			if err := signer.SignHTTP(t.Context(), credentials, request, hex.EncodeToString(digest[:]), "s3", region, time.Now()); err != nil {
				t.Fatal(err)
			}
			// SigV4 canonicalizes query order; raw replay must still transmit
			// the captured target, including repeated-value ordering.
			request.URL.RawQuery = query
		}
	}
	for name, value := range row.AfterSigningHeaders {
		request.Header.Set(name, value)
	}
	replay.values[fmt.Sprintf("host%d", row.Sequence)] = request.Host
	// Inspect the wire response itself: Client.Do parses redirect locations even
	// when redirect following is disabled; native S3 permits literal "%" here.
	response, err := replay.clients.server.Client().Transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("reading public response: %v %v", readErr, closeErr)
	}
	if capture, ok := replay.httpClient.(*s3AttributesAuditWire); ok {
		capture.capture(request, response, data)
	}
	var result struct {
		Code, Message, UploadId, ETag string
		Details                       []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	}
	if row.ResponseFormat != "html" && len(data) != 0 && (row.Operation != "GetObject" || response.StatusCode >= 400) {
		if row.ResponseFormat == "json" && response.StatusCode < 400 {
			if !json.Valid(data) {
				t.Fatalf("invalid JSON response: %s", data)
			}
		} else if err := xml.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
	}
	if row.ResponseFormat == "s3control" && response.StatusCode >= 400 {
		var envelope struct {
			XMLName xml.Name
			Error   struct {
				Code, Message string
				Details       []struct {
					XMLName xml.Name
					Value   string `xml:",chardata"`
				} `xml:",any"`
			}
			RequestId, HostId string
		}
		if err := xml.Unmarshal(data, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.XMLName.Local != "ErrorResponse" || envelope.RequestId == "" || envelope.HostId == "" {
			t.Fatalf("missing S3 Control error envelope: %s", data)
		}
		if envelope.RequestId != response.Header.Get("x-amz-request-id") || envelope.HostId != response.Header.Get("x-amz-id-2") {
			t.Fatalf("S3 Control error IDs differ from response headers: %s", data)
		}
		result.Code, result.Message, result.Details = envelope.Error.Code, envelope.Error.Message, envelope.Error.Details
	}
	if response.StatusCode != row.Status && !(row.Operation == "CompleteMultipartUpload" && row.Code != "" && response.StatusCode == 200) {
		t.Fatalf("%s: native HTTP %d, got %d: %s", row.Label, row.Status, response.StatusCode, data)
	}
	if result.Code != row.Code {
		t.Fatalf("%s: native error %q, got %q: %s", row.Label, row.Code, result.Code, data)
	}
	for name, want := range row.ResponseHeaders {
		var rebound string
		if err := json.Unmarshal(replay.rebind(t, want), &rebound); err != nil {
			t.Fatal(err)
		}
		if actual := response.Header.Get(name); len(response.Header.Values(name)) == 0 || actual != rebound {
			t.Fatalf("native header %s=%q, got %q", name, rebound, actual)
		}
	}
	for _, name := range row.AbsentHeaders {
		if values := response.Header.Values(name); len(values) != 0 {
			t.Fatalf("native response omits %s, got %q", name, values)
		}
	}
	if row.ResponseBody != nil {
		var expected string
		if err := json.Unmarshal(replay.rebind(t, *row.ResponseBody), &expected); err != nil {
			t.Fatal(err)
		}
		if string(data) != expected {
			t.Fatalf("native response body %q, got %q", expected, data)
		}
	}
	for _, name := range row.AbsentErrorDetails {
		for _, detail := range result.Details {
			if detail.XMLName.Local == name {
				t.Fatalf("unexpected error field %s: %s", name, data)
			}
		}
	}
	for _, expected := range row.BodyContains {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("native body contains %q, got %q", expected, data)
		}
	}
	for name, want := range row.ErrorDetails {
		var rebound string
		if err := json.Unmarshal(replay.rebind(t, want), &rebound); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, detail := range result.Details {
			if detail.XMLName.Local == name {
				found = true
				if detail.Value != rebound {
					t.Fatalf("native error field %s=%q, got %s", name, rebound, data)
				}
				break
			}
		}
		if !found {
			t.Fatalf("native error field %s absent: %s", name, data)
		}
	}
	etag := response.Header.Get("ETag")
	if row.Operation == "CompleteMultipartUpload" || row.Operation == "CopyObject" || row.Operation == "UploadPartCopy" {
		etag = result.ETag
	}
	if row.ETag != "" && etag != row.ETag {
		t.Fatalf("native ETag %q, got %q", row.ETag, etag)
	}
	for name, path := range row.Bind {
		var value string
		switch path {
		case "UploadId":
			value = result.UploadId
		case "ETag":
			value = etag
		default:
			header, ok := strings.CutPrefix(path, "Header.")
			if !ok {
				t.Fatalf("unknown response binding %q", path)
			}
			value = response.Header.Get(header)
		}
		if value == "" {
			t.Fatalf("response omitted bound %s", path)
		}
		replay.values[name] = value
	}
	if row.ResponseDigest != nil && (len(data) != row.ResponseDigest.Length || fmt.Sprintf("%x", sha256.Sum256(data)) != row.ResponseDigest.SHA256) {
		t.Fatal("consumer bytes differ from native range read")
	}
	return s3MultipartEventWire{id: response.Header.Get("x-amz-request-id"), extended: response.Header.Get("x-amz-id-2"), eventTime: now.UTC().Format(time.RFC3339), message: result.Message, status: response.StatusCode, bytesIn: len(payload), bytesOut: len(data), target: request.URL}
}

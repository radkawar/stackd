package stackd_test

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
)

type s3NotificationControlCall struct {
	s3KMSCall
	Configuration map[string]any
	BindHeaders   map[string]string
	AbsentHeaders []string
	Audit         map[string]any
	AuditSequence int
	TestMessage   *struct {
		SourceSequence    int
		Envelope, Payload map[string]any
		Required          []string
	}
}

// Each scenario points into the unabridged native captures. Propagation retries,
// cleanup and audit documents remain evidence, not extra API admission rules.
func TestS3NotificationsNativeControls(t *testing.T) {
	var fixture struct {
		Cases []struct {
			Name       string
			Calls      []s3NotificationControlCall
			ReopenRead *s3NotificationControlCall
		}
	}
	awsReadFixture(t, "s3/notifications_controls_replay.json.gz", &fixture)
	for _, scenario := range fixture.Cases {
		t.Run(scenario.Name, func(t *testing.T) {
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					source := clock.NewManual(time.Date(2026, 9, 20, 1, 26, 0, 0, time.UTC))
					clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
						return startPublicCloud(t, config)
					})
					replay := newS3KMSReplay(clients)
					replay.values["callerARN"] = "arn:aws:iam::123456789012:root"
					for _, row := range scenario.Calls {
						if row.Reopen {
							replay.clients = reopen()
						}
						if row.TestMessage != nil {
							// Advance service time and drain accepted work, without making
							// the local adoption delay a claimed native delivery SLA.
							advanceClock(t, source, 2*time.Minute)
							trailNativeDrain(t, replay.clients.server.Config.Handler.(*stackd.Stack))
						}
						if !t.Run(row.Label, func(t *testing.T) {
							s3NotificationControlCheck(t, replay, row, replay.call(t, row.s3KMSCall))
						}) {
							return
						}
					}
					if scenario.ReopenRead != nil {
						replay.clients = reopen()
						row := *scenario.ReopenRead
						s3NotificationControlCheck(t, replay, row, replay.call(t, row.s3KMSCall))
					}
				})
			}
		})
	}
}

func s3NotificationControlCheck(t *testing.T, replay *s3KMSReplay, row s3NotificationControlCall, out any) {
	t.Helper()
	if out == nil {
		return // The shared SDK caller already checked the native error code/status.
	}
	if row.Configuration != nil {
		data, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		// IDs are opaque. Bind once, then compare them on every subsequent GET,
		// including failed replacements and SQLite reopen reads.
		for kind, value := range row.Configuration {
			wantRules, _ := value.([]any)
			gotRules, _ := got[kind].([]any)
			for i, rule := range wantRules {
				id, _ := rule.(map[string]any)["Id"].(string)
				if !strings.HasPrefix(id, "${generated") {
					continue
				}
				binding := strings.TrimSuffix(strings.TrimPrefix(id, "${"), "}")
				if _, bound := replay.values[binding]; bound {
					continue
				}
				if i >= len(gotRules) {
					t.Fatalf("%s: missing generated-ID configuration", row.Label)
				}
				actual, _ := gotRules[i].(map[string]any)["Id"].(string)
				if actual == "" {
					t.Fatalf("%s: missing native-generated configuration ID", row.Label)
				}
				replay.values[binding] = actual
			}
		}
		var want map[string]any
		if err := json.Unmarshal(replay.rebind(t, row.Configuration), &want); err != nil {
			t.Fatal(err)
		}
		s3NativeProjection(t, row.Label, want, got)
	}
	if len(row.BindHeaders) != 0 || len(row.AbsentHeaders) != 0 {
		metadata := reflect.ValueOf(out).Elem().FieldByName("ResultMetadata").Interface().(middleware.Metadata)
		response, ok := awsmiddleware.GetRawResponse(metadata).(*smithyhttp.Response)
		if !ok {
			t.Fatalf("%s: missing public response headers", row.Label)
		}
		for header, binding := range row.BindHeaders {
			value := response.Header.Get(header)
			if value == "" {
				t.Fatalf("%s: missing native header %s", row.Label, header)
			}
			replay.values[binding] = value
		}
		for _, header := range row.AbsentHeaders {
			if value := response.Header.Get(header); value != "" {
				t.Fatalf("%s: unexpected header %s=%s", row.Label, header, value)
			}
		}
	}
	if row.Audit != nil {
		var want map[string]any
		if err := json.Unmarshal(replay.rebind(t, row.Audit), &want); err != nil {
			t.Fatal(err)
		}
		got := auditLookupRecord(t, replay.cloudtrailClient("caller", "us-east-1"), nativeAuditRequestID(t, out, nil), want["eventName"].(string))
		s3NativeProjection(t, row.Label+" audit", want, got)
	}
	if row.TestMessage != nil {
		messages := out.(*sqs.ReceiveMessageOutput).Messages
		if len(messages) == 0 {
			t.Fatalf("%s (%s:%d): missing test publication from request %d", row.Label, row.Source, row.Sequence, row.TestMessage.SourceSequence)
		}
		var want struct {
			Envelope, Payload map[string]any
			Required          []string
		}
		if err := json.Unmarshal(replay.rebind(t, row.TestMessage), &want); err != nil {
			t.Fatal(err)
		}
		var input sqs.ReceiveMessageInput
		if err := json.Unmarshal(replay.rebind(t, row.Input), &input); err != nil {
			t.Fatal(err)
		}
		cred := replay.sessions[row.Actor]
		client := replay.clients.sqs(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
		for _, message := range messages {
			var payload map[string]any
			if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &payload); err != nil {
				t.Fatal(err)
			}
			if len(want.Envelope) != 0 {
				s3NativeProjection(t, row.Label+" SNS envelope", want.Envelope, payload)
				body, _ := payload["Message"].(string)
				payload = nil
				if err := json.Unmarshal([]byte(body), &payload); err != nil {
					t.Fatal(err)
				}
			}
			s3NativeProjection(t, row.Label+" test payload", want.Payload, payload)
			for _, key := range want.Required {
				if value, _ := payload[key].(string); value == "" {
					t.Fatalf("%s: missing native test-event field %s", row.Label, key)
				}
			}
			if _, err := client.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: input.QueueUrl, ReceiptHandle: message.ReceiptHandle}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

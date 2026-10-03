package eventbridge_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/eventbridge"
	"stackd/journal"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/eventbridge"
	sqljournal "stackd/storage/sqlite/journal"
)

type backend struct {
	repository service.Repository
	events     journal.Storage
	reopen     func()
}

func backends(t *testing.T, fn func(*testing.T, *backend)) {
	t.Helper()
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var b backend
			if kind == "memory" {
				domain := memory.NewDomain()
				b.repository = service.NewMemoryRepository(domain)
				b.events = journal.NewMemory(domain)
				b.reopen = func() {}
			} else {
				path := filepath.Join(t.TempDir(), "state.sqlite")
				var db *sql.DB
				b.reopen = func() {
					if db != nil {
						if err := db.Close(); err != nil {
							t.Fatal(err)
						}
					}
					var err error
					db, err = sqlite.Open(t.Context(), path)
					if err != nil {
						t.Fatal(err)
					}
					b.repository = sqlrepo.New(db)
					b.events = sqljournal.New(db)
				}
				b.reopen()
				t.Cleanup(func() { _ = db.Close() })
			}
			fn(t, &b)
		})
	}
}

type sender struct {
	mu       sync.Mutex
	requests []service.DeliveryRequest
	result   *awswire.Error
}

func (s *sender) Send(_ context.Context, r service.DeliveryRequest) *awswire.Error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r)
	return s.result
}
func (s *sender) set(err *awswire.Error) { s.mu.Lock(); defer s.mu.Unlock(); s.result = err }
func (s *sender) received() []service.DeliveryRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]service.DeliveryRequest(nil), s.requests...)
}
func newService(t *testing.T, b *backend, c *clock.Manual, d service.Delivery) *service.Service {
	t.Helper()
	s := service.NewWithConfig(service.Config{Repository: b.repository, Events: b.events, Clock: c, Delivery: d})
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func call(t *testing.T, s *service.Service, action string, input any) (int, map[string]json.RawMessage) {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := api.DecodeRequest(action, awsapi.Request{JSON: body})
	if err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", RequestID: "original-command"})
	ctx = awsapi.WithDecodedRequest(ctx, decoded)
	r := httptest.NewRequest("POST", "http://localhost/", bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("X-Amz-Target", "AWSEvents."+action)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var out map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %d %s", action, w.Code, w.Body.String())
	}
	return w.Code, out
}
func success(t *testing.T, s *service.Service, action string, in any) map[string]json.RawMessage {
	t.Helper()
	code, out := call(t, s, action, in)
	if code != 200 {
		t.Fatalf("%s: status %d: %s", action, code, mustJSON(t, out))
	}
	return out
}
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func setupRule(t *testing.T, s *service.Service, targets []map[string]any) {
	t.Helper()
	success(t, s, "CreateEventBus", map[string]any{"Name": "orders", "Tags": []map[string]string{{"Key": "owner", "Value": "test"}}})
	success(t, s, "PutRule", map[string]any{"Name": "paid", "EventBusName": "orders", "EventPattern": `{"source":["test.orders"],"detail":{"amount":[{"numeric":[">",0]}]}}`})
	success(t, s, "PutTargets", map[string]any{"Rule": "paid", "EventBusName": "orders", "Targets": targets})
}
func put(t *testing.T, s *service.Service, detail string) string {
	t.Helper()
	out := success(t, s, "PutEvents", map[string]any{"Entries": []map[string]any{{"EventBusName": "orders", "Source": "test.orders", "DetailType": "order", "Detail": detail}}})
	var n int
	_ = json.Unmarshal(out["FailedEntryCount"], &n)
	if n != 0 {
		t.Fatalf("PutEvents: %s", mustJSON(t, out))
	}
	var rows []struct {
		EventID string `json:"EventId"`
	}
	_ = json.Unmarshal(out["Entries"], &rows)
	return rows[0].EventID
}
func drain(t *testing.T, s *service.Service) {
	t.Helper()
	if _, err := s.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
}

func TestCommittedEnvelopeAndTargetSnapshots(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		c := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
		d := &sender{}
		s := newService(t, b, c, d)
		setupRule(t, s, []map[string]any{{"Id": "queue", "Arn": "arn:aws:sqs:us-east-1:123456789012:orders"}, {"Id": "static", "Arn": "arn:aws:sqs:us-east-1:123456789012:static", "Input": "{\"fixed\":true}"}})
		id := put(t, s, `{"amount":12.50,"order":"one"}`)
		put(t, s, `{"amount":0}`)
		drain(t, s)
		requests := d.received()
		if len(requests) != 2 {
			t.Fatalf("deliveries=%d, want 2", len(requests))
		}
		for _, r := range requests {
			payload, err := r.Payload()
			if err != nil {
				t.Fatal(err)
			}
			if r.Delivery.TargetARN == "arn:aws:sqs:us-east-1:123456789012:static" {
				if payload != `{"fixed":true}` {
					t.Fatal(payload)
				}
			} else {
				var body map[string]json.RawMessage
				if json.Unmarshal([]byte(payload), &body) != nil || string(body["id"]) != `"`+id+`"` || string(body["account"]) != `"123456789012"` {
					t.Fatal(payload)
				}
				if string(body["detail"]) != `{"amount":12.50,"order":"one"}` {
					t.Fatalf("customer numeric representation changed: %s", payload)
				}
			}
		}
	})
}

func TestDeliveryRecoveryAndDeadLetter(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		c := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
		d := &sender{result: &awswire.Error{Code: "ThrottlingException", Message: "slow down", StatusCode: 400}}
		s := newService(t, b, c, d)
		setupRule(t, s, []map[string]any{{"Id": "queue", "Arn": "arn:aws:sqs:us-east-1:123456789012:orders", "RetryPolicy": map[string]int{"MaximumRetryAttempts": 1}, "DeadLetterConfig": map[string]string{"Arn": "arn:aws:sqs:us-east-1:123456789012:dead"}}})
		trace := "Root=1-6ab2832c-0123456789abcdef01234567;Parent=0123456789abcdef;Sampled=0"
		accepted := success(t, s, "PutEvents", map[string]any{"Entries": []map[string]any{{
			"EventBusName": "orders", "Source": "test.orders", "DetailType": "order", "Detail": `{"amount":1}`, "TraceHeader": trace,
		}}})
		var entries []struct{ EventId string }
		if err := json.Unmarshal(accepted["Entries"], &entries); err != nil || len(entries) != 1 || entries[0].EventId == "" {
			t.Fatal("trace event was not accepted", accepted, err)
		}
		id := entries[0].EventId
		drain(t, s)
		if got := d.received(); len(got) != 1 {
			t.Fatalf("throttled delivery retried before its deadline: %d attempts", len(got))
		}
		_ = s.Close()
		b.reopen()
		s = newService(t, b, c, d)
		d.set(nil)
		if err := c.Advance(time.Minute); err != nil {
			t.Fatal(err)
		}
		drain(t, s)
		got := d.received()
		if len(got) != 2 {
			t.Fatalf("recovered attempts = %d, want 2", len(got))
		}
		if got[0].Event.TraceHeader != trace || got[1].Event.TraceHeader != trace {
			t.Fatalf("retry/reopen lost trace: first=%q retry=%q", got[0].Event.TraceHeader, got[1].Event.TraceHeader)
		}
		payload, err := got[1].Payload()
		var envelope struct{ ID string }
		if err != nil || json.Unmarshal([]byte(payload), &envelope) != nil || envelope.ID != id {
			t.Fatalf("recovered delivery changed native event identity: %s, %v", payload, err)
		}
		d.set(&awswire.Error{Code: "AccessDenied", Message: "queue policy denied", StatusCode: 403})
		put(t, s, `{"amount":2}`)
		drain(t, s)
		requests := d.received()
		if len(requests) != 4 {
			t.Fatalf("denial should cause one target + one DLQ attempt, got %d", len(requests))
		}
		last := requests[3]
		if last.Delivery.TargetARN != "arn:aws:sqs:us-east-1:123456789012:dead" || last.Attributes["ERROR_CODE"] != "NO_PERMISSIONS" {
			t.Fatalf("bad dead letter: %+v", last)
		}
		if _, exists := last.Attributes["RETRY_ATTEMPTS"]; exists {
			t.Fatalf("immediate native denial omits retry metadata: %+v", last.Attributes)
		}
	})
}

type failingEvents struct{ journal.Storage }

func (e failingEvents) AppendEventBridgeAccepted(ctx context.Context, envelope journal.Envelope, v journal.EventBridgeAccepted) error {
	if err := e.Storage.AppendEventBridgeAccepted(ctx, envelope, v); err != nil {
		return err
	}
	return errors.New("journal commit failed")
}

type denyPut struct{}

func (denyPut) Authorize(_ context.Context, r authorization.Request) *awswire.Error {
	if r.Action == "events:PutEvents" && len(r.Context["events:source"]) > 0 && r.Context["events:source"][0] == "test.denied" {
		return &awswire.Error{Code: "AccessDenied", Message: "denied", StatusCode: 403}
	}
	return nil
}
func TestAdmissionFailureAndPartialResults(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		c := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
		d := &sender{}
		s := newService(t, b, c, d)
		setupRule(t, s, []map[string]any{{"Id": "queue", "Arn": "arn:aws:sqs:us-east-1:123456789012:orders"}})
		out := success(t, s, "PutEvents", map[string]any{"Entries": []map[string]any{{"EventBusName": "orders", "Source": "test.orders", "DetailType": "order", "Detail": "{"}, {"EventBusName": "orders", "Source": "test.orders", "DetailType": "order", "Detail": "{\"amount\":1}"}, {"EventBusName": "missing", "Source": "test.orders", "DetailType": "order", "Detail": "{}"}, {"EventBusName": "orders", "Source": "aws.iam", "DetailType": "fake AWS", "Detail": "{}"}}})
		if string(out["FailedEntryCount"]) != "2" {
			t.Fatalf("partial results: %s", mustJSON(t, out))
		}
		drain(t, s)
		if len(d.received()) != 1 {
			t.Fatal("invalid or missing-bus entry delivered")
		}
		before, err := b.events.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(before) != 1 {
			t.Fatalf("accepted events=%d", len(before))
		}
		_ = s.Close()
		s = service.NewWithConfig(service.Config{Repository: b.repository, Events: failingEvents{b.events}, Clock: c, Delivery: d})
		defer s.Close()
		code, out := call(t, s, "PutEvents", map[string]any{"Entries": []map[string]any{{"EventBusName": "orders", "Source": "test.orders", "DetailType": "order", "Detail": "{\"amount\":2}"}}})
		if code != 500 || string(out["__type"]) != `"InternalException"` {
			t.Fatal("journal error did not fail admission")
		}
		drain(t, s)
		after, err := b.events.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) || len(d.received()) != 1 {
			t.Fatal("journal failure published event or target work")
		}
		_ = s.Close()
		s = service.NewWithConfig(service.Config{Repository: b.repository, Events: b.events, Clock: c, Delivery: d, Authorizer: denyPut{}})
		defer s.Close()
		code, out = call(t, s, "PutEvents", map[string]any{"Entries": []map[string]any{{"EventBusName": "orders", "Source": "test.orders", "DetailType": "order", "Detail": "{\"amount\":3}"}, {"EventBusName": "orders", "Source": "test.denied", "DetailType": "order", "Detail": "{}"}}})
		if code != 400 || string(out["__type"]) != `"AccessDeniedException"` {
			t.Fatal("unauthorized entry succeeded")
		}
		drain(t, s)
		if len(d.received()) != 1 {
			t.Fatal("unauthorized entry delivered")
		}
		after, err = b.events.Read(t.Context(), 0, 100)
		if err != nil || len(after) != len(before) {
			t.Fatal("denied batch committed its authorized entry", after, err)
		}
	})
}

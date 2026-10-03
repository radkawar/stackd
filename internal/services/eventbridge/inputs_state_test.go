package eventbridge_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awswire"
	service "stackd/internal/services/eventbridge"
)

type interruptedInputDelivery struct{}

func (interruptedInputDelivery) Send(ctx context.Context, _ service.DeliveryRequest) *awswire.Error {
	<-ctx.Done()
	return nil
}

// This tests the durable command boundary, independently of the native renderer
// fixtures: later resource changes and retry execution cannot project the event
// again using a different target definition or a different ingestion timestamp.
func TestInputSnapshotSurvivesTargetDeletionAndRetry(t *testing.T) {
	backends(t, func(t *testing.T, b *backend) {
		c := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 123456789, time.UTC))
		d := &sender{result: &awswire.Error{Code: "ThrottlingException", Message: "try later", StatusCode: 400}}
		s := newService(t, b, c, interruptedInputDelivery{})
		target := map[string]any{
			"Id": "queue", "Arn": "arn:aws:sqs:us-east-1:123456789012:first",
			"RetryPolicy": map[string]int{"MaximumRetryAttempts": 1},
			"InputTransformer": map[string]any{
				"InputPathsMap": map[string]string{"id": "$.id", "order": "$.detail.order"},
				"InputTemplate": `{"id":<id>,"rule":<aws.events.rule-name>,"ingested":<aws.events.event.ingestion-time>,"order":<order>,"definition":"first"}`,
			},
		}
		setupRule(t, s, []map[string]any{target})
		type snapshot struct{ ID, Rule, Ingested, Order, Definition string }
		firstTime := c.Now()
		first := put(t, s, `{"amount":1,"order":"first"}`)
		if err := c.Advance(17 * time.Second); err != nil {
			t.Fatal(err)
		}
		target["Arn"] = "arn:aws:sqs:us-east-1:123456789012:second"
		target["InputTransformer"].(map[string]any)["InputTemplate"] = `{"id":<id>,"rule":<aws.events.rule-name>,"ingested":<aws.events.event.ingestion-time>,"order":<order>,"definition":"second"}`
		success(t, s, "PutTargets", map[string]any{"Rule": "paid", "EventBusName": "orders", "Targets": []map[string]any{target}})
		secondTime := c.Now()
		second := put(t, s, `{"amount":1,"order":"second"}`)
		want := map[string]snapshot{
			first:  {first, "paid", firstTime.Format("2006-01-02T15:04:05.000Z"), "first", "first"},
			second: {second, "paid", secondTime.Format("2006-01-02T15:04:05.000Z"), "second", "second"},
		}
		success(t, s, "DisableRule", map[string]any{"Name": "paid", "EventBusName": "orders"})
		success(t, s, "RemoveTargets", map[string]any{"Rule": "paid", "EventBusName": "orders", "Ids": []string{"queue"}})
		success(t, s, "DeleteRule", map[string]any{"Name": "paid", "EventBusName": "orders"})
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		b.reopen()
		s = newService(t, b, c, d)
		if err := c.Advance(time.Hour); err != nil {
			t.Fatal(err)
		}
		drain(t, s)
		firstAttempts := d.received()
		if len(firstAttempts) != len(want) {
			t.Fatalf("retained first attempts = %d, want %d", len(firstAttempts), len(want))
		}
		bodies := make(map[string]string, len(want))
		for _, request := range firstAttempts {
			payload, err := request.Payload()
			if err != nil {
				t.Fatal(err)
			}
			var body snapshot
			if err := json.Unmarshal([]byte(payload), &body); err != nil {
				t.Fatal(err)
			}
			expected, exists := want[body.ID]
			if !exists || body != expected {
				t.Fatalf("admitted input changed after target deletion: got %+v, want %+v", body, expected)
			}
			if request.Delivery.TargetARN != "arn:aws:sqs:us-east-1:123456789012:"+expected.Definition {
				t.Fatalf("target snapshot changed: %+v", request)
			}
			bodies[body.ID] = payload
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		b.reopen()
		s = newService(t, b, c, d)
		d.set(nil)
		if err := c.Advance(time.Minute); err != nil {
			t.Fatal(err)
		}
		drain(t, s)
		requests := d.received()
		if len(requests) != 2*len(want) {
			t.Fatalf("recovered attempts = %d, want %d", len(requests), 2*len(want))
		}
		for _, request := range requests[len(firstAttempts):] {
			payload, err := request.Payload()
			var body snapshot
			if err != nil || json.Unmarshal([]byte(payload), &body) != nil || payload != bodies[body.ID] {
				t.Fatalf("retry changed admitted input: %s, %v", payload, err)
			}
			delete(bodies, body.ID)
		}
		if len(bodies) != 0 {
			t.Fatalf("events were not retried: %v", bodies)
		}
	})
}

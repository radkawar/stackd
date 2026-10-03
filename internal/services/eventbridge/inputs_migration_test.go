package eventbridge_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage/sqlite"
	sqlrepo "stackd/storage/sqlite/eventbridge"
	sqljournal "stackd/storage/sqlite/journal"
)

func TestVersion21RetainsTargetInputsAndPendingDeliveries(t *testing.T) {
	current := filepath.Join(t.TempDir(), "current.sqlite")
	db, err := sqlite.Open(t.Context(), current)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	b := &backend{repository: sqlrepo.New(db), events: sqljournal.New(db)}
	c := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
	d := &sender{}
	s := newService(t, b, c, interruptedInputDelivery{})
	setupRule(t, s, []map[string]any{
		{"Id": "static", "Arn": "arn:aws:sqs:us-east-1:123456789012:static", "Input": `{ "fixed": true }`},
		{"Id": "original", "Arn": "arn:aws:sqs:us-east-1:123456789012:original"},
	})
	id := put(t, s, `{"amount":12.50,"order":"retained"}`)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "version21.sqlite")
	historical := awstest.HistoricalSQLite(t, path, "../../../storage/sqlite/schema", 21, current, map[string]string{
		"eventbridge_targets": `SELECT partition,account,region,bus_name,rule_name,id,arn,COALESCE(input,'') AS input,input IS NOT NULL AS has_input,message_group_id,dead_letter_arn,max_retries,max_age_seconds,has_retry_policy,has_max_retries,has_max_age FROM fixture.eventbridge_targets`,
	})
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	b.repository, b.events = sqlrepo.New(db), sqljournal.New(db)
	s = newService(t, b, c, d)
	listed := success(t, s, "ListTargetsByRule", map[string]any{"Rule": "paid", "EventBusName": "orders"})
	var targets []struct {
		ID, ARN string
		Input   *string
	}
	if err := json.Unmarshal(listed["Targets"], &targets); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].ID != "original" || targets[0].Input != nil || targets[1].ID != "static" || targets[1].Input == nil || *targets[1].Input != `{ "fixed": true }` {
		t.Fatalf("migration changed native target definitions: %+v", targets)
	}
	drain(t, s)
	requests := d.received()
	if len(requests) != 2 {
		t.Fatalf("migration lost pending work: %+v", requests)
	}
	for _, request := range requests {
		payload, err := request.Payload()
		if err != nil {
			t.Fatal(err)
		}
		if request.Delivery.TargetARN == "arn:aws:sqs:us-east-1:123456789012:static" {
			if payload != `{ "fixed": true }` {
				t.Fatal("migration changed static payload", payload)
			}
			continue
		}
		var envelope struct {
			ID, Region string
			Detail     json.RawMessage
		}
		if err := json.Unmarshal([]byte(payload), &envelope); err != nil || envelope.ID != id || envelope.Region != "us-east-1" || string(envelope.Detail) != `{"amount":12.50,"order":"retained"}` {
			t.Fatalf("migration changed the native event envelope: %s, %v", payload, err)
		}
	}
}

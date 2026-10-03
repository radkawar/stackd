package scheduler_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/scheduler"
	"stackd/internal/awscatalog"
	"stackd/internal/awsschedule"
	service "stackd/internal/services/scheduler"
)

func TestSchedulerNativeDefaultNotificationAndReadback(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/scheduler_pipes/default_input.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Started  string `json:"started_at"`
		Identity struct{ Account string }
		Calls    []struct {
			Label              string
			Parameters, Output json.RawMessage
		}
		Observations struct {
			Messages []struct{ Body string } `json:"omitted_input_messages"`
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, fixture.Started)
	if err != nil {
		t.Fatal(err)
	}
	c := clock.NewManual(now)
	r := &receiver{}
	s := service.NewWithConfig(service.Config{Clock: c, Delivery: r, Roles: r})
	defer s.Close()
	model, _ := awscatalog.LookupService("scheduler")
	for _, call := range fixture.Calls {
		var input any
		var action string
		switch call.Label {
		case "group":
			action, input = "CreateScheduleGroup", &api.CreateScheduleGroupInput{}
		case "create-defaults", "create-omitted-input":
			action, input = "CreateSchedule", &api.CreateScheduleInput{}
		case "get-defaults", "get-omitted-input":
			action, input = "GetSchedule", &api.GetScheduleInput{}
		default:
			continue
		}
		operation, _ := model.Operation(action)
		if err := awsapi.DecodeSDKInput(model, operation, call.Parameters, input); err != nil {
			t.Fatal(err)
		}
		output, rejected := command(t, s, fixture.Identity.Account, action, input)
		if rejected != nil {
			t.Fatalf("%s: %v", call.Label, rejected)
		}
		if action == "GetSchedule" {
			var want, got map[string]any
			if err := json.Unmarshal(call.Output, &want); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(output)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			// Native processing instants and transport metadata are not replay inputs.
			for _, key := range []string{"ResponseMetadata", "CreationDate", "LastModificationDate"} {
				delete(want, key)
				delete(got, key)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s readback mismatch\nlocal: %#v\nnative: %#v", call.Label, got, want)
			}
		}
	}
	if len(fixture.Observations.Messages) != 1 {
		t.Fatal("native fixture must contain the one owned default delivery")
	}
	var want, got map[string]any
	if err := json.Unmarshal([]byte(fixture.Observations.Messages[0].Body), &want); err != nil {
		t.Fatal(err)
	}
	scheduled, err := time.Parse(time.RFC3339, want["time"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Advance(scheduled.Sub(c.Now())); err != nil {
		t.Fatal(err)
	}
	if _, err := s.JobDriver().RunDue(t.Context(), 100); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	attempts := append([]deliveryAttempt(nil), r.attempts...)
	r.mu.Unlock()
	if len(attempts) != 1 {
		t.Fatalf("default-notification delivery attempts=%d", len(attempts))
	}
	if err := json.Unmarshal([]byte(attempts[0].body), &got); err != nil {
		t.Fatal(err)
	}
	// The occurrence ID is intentionally generated locally; all notification
	// fields, including the string-valued detail and nominal time, are compared.
	delete(want, "id")
	delete(got, "id")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("default notification mismatch\nlocal: %#v\nnative: %#v", got, want)
	}
}

func TestSchedulerAdmitsAtInDSTGapWithoutChangingScaling(t *testing.T) {
	// lifecycle_success.json's dst-gap CreateSchedule succeeded while DISABLED.
	expression := "at(2027-03-14T02:30:00)"
	if _, err := awsschedule.ParseScheduler(expression, "America/New_York"); err != nil {
		t.Fatalf("native Scheduler gap admission rejected: %v", err)
	}
	if _, err := awsschedule.ParseApplicationAutoScaling(expression, "America/New_York"); err == nil {
		t.Fatal("Scheduler admission changed the existing scaling dialect")
	}
}

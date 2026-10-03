package eventbridge_test

import (
	"encoding/json"
	"maps"
	"os"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awstest"
	service "stackd/internal/services/eventbridge"
)

type scheduledCommand struct {
	Label, Operation string
	Input            json.RawMessage
}

type scheduledOccurrence struct {
	Target, Origin string
	Time           time.Time
}

type scheduledLifecycle struct {
	Start time.Time
	Setup []scheduledCommand
	Steps []struct {
		Name                          string
		AfterSeconds                  int
		Restart, RestartAfterFirstJob bool
		Commands                      []scheduledCommand
		Expected                      []scheduledOccurrence
	}
}

func scheduledFixture(t *testing.T) scheduledLifecycle {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/eventbridge/scheduled_delivery.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Lifecycle scheduledLifecycle }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Lifecycle
}

func scheduledCommands(t *testing.T, s *service.Service, commands []scheduledCommand) {
	t.Helper()
	client := sdkClient(t, s)
	for _, command := range commands {
		if _, err := awstest.CallSDK(t.Context(), client, command.Operation, command.Input); err != nil {
			t.Fatal(command.Label, err)
		}
	}
}

func scheduledOccurrences(t *testing.T, requests []service.DeliveryRequest, expected []scheduledOccurrence) {
	t.Helper()
	got, want := make(map[scheduledOccurrence]int), make(map[scheduledOccurrence]int)
	for _, request := range requests {
		body, err := request.Payload()
		if err != nil {
			t.Fatal(err)
		}
		var event struct {
			Time      time.Time
			Resources []string
		}
		if err := json.Unmarshal([]byte(body), &event); err != nil || len(event.Resources) != 1 {
			t.Fatalf("invalid scheduled envelope %s: %v", body, err)
		}
		got[scheduledOccurrence{request.Delivery.TargetARN, event.Resources[0], event.Time}]++
	}
	for _, occurrence := range expected {
		want[occurrence]++
	}
	if !maps.Equal(got, want) {
		t.Fatalf("scheduled target occurrences: got=%+v want=%+v", got, want)
	}
}

func TestScheduledRuleLifecycle(t *testing.T) {
	fixture := scheduledFixture(t)
	backends(t, func(t *testing.T, b *backend) {
		source := clock.NewManual(fixture.Start)
		destination := &sender{}
		s := newService(t, b, source, destination)
		scheduledCommands(t, s, fixture.Setup)
		reopen := func() {
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			b.reopen()
			s = newService(t, b, source, destination)
		}
		previous := 0
		for _, step := range fixture.Steps {
			if !t.Run(step.Name, func(t *testing.T) {
				if step.Restart || step.RestartAfterFirstJob {
					// A newly constructed driver has not started automatic
					// work; this permits the retained one-job crash boundary.
					reopen()
				}
				at := fixture.Start.Add(time.Duration(step.AfterSeconds) * time.Second)
				if err := source.Advance(at.Sub(source.Now())); err != nil {
					t.Fatal(err)
				}
				scheduledCommands(t, s, step.Commands)
				if step.RestartAfterFirstJob {
					if _, err := s.JobDriver().RunDue(t.Context(), 1); err != nil {
						t.Fatal(err)
					}
					reopen()
				}
				drain(t, s)
				received := destination.received()
				scheduledOccurrences(t, received[previous:], step.Expected)
				previous = len(received)
			}) {
				return
			}
		}
	})
}

func TestScheduledRuleJournalRollback(t *testing.T) {
	fixture := scheduledFixture(t)
	backends(t, func(t *testing.T, b *backend) {
		source := clock.NewManual(fixture.Start)
		destination := &sender{}
		s := service.NewWithConfig(service.Config{Repository: b.repository, Events: failingEvents{b.events}, Clock: source, Delivery: destination})
		t.Cleanup(func() { _ = s.Close() })
		scheduledCommands(t, s, fixture.Setup)
		if _, err := s.JobDriver().RunDue(t.Context(), 100); err == nil {
			t.Fatal("source commit ignored a failed journal write")
		}
		if len(destination.received()) != 0 {
			t.Fatal("failed scheduled occurrence escaped to a target")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		b.reopen()
		s = newService(t, b, source, destination)
		drain(t, s)
		drain(t, s)
		received := destination.received()
		scheduledOccurrences(t, received, fixture.Steps[0].Expected)
		ids := make(map[string]bool)
		for _, request := range received {
			ids[request.Event.ID] = true
		}
		events, err := b.events.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if id := event.EventBridgeAccepted.EventID; id != "" {
				if !ids[id] {
					t.Fatalf("journal exposed an uncommitted or duplicate scheduled event: %s", id)
				}
				delete(ids, id)
			}
		}
		if len(ids) != 0 {
			t.Fatalf("scheduled delivery escaped its source journal commit: %+v", ids)
		}
	})
}

package eventbridge_test

import (
	"testing"
	"time"

	"stackd/clock"
)

// Constant Input is a JSON document, not a quoted JSON string or the scheduled
// event envelope. Disabling a rule cancels future occurrences, not admitted work.
func TestScheduledRuleConstantInputAndEnabledState(t *testing.T) {
	for _, expression := range []string{"rate(1 minute)", "cron(* * * * ? *)"} {
		t.Run(expression, func(t *testing.T) {
			backends(t, func(t *testing.T, b *backend) {
				source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
				destination := &sender{}
				s := newService(t, b, source, destination)
				const input = `{ "message": "line\nquote\"", "unicode": "é", "values": [true, null, 7] }`
				success(t, s, "PutRule", map[string]any{"Name": "scheduled", "ScheduleExpression": expression, "State": "DISABLED"})
				success(t, s, "PutTargets", map[string]any{"Rule": "scheduled", "Targets": []map[string]any{{"Id": "lambda", "Arn": "arn:aws:lambda:us-east-1:123456789012:function:handler", "Input": input}}})
				if err := source.Advance(2 * time.Minute); err != nil {
					t.Fatal(err)
				}
				drain(t, s)
				if len(destination.received()) != 0 {
					t.Fatal("disabled schedule delivered work")
				}
				success(t, s, "EnableRule", map[string]any{"Name": "scheduled"})
				if err := source.Advance(2 * time.Minute); err != nil {
					t.Fatal(err)
				}
				drain(t, s)
				received := destination.received()
				if len(received) == 0 {
					t.Fatal("enabled schedule did not deliver")
				}
				for _, request := range received {
					body, err := request.Payload()
					if err != nil || body != input {
						t.Fatalf("scheduled Input changed: got %q want %q err=%v", body, input, err)
					}
				}
				success(t, s, "DisableRule", map[string]any{"Name": "scheduled"})
				before := len(received)
				if err := source.Advance(5 * time.Minute); err != nil {
					t.Fatal(err)
				}
				drain(t, s)
				if len(destination.received()) != before {
					t.Fatal("disabled rule admitted new occurrences")
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				b.reopen()
				s = newService(t, b, source, destination)
				success(t, s, "EnableRule", map[string]any{"Name": "scheduled"})
				if err := source.Advance(2 * time.Minute); err != nil {
					t.Fatal(err)
				}
				drain(t, s)
				if len(destination.received()) <= before {
					t.Fatal("recovered schedule did not resume")
				}
				for _, request := range destination.received()[before:] {
					body, err := request.Payload()
					if err != nil || body != input {
						t.Fatalf("recovered Input changed: %q %v", body, err)
					}
				}
			})
		})
	}
}

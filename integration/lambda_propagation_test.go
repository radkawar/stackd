package stackd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"stackd/clock"
	"stackd/storage"
)

func TestLambdaDockerConfigPropagation(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	fixture := lambdaFixture[struct {
		lambdaEventsFixture
		Late   []lambdaEventsObservation `json:"late_admission_observations"`
		Paired struct {
			Attempts map[string]struct{ Count int }
		} `json:"paired_config_change_observation"`
		LateCounts map[string]struct {
			Count int `json:"attempt_count"`
		} `json:"late_config_change_observation"`
	}](t, "event_config_timing")
	fixture.Observations = append(fixture.Observations, fixture.Late...)
	setup := lambdaFixture[lambdaEventsFixture](t, "event_invocation")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			start := time.Date(2026, 9, 13, 15, 44, 48, 0, time.UTC)
			source := clock.NewManual(start)
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "lambda-propagation.sqlite")
			var closeDatabase func()
			if backend == "sqlite" {
				backends, closeDatabase = openSQLiteBackends(t, path)
			}
			c := lambdaEventsConnect(t, backends, source)
			lambdaEventsProvision(t, c, setup)
			if _, err := c.lambda.PutFunctionEventInvokeConfig(t.Context(), lambdaEventsInput[awslambda.PutFunctionEventInvokeConfigInput](t, fixture.lambdaEventsFixture, "paired_set_retry_two")); err != nil {
				t.Fatal(err)
			}
			type invocation struct {
				id, arn string
				payload map[string]any
				count   int
			}
			accepted := map[string]*invocation{}
			var acceptedRequests []string
			accept := func(label string) {
				t.Helper()
				id, payload := lambdaEventsInvoke(t, c, fixture.lambdaEventsFixture, label)
				acceptedRequests = append(acceptedRequests, id)
				var input struct{ Qualifier string }
				if err := json.Unmarshal(fixture.observation(t, label).Input, &input); err != nil {
					t.Fatal(err)
				}
				arn := c.functionARN
				if input.Qualifier != "" {
					arn += ":" + input.Qualifier
				}
				accepted[payload["experiment"].(string)] = &invocation{id: id, arn: arn, payload: payload}
			}
			observe := func(messages []sqstypes.Message) {
				t.Helper()
				for _, message := range messages {
					var record struct{ Event struct{ Experiment string } }
					if err := json.Unmarshal([]byte(aws.ToString(message.Body)), &record); err != nil {
						t.Fatal(err)
					}
					invocation, ok := accepted[record.Event.Experiment]
					if !ok {
						t.Fatalf("unexpected invocation: %s", aws.ToString(message.Body))
					}
					lambdaEventsRecord(t, invocation.arn, message, invocation.id, invocation.payload)
					invocation.count++
				}
			}
			accept("paired_accept_old_event")
			observe(lambdaEventsReceive(t, c, c.outputURL, 1))
			lambdaEventsAwaitRetry(t, c, start.Add(time.Minute), acceptedRequests...)
			if _, err := c.lambda.UpdateFunctionEventInvokeConfig(t.Context(), lambdaEventsInput[awslambda.UpdateFunctionEventInvokeConfigInput](t, fixture.lambdaEventsFixture, "paired_change_retries_zero")); err != nil {
				t.Fatal(err)
			}
			visible, err := c.lambda.GetFunctionEventInvokeConfig(t.Context(), lambdaEventsInput[awslambda.GetFunctionEventInvokeConfigInput](t, fixture.lambdaEventsFixture, "paired_confirm_retries_zero"))
			if err != nil || visible.MaximumRetryAttempts == nil || *visible.MaximumRetryAttempts != 0 {
				t.Fatalf("visible retry configuration: %+v %v", visible, err)
			}
			accept("paired_accept_new_event")
			observe(lambdaEventsReceive(t, c, c.outputURL, 1))
			// The older event already owns this deadline. Its queued retry cannot
			// stand in for completion of the newly accepted handler.
			lambdaEventsAwaitRetry(t, c, start.Add(time.Minute), acceptedRequests...)
			advanceClock(t, source, time.Minute)
			observe(lambdaEventsReceive(t, c, c.outputURL, 2))
			lambdaEventsAwaitRetry(t, c, start.Add(3*time.Minute), acceptedRequests...)
			advanceClock(t, source, 40*time.Second)
			if backend == "sqlite" {
				// Pending configuration and queued attempts retain their original deadlines
				// across a real database reopen. No function configuration is rewritten.
				if err := c.cloud.Close(); err != nil {
					t.Fatal(err)
				}
				c.server.Close()
				closeDatabase()
				backends, _ = openSQLiteBackends(t, path)
				previous := c
				c = lambdaEventsConnect(t, backends, source)
				c.functionName, c.functionARN = previous.functionName, previous.functionARN
				c.outputURL, c.dlqURL = previous.outputURL, previous.dlqURL
			}
			// The capture's late events arrived about152s after the configuration change.
			// This checks the observed distinction, not an exact AWS propagation SLA.
			advanceClock(t, source, 52*time.Second)
			for _, row := range fixture.Late {
				if row.Label == "late_confirm_retry_zero" {
					continue
				}
				accept(row.Label)
				observe(lambdaEventsReceive(t, c, c.outputURL, 1))
			}
			// Drain nominal retry opportunities before the configured300s age boundary,
			// so expiry cannot disguise an incorrectly retained retry budget.
			for _, at := range []time.Duration{180 * time.Second, 212 * time.Second, 280 * time.Second} {
				advanceClock(t, source, start.Add(at).Sub(source.Now()))
				lambdaEventsQuiet(t, c, c.outputURL)
			}
			for name, invocation := range accepted {
				expected, ok := fixture.Paired.Attempts[name]
				want := expected.Count
				if !ok {
					want = fixture.LateCounts[name].Count
				}
				if invocation.count != want {
					t.Errorf("%s deliveries=%d, native=%d", name, invocation.count, want)
				}
			}
		})
	}
}

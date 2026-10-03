package stackd_test

import (
	"slices"
	"strings"
	"testing"

	"stackd"
	"stackd/clock"
)

func TestApplicationAutoScalingNativeActivitySuppressionAcrossReopen(t *testing.T) {
	fixture := aasFixture(t, "activity_suppression")
	labels := []string{
		"create-cluster", "register-task-definition", "create-service",
		"register-min-max-zero",
		"policy-out-a", "alarm-out-a", "policy-out-b", "alarm-out-b",
		"policy-in", "alarm-in", "policy-exact", "alarm-exact",
		"history-initial", "include-false-after-max", "include-omitted-after-max",
		"include-false-after-reasons", "open-max-for-exact", "restore-max-zero",
		"query-dimension-without-resource", "query-nonexistent-resource",
		"query-invalid-namespace", "query-limit-0", "query-limit--1", "query-limit-51",
		"query-token-malformed", "query-token-empty", "page-one",
		"history-before-deregister", "deregister-target-history-check",
		"history-after-deregister", "history-after-deregister-delayed",
		"reregister-same-id", "history-after-reregister",
	}
	// Each episode performs the native CloudWatch state transition and reset,
	// then compares the complete AAS history, not merely its size or last reason.
	// In particular, another policy with the same reason must retain the first
	// activity's ID and cause; changing reason must allocate a new activity.
	for _, episode := range []string{
		"max-first", "max-repeat-same-policy", "max-other-policy",
		"min-switch-reason", "max-switch-back", "exact-current-zero",
		"exact-current-repeat", "exact-current-open-max",
		"max-after-target-update", "max-after-reregister",
	} {
		for _, suffix := range []string{"-OK", "-ALARM", "-reset", "-poll"} {
			labels = append(labels, episode+suffix)
		}
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{
				AccountID: fixture.Account, Clock: source,
				ECSExecutor: aasExecutor(t), ComputeEndpoint: "http://stackd.invalid",
			})
			bindings, times := map[string]string{}, map[float64]float64{}
			for _, row := range fixture.Calls {
				if !slices.Contains(labels, row.Label) {
					continue
				}
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				if !t.Run(row.Label, func(t *testing.T) {
					aasFixtureRow(t, clients, row, bindings, times)
					// Deliver real CloudWatch actions before the captured reset can
					// invalidate them. Draining never advances time or creates capacity.
					result, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000)
					if err != nil || result.More {
						t.Fatalf("activity replay did not settle: %+v, %v", result, err)
					}
					if row.Label == "exact-current-repeat-poll" {
						// The native default-filter oracle remains empty even after a
						// Successful exact-current no-op, not only Failed max/min no-ops.
						aasReplay(t, clients, fixture.row(t, "include-omitted-after-max"), bindings, times)
					}
				}) {
					return
				}
				if strings.HasSuffix(row.Label, "-poll") || row.Label == "deregister-target-history-check" || row.Label == "reregister-same-id" {
					// Carry the identity/time bijections across reconstruction. The
					// next snapshot must retain original history and deduplication.
					clients = reopen()
				}
			}
		})
	}
}

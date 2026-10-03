package stackd_test

import (
	"fmt"
	"testing"
	"time"

	"stackd"
	"stackd/clock"
)

// Raw requests retain header presence and malformed numeric bindings that the
// typed SDK cannot express. SDK steps supply only their native prerequisites and
// inspect exact ordered listings; both drivers use the public signed listener.
func TestS3MultipartNativeRawReplay(t *testing.T) {
	runS3MixedReplay(t, "s3/multipart_raw_replay.json")
}

func runS3MixedReplay(t *testing.T, path string) {
	t.Helper()
	var fixture struct {
		Payloads  map[string][]s3MultipartPayload
		Scenarios []struct {
			Name  string
			TLS   bool
			Calls []struct {
				Source string
				SDK    *s3MultipartCall
				Raw    *s3MultipartEventCall
			}
		}
	}
	awsReadFixture(t, path, &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				// Same-key native initiations share a displayed second. Keep the
				// service clock fixed so cursor ordering cannot rely on distinct times.
				source := clock.NewManual(time.Date(2026, 9, 20, 8, 37, 0, 0, time.UTC))
				clients, reopen := retainedS3ReplayCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, scenario.TLS)
				replay := newS3KMSReplay(clients)
				for _, step := range scenario.Calls {
					if step.SDK != nil {
						row := *step.SDK
						if row.Reopen {
							replay.clients = reopen()
						}
						if !t.Run(fmt.Sprintf("%d-%s", row.Sequence, row.Label), func(t *testing.T) {
							s3MultipartReplayCall(t, replay, fixture.Payloads, row)
						}) {
							return // Later steps depend on successful setup and issued IDs.
						}
						continue
					}
					row := *step.Raw
					t.Run(fmt.Sprintf("%d-%s", row.Sequence, row.Label), func(t *testing.T) {
						t.Logf("native source: %s:%d", step.Source, row.Sequence)
						s3MultipartEventRequest(t, replay, replay.sessions["caller"], row, source.Now())
					})
				}
			})
		}
	}
}

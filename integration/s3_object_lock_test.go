package stackd_test

import "testing"

// Requests and outcomes retain their native sequence/label. Explicit deadlines
// stay exact; generated deadlines use the manual time of the observed creation,
// initiation, read, duration reduction or release, with calendar-year arithmetic.
// The isolated native post-activation anomaly is documented in the fixture, not
// made into a deterministic prohibition on configuring a pre-existing null version.
func TestS3ObjectLockNativeControlsReplay(t *testing.T) {
	var fixture struct {
		Calls []s3ObjectCall
	}
	awsReadFixture(t, "s3/object_lock_controls_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			runS3ObjectCalls(t, backend, nil, fixture.Calls, false)
		})
	}
}

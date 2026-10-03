package stackd_test

import "testing"

// Native rows retain their experiment, sequence and label. Local scheduling and
// reopen boundaries are explicit projections; the isolated midnight/expiry/copy
// scenario is derived regression coverage, not an unobserved AWS expiration.
func TestS3RestoreNativeReplay(t *testing.T) {
	var fixture struct {
		Scenarios []struct {
			Name  string
			Setup []s3KMSCall
			Calls []s3ObjectCall
		}
	}
	awsReadFixture(t, "s3/restore_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				runS3ObjectCalls(t, backend, scenario.Setup, scenario.Calls, false)
			})
		}
	}
}

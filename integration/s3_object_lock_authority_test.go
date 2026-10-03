package stackd_test

import "testing"

// Native session policies execute through real STS credentials, with independent
// bucket grants for the foreign role. Local CLI preflight failures are retained
// in fixture exclusions, never interpreted as service authorization outcomes.
func TestS3ObjectLockNativeAuthorityReplay(t *testing.T) {
	var fixture struct {
		Scenarios []struct {
			Name  string
			Setup []s3KMSCall
			Calls []s3ObjectCall
		}
	}
	awsReadFixture(t, "s3/object_lock_authority_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Scenarios {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				runS3ObjectCalls(t, backend, scenario.Setup, scenario.Calls, false)
			})
		}
	}
}

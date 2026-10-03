package stackd_test

import "testing"

func TestS3LifecycleNativeReplay(t *testing.T) {
	for _, group := range []string{"control", "header_authority"} {
		t.Run(group, func(t *testing.T) {
			var fixture struct {
				Scenarios []struct {
					Name  string
					Setup []s3KMSCall
					Calls []s3ObjectCall
				}
			}
			awsReadFixture(t, "s3/lifecycle_"+group+"_replay.json", &fixture)
			for _, backend := range []string{"memory", "sqlite"} {
				for _, scenario := range fixture.Scenarios {
					t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
						runS3ObjectCalls(t, backend, scenario.Setup, scenario.Calls, false)
					})
				}
			}
		})
	}
}

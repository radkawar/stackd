package stackd_test

import "testing"

// Native evidence and projection limits live beside each fixture. Scheduling and
// reopen boundaries exercise retained work without asserting native latency.
func TestS3ReplicationNativeReplay(t *testing.T) {
	for _, group := range []string{"control", "flow", "authority", "read_alias", "tag_alias", "tag_filter"} {
		t.Run(group, func(t *testing.T) {
			var fixture struct {
				Scenarios []struct {
					Name  string
					Setup []s3KMSCall
					Calls []s3ObjectCall
				}
			}
			awsReadFixture(t, "s3/replication_"+group+"_replay.json", &fixture)
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

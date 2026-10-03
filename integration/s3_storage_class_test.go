package stackd_test

import "testing"

func TestS3StorageClassNativeReplay(t *testing.T) {
	var fixture struct {
		Cases []struct {
			Name  string
			Calls []s3ObjectCall
		}
	}
	awsReadFixture(t, "s3/storage_class_replay.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range fixture.Cases {
			t.Run(backend+"/"+scenario.Name, func(t *testing.T) {
				runS3ObjectCalls(t, backend, nil, scenario.Calls, false)
			})
		}
	}
}

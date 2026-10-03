package stackd_test

import "testing"

// Native fixtures retain their own control and authority scope; execution below
// is document-derived and does not claim captured native archive timing.
func TestS3IntelligentTieringNativeReplay(t *testing.T) {
	for _, group := range []string{"control", "authority"} {
		t.Run(group, func(t *testing.T) {
			runS3ExecutionReplay(t, "s3/intelligent_tiering_"+group+"_replay.json")
		})
	}
}

func TestS3IntelligentTieringExecutionReplay(t *testing.T) {
	runS3ExecutionReplay(t, "s3/intelligent_tiering_execution_replay.json")
}

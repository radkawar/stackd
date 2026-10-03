package stackd_test

import "testing"

func TestS3AnalyticsNativeControls(t *testing.T) {
	runS3ExecutionReplay(t, "s3/analytics_controls_replay.json")
}

func TestS3AnalyticsNativeBoundaries(t *testing.T) {
	runS3ExecutionReplay(t, "s3/analytics_boundaries_replay.json")
}

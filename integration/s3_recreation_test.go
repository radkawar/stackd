package stackd_test

import "testing"

func TestS3RecreationNativeControls(t *testing.T) {
	runS3ExecutionReplay(t, "s3/recreation_controls_replay.json")
}

func TestS3RecreationNativeAuthority(t *testing.T) {
	runS3ExecutionReplay(t, "s3/recreation_authority_replay.json")
}

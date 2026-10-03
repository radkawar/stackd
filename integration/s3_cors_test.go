package stackd_test

import "testing"

func TestS3NativeCORSControls(t *testing.T) {
	runS3NativeControlReplay(t, "s3/cors_replay.json")
}

func TestS3NativeCORSHTTP(t *testing.T) {
	runS3NativeRawReplay(t, "s3/cors_raw_replay.json")
}

func TestS3NativeCORSAudit(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/cors_audit_replay.json")
}

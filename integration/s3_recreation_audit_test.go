package stackd_test

import "testing"

func TestS3RecreationNativeAudit(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/recreation_audit_replay.json")
}

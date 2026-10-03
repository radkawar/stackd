package stackd_test

import "testing"

func TestS3AccelerationNativeControls(t *testing.T) {
	runS3ExecutionReplay(t, "s3/acceleration_controls_replay.json")
}

func TestS3AccelerationNativeData(t *testing.T) {
	runS3ExecutionReplay(t, "s3/acceleration_data_replay.json")
}

func TestS3AccelerationNativeAudit(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/acceleration_audit_replay.json")
}

func TestS3AccelerationNativeRouting(t *testing.T) {
	runS3ExecutionReplay(t, "s3/acceleration_routing_replay.json")
}

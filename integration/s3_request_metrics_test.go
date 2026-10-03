package stackd_test

import "testing"

func TestS3RequestMetricsNativeControls(t *testing.T) {
	runS3ExecutionReplay(t, "s3/request_metrics_control_replay.json")
}

func TestS3RequestMetricsNativeAudit(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/request_metrics_audit_replay.json")
}

func TestS3RequestMetricsNativePublication(t *testing.T) {
	runS3SignalsReplay(t, "s3/request_metrics_data_replay.json")
}

func TestS3RequestMetricsNativeMetadata(t *testing.T) {
	runS3SignalsReplay(t, "s3/request_metrics_metadata_replay.json")
}

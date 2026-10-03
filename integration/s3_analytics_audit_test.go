package stackd_test

import "testing"

// Positively correlated native management history is delivered through the
// configured classic selector and actual S3 gzip sink, on both repositories.
// Unmatched history calls do not establish exclusions or analytics report parity.
func TestS3AnalyticsNativeAuditDelivery(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/analytics_audit_replay.json")
}

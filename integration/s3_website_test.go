package stackd_test

import "testing"

func TestS3NativeWebsiteAdmission(t *testing.T) {
	runS3NativeRawReplay(t, "s3/website_admission_replay.json")
	runS3NativeControlReplay(t, "s3/website_rules_replay.json")
}

func TestS3NativeWebsiteHTTP(t *testing.T) {
	runS3NativeRawReplay(t, "s3/website_http_replay.json")
}

func TestS3NativeWebsiteAudit(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/website_audit_replay.json")
}

// These local contracts exercise integration boundaries not measured by the
// native website probe: shared ranges/conditions, local hosts and CORS without
// granting object authority. They are not represented as native observations.
func TestS3WebsiteReadIntegration(t *testing.T) {
	runS3NativeRawReplay(t, "s3/website_local_replay.json")
}

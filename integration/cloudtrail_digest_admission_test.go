package stackd_test

import (
	"net/http/httptest"
	"testing"

	"stackd"
)

func TestCloudTrailDigestNativeDestinationAdmission(t *testing.T) {
	fixture := s3NativeLoad(t, "cloudtrail", "digest_admission")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			objects := s3NativeClient(c, eventDeliveryAccount, "test")
			s3NativeReplay(t, objects, fixture, "create-bucket")
			s3NativeReplay(t, objects, fixture, "put-bucket-policy")
			s3NativeReplay(t, trailNativeClient(c), fixture, "create-trail")
			// A successful log-marker effect is not rolled back with the failed
			// digest preflight, but the trail itself must never be published.
			c = reopen()
			s3NativeReplay(t, trailNativeClient(c), fixture, "get-trail")
			s3NativeReplay(t, s3NativeClient(c, eventDeliveryAccount, "test"), fixture, "list-objects-v2")
			for _, label := range []string{"create-disabled", "update-denied", "get-after-denied"} {
				s3NativeReplay(t, trailNativeClient(c), fixture, label)
			}
			s3NativeReplay(t, s3NativeClient(c, eventDeliveryAccount, "test"), fixture, "allow-digest")
			s3NativeReplay(t, trailNativeClient(c), fixture, "update-enabled")
			c = reopen()
			s3NativeReplay(t, trailNativeClient(c), fixture, "get-enabled")
			s3NativeReplay(t, s3NativeClient(c, eventDeliveryAccount, "test"), fixture, "list-markers")
			s3NativeReplay(t, trailNativeClient(c), fixture, "update-disabled")
			c = reopen()
			s3NativeReplay(t, trailNativeClient(c), fixture, "get-disabled")
		})
	}
}

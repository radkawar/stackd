package stackd_test

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"stackd"
	"stackd/clock"
)

// These execution expectations are document-derived, not a native lifecycle
// capture. At/Drain encode the local daily scheduler contract, not an AWS SLA.
func TestS3LifecycleExecutionReplay(t *testing.T) {
	runS3ExecutionReplay(t, "s3/lifecycle_execution_replay.json")
}

// More than one metadata page expires while its last visited version is deleted.
func TestS3LifecyclePagedExpiration(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC))
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: "123456789012", Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			client := newS3KMSReplay(clients).s3Client("caller")
			bucket, key := "lifecycle-paged-expiration", "object"
			if _, err := client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.PutBucketVersioning(t.Context(), &s3.PutBucketVersioningInput{
				Bucket: &bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled},
			}); err != nil {
				t.Fatal(err)
			}
			var latest *string
			for range 1001 {
				out, err := client.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: strings.NewReader("version")})
				if err != nil {
					t.Fatal(err)
				}
				latest = out.VersionId
			}
			if _, err := client.PutBucketLifecycleConfiguration(t.Context(), &s3.PutBucketLifecycleConfigurationInput{
				Bucket: &bucket, LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: []types.LifecycleRule{{
					ID: aws.String("expire-history"), Status: types.ExpirationStatusEnabled, Filter: &types.LifecycleRuleFilter{},
					Expiration:                  &types.LifecycleExpiration{Days: aws.Int32(1)},
					NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{NoncurrentDays: aws.Int32(1)},
				}}},
			}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 36*time.Hour)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			out, err := client.ListObjectVersions(t.Context(), &s3.ListObjectVersionsInput{Bucket: &bucket})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToBool(out.IsTruncated) || len(out.Versions) != 1 || aws.ToString(out.Versions[0].VersionId) != aws.ToString(latest) ||
				aws.ToBool(out.Versions[0].IsLatest) || len(out.DeleteMarkers) != 1 || !aws.ToBool(out.DeleteMarkers[0].IsLatest) {
				t.Fatalf("expiration left stale history or removed its new marker: %+v", out)
			}
		})
	}
}

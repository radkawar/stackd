package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd/clock"
	"stackd/storage"
)

func TestS3BucketABACNativeReplay(t *testing.T) {
	for _, name := range []string{"controls", "authorization", "tag_transitions"} {
		t.Run(name, func(t *testing.T) {
			runS3ExecutionReplay(t, "s3/abac_"+name+"_replay.json")
		})
	}
}

func TestS3BucketABACNativeAudit(t *testing.T) {
	runS3NativeAuditReplay(t, "s3/abac_audit_replay.json")
}

func TestS3NativeBucketTaggingReplay(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "testdata", "aws", "s3", "bucket_tags.json"))
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		s3NativeFixture
		SupplementalRuns []s3NativeFixture `json:"supplemental_runs"`
	}
	if err := json.Unmarshal(body, &capture); err != nil {
		t.Fatal(err)
	}
	fixture := capture.s3NativeFixture
	for _, supplement := range capture.SupplementalRuns {
		for _, row := range supplement.Observations {
			if strings.HasPrefix(row.Label, "put-character-") {
				fixture.Observations = append(fixture.Observations, row)
			}
		}
	}
	// Captures retain CLI operation names. The shared replay boundary invokes
	// generated SDK operations without replacing the captured input.
	for i := range fixture.Observations {
		parts := strings.Split(fixture.Observations[i].Operation, "-")
		for j, part := range parts {
			if part != "" {
				parts[j] = strings.ToUpper(part[:1]) + part[1:]
			}
		}
		fixture.Observations[i].Operation = strings.Join(parts, "")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "bucket-tags.sqlite")
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC))
			_, clients, closeStack := startEventDeliveryCloud(t, backends, source)
			account, bucket := fixture.Identity["account"], fixture.Identity["bucket"]
			client := s3NativeClient(clients, account, "test")
			for _, row := range fixture.Observations {
				switch row.Operation {
				case "CreateBucket", "GetBucketTagging", "PutBucketTagging", "DeleteBucketTagging":
				default:
					continue
				}
				// CLI-side parameter rejection sent no request and is not an
				// observation of S3's service behavior.
				if row.Result.Code == "CLIError" {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					s3BucketTagReplay(t, client, fixture, row)
				})
				if backend == "sqlite" && (row.Label == "put-ordered-get" || row.Label == "get-after-delete-with-tags") {
					closeStack()
					closeDB()
					backends, closeDB = openSQLiteBackends(t, path)
					_, clients, closeStack = startEventDeliveryCloud(t, backends, source)
					client = s3NativeClient(clients, account, "test")
					// Reopen with a populated set and with durable removal. The
					// native Get outcome must survive both transitions.
					s3BucketTagReplay(t, client, fixture, row)
				}
			}

			// Bucket policy grants govern the actual stored set. Delete shares
			// PutBucketTagging permission; it is not a separate IAM action.
			_, key, secret := clients.user(t, account, "bucket-tag-writer")
			writer := s3NativeClient(clients, key, secret)
			principal := "arn:aws:iam::" + account + ":user/bucket-tag-writer"
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"s3:PutBucketTagging","Resource":%q}]}`, principal, "arn:aws:s3:::"+bucket)
			if _, err := client.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &policy}); err != nil {
				t.Fatal(err)
			}
			s3BucketTagReplay(t, writer, fixture, fixture.row(t, "put-ordered"))
			_, err := writer.GetBucketTagging(t.Context(), &s3.GetBucketTaggingInput{Bucket: &bucket})
			assertAPIError(t, err, "AccessDenied")
			if _, err := writer.DeleteBucketTagging(t.Context(), &s3.DeleteBucketTaggingInput{Bucket: &bucket}); err != nil {
				t.Fatal(err)
			}
			s3BucketTagReplay(t, client, fixture, fixture.row(t, "get-after-delete-with-tags"))
			s3BucketTagReplay(t, client, fixture, fixture.row(t, "put-ordered"))
			policy = fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"s3:*","Resource":%q},{"Effect":"Deny","Principal":{"AWS":%q},"Action":"s3:PutBucketTagging","Resource":%q}]}`, principal, "arn:aws:s3:::"+bucket, principal, "arn:aws:s3:::"+bucket)
			if _, err := client.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &policy}); err != nil {
				t.Fatal(err)
			}
			_, err = writer.DeleteBucketTagging(t.Context(), &s3.DeleteBucketTaggingInput{Bucket: aws.String(bucket)})
			assertAPIError(t, err, "AccessDenied")
			s3BucketTagReplay(t, writer, fixture, fixture.row(t, "put-ordered-get"))
		})
	}
}

func s3BucketTagReplay(t *testing.T, client *s3.Client, fixture s3NativeFixture, row s3NativeObservation) {
	t.Helper()
	if row.Operation != "GetBucketTagging" || row.Result.Code != "Success" {
		s3NativeReplay(t, client, fixture, row.Label)
		return
	}
	got, _, err := s3NativeInvoke(t, client, row, nil)
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	assertS3NativeTagSet(t, row.Label, row.Result.Output["TagSet"], got["TagSet"])
}

type s3NativeTagValue struct{ Key, Value string }

func assertS3NativeTagSet(t *testing.T, label string, want, got any) {
	t.Helper()
	// Tags and filter predicates are unordered. Preserve complete elements and
	// multiplicity rather than collapsing repeated keys.
	sets := [2]map[s3NativeTagValue]int{}
	for i, output := range []any{want, got} {
		body, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		var values []s3NativeTagValue
		if err := json.Unmarshal(body, &values); err != nil {
			t.Fatal(err)
		}
		sets[i] = make(map[s3NativeTagValue]int, len(values))
		for _, value := range values {
			sets[i][value]++
		}
	}
	if !reflect.DeepEqual(sets[0], sets[1]) {
		t.Fatalf("%s set: got %#v; native %#v", label, sets[1], sets[0])
	}
}

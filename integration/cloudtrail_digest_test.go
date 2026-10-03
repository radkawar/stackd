package stackd_test

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"stackd"
	"stackd/clock"
)

type trailDigestDocument struct {
	Account           string  `json:"awsAccountId"`
	Start             string  `json:"digestStartTime"`
	End               string  `json:"digestEndTime"`
	Bucket            string  `json:"digestS3Bucket"`
	Object            string  `json:"digestS3Object"`
	Fingerprint       string  `json:"digestPublicKeyFingerprint"`
	PreviousObject    *string `json:"previousDigestS3Object"`
	PreviousHash      *string `json:"previousDigestHashValue"`
	PreviousSignature *string `json:"previousDigestSignature"`
	Logs              []struct {
		Bucket string `json:"s3Bucket"`
		Object string `json:"s3Object"`
		Hash   string `json:"hashValue"`
	} `json:"logFiles"`
}

func digestUnzip(t *testing.T, data []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func digestSHA(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func digestObjects(t *testing.T, c cloudClients, bucket, prefix string) []string {
	t.Helper()
	out, err := s3NativeClient(c, eventDeliveryAccount, "test").ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &prefix})
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, o := range out.Contents {
		if strings.HasSuffix(aws.ToString(o.Key), ".json.gz") {
			keys = append(keys, aws.ToString(o.Key))
		}
	}
	sort.Strings(keys)
	return keys
}
func verifyTrailDigest(t *testing.T, c cloudClients, bucket, key, region string) (trailDigestDocument, []byte, string) {
	t.Helper()
	objects := s3NativeClient(c, eventDeliveryAccount, "test")
	out, err := objects.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := io.ReadAll(out.Body)
	out.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	raw := digestUnzip(t, compressed)
	var doc trailDigestDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Bucket != bucket || doc.Object != key {
		t.Fatal("digest location was not signed at its actual S3 location")
	}
	end, err := time.Parse(time.RFC3339, doc.End)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := organizationTrailClient(c, eventDeliveryAccount, region).ListPublicKeys(t.Context(), &cloudtrail.ListPublicKeysInput{StartTime: &end, EndTime: &end})
	if err != nil {
		t.Fatal(err)
	}
	var public *rsa.PublicKey
	for _, k := range keys.PublicKeyList {
		if aws.ToString(k.Fingerprint) == doc.Fingerprint {
			public, err = x509.ParsePKCS1PublicKey(k.Value)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if public == nil {
		t.Fatal("digest signer was not discoverable in its source region")
	}
	signature, err := hex.DecodeString(out.Metadata["signature"])
	if err != nil {
		t.Fatal(err)
	}
	if out.Metadata["signature-algorithm"] != "SHA256withRSA" {
		t.Fatal("missing digest signature metadata")
	}
	previous := "null"
	if doc.PreviousSignature != nil {
		previous = *doc.PreviousSignature
	}
	signing := sha256.Sum256([]byte(doc.End + "\n" + bucket + "/" + key + "\n" + digestSHA(raw) + "\n" + previous))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, signing[:], signature); err != nil {
		t.Fatal(err)
	}
	for _, log := range doc.Logs {
		got, err := objects.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &log.Bucket, Key: &log.Object})
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(got.Body)
		got.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if digestSHA(digestUnzip(t, data)) != log.Hash {
			t.Fatal("digest did not hash the delivered gzip content")
		}
	}
	return doc, raw, out.Metadata["signature"]
}

// Native fixtures establish starting/hourly intervals and empty chaining;
// log-bearing delivery also follows the primary AWS digest validation contract.
func TestCloudTrailDigestDeliveryRestartAndLifecycle(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/cloudtrail/digest_starting.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Started   time.Time           `json:"logging_started_at"`
		Document  trailDigestDocument `json:"document"`
		Successor trailDigestDocument `json:"successor"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Started)
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			const name, bucket = "digest-owned", "digest-owned-bucket"
			arn := "arn:aws:cloudtrail:us-east-1:" + eventDeliveryAccount + ":trail/" + name
			objects := s3NativeClient(c, eventDeliveryAccount, "test")
			trails := trailNativeClient(c)
			ctx := t.Context()
			if _, err := objects.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
				t.Fatal(err)
			}
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%s","Condition":{"StringEquals":{"aws:SourceArn":"%s"}}},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/AWSLogs/%s/*","Condition":{"StringEquals":{"aws:SourceArn":"%s","s3:x-amz-acl":"bucket-owner-full-control"}}}]}`, bucket, arn, bucket, eventDeliveryAccount, arn)
			setPolicy := func(p string) {
				t.Helper()
				if _, err := s3NativeClient(c, eventDeliveryAccount, "test").PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: &p}); err != nil {
					t.Fatal(err)
				}
			}
			setPolicy(policy)
			created, err := trails.CreateTrail(ctx, &cloudtrail.CreateTrailInput{Name: aws.String(name), S3BucketName: aws.String(bucket), EnableLogFileValidation: aws.Bool(true), RecursiveLogging: aws.Bool(false)})
			if err != nil || !aws.ToBool(created.LogFileValidationEnabled) {
				t.Fatalf("enable validation: %v %v", created, err)
			}
			// Only writes below probe/ are selected, making empty hours genuine.
			_, err = trails.PutEventSelectors(ctx, &cloudtrail.PutEventSelectorsInput{TrailName: aws.String(name), AdvancedEventSelectors: []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{{Field: aws.String("eventCategory"), Equals: []string{"Data"}}, {Field: aws.String("resources.type"), Equals: []string{"AWS::S3::Object"}}, {Field: aws.String("resources.ARN"), StartsWith: []string{"arn:aws:s3:::" + bucket + "/probe/"}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = trails.StartLogging(ctx, &cloudtrail.StartLoggingInput{Name: aws.String(name)}); err != nil {
				t.Fatal(err)
			}
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			prefix := "AWSLogs/" + eventDeliveryAccount + "/CloudTrail-Digest/us-east-1/"
			files := digestObjects(t, c, bucket, prefix)
			if len(files) != 1 {
				t.Fatalf("starting digest missing: %v", files)
			}
			starting, _, _ := verifyTrailDigest(t, c, bucket, files[0], "us-east-1")
			if starting.Start != fixture.Document.Start || starting.End != fixture.Document.End || len(starting.Logs) != 0 || starting.PreviousObject != nil {
				t.Fatalf("starting interval differs from native: %+v", starting)
			}
			if _, err = objects.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String("probe/one"), Body: strings.NewReader("real event")}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, 6*time.Minute)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			c = reopen()
			advanceClock(t, source, 54*time.Minute)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			files = digestObjects(t, c, bucket, prefix)
			if len(files) != 2 {
				t.Fatalf("first hourly digest: %v", files)
			}
			first, raw, signature := verifyTrailDigest(t, c, bucket, files[1], "us-east-1")
			if first.Start != fixture.Successor.Start || first.End != fixture.Successor.End || len(first.Logs) != 1 || aws.ToString(first.PreviousObject) != files[0] {
				t.Fatalf("first log-bearing digest: %+v", first)
			}
			c = reopen()
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			files = digestObjects(t, c, bucket, prefix)
			if len(files) != 3 {
				t.Fatalf("empty hour missing: %v", files)
			}
			second, _, _ := verifyTrailDigest(t, c, bucket, files[2], "us-east-1")
			if len(second.Logs) != 0 || aws.ToString(second.PreviousObject) != files[1] || aws.ToString(second.PreviousHash) != digestSHA(raw) || aws.ToString(second.PreviousSignature) != signature {
				t.Fatalf("restarted empty chain: %+v", second)
			}
			other, err := organizationTrailClient(c, eventDeliveryAccount, "eu-west-1").ListPublicKeys(ctx, &cloudtrail.ListPublicKeysInput{})
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range other.PublicKeyList {
				if aws.ToString(key.Fingerprint) == first.Fingerprint {
					t.Fatal("regional signer leaked")
				}
			}
			// A failed digest is pending, not a success; restart and restored policy retry
			// precisely the same chain position and eventually expose actual success.
			denied := policy[:len(policy)-2] + fmt.Sprintf(`,{"Effect":"Deny","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/%s*"}]}`, bucket, prefix)
			setPolicy(denied)
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			status, err := trailNativeClient(c).GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: aws.String(name)})
			if err != nil || aws.ToString(status.LatestDigestDeliveryError) == "" {
				t.Fatalf("missing real delivery error: %+v %v", status, err)
			}
			if files = digestObjects(t, c, bucket, prefix); len(files) != 3 {
				t.Fatal("denied digest was reported as delivered")
			}
			c = reopen()
			setPolicy(policy)
			advanceClock(t, source, time.Minute)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			files = digestObjects(t, c, bucket, prefix)
			if len(files) != 4 {
				t.Fatalf("pending digest not recovered: %v", files)
			}
			verifyTrailDigest(t, c, bucket, files[3], "us-east-1")
			if _, err := trailNativeClient(c).UpdateTrail(ctx, &cloudtrail.UpdateTrailInput{Name: aws.String(name), EnableLogFileValidation: aws.Bool(false)}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			closedCount := len(digestObjects(t, c, bucket, prefix))
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			if len(digestObjects(t, c, bucket, prefix)) != closedCount {
				t.Fatal("disabled validation continued generating digests")
			}
			if _, err := trailNativeClient(c).UpdateTrail(ctx, &cloudtrail.UpdateTrailInput{Name: aws.String(name), EnableLogFileValidation: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			files = digestObjects(t, c, bucket, prefix)
			restarted, _, _ := verifyTrailDigest(t, c, bucket, files[closedCount], "us-east-1")
			if restarted.PreviousObject != nil {
				t.Fatal("reenabled validation did not start a new chain")
			}
			if _, err := trailNativeClient(c).StopLogging(ctx, &cloudtrail.StopLoggingInput{Name: aws.String(name)}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			stoppedCount := len(digestObjects(t, c, bucket, prefix))
			c = reopen()
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			if len(digestObjects(t, c, bucket, prefix)) != stoppedCount {
				t.Fatal("stopped logging continued creating digests")
			}
			if _, err := trailNativeClient(c).StartLogging(ctx, &cloudtrail.StartLoggingInput{Name: aws.String(name)}); err != nil {
				t.Fatal(err)
			}
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			files = digestObjects(t, c, bucket, prefix)
			afterStop, _, _ := verifyTrailDigest(t, c, bucket, files[stoppedCount], "us-east-1")
			if afterStop.PreviousObject != nil {
				t.Fatal("logging restart retained the stopped chain")
			}
			if _, err := trailNativeClient(c).DeleteTrail(ctx, &cloudtrail.DeleteTrailInput{Name: aws.String(name)}); err != nil {
				t.Fatal(err)
			}
			c = reopen()
			advanceClock(t, source, time.Hour)
			trailNativeDrain(t, c.server.Config.Handler.(*stackd.Stack))
			afterDelete := digestObjects(t, c, bucket, prefix)
			if len(afterDelete) != len(files)+1 {
				t.Fatal("deleted trail lost its retained final digest")
			}
			verifyTrailDigest(t, c, bucket, afterDelete[len(afterDelete)-1], "us-east-1")
			// Replacing one decompressed log byte must disagree with its signed digest.
			log := first.Logs[0]
			got, err := s3NativeClient(c, eventDeliveryAccount, "test").GetObject(ctx, &s3.GetObjectInput{Bucket: &log.Bucket, Key: &log.Object})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(got.Body)
			got.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			plain := digestUnzip(t, body)
			plain[0] ^= 1
			var changed bytes.Buffer
			gz := gzip.NewWriter(&changed)
			if _, err = gz.Write(plain); err != nil {
				t.Fatal(err)
			}
			if err = gz.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = s3NativeClient(c, eventDeliveryAccount, "test").PutObject(ctx, &s3.PutObjectInput{Bucket: &log.Bucket, Key: &log.Object, Body: bytes.NewReader(changed.Bytes())}); err != nil {
				t.Fatal(err)
			}
			got, err = s3NativeClient(c, eventDeliveryAccount, "test").GetObject(ctx, &s3.GetObjectInput{Bucket: &log.Bucket, Key: &log.Object})
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(got.Body)
			got.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if digestSHA(digestUnzip(t, body)) == log.Hash {
				t.Fatal("tampered object passed signed log hash")
			}
		})
	}
}

package stackd_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/middleware"

	"stackd"
	"stackd/clock"
	"stackd/internal/awsapi"
	s3store "stackd/storage/s3"
)

const s3UpdateAccount = "314159265358"

func s3UpdateTLSCloud(t *testing.T, config stackd.Config) (*stackd.Stack, *httptest.Server) {
	t.Helper()
	cloud, err := stackd.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return cloud, httptest.NewTLSServer(cloud)
}

func s3UpdateKey(t *testing.T, client *kms.Client) string {
	t.Helper()
	out, err := client.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.KeyMetadata.Arn)
}

func s3UpdateInput(bucket, key, version, arn string) *s3.UpdateObjectEncryptionInput {
	in := &s3.UpdateObjectEncryptionInput{Bucket: &bucket, Key: &key,
		ObjectEncryption: &types.ObjectEncryptionMemberSSEKMS{Value: types.SSEKMSEncryption{KMSKeyArn: &arn}}}
	if version != "" {
		in.VersionId = &version
	}
	return in
}

func s3UpdateHead(t *testing.T, client *s3.Client, bucket, key, version string) *s3.HeadObjectOutput {
	t.Helper()
	in := &s3.HeadObjectInput{Bucket: &bucket, Key: &key, ChecksumMode: types.ChecksumModeEnabled}
	if version != "" {
		in.VersionId = &version
	}
	out, err := client.HeadObject(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	out.ResultMetadata = middleware.Metadata{}
	return out
}

func s3UpdateSameMetadata(t *testing.T, before, after *s3.HeadObjectOutput) {
	t.Helper()
	left, right := *before, *after
	left.ServerSideEncryption, right.ServerSideEncryption = "", ""
	left.SSEKMSKeyId, right.SSEKMSKeyId = nil, nil
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("encryption update changed object metadata:\nbefore %#v\nafter %#v", left, right)
	}
}

func s3UpdateBytes(t *testing.T, client *s3.Client, bucket, key, version, arn string, want []byte, part int32) {
	t.Helper()
	in := &s3.GetObjectInput{Bucket: &bucket, Key: &key, ChecksumMode: types.ChecksumModeEnabled}
	if version != "" {
		in.VersionId = &version
	}
	if part != 0 {
		in.PartNumber = &part
	}
	out, err := client.GetObject(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(out.Body)
	closeErr := out.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, want) || aws.ToString(out.SSEKMSKeyId) != arn {
		t.Fatalf("public GetObject changed bytes or key authority: bytes=%d want=%d key=%q want=%q read=%v close=%v", len(got), len(want), aws.ToString(out.SSEKMSKeyId), arn, readErr, closeErr)
	}
}

func TestS3UpdateObjectEncryptionVersionsAndKeyAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: s3UpdateAccount, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return s3UpdateTLSCloud(t, config)
			})
			objects, keys := s3NativeClient(clients, "test", "test"), clients.kms("test", "test", "")
			bucket, key := "update-encryption-versions", "history/object"
			if _, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
				t.Fatal(err)
			}
			if _, err := objects.PutBucketVersioning(t.Context(), &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
				t.Fatal(err)
			}
			body := []byte("preserve the original SSE-S3 data key and exact historical object bytes\x00\xff")
			put, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(body),
				StorageClass: types.StorageClassStandardIa, ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
				Metadata: map[string]string{"origin": "historical"}, ContentType: aws.String("application/x-preserved"), CacheControl: aws.String("max-age=123")})
			if err != nil {
				t.Fatal(err)
			}
			version := aws.ToString(put.VersionId)
			before := s3UpdateHead(t, objects, bucket, key, version)
			if version == "" || before.ChecksumSHA256 == nil {
				t.Fatal("versioned write omitted consumer version/checksum")
			}
			source.Advance(time.Hour)
			currentBody := []byte("the current version must remain isolated")
			current, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(currentBody)})
			if err != nil {
				t.Fatal(err)
			}
			currentBefore := s3UpdateHead(t, objects, bucket, key, "")
			versionsBefore, err := objects.ListObjectVersions(t.Context(), &s3.ListObjectVersionsInput{Bucket: &bucket})
			if err != nil {
				t.Fatal(err)
			}
			oldKey, newKey := s3UpdateKey(t, keys), s3UpdateKey(t, keys)
			if _, err := objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, oldKey)); err != nil {
				t.Fatal(err)
			}
			converted := s3UpdateHead(t, objects, bucket, key, version)
			s3UpdateSameMetadata(t, before, converted)
			if converted.ServerSideEncryption != types.ServerSideEncryptionAwsKms || aws.ToString(converted.SSEKMSKeyId) != oldKey {
				t.Fatalf("SSE-S3 envelope did not become a real KMS envelope: %#v", converted)
			}
			s3UpdateBytes(t, objects, bucket, key, version, oldKey, body, 0)
			if _, err := objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, newKey)); err != nil {
				t.Fatal(err)
			}
			if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: &oldKey}); err != nil {
				t.Fatal(err)
			}
			s3UpdateBytes(t, objects, bucket, key, version, newKey, body, 0)
			s3UpdateSameMetadata(t, before, s3UpdateHead(t, objects, bucket, key, version))
			if got := s3UpdateHead(t, objects, bucket, key, ""); !reflect.DeepEqual(currentBefore, got) {
				t.Fatal("updating historical encryption changed the current version")
			}
			s3UpdateBytes(t, objects, bucket, key, aws.ToString(current.VersionId), "", currentBody, 0)
			if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: &newKey}); err != nil {
				t.Fatal(err)
			}
			_, err = objects.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &key, VersionId: &version})
			assertAPIError(t, err, "KMS.DisabledException")
			if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: &newKey}); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			objects = s3NativeClient(clients, "test", "test")
			s3UpdateBytes(t, objects, bucket, key, version, newKey, body, 0)
			s3UpdateSameMetadata(t, before, s3UpdateHead(t, objects, bucket, key, version))
			versionsAfter, err := objects.ListObjectVersions(t.Context(), &s3.ListObjectVersionsInput{Bucket: &bucket})
			if err != nil || !reflect.DeepEqual(versionsBefore.Versions, versionsAfter.Versions) || len(versionsAfter.DeleteMarkers) != 0 {
				t.Fatalf("encryption update allocated or reordered history: %v", err)
			}
			// An omitted version selects current; it still must not create a version.
			if _, err := objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, "", newKey)); err != nil {
				t.Fatal(err)
			}
			s3UpdateSameMetadata(t, currentBefore, s3UpdateHead(t, objects, bucket, key, ""))
			s3UpdateBytes(t, objects, bucket, key, "", newKey, currentBody, 0)
		})
	}
}

func TestS3UpdateObjectEncryptionMultipartAndArchive(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: s3UpdateAccount})
			objects, keys := s3NativeClient(clients, "test", "test"), clients.kms("test", "test", "")
			bucket, key := "update-encryption-multipart", "multipart/object"
			if _, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
				t.Fatal(err)
			}
			upload, err := objects.CreateMultipartUpload(t.Context(), &s3.CreateMultipartUploadInput{Bucket: &bucket, Key: &key,
				ChecksumAlgorithm: types.ChecksumAlgorithmSha256, StorageClass: types.StorageClassStandardIa})
			if err != nil {
				t.Fatal(err)
			}
			parts := [][]byte{bytes.Repeat([]byte("part-one"), 655360), []byte("last part keeps its exact boundaries\x00\xff")}
			completed := make([]types.CompletedPart, 0, len(parts))
			for i, body := range parts {
				number := int32(i + 1)
				part, err := objects.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId,
					PartNumber: &number, Body: bytes.NewReader(body), ChecksumAlgorithm: types.ChecksumAlgorithmSha256})
				if err != nil {
					t.Fatal(err)
				}
				completed = append(completed, types.CompletedPart{PartNumber: &number, ETag: part.ETag, ChecksumSHA256: part.ChecksumSHA256})
			}
			if _, err := objects.CompleteMultipartUpload(t.Context(), &s3.CompleteMultipartUploadInput{Bucket: &bucket, Key: &key, UploadId: upload.UploadId,
				MultipartUpload: &types.CompletedMultipartUpload{Parts: completed}}); err != nil {
				t.Fatal(err)
			}
			before := s3UpdateHead(t, objects, bucket, key, "")
			attributes := &s3.GetObjectAttributesInput{Bucket: &bucket, Key: &key, ObjectAttributes: []types.ObjectAttributes{types.ObjectAttributesObjectParts, types.ObjectAttributesChecksum, types.ObjectAttributesEtag, types.ObjectAttributesObjectSize, types.ObjectAttributesStorageClass}}
			beforeParts, err := objects.GetObjectAttributes(t.Context(), attributes)
			if err != nil {
				t.Fatal(err)
			}
			arn := s3UpdateKey(t, keys)
			if _, err := objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, "", arn)); err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			objects = s3NativeClient(clients, "test", "test")
			afterParts, err := objects.GetObjectAttributes(t.Context(), attributes)
			if err != nil || !reflect.DeepEqual(beforeParts.ObjectParts, afterParts.ObjectParts) || !reflect.DeepEqual(beforeParts.Checksum, afterParts.Checksum) {
				t.Fatalf("rewrapping changed completed part/checksum records: %v", err)
			}
			s3UpdateSameMetadata(t, before, s3UpdateHead(t, objects, bucket, key, ""))
			for i, body := range parts {
				s3UpdateBytes(t, objects, bucket, key, "", arn, body, int32(i+1))
			}
			s3UpdateBytes(t, objects, bucket, key, "", arn, bytes.Join(parts, nil), 0)
			archiveKey := "archive/object"
			if _, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &archiveKey,
				Body: strings.NewReader("archive ciphertext must not be restored"), StorageClass: types.StorageClassDeepArchive}); err != nil {
				t.Fatal(err)
			}
			archiveBefore := s3UpdateHead(t, objects, bucket, archiveKey, "")
			if _, err := objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, archiveKey, "", arn)); err != nil {
				t.Fatal(err)
			}
			s3UpdateSameMetadata(t, archiveBefore, s3UpdateHead(t, objects, bucket, archiveKey, ""))
			_, err = objects.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &archiveKey})
			assertAPIError(t, err, "InvalidObjectState")
		})
	}
}

func TestS3UpdateObjectEncryptionDenialsAreAtomic(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: s3UpdateAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return s3UpdateTLSCloud(t, config)
			})
			objects, keys := s3NativeClient(clients, "test", "test"), clients.kms("test", "test", "")
			bucket, key := "update-encryption-denials", "protected/object"
			if _, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket, ObjectLockEnabledForBucket: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			source, destination := s3UpdateKey(t, keys), s3UpdateKey(t, keys)
			body := []byte("all rejected updates must leave this version and key unchanged")
			contextValue := base64.StdEncoding.EncodeToString([]byte(`{"purpose":"retained-context"}`))
			put, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(body),
				ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: &source, SSEKMSEncryptionContext: &contextValue, ChecksumAlgorithm: types.ChecksumAlgorithmSha256})
			if err != nil {
				t.Fatal(err)
			}
			version := aws.ToString(put.VersionId)
			before := s3UpdateHead(t, objects, bucket, key, version)
			unchanged := func() {
				t.Helper()
				if after := s3UpdateHead(t, objects, bucket, key, version); !reflect.DeepEqual(before, after) {
					t.Fatal("denied encryption update changed retained metadata or KMS key")
				}
				s3UpdateBytes(t, objects, bucket, key, version, source, body, 0)
			}
			_, userKey, userSecret := clients.user(t, "test", "encryption-updater")
			user := s3NativeClient(clients, userKey, userSecret)
			for _, action := range []string{"s3:UpdateObjectEncryption", "kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncryptTo", "kms:Decrypt", "kms:ReEncryptFrom"} {
				putUserPolicy(t, clients.iam("test", "test", ""), "encryption-updater", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":["s3:*","kms:*"],"Resource":"*"},{"Effect":"Deny","Action":%q,"Resource":"*"}]}`, action))
				_, err := user.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, destination))
				assertAPIError(t, err, "AccessDenied")
				unchanged()
			}
			for _, target := range []string{source, destination} {
				if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: &target}); err != nil {
					t.Fatal(err)
				}
				_, err := objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, destination))
				assertAPIError(t, err, "KMS.DisabledException")
				if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: &target}); err != nil {
					t.Fatal(err)
				}
				unchanged()
			}
			for _, target := range []string{source, destination} {
				original, err := keys.GetKeyPolicy(t.Context(), &kms.GetKeyPolicyInput{KeyId: &target, PolicyName: aws.String("default")})
				if err != nil {
					t.Fatal(err)
				}
				deny := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"kms:*","Resource":"*"},{"Effect":"Deny","Principal":"*","Action":["kms:Encrypt","kms:ReEncryptFrom","kms:ReEncryptTo"],"Resource":"*"}]}`, s3UpdateAccount)
				if _, err := keys.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: &target, PolicyName: aws.String("default"), Policy: &deny}); err != nil {
					t.Fatal(err)
				}
				_, err = objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, destination))
				assertAPIError(t, err, "AccessDenied")
				if _, err := keys.PutKeyPolicy(t.Context(), &kms.PutKeyPolicyInput{KeyId: &target, PolicyName: aws.String("default"), Policy: original.Policy}); err != nil {
					t.Fatal(err)
				}
				unchanged()
			}
			other := s3UpdateKey(t, clients.kms("271828182845", "test", ""))
			wrongRegion := s3UpdateKey(t, clients.kmsRegion("us-west-2", "test", "test", ""))
			for _, denied := range []struct {
				arn, owner, code string
				bucketKey        bool
			}{
				{arn: destination, owner: "271828182845", code: "AccessDenied"},
				{arn: other, code: "AccessDenied"},
				{arn: wrongRegion, code: "InvalidRequest"},
				{arn: "alias/customer", code: "InvalidRequest"},
				{arn: strings.TrimPrefix(destination, "arn:aws:kms:us-east-1:"+s3UpdateAccount+":key/"), code: "InvalidRequest"},
				{arn: destination, bucketKey: true, code: "NotImplemented"},
			} {
				in := s3UpdateInput(bucket, key, version, denied.arn)
				if denied.owner != "" {
					in.ExpectedBucketOwner = &denied.owner
				}
				if denied.bucketKey {
					in.ObjectEncryption.(*types.ObjectEncryptionMemberSSEKMS).Value.BucketKeyEnabled = aws.Bool(true)
				}
				_, err := objects.UpdateObjectEncryption(t.Context(), in)
				assertAPIError(t, err, denied.code)
				unchanged()
			}
			if _, err := objects.PutObjectLegalHold(t.Context(), &s3.PutObjectLegalHoldInput{Bucket: &bucket, Key: &key, VersionId: &version, LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOn}}); err != nil {
				t.Fatal(err)
			}
			_, err = objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, destination))
			assertAPIError(t, err, "AccessDenied")
			if _, err := objects.PutObjectLegalHold(t.Context(), &s3.PutObjectLegalHoldInput{Bucket: &bucket, Key: &key, VersionId: &version, LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOff}}); err != nil {
				t.Fatal(err)
			}
			// LegalHold OFF is retained metadata, not an applied hold.
			before = s3UpdateHead(t, objects, bucket, key, version)
			for _, mode := range []types.ObjectLockRetentionMode{types.ObjectLockRetentionModeGovernance, types.ObjectLockRetentionModeCompliance} {
				lockKey := "retention/" + string(mode)
				locked, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &lockKey, Body: bytes.NewReader(body),
					ObjectLockMode: types.ObjectLockMode(mode), ObjectLockRetainUntilDate: aws.Time(time.Now().UTC().Add(24 * time.Hour)), ChecksumAlgorithm: types.ChecksumAlgorithmSha256})
				if err != nil {
					t.Fatal(err)
				}
				lockedBefore := s3UpdateHead(t, objects, bucket, lockKey, aws.ToString(locked.VersionId))
				_, err = objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, lockKey, aws.ToString(locked.VersionId), destination))
				assertAPIError(t, err, "AccessDenied")
				if after := s3UpdateHead(t, objects, bucket, lockKey, aws.ToString(locked.VersionId)); !reflect.DeepEqual(lockedBefore, after) {
					t.Fatal("retention rejection changed object metadata")
				}
			}
			_, err = objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, "absent", "", destination))
			assertAPIError(t, err, "NoSuchKey")
			clients = reopen()
			objects = s3NativeClient(clients, "test", "test")
			unchanged()
			// A genuine key change with additional context must remain readable.
			if _, err := objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, destination)); err != nil {
				t.Fatal(err)
			}
			s3UpdateBytes(t, objects, bucket, key, version, destination, body, 0)
		})
	}
}

func TestS3UpdateObjectEncryptionRequestIntegrity(t *testing.T) {
	clients, _ := retainedCloud(t, "memory", stackd.Config{AccountID: s3UpdateAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
		return s3UpdateTLSCloud(t, config)
	})
	objects, keys := s3NativeClient(clients, "test", "test"), clients.kms("test", "test", "")
	bucket, key := "update-encryption-integrity", "object"
	if _, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatal(err)
	}
	body := []byte("integrity rejections preserve the existing object")
	if _, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(body)}); err != nil {
		t.Fatal(err)
	}
	before := s3UpdateHead(t, objects, bucket, key, "")
	arn := s3UpdateKey(t, keys)
	valid := `<ObjectEncryption><SSE-KMS><KMSKeyArn>` + arn + `</KMSKeyArn><BucketKeyEnabled>false</BucketKeyEnabled></SSE-KMS></ObjectEncryption>`
	for _, row := range []struct {
		name, body, md5, checksum, code string
		unsigned                        bool
		status                          int
	}{
		{name: "missing digest", body: valid, code: "InvalidRequest", status: 400},
		{name: "bad digest", body: valid, md5: base64.StdEncoding.EncodeToString(make([]byte, md5.Size)), code: "BadDigest", status: 400},
		{name: "missing flexible checksum", body: valid, checksum: "SHA256", code: "InvalidRequest", status: 400},
		{name: "unsigned", body: valid, unsigned: true, code: "InvalidRequest", status: 400},
		{name: "SSE-S3 destination", body: `<ObjectEncryption><SSE-S3/></ObjectEncryption>`, code: "InvalidRequest", status: 400},
		{name: "DSSE-KMS destination", body: `<ObjectEncryption><DSSE-KMS><KMSKeyArn>` + arn + `</KMSKeyArn></DSSE-KMS></ObjectEncryption>`, code: "InvalidRequest", status: 400},
		{name: "header settings", body: valid, code: "InvalidRequest", status: 400},
		{name: "mixed method", body: strings.Replace(valid, `</ObjectEncryption>`, `<SSE-C/></ObjectEncryption>`, 1), code: "InvalidRequest", status: 400},
		{name: "invalid boolean", body: strings.Replace(valid, `false`, `not-false`, 1), code: "InvalidRequest", status: 400},
		{name: "duplicate key", body: strings.Replace(valid, `</SSE-KMS>`, `<KMSKeyArn>`+arn+`</KMSKeyArn></SSE-KMS>`, 1), code: "InvalidRequest", status: 400},
	} {
		t.Run(row.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, clients.server.URL+"/"+bucket+"/"+key+"?encryption", strings.NewReader(row.body))
			if err != nil {
				t.Fatal(err)
			}
			if row.name != "missing digest" && row.name != "missing flexible checksum" {
				digest := md5.Sum([]byte(row.body))
				request.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(digest[:]))
			}
			if row.md5 != "" {
				request.Header.Set("Content-MD5", row.md5)
			}
			if row.checksum != "" {
				request.Header.Set("x-amz-sdk-checksum-algorithm", row.checksum)
			}
			if row.name == "header settings" {
				request.Header.Set("x-amz-server-side-encryption", "AES256")
			}
			if !row.unsigned {
				digest := sha256.Sum256([]byte(row.body))
				payload := hex.EncodeToString(digest[:])
				request.Header.Set("x-amz-content-sha256", payload)
				if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, payload, "s3", "us-east-1", time.Now().UTC()); err != nil {
					t.Fatal(err)
				}
			}
			s3HTTPResponse(t, clients.server.Client(), request, row.status, row.code)
			if after := s3UpdateHead(t, objects, bucket, key, ""); !reflect.DeepEqual(before, after) {
				t.Fatal("rejected transport/document changed object")
			}
			s3UpdateBytes(t, objects, bucket, key, "", "", body, 0)
		})
	}
	// Real SSE-C bytes are not eligible for an envelope-only update.
	if _, err := objects.PutBucketEncryption(t.Context(), &s3.PutBucketEncryptionInput{Bucket: &bucket,
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{Rules: []types.ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{SSEAlgorithm: types.ServerSideEncryptionAes256},
			BlockedEncryptionTypes:             &types.BlockedEncryptionTypes{EncryptionType: []types.EncryptionType{types.EncryptionTypeNone}},
		}}}}); err != nil {
		t.Fatal(err)
	}
	customerBytes := bytes.Repeat([]byte{0x73}, 32)
	customer := base64.StdEncoding.EncodeToString(customerBytes)
	customerDigest := md5.Sum(customerBytes)
	customerMD5 := base64.StdEncoding.EncodeToString(customerDigest[:])
	customerKey := "customer-object"
	put, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &customerKey, Body: bytes.NewReader(body),
		SSECustomerAlgorithm: aws.String("AES256"), SSECustomerKey: &customer, SSECustomerKeyMD5: &customerMD5})
	if err != nil {
		t.Fatal(err)
	}
	_, err = objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, customerKey, "", arn))
	assertAPIError(t, err, "InvalidRequest")
	got, err := objects.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: &customerKey, SSECustomerAlgorithm: aws.String("AES256"), SSECustomerKey: &customer, SSECustomerKeyMD5: &customerMD5})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	actual, err := io.ReadAll(got.Body)
	if err != nil || !bytes.Equal(actual, body) || aws.ToString(got.ETag) != aws.ToString(put.ETag) {
		t.Fatalf("unsupported SSE-C source was changed: %v", err)
	}
}

// The gate injects another real public command only after KMS completes and
// before S3 opens its publication transaction. It never mocks data keys/crypto.
type s3UpdateFenceRepository struct {
	s3store.Repository
	before func()
}

func (r *s3UpdateFenceRepository) Update(ctx context.Context, fn func(s3store.Transaction) error) error {
	request, ok := awsapi.FromContext(ctx)
	if ok && request.Operation.Name == "UpdateObjectEncryption" && r.before != nil {
		before := r.before
		r.before = nil
		before()
	}
	return r.Repository.Update(ctx, fn)
}

func TestS3UpdateObjectEncryptionRevalidatesAfterKMS(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var fence *s3UpdateFenceRepository
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: s3UpdateAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				fence = &s3UpdateFenceRepository{Repository: config.Storage.S3}
				config.Storage.S3 = fence
				return s3UpdateTLSCloud(t, config)
			})
			objects, keys := s3NativeClient(clients, "test", "test"), clients.kms("test", "test", "")
			bucket, key := "update-encryption-fences", "object"
			if _, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket, ObjectLockEnabledForBucket: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			arn := s3UpdateKey(t, keys)
			body := []byte("original bytes before external envelope effects")
			put, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(body)})
			if err != nil {
				t.Fatal(err)
			}
			version := aws.ToString(put.VersionId)
			before := s3UpdateHead(t, objects, bucket, key, version)
			fence.before = func() {
				if _, err := keys.DisableKey(t.Context(), &kms.DisableKeyInput{KeyId: &arn}); err != nil {
					t.Fatal(err)
				}
			}
			_, err = objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, arn))
			assertAPIError(t, err, "KMS.DisabledException")
			if after := s3UpdateHead(t, objects, bucket, key, version); !reflect.DeepEqual(before, after) {
				t.Fatal("key disabled across effects still committed its envelope")
			}
			if _, err := keys.EnableKey(t.Context(), &kms.EnableKeyInput{KeyId: &arn}); err != nil {
				t.Fatal(err)
			}
			fence.before = func() {
				if _, err := objects.PutObjectLegalHold(t.Context(), &s3.PutObjectLegalHoldInput{Bucket: &bucket, Key: &key, VersionId: &version, LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOn}}); err != nil {
					t.Fatal(err)
				}
			}
			_, err = objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, version, arn))
			assertAPIError(t, err, "AccessDenied")
			s3UpdateBytes(t, objects, bucket, key, version, "", body, 0)
			if aws.ToString(s3UpdateHead(t, objects, bucket, key, version).SSEKMSKeyId) != "" {
				t.Fatal("new legal hold failed to fence encryption publication")
			}
			// A new current version must not receive an old version's data key.
			if _, err := objects.PutObjectLegalHold(t.Context(), &s3.PutObjectLegalHoldInput{Bucket: &bucket, Key: &key, VersionId: &version, LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOff}}); err != nil {
				t.Fatal(err)
			}
			replacement := []byte("new current bytes written while KMS was outside S3")
			fence.before = func() {
				if _, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(replacement)}); err != nil {
					t.Fatal(err)
				}
			}
			_, err = objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, "", arn))
			assertAPIError(t, err, "OperationAborted")
			s3UpdateBytes(t, objects, bucket, key, "", "", replacement, 0)
			s3UpdateBytes(t, objects, bucket, key, version, "", body, 0)
		})
	}
}

func TestS3UpdateObjectEncryptionCloudTrailDataPrivacy(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Now().UTC().Truncate(time.Second))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: s3UpdateAccount, Clock: source})
			objects := s3NativeClient(clients, "test", "test")
			bucket, logs, key := "update-encryption-audit-data", "update-encryption-audit-logs", "private-object"
			for _, name := range []string{bucket, logs} {
				if _, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &name}); err != nil {
					t.Fatal(err)
				}
			}
			trailName := "encryption-updates"
			trailARN := "arn:aws:cloudtrail:us-east-1:" + s3UpdateAccount + ":trail/" + trailName
			policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%s","Condition":{"StringEquals":{"aws:SourceArn":%q}}},{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/AWSLogs/%s/*","Condition":{"StringEquals":{"aws:SourceArn":%q,"s3:x-amz-acl":"bucket-owner-full-control"}}}]}`, logs, trailARN, logs, s3UpdateAccount, trailARN)
			if _, err := objects.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{Bucket: &logs, Policy: &policy}); err != nil {
				t.Fatal(err)
			}
			trails := organizationTrailClient(clients, s3UpdateAccount, "us-east-1")
			if _, err := trails.CreateTrail(t.Context(), &cloudtrail.CreateTrailInput{Name: &trailName, S3BucketName: &logs}); err != nil {
				t.Fatal(err)
			}
			if _, err := trails.PutEventSelectors(t.Context(), &cloudtrail.PutEventSelectorsInput{TrailName: &trailName,
				AdvancedEventSelectors: []trailtypes.AdvancedEventSelector{{FieldSelectors: []trailtypes.AdvancedFieldSelector{
					{Field: aws.String("eventCategory"), Equals: []string{"Data"}},
					{Field: aws.String("resources.type"), Equals: []string{"AWS::S3::Object"}},
					{Field: aws.String("resources.ARN"), StartsWith: []string{"arn:aws:s3:::" + bucket + "/"}},
				}}},
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := trails.StartLogging(t.Context(), &cloudtrail.StartLoggingInput{Name: &trailName}); err != nil {
				t.Fatal(err)
			}
			private := []byte("private payload must never enter encryption-update audit")
			if _, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: bytes.NewReader(private)}); err != nil {
				t.Fatal(err)
			}
			arn := s3UpdateKey(t, clients.kms("test", "test", ""))
			out, err := objects.UpdateObjectEncryption(t.Context(), s3UpdateInput(bucket, key, "", arn))
			if err != nil {
				t.Fatal(err)
			}
			requestID := nativeAuditRequestID(t, out, nil)
			clients = reopen()
			source.Advance(6 * time.Minute)
			trailNativeDrain(t, clients.server.Config.Handler.(*stackd.Stack))
			records := trailNativeRecords(t, trailNativeObjects(t, s3NativeClient(clients, "test", "test"), logs, "AWSLogs/"))
			var found map[string]any
			for _, record := range records {
				if record["requestID"] == requestID {
					found = record
				}
			}
			if found == nil || found["eventName"] != "UpdateObjectEncryption" || found["eventCategory"] != "Data" || found["readOnly"] != false || found["managementEvent"] != false || found["responseElements"] != nil {
				t.Fatalf("missing or misclassified delivered encryption-update data event: %#v", found)
			}
			params, ok := found["requestParameters"].(map[string]any)
			if !ok || params["bucketName"] != bucket || params["key"] != key || params["ObjectEncryption"] == nil {
				t.Fatalf("data event lost safe public object/encryption identity: %#v", params)
			}
			encoded, err := json.Marshal(found)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{string(private), "EncryptionKey", "CiphertextBlob", "Plaintext", "SSECustomerKey", "ContentMD5"} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("encryption-update data event leaked private data: %s", forbidden)
				}
			}
			s3UpdateBytes(t, s3NativeClient(clients, "test", "test"), bucket, key, "", arn, private, 0)
		})
	}
}

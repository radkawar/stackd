package stackd_test

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"stackd/clock"
	"stackd/storage"
)

func TestS3NativeBinarySDKReplay(t *testing.T) {
	object := s3NativeLoad(t, "s3", "owned_object_delivery")
	binary := s3NativeLoad(t, "s3", "owned_binary_headers")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "s3.sqlite")
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.Date(2026, 9, 13, 17, 12, 0, 0, time.UTC))
			_, clients, closeStack := startEventDeliveryCloud(t, backends, source)
			client := s3NativeClient(clients, object.Identity["account"], "test")
			bucket := object.Identity["source_bucket"]
			s3NativeReplay(t, client, object, "create-"+bucket)
			for _, label := range []string{"source-object-private-acl", "source-object-no-acl-default-checksum", "baseline-put", "baseline-head-default", "baseline-head-checksum", "baseline-get", "baseline-range", "baseline-list"} {
				s3NativeReplay(t, client, object, label)
			}
			for _, label := range []string{"binary-put-sha256", "binary-head-default", "binary-get-default", "binary-head-enabled", "binary-get-enabled", "binary-range-head", "binary-invalid-range-get", "binary-get-if-match-fails", "binary-put-invalid-md5"} {
				s3NativeReplay(t, client, binary, label)
			}
			// A failed checksum must not create even an empty object.
			_, err := client.GetObject(t.Context(), &s3.GetObjectInput{Bucket: &bucket, Key: aws.String("supplement/bad-digest.bin")})
			assertAPIError(t, err, "NoSuchKey")
			head, err := client.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: &bucket, Key: aws.String("supplement/binary.bin")})
			if err != nil || head.ChecksumSHA256 != nil || head.ChecksumType != "" {
				t.Fatalf("default HEAD exposed checksum omitted by native response: %+v %v", head, err)
			}
			if backend == "sqlite" {
				closeStack()
				closeDB()
				backends, _ = openSQLiteBackends(t, path)
				_, clients, _ = startEventDeliveryCloud(t, backends, source)
				client = s3NativeClient(clients, object.Identity["account"], "test")
				s3NativeReplay(t, client, binary, "binary-get-enabled")
			}
			for _, label := range []string{"baseline-delete", "baseline-head-missing", "baseline-get-missing", "baseline-delete-missing"} {
				s3NativeReplay(t, client, object, label)
			}
			_, userKey, userSecret := clients.user(t, object.Identity["account"], "s3-native-reader")
			reader := s3NativeClient(clients, userKey, userSecret)
			input := &s3.GetObjectInput{Bucket: &bucket, Key: aws.String("supplement/binary.bin")}
			_, err = reader.GetObject(t.Context(), input)
			assertAPIError(t, err, "AccessDenied")
			policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:user/s3-native-reader"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/supplement/*"}]}`, object.Identity["account"], bucket)
			if _, err := client.PutBucketPolicy(t.Context(), &s3.PutBucketPolicyInput{Bucket: &bucket, Policy: &policy}); err != nil {
				t.Fatal(err)
			}
			permitted, err := reader.GetObject(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(permitted.Body)
			permitted.Body.Close()
			if err != nil || !bytes.Equal(body, binary.payload(t)) {
				t.Fatalf("resource policy grant body: %x %v", body, err)
			}
			if _, err := client.DeleteBucketPolicy(t.Context(), &s3.DeleteBucketPolicyInput{Bucket: &bucket}); err != nil {
				t.Fatal(err)
			}
			_, err = reader.GetObject(t.Context(), input)
			assertAPIError(t, err, "AccessDenied")
		})
	}
}

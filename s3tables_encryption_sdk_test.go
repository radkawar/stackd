package stackd_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// These public assertions complement the physical ciphertext/migration tests:
// supported AES256 defaults and explicit requests must survive native multipart
// publication/reopen, rather than merely echoing an unimplemented request option.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/developing-s3-tables-APIs.html
func TestS3TablesSDKServerSideEncryptionDefaultAndExplicit(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newMultipartSDKFixture(t, backend)
			for _, mode := range []string{"default", "explicit"} {
				key := "data/encrypted-" + mode
				input := &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), Body: strings.NewReader("typed encrypted payload " + mode)}
				if mode == "explicit" {
					input.ServerSideEncryption = s3types.ServerSideEncryptionAes256
				}
				created, err := f.fixture.s3.PutObject(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				if created.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
					t.Fatalf("%s PutObject encryption was not authoritative: %q", mode, created.ServerSideEncryption)
				}
				f.restart(t)
				get, head := f.object(t, key, []byte("typed encrypted payload "+mode), created.ETag)
				if get.ServerSideEncryption != s3types.ServerSideEncryptionAes256 || head.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
					t.Fatalf("%s encryption disappeared after reopen: GET=%q HEAD=%q", mode, get.ServerSideEncryption, head.ServerSideEncryption)
				}
				_, err = f.fixture.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), Body: strings.NewReader("unsupported replacement"), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms})
				multipartSDKError(t, err, http.StatusBadRequest, "InvalidRequest")
				f.object(t, key, []byte("typed encrypted payload "+mode), created.ETag)
			}
			key := "metadata/encrypted-manifest.avro"
			created, err := f.fixture.s3.CreateMultipartUpload(t.Context(), &s3.CreateMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), ServerSideEncryption: s3types.ServerSideEncryptionAes256})
			if err != nil {
				t.Fatal(err)
			}
			if created.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
				t.Fatalf("multipart encryption default changed: %q", created.ServerSideEncryption)
			}
			part, err := f.fixture.s3.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("native manifest payload")})
			if err != nil {
				t.Fatal(err)
			}
			if part.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
				t.Fatalf("staged part encryption was not acknowledged: %q", part.ServerSideEncryption)
			}
			f.restart(t)
			completed := f.complete(t, key, created.UploadId, s3types.CompletedPart{PartNumber: aws.Int32(1), ETag: part.ETag, ChecksumCRC32: part.ChecksumCRC32})
			if completed.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
				t.Fatalf("multipart completion lost encryption: %q", completed.ServerSideEncryption)
			}
			f.restart(t)
			get, head := f.object(t, key, []byte("native manifest payload"), completed.ETag)
			if get.ServerSideEncryption != s3types.ServerSideEncryptionAes256 || head.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
				t.Fatalf("completed encrypted object lost mode across reopen: GET=%q HEAD=%q", get.ServerSideEncryption, head.ServerSideEncryption)
			}
			f.deleteTable(t)
		})
	}
}

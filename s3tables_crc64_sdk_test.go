package stackd_test

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"stackd/internal/awschecksum"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// Protocol matrix expectations follow the general S3 API:
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html
// The sanitized native capture calibrates the resulting nine-byte object's
// checksum/type/ETag, not the client's initiation headers or request matrix.
func TestS3TablesSDKCRC64NVMEFullObject(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/explicit=%t", backend, explicit), func(t *testing.T) {
				f := newMultipartSDKFixture(t, backend)
				key := "data/crc64.parquet"
				sum := func(data []byte) string {
					t.Helper()
					value, err := awschecksum.Sum("CRC64NVME", data)
					if err != nil {
						t.Fatal(err)
					}
					return value
				}
				old := []byte("123456789")
				// Sanitized native PyArrow/S3 Tables observation, 2026-11-05.
				if sum(old) != "rosUhgp5mIg=" {
					t.Fatalf("CRC64NVME native known vector: %q", sum(old))
				}
				put, err := f.fixture.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), Body: bytes.NewReader(old), ChecksumAlgorithm: s3types.ChecksumAlgorithmCrc64nvme, ChecksumCRC64NVME: aws.String(sum(old))})
				if err != nil || aws.ToString(put.ChecksumCRC64NVME) != sum(old) {
					t.Fatalf("PutObject CRC64: %v %v", put, err)
				}
				get, head := f.object(t, key, old, put.ETag)
				if aws.ToString(get.ChecksumCRC64NVME) != sum(old) || aws.ToString(head.ChecksumCRC64NVME) != sum(old) || get.ChecksumType != s3types.ChecksumTypeFullObject || head.ChecksumType != s3types.ChecksumTypeFullObject {
					t.Fatalf("PutObject GET/HEAD checksum: %v / %v", get, head)
				}
				createInput := &s3.CreateMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key)}
				if explicit {
					createInput.ChecksumAlgorithm = s3types.ChecksumAlgorithmCrc64nvme
					createInput.ChecksumType = s3types.ChecksumTypeFullObject
				}
				created, err := f.fixture.s3.CreateMultipartUpload(t.Context(), createInput)
				if err != nil {
					t.Fatal(err)
				}
				if explicit && created.ChecksumType != s3types.ChecksumTypeFullObject {
					t.Fatalf("initiation type: %q", created.ChecksumType)
				}
				payloads := [][]byte{bytes.Repeat([]byte("a"), 5*1024*1024), []byte("PAR1 CRC64 tail PAR1")}
				parts := make([]s3types.CompletedPart, 0, len(payloads))
				for i, payload := range payloads {
					input := &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, PartNumber: aws.Int32(int32(i + 1)), Body: bytes.NewReader(payload), ChecksumAlgorithm: s3types.ChecksumAlgorithmCrc64nvme, ChecksumCRC64NVME: aws.String(sum([]byte("wrong")))}
					_, err := f.fixture.s3.UploadPart(t.Context(), input)
					multipartSDKError(t, err, http.StatusBadRequest, "BadDigest")
					input.Body = bytes.NewReader(payload)
					input.ChecksumCRC64NVME = aws.String(sum(payload))
					part, err := f.fixture.s3.UploadPart(t.Context(), input)
					if err != nil || aws.ToString(part.ChecksumCRC64NVME) != sum(payload) {
						t.Fatalf("UploadPart CRC64: %v %v", part, err)
					}
					parts = append(parts, s3types.CompletedPart{PartNumber: input.PartNumber, ETag: part.ETag, ChecksumCRC64NVME: part.ChecksumCRC64NVME})
				}
				f.restart(t)
				listed, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId})
				if err != nil {
					t.Fatal(err)
				}
				if len(listed.Parts) != 2 || explicit && (listed.ChecksumAlgorithm != s3types.ChecksumAlgorithmCrc64nvme || listed.ChecksumType != s3types.ChecksumTypeFullObject) {
					t.Fatalf("ListParts: %v", listed)
				}
				for i, part := range listed.Parts {
					if aws.ToString(part.ChecksumCRC64NVME) != sum(payloads[i]) {
						t.Fatalf("persisted part checksum: %v", part)
					}
				}
				data := append(payloads[0], payloads[1]...)
				full := sum(data)
				input := &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts}, ChecksumCRC64NVME: aws.String(full), ChecksumType: s3types.ChecksumTypeFullObject}
				for _, failure := range []string{"part", "checksum", "type", "size"} {
					bad := *input
					badParts := append([]s3types.CompletedPart(nil), parts...)
					switch failure {
					case "part":
						badParts[0].ChecksumCRC64NVME = aws.String(sum([]byte("wrong")))
						bad.MultipartUpload = &s3types.CompletedMultipartUpload{Parts: badParts}
					case "checksum":
						bad.ChecksumCRC64NVME = aws.String(sum([]byte("wrong")))
					case "type":
						bad.ChecksumType = s3types.ChecksumTypeComposite
					case "size":
						bad.MpuObjectSize = aws.Int64(int64(len(data) + 1))
					}
					_, err := f.fixture.s3.CompleteMultipartUpload(t.Context(), &bad)
					code := "BadDigest"
					switch failure {
					case "part":
						code = "InvalidPart"
					case "type":
						code = "InvalidRequest"
					case "size":
						code = "S3TablesUnsupportedHeader"
					}
					multipartSDKError(t, err, http.StatusBadRequest, code)
					f.object(t, key, old, put.ETag)
					still, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId})
					if err != nil || len(still.Parts) != 2 {
						t.Fatalf("%s consumed upload: %v %v", failure, still, err)
					}
				}
				_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
				multipartSDKError(t, err, http.StatusPreconditionFailed, "PreconditionFailed")
				f.object(t, key, old, put.ETag)
				if _, err = f.fixture.s3.AbortMultipartUpload(t.Context(), &s3.AbortMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId}); err != nil {
					t.Fatal(err)
				}
				// A valid completion publishes a fresh immutable object.
				key += ".new"
				createInput.Key = aws.String(key)
				created, err = f.fixture.s3.CreateMultipartUpload(t.Context(), createInput)
				if err != nil {
					t.Fatal(err)
				}
				parts = parts[:0]
				for i, payload := range payloads {
					part, err := f.fixture.s3.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, PartNumber: aws.Int32(int32(i + 1)), Body: bytes.NewReader(payload), ChecksumAlgorithm: s3types.ChecksumAlgorithmCrc64nvme, ChecksumCRC64NVME: aws.String(sum(payload))})
					if err != nil {
						t.Fatal(err)
					}
					parts = append(parts, s3types.CompletedPart{PartNumber: aws.Int32(int32(i + 1)), ETag: part.ETag, ChecksumCRC64NVME: part.ChecksumCRC64NVME})
				}
				input.Key, input.UploadId = aws.String(key), created.UploadId
				input.MultipartUpload = &s3types.CompletedMultipartUpload{Parts: parts}
				// Per-part checksums are optional for FULL_OBJECT completion.
				parts[1].ChecksumCRC64NVME = nil
				if !explicit {
					// Native clients may omit the full checksum at completion;
					// stored part checksums must still infer FULL_OBJECT CRC64.
					input.ChecksumCRC64NVME = nil
				}
				completed, err := f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
				if err != nil || aws.ToString(completed.ChecksumCRC64NVME) != full || completed.ChecksumType != s3types.ChecksumTypeFullObject {
					t.Fatalf("Complete CRC64: %v %v", completed, err)
				}
				f.restart(t)
				get, head = f.object(t, key, data, completed.ETag)
				if aws.ToString(get.ChecksumCRC64NVME) != full || aws.ToString(head.ChecksumCRC64NVME) != full || get.ChecksumType != s3types.ChecksumTypeFullObject || head.ChecksumType != s3types.ChecksumTypeFullObject {
					t.Fatalf("completed GET/HEAD checksum: %v / %v", get, head)
				}
				_, err = f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId})
				multipartSDKError(t, err, http.StatusNotFound, "NoSuchUpload")
			})
		}
	}
}

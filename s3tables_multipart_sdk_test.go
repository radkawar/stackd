package stackd_test

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3tables"
	tabletypes "github.com/aws/aws-sdk-go-v2/service/s3tables/types"
	"github.com/aws/smithy-go"
)

// These are the supported public object operations, not ordinary S3 bucket
// ownership: https://docs.aws.amazon.com/AmazonS3/latest/developerguide/developing-s3-tables-APIs.html.
// All setup, bytes, IAM changes and teardown go through real signed AWS SDKs.
type multipartSDKFixture struct {
	fixture   *icebergRESTFixture
	reopen    func() *icebergRESTFixture
	owner     *s3tables.Client
	bucketARN *string
	tableARN  *string
	warehouse string
	metadata  string
}

func newMultipartSDKFixture(t *testing.T, backend string) *multipartSDKFixture {
	t.Helper()
	fixture, reopen := newIcebergRESTFixture(t, backend)
	f := &multipartSDKFixture{fixture: fixture, reopen: reopen}
	f.refreshOwner()
	bucket, err := f.owner.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("multipart-tables")})
	if err != nil {
		t.Fatal(err)
	}
	f.bucketARN = bucket.Arn
	if _, err := f.owner.CreateNamespace(t.Context(), &s3tables.CreateNamespaceInput{TableBucketARN: f.bucketARN, Namespace: []string{"analytics"}}); err != nil {
		t.Fatal(err)
	}
	f.createTable(t)
	return f
}

func (f *multipartSDKFixture) refreshOwner() {
	f.owner = s3tables.New(s3tables.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(f.fixture.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: f.fixture.server.Client(), RetryMaxAttempts: 1})
}

func (f *multipartSDKFixture) restart(t *testing.T) {
	t.Helper()
	f.fixture = f.reopen()
	f.refreshOwner()
}

func (f *multipartSDKFixture) createTable(t *testing.T) {
	t.Helper()
	created, err := f.owner.CreateTable(t.Context(), &s3tables.CreateTableInput{
		TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: aws.String("events"), Format: tabletypes.OpenTableFormatIceberg,
		Metadata: &tabletypes.TableMetadataMemberIceberg{Value: tabletypes.IcebergMetadata{Schema: &tabletypes.IcebergSchema{Fields: []tabletypes.SchemaField{{Name: aws.String("id"), Type: aws.String("long")}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.tableARN = created.TableARN
	location, err := f.owner.GetTableMetadataLocation(t.Context(), &s3tables.GetTableMetadataLocationInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: aws.String("events")})
	if err != nil {
		t.Fatal(err)
	}
	warehouse, err := url.Parse(aws.ToString(location.WarehouseLocation))
	if err != nil || warehouse.Scheme != "s3" || !strings.HasSuffix(warehouse.Host, "--table-s3") || warehouse.Path != "" {
		t.Fatalf("invalid private warehouse %q: %v", aws.ToString(location.WarehouseLocation), err)
	}
	f.warehouse = warehouse.Host
	f.metadata = strings.TrimPrefix(aws.ToString(location.MetadataLocation), "s3://"+f.warehouse+"/")
}

func (f *multipartSDKFixture) deleteTable(t *testing.T) {
	t.Helper()
	table, err := f.owner.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.DeleteTable(t.Context(), &s3tables.DeleteTableInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: aws.String("events"), VersionToken: table.VersionToken}); err != nil {
		t.Fatal(err)
	}
}

func (f *multipartSDKFixture) begin(t *testing.T, key string, options ...func(*s3.CreateMultipartUploadInput)) *string {
	t.Helper()
	input := &s3.CreateMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key)}
	for _, option := range options {
		option(input)
	}
	out, err := f.fixture.s3.CreateMultipartUpload(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(out.UploadId) == "" {
		t.Fatal("CreateMultipartUpload returned an empty upload ID")
	}
	return out.UploadId
}

func (f *multipartSDKFixture) part(t *testing.T, key string, id *string, number int32, data []byte) s3types.CompletedPart {
	t.Helper()
	out, err := f.fixture.s3.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, PartNumber: aws.Int32(number), Body: bytes.NewReader(data)})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(out.ETag) == "" {
		t.Fatal("UploadPart returned an empty ETag")
	}
	return s3types.CompletedPart{PartNumber: aws.Int32(number), ETag: out.ETag, ChecksumCRC32: out.ChecksumCRC32, ChecksumCRC32C: out.ChecksumCRC32C, ChecksumSHA1: out.ChecksumSHA1, ChecksumSHA256: out.ChecksumSHA256}
}

func (f *multipartSDKFixture) complete(t *testing.T, key string, id *string, parts ...s3types.CompletedPart) *s3.CompleteMultipartUploadOutput {
	t.Helper()
	out, err := f.fixture.s3.CompleteMultipartUpload(t.Context(), &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *multipartSDKFixture) object(t *testing.T, key string, expected []byte, etag *string) (*s3.GetObjectOutput, *s3.HeadObjectOutput) {
	t.Helper()
	out, err := f.fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), ChecksumMode: s3types.ChecksumModeEnabled})
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(out.Body)
	closeErr := out.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("reading object: %v; closing: %v", readErr, closeErr)
	}
	if !bytes.Equal(body, expected) {
		t.Fatalf("object bytes differ: got %d bytes, want %d", len(body), len(expected))
	}
	head, err := f.fixture.s3.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), ChecksumMode: s3types.ChecksumModeEnabled})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToInt64(out.ContentLength) != int64(len(expected)) || aws.ToInt64(head.ContentLength) != int64(len(expected)) {
		t.Fatalf("GET/HEAD sizes differ from completed bytes: %v / %v", out.ContentLength, head.ContentLength)
	}
	if aws.ToString(out.ETag) != aws.ToString(etag) || aws.ToString(head.ETag) != aws.ToString(etag) {
		t.Fatalf("completion/GET/HEAD ETags differ: %q / %q / %q", aws.ToString(etag), aws.ToString(out.ETag), aws.ToString(head.ETag))
	}
	return out, head
}

func multipartSDKError(t *testing.T, err error, status int, codes ...string) {
	t.Helper()
	var api smithy.APIError
	var response interface{ HTTPStatusCode() int }
	if err == nil || !errors.As(err, &api) || !errors.As(err, &response) {
		t.Fatalf("expected modeled HTTP %d error, got %v", status, err)
	}
	if response.HTTPStatusCode() != status || api.ErrorCode() == "" {
		t.Fatalf("expected HTTP %d, got %d %s: %v", status, response.HTTPStatusCode(), api.ErrorCode(), err)
	}
	if len(codes) != 0 {
		for _, code := range codes {
			if api.ErrorCode() == code {
				return
			}
		}
		t.Fatalf("expected one of %v, got %s", codes, api.ErrorCode())
	}
}

func multipartSDKETag(parts ...[]byte) string {
	var hashes []byte
	for _, part := range parts {
		sum := md5.Sum(part)
		hashes = append(hashes, sum[:]...)
	}
	sum := md5.Sum(hashes)
	return fmt.Sprintf("\"%s-%d\"", hex.EncodeToString(sum[:]), len(parts))
}

func TestS3TablesMultipartSDKNativeAppendAndRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newMultipartSDKFixture(t, backend)
			expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
			attributes := func(in *s3.CreateMultipartUploadInput) {
				in.ContentType = aws.String("application/vnd.apache.parquet")
				in.CacheControl = aws.String("max-age=3600")
				in.ContentDisposition = aws.String("attachment; filename=part.parquet")
				in.ContentEncoding = aws.String("identity")
				in.ContentLanguage = aws.String("en")
				in.Expires = &expires
			}
			assertAttributes := func(t *testing.T, get *s3.GetObjectOutput, head *s3.HeadObjectOutput) {
				t.Helper()
				for name, values := range map[string][3]string{
					"ContentType":        {aws.ToString(get.ContentType), aws.ToString(head.ContentType), "application/vnd.apache.parquet"},
					"CacheControl":       {aws.ToString(get.CacheControl), aws.ToString(head.CacheControl), "max-age=3600"},
					"ContentDisposition": {aws.ToString(get.ContentDisposition), aws.ToString(head.ContentDisposition), "attachment; filename=part.parquet"},
					"ContentEncoding":    {aws.ToString(get.ContentEncoding), aws.ToString(head.ContentEncoding), "identity"},
					"ContentLanguage":    {aws.ToString(get.ContentLanguage), aws.ToString(head.ContentLanguage), "en"},
					"Expires":            {aws.ToString(get.ExpiresString), aws.ToString(head.ExpiresString), expires.Format(http.TimeFormat)},
				} {
					if values[0] != values[2] || values[1] != values[2] {
						t.Errorf("%s not persisted through GET/HEAD: %q / %q, want %q", name, values[0], values[1], values[2])
					}
				}
			}
			t.Run("tiny-final-part-native-append", func(t *testing.T) {
				// PyArrow's native append initiates multipart even for a tiny final file.
				key, data := "data/tiny.parquet", []byte("PAR1tiny-native-appendPAR1")
				id := f.begin(t, key, attributes)
				part := f.part(t, key, id, 1, data)
				out := f.complete(t, key, id, part)
				if aws.ToString(out.ETag) != multipartSDKETag(data) {
					t.Fatalf("wrong multipart ETag: %q", aws.ToString(out.ETag))
				}
				get, head := f.object(t, key, data, out.ETag)
				assertAttributes(t, get, head)
				_, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id})
				multipartSDKError(t, err, http.StatusNotFound, "NoSuchUpload")
			})
			t.Run("ordered-by-number-not-upload-time", func(t *testing.T) {
				key := "data/ordered.parquet"
				first, last := bytes.Repeat([]byte{0x51}, 5*1024*1024), []byte("small-final-part")
				id := f.begin(t, key)
				part2 := f.part(t, key, id, 2, last)
				part1 := f.part(t, key, id, 1, first)
				listed, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id})
				if err != nil {
					t.Fatal(err)
				}
				if len(listed.Parts) != 2 || aws.ToInt32(listed.Parts[0].PartNumber) != 1 || aws.ToInt32(listed.Parts[1].PartNumber) != 2 || aws.ToInt64(listed.Parts[0].Size) != int64(len(first)) || aws.ToInt64(listed.Parts[1].Size) != int64(len(last)) || aws.ToString(listed.Parts[0].ETag) != aws.ToString(part1.ETag) || aws.ToString(listed.Parts[1].ETag) != aws.ToString(part2.ETag) {
					t.Fatalf("ListParts lost ordered part identity: %+v", listed.Parts)
				}
				out := f.complete(t, key, id, part1, part2)
				if aws.ToString(out.ETag) != multipartSDKETag(first, last) {
					t.Fatalf("wrong multipart ETag: %q", aws.ToString(out.ETag))
				}
				f.object(t, key, append(first, last...), out.ETag)
			})
			t.Run("partial-upload-and-attributes-survive-reopen", func(t *testing.T) {
				key := "data/restarted.parquet"
				first, last := bytes.Repeat([]byte{0x52}, 5*1024*1024), []byte("after-restart")
				id := f.begin(t, key, attributes)
				part1 := f.part(t, key, id, 1, first)
				f.restart(t)
				listed, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id})
				if err != nil || listed == nil || len(listed.Parts) != 1 {
					t.Fatalf("partial upload lost on reopen: %+v %v", listed, err)
				}
				if aws.ToString(listed.Parts[0].ETag) != aws.ToString(part1.ETag) || aws.ToInt64(listed.Parts[0].Size) != int64(len(first)) {
					t.Fatalf("reopened part changed: %+v", listed.Parts[0])
				}
				part2 := f.part(t, key, id, 2, last)
				out := f.complete(t, key, id, part1, part2)
				f.restart(t)
				get, head := f.object(t, key, append(first, last...), out.ETag)
				assertAttributes(t, get, head)
			})
			// Only the table service can clean up a managed warehouse.
			f.deleteTable(t)
			out, err := f.fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String("data/tiny.parquet")})
			if err == nil {
				out.Body.Close()
				t.Fatal("DeleteTable left completed warehouse data readable")
			}
			multipartSDKError(t, err, http.StatusNotFound)
		})
	}
}

func TestS3TablesMultipartSDKValidationAndConditionalCompletion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newMultipartSDKFixture(t, backend)
			first, last := bytes.Repeat([]byte{0x61}, 5*1024*1024), []byte("final")
			t.Run("invalid-part-does-not-consume-upload", func(t *testing.T) {
				key := "data/etag-validation"
				id := f.begin(t, key)
				part := f.part(t, key, id, 1, last)
				bad := part
				bad.ETag = aws.String("\"00000000000000000000000000000000\"")
				_, err := f.fixture.s3.CompleteMultipartUpload(t.Context(), &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{bad}}})
				multipartSDKError(t, err, http.StatusBadRequest, "InvalidPart")
				_, err = f.fixture.s3.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key)})
				multipartSDKError(t, err, http.StatusNotFound)
				out := f.complete(t, key, id, part)
				f.object(t, key, last, out.ETag)
			})
			t.Run("out-of-order-parts", func(t *testing.T) {
				key := "data/order-validation"
				id := f.begin(t, key)
				part1, part2 := f.part(t, key, id, 1, first), f.part(t, key, id, 2, last)
				_, err := f.fixture.s3.CompleteMultipartUpload(t.Context(), &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{part2, part1}}})
				multipartSDKError(t, err, http.StatusBadRequest, "InvalidPartOrder")
				out := f.complete(t, key, id, part1, part2)
				f.object(t, key, append(first[:len(first):len(first)], last...), out.ETag)
			})
			t.Run("minimum-size-only-for-nonfinal-parts", func(t *testing.T) {
				key := "data/size-validation"
				id := f.begin(t, key)
				part1, part2 := f.part(t, key, id, 1, []byte("too small")), f.part(t, key, id, 2, last)
				_, err := f.fixture.s3.CompleteMultipartUpload(t.Context(), &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{part1, part2}}})
				multipartSDKError(t, err, http.StatusBadRequest, "EntityTooSmall")
				part1 = f.part(t, key, id, 1, first)
				out := f.complete(t, key, id, part1, part2)
				f.object(t, key, append(first[:len(first):len(first)], last...), out.ETag)
			})
			t.Run("write-once-and-unsupported-if-match", func(t *testing.T) {
				key := "data/conditional"
				original, err := f.fixture.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), Body: strings.NewReader("old")})
				if err != nil {
					t.Fatal(err)
				}
				for _, body := range []string{"old", "different"} {
					_, err = f.fixture.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), Body: strings.NewReader(body)})
					multipartSDKError(t, err, http.StatusPreconditionFailed, "PreconditionFailed")
					f.object(t, key, []byte("old"), original.ETag)
				}
				id := f.begin(t, key)
				part := f.part(t, key, id, 1, last)
				input := &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, IfMatch: original.ETag, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{part}}}
				_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
				multipartSDKError(t, err, http.StatusNotImplemented, "NotImplemented")
				input.IfMatch = nil
				_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
				multipartSDKError(t, err, http.StatusPreconditionFailed, "PreconditionFailed")
				f.object(t, key, []byte("old"), original.ETag)
				retained, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id})
				if err != nil || len(retained.Parts) != 1 || aws.ToString(retained.Parts[0].ETag) != aws.ToString(part.ETag) {
					t.Fatalf("rejected completion changed staged parts: %v %v", retained, err)
				}
			})
			t.Run("if-none-match-and-abort-fence", func(t *testing.T) {
				key := "data/no-overwrite"
				current, err := f.fixture.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), Body: strings.NewReader("retained")})
				if err != nil {
					t.Fatal(err)
				}
				id := f.begin(t, key)
				part := f.part(t, key, id, 1, last)
				input := &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, IfNoneMatch: aws.String("*"), MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{part}}}
				_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
				multipartSDKError(t, err, http.StatusPreconditionFailed, "PreconditionFailed")
				f.object(t, key, []byte("retained"), current.ETag)
				if _, err := f.fixture.s3.AbortMultipartUpload(t.Context(), &s3.AbortMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id}); err != nil {
					t.Fatal(err)
				}
				f.restart(t)
				input.IfNoneMatch = nil
				_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
				multipartSDKError(t, err, http.StatusNotFound, "NoSuchUpload")
				_, err = f.fixture.s3.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, PartNumber: aws.Int32(1), Body: strings.NewReader("late")})
				multipartSDKError(t, err, http.StatusNotFound, "NoSuchUpload")
				_, err = f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id})
				multipartSDKError(t, err, http.StatusNotFound, "NoSuchUpload")
				key += ".new"
				fresh := f.begin(t, key)
				if aws.ToString(fresh) == aws.ToString(id) {
					t.Fatal("aborted upload ID was reused")
				}
				out := f.complete(t, key, fresh, f.part(t, key, fresh, 1, last))
				f.object(t, key, last, out.ETag)
			})
		})
	}
}

func multipartSDKChecksum(algorithm s3types.ChecksumAlgorithm, data []byte) string {
	if algorithm == s3types.ChecksumAlgorithmSha256 {
		sum := sha256.Sum256(data)
		return base64.StdEncoding.EncodeToString(sum[:])
	}
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE(data))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func TestS3TablesMultipartSDKChecksums(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newMultipartSDKFixture(t, backend)
			for _, algorithm := range []s3types.ChecksumAlgorithm{s3types.ChecksumAlgorithmCrc32, s3types.ChecksumAlgorithmSha256} {
				t.Run(string(algorithm), func(t *testing.T) {
					key := "data/checksum-" + string(algorithm)
					id := f.begin(t, key, func(in *s3.CreateMultipartUploadInput) { in.ChecksumAlgorithm = algorithm })
					data := [][]byte{bytes.Repeat([]byte("c"), 5*1024*1024), []byte("checksum-final")}
					var parts []s3types.CompletedPart
					var binaryChecksums []byte
					for index, body := range data {
						checksum := multipartSDKChecksum(algorithm, body)
						input := &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, PartNumber: aws.Int32(int32(index + 1)), Body: bytes.NewReader(body)}
						if algorithm == s3types.ChecksumAlgorithmSha256 {
							input.ChecksumSHA256 = aws.String(multipartSDKChecksum(algorithm, []byte("wrong")))
						} else {
							input.ChecksumCRC32 = aws.String(multipartSDKChecksum(algorithm, []byte("wrong")))
						}
						_, err := f.fixture.s3.UploadPart(t.Context(), input)
						multipartSDKError(t, err, http.StatusBadRequest, "BadDigest")
						input.Body = bytes.NewReader(body)
						if algorithm == s3types.ChecksumAlgorithmSha256 {
							input.ChecksumSHA256 = aws.String(checksum)
						} else {
							input.ChecksumCRC32 = aws.String(checksum)
						}
						out, err := f.fixture.s3.UploadPart(t.Context(), input)
						if err != nil {
							t.Fatal(err)
						}
						actual := aws.ToString(out.ChecksumCRC32)
						if algorithm == s3types.ChecksumAlgorithmSha256 {
							actual = aws.ToString(out.ChecksumSHA256)
						}
						if actual != checksum {
							t.Fatalf("UploadPart did not return its validated %s: %q, want %q", algorithm, actual, checksum)
						}
						parts = append(parts, s3types.CompletedPart{PartNumber: input.PartNumber, ETag: out.ETag, ChecksumCRC32: out.ChecksumCRC32, ChecksumSHA256: out.ChecksumSHA256})
						decoded, err := base64.StdEncoding.DecodeString(checksum)
						if err != nil {
							t.Fatal(err)
						}
						binaryChecksums = append(binaryChecksums, decoded...)
					}
					f.restart(t)
					listed, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id})
					if err != nil || listed == nil || len(listed.Parts) != 2 {
						t.Fatalf("checksummed parts lost on reopen: %+v %v", listed, err)
					}
					for index, part := range listed.Parts {
						actual := aws.ToString(part.ChecksumCRC32)
						if algorithm == s3types.ChecksumAlgorithmSha256 {
							actual = aws.ToString(part.ChecksumSHA256)
						}
						if actual != multipartSDKChecksum(algorithm, data[index]) {
							t.Fatalf("ListParts lost %s for part %d", algorithm, index+1)
						}
					}
					composite := multipartSDKChecksum(algorithm, binaryChecksums) + "-2"
					input := &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: id, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts}}
					badParts := append([]s3types.CompletedPart(nil), parts...)
					if algorithm == s3types.ChecksumAlgorithmSha256 {
						badParts[0].ChecksumSHA256 = aws.String(multipartSDKChecksum(algorithm, []byte("wrong-part")))
					} else {
						badParts[0].ChecksumCRC32 = aws.String(multipartSDKChecksum(algorithm, []byte("wrong-part")))
					}
					input.MultipartUpload = &s3types.CompletedMultipartUpload{Parts: badParts}
					_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
					multipartSDKError(t, err, http.StatusBadRequest, "InvalidPart", "BadDigest")
					input.MultipartUpload = &s3types.CompletedMultipartUpload{Parts: parts}
					bad := multipartSDKChecksum(algorithm, []byte("wrong-composite")) + "-2"
					if algorithm == s3types.ChecksumAlgorithmSha256 {
						input.ChecksumSHA256 = &bad
					} else {
						input.ChecksumCRC32 = &bad
					}
					_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
					multipartSDKError(t, err, http.StatusBadRequest, "BadDigest")
					if algorithm == s3types.ChecksumAlgorithmSha256 {
						input.ChecksumSHA256 = &composite
					} else {
						input.ChecksumCRC32 = &composite
					}
					out, err := f.fixture.s3.CompleteMultipartUpload(t.Context(), input)
					if err != nil {
						t.Fatal(err)
					}
					f.restart(t)
					get, head := f.object(t, key, append(data[0], data[1]...), out.ETag)
					checksums := []string{aws.ToString(out.ChecksumCRC32), aws.ToString(get.ChecksumCRC32), aws.ToString(head.ChecksumCRC32)}
					if algorithm == s3types.ChecksumAlgorithmSha256 {
						checksums = []string{aws.ToString(out.ChecksumSHA256), aws.ToString(get.ChecksumSHA256), aws.ToString(head.ChecksumSHA256)}
					}
					for _, checksum := range checksums {
						if checksum != composite {
							t.Fatalf("completion/GET/HEAD lost composite %s: %q, want %q", algorithm, checksum, composite)
						}
					}
				})
			}
		})
	}
}

func TestS3TablesMultipartSDKCurrentIAMAndTableIdentity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newMultipartSDKFixture(t, backend)
			const user = "multipart-writer"
			if _, err := f.fixture.iam.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)}); err != nil {
				t.Fatal(err)
			}
			access, err := f.fixture.iam.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String(user)})
			if err != nil {
				t.Fatal(err)
			}
			writer := s3.New(s3.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(f.fixture.server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(aws.ToString(access.AccessKey.AccessKeyId), aws.ToString(access.AccessKey.SecretAccessKey), ""), HTTPClient: f.fixture.server.Client(), RetryMaxAttempts: 1})
			setPolicy := func(actions ...string) {
				t.Helper()
				document, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": actions, "Resource": aws.ToString(f.tableARN)}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.fixture.iam.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String("current-table-data"), PolicyDocument: aws.String(string(document))}); err != nil {
					t.Fatal(err)
				}
			}
			setPolicy("s3tables:GetTableData", "s3tables:PutTableData")
			key := "data/iam-fenced"
			created, err := writer.CreateMultipartUpload(t.Context(), &s3.CreateMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key)})
			if err != nil {
				t.Fatal(err)
			}
			part, err := writer.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("authorized")})
			if err != nil {
				t.Fatal(err)
			}
			input := &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{{PartNumber: aws.Int32(1), ETag: part.ETag, ChecksumCRC32: part.ChecksumCRC32}}}}
			setPolicy("s3tables:GetTableData")
			_, err = writer.CompleteMultipartUpload(t.Context(), input)
			multipartSDKError(t, err, http.StatusForbidden, "AccessDenied")
			_, err = writer.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("revoked")})
			multipartSDKError(t, err, http.StatusForbidden, "AccessDenied")
			_, err = writer.AbortMultipartUpload(t.Context(), &s3.AbortMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId})
			multipartSDKError(t, err, http.StatusForbidden, "AccessDenied")
			// ListParts is a read operation: PutTableData revocation must not deny it.
			listed, err := writer.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId})
			if err != nil || listed == nil || len(listed.Parts) != 1 || aws.ToString(listed.Parts[0].ETag) != aws.ToString(part.ETag) {
				t.Fatalf("denied mutation changed readable upload: %+v %v", listed, err)
			}
			setPolicy("s3tables:PutTableData")
			_, err = writer.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId})
			multipartSDKError(t, err, http.StatusForbidden, "AccessDenied")
			setPolicy("s3tables:GetTableData", "s3tables:PutTableData")
			completed, err := writer.CompleteMultipartUpload(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			f.object(t, key, []byte("authorized"), completed.ETag)
			// Include an empty upload: cleanup cannot depend on completed object listing.
			pendingKey := "data/pending-at-delete"
			pending := f.begin(t, pendingKey)
			pendingPart := f.part(t, pendingKey, pending, 1, []byte("pending"))
			empty := f.begin(t, "data/empty-at-delete")
			oldWarehouse, oldTable := f.warehouse, aws.ToString(f.tableARN)
			f.deleteTable(t)
			f.createTable(t)
			if f.warehouse == oldWarehouse || aws.ToString(f.tableARN) == oldTable {
				t.Fatal("logical table recreation reused immutable table or warehouse identity")
			}
			f.restart(t)
			for _, upload := range []struct {
				key string
				id  *string
			}{{pendingKey, pending}, {"data/empty-at-delete", empty}} {
				_, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(oldWarehouse), Key: aws.String(upload.key), UploadId: upload.id})
				multipartSDKError(t, err, http.StatusNotFound)
				_, err = f.fixture.s3.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: aws.String(oldWarehouse), Key: aws.String(upload.key), UploadId: upload.id, PartNumber: aws.Int32(1), Body: strings.NewReader("late")})
				multipartSDKError(t, err, http.StatusNotFound)
				_, err = f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(upload.key), UploadId: upload.id})
				multipartSDKError(t, err, http.StatusNotFound, "NoSuchUpload")
				for _, warehouse := range []string{oldWarehouse, f.warehouse} {
					_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), &s3.CompleteMultipartUploadInput{Bucket: aws.String(warehouse), Key: aws.String(upload.key), UploadId: upload.id, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{pendingPart}}})
					multipartSDKError(t, err, http.StatusNotFound)
				}
			}
			old, err := f.fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(oldWarehouse), Key: aws.String(key)})
			if err == nil {
				old.Body.Close()
				t.Fatal("deleted warehouse remained readable after recreation and reopen")
			}
			multipartSDKError(t, err, http.StatusNotFound)
			fresh := f.begin(t, key)
			out := f.complete(t, key, fresh, f.part(t, key, fresh, 1, []byte("new-table")))
			f.object(t, key, []byte("new-table"), out.ETag)
			f.deleteTable(t)
		})
	}
}

func TestS3TablesMultipartSDKMetadataProtectionAndUnsupportedOperations(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newMultipartSDKFixture(t, backend)
			before, err := f.owner.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN})
			if err != nil {
				t.Fatal(err)
			}
			original, err := f.fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(f.metadata)})
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(original.Body)
			original.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			var accepted struct {
				Schemas []struct {
					Fields []struct {
						Name string `json:"name"`
						Type string `json:"type"`
					} `json:"fields"`
				} `json:"schemas"`
			}
			if err := json.Unmarshal(data, &accepted); err != nil {
				t.Fatal(err)
			}
			if len(accepted.Schemas) != 1 || len(accepted.Schemas[0].Fields) != 1 || accepted.Schemas[0].Fields[0].Name != "id" || accepted.Schemas[0].Fields[0].Type != "long" {
				t.Fatalf("typed CreateTable did not materialize its accepted schema: %s", data)
			}
			created, err := f.fixture.s3.CreateMultipartUpload(t.Context(), &s3.CreateMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(f.metadata)})
			if err != nil {
				t.Fatal(err)
			}
			part := f.part(t, f.metadata, created.UploadId, 1, []byte("different immutable metadata"))
			_, err = f.fixture.s3.CompleteMultipartUpload(t.Context(), &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(f.metadata), UploadId: created.UploadId, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{part}}})
			multipartSDKError(t, err, http.StatusPreconditionFailed, "PreconditionFailed")
			if _, err := f.fixture.s3.AbortMultipartUpload(t.Context(), &s3.AbortMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(f.metadata), UploadId: created.UploadId}); err != nil {
				t.Fatal(err)
			}
			// Byte-for-byte preservation includes the accepted Iceberg schema above.
			f.object(t, f.metadata, data, original.ETag)
			after, err := f.owner.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(before.MetadataLocation) != aws.ToString(after.MetadataLocation) || aws.ToString(before.VersionToken) != aws.ToString(after.VersionToken) {
				t.Fatal("rejected metadata overwrite changed the accepted pointer/version")
			}
			key := "data/unsupported-source"
			id := f.begin(t, key)
			out := f.complete(t, key, id, f.part(t, key, id, 1, []byte("retained-source")))
			copyKey := "data/unsupported-copy"
			copyUpload := f.begin(t, copyKey)
			t.Run("CopyObject", func(t *testing.T) {
				_, err := f.fixture.s3.CopyObject(t.Context(), &s3.CopyObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(copyKey), CopySource: aws.String(f.warehouse + "/" + key)})
				multipartSDKError(t, err, http.StatusNotImplemented)
			})
			t.Run("UploadPartCopy", func(t *testing.T) {
				_, err := f.fixture.s3.UploadPartCopy(t.Context(), &s3.UploadPartCopyInput{Bucket: aws.String(f.warehouse), Key: aws.String(copyKey), UploadId: copyUpload, PartNumber: aws.Int32(1), CopySource: aws.String(f.warehouse + "/" + key)})
				multipartSDKError(t, err, http.StatusNotImplemented)
			})
			t.Run("ListObjects", func(t *testing.T) {
				_, err := f.fixture.s3.ListObjects(t.Context(), &s3.ListObjectsInput{Bucket: aws.String(f.warehouse)})
				multipartSDKError(t, err, http.StatusNotImplemented)
			})
			t.Run("ListObjectsV2", func(t *testing.T) {
				_, err := f.fixture.s3.ListObjectsV2(t.Context(), &s3.ListObjectsV2Input{Bucket: aws.String(f.warehouse)})
				multipartSDKError(t, err, http.StatusNotImplemented)
			})
			t.Run("DeleteObject", func(t *testing.T) {
				_, err := f.fixture.s3.DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key)})
				multipartSDKError(t, err, http.StatusNotImplemented)
			})
			f.object(t, key, []byte("retained-source"), out.ETag)
			_, err = f.fixture.s3.HeadObject(t.Context(), &s3.HeadObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(copyKey)})
			multipartSDKError(t, err, http.StatusNotFound)
			listed, err := f.fixture.s3.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(copyKey), UploadId: copyUpload})
			if err != nil || listed == nil || len(listed.Parts) != 0 {
				t.Fatalf("unsupported copy mutated multipart state: %+v %v", listed, err)
			}
			f.deleteTable(t)
			deleted, err := f.fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key)})
			if err == nil {
				deleted.Body.Close()
				t.Fatal("service-owned deletion did not clean up protected warehouse bytes")
			}
			multipartSDKError(t, err, http.StatusNotFound)
		})
	}
}

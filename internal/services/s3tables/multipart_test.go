package s3tables_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	owner "stackd/internal/services/s3tables"
)

func multipartCode(t *testing.T, err error, want string) {
	t.Helper()
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}
func multipartExpectedETag(data ...[]byte) string {
	var sums []byte
	for _, part := range data {
		sum := md5.Sum(part)
		sums = append(sums, sum[:]...)
	}
	sum := md5.Sum(sums)
	return "\"" + hex.EncodeToString(sum[:]) + "-" + strconv.Itoa(len(data)) + "\""
}
func TestMultipartTinyPartPersistsAttributesAndMultipartETag(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "multipart")
	location := string(*table.WarehouseLocation) + "/data/tiny.parquet"
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	attrs := owner.ObjectAttributes{ContentType: "application/vnd.apache.parquet", CacheControl: "max-age=300", ContentDisposition: "attachment", ContentEncoding: "gzip", ContentLanguage: "en", Expires: &expires, ChecksumAlgorithm: "SHA256"}
	id, err := f.service.CreateMultipart(f.ctx, location, attrs)
	if err != nil {
		t.Fatal(err)
	}
	originalExpires := expires
	expires = expires.Add(time.Hour)
	data := []byte("a tiny native writer output")
	sum := sha256.Sum256(data)
	checksums := owner.ObjectChecksums{SHA256: base64.StdEncoding.EncodeToString(sum[:])}
	if _, err = f.service.UploadMultipartPart(f.ctx, location, id, 1, data, owner.ObjectChecksums{}); err == nil {
		t.Fatal("missing initiated checksum accepted")
	}
	part, err := f.service.UploadMultipartPart(f.ctx, location, id, 1, data, checksums)
	if err != nil {
		t.Fatal(err)
	}
	// Reconstructing the owner must not lose an upload, parts, or attributes.
	f.service = owner.New(owner.Config{Repository: f.repository, Objects: f.objects})
	upload, parts, err := f.service.ListMultipartParts(f.ctx, location, id)
	if err != nil || len(parts) != 1 || parts[0].ETag != part.ETag || upload.Attributes.Expires == nil || !upload.Attributes.Expires.Equal(originalExpires) {
		t.Fatalf("upload state lost: %#v %#v %v", upload, parts, err)
	}
	composite := sha256.Sum256(sum[:])
	wantChecksum := base64.StdEncoding.EncodeToString(composite[:]) + "-1"
	completed, err := f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: part.ETag, Checksums: checksums}}, owner.ObjectConditions{IfNoneMatch: "*"}, owner.ObjectChecksums{SHA256: wantChecksum})
	if err != nil {
		t.Fatal(err)
	}
	actual, info, err := f.service.ReadObject(f.ctx, location)
	if err != nil || !bytes.Equal(actual, data) || info.ETag != completed.ETag || info.ETag != multipartExpectedETag(data) || info.Attributes.Checksums.SHA256 != wantChecksum || info.Attributes.ContentType != attrs.ContentType || info.Attributes.CacheControl != attrs.CacheControl || info.Attributes.Expires == nil || !info.Attributes.Expires.Equal(originalExpires) {
		t.Fatalf("completed object mismatch: %#v %q %v", info, actual, err)
	}
	_, _, err = f.service.ListMultipartParts(f.ctx, location, id)
	multipartCode(t, err, "NoSuchUpload")
	_, err = f.service.UploadMultipartPart(f.ctx, location, id, 1, data, checksums)
	multipartCode(t, err, "NoSuchUpload")
}
func TestMultipartValidationConditionsReplacementAndAbort(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "validation")
	location := string(*table.WarehouseLocation) + "/data/object"
	old, err := f.service.WriteObject(f.ctx, location, []byte("old"), owner.ObjectAttributes{CacheControl: "immutable"}, owner.ObjectConditions{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{})
	if err != nil {
		t.Fatal(err)
	}
	one, err := f.service.UploadMultipartPart(f.ctx, location, id, 1, []byte("tiny"), owner.ObjectChecksums{})
	if err != nil {
		t.Fatal(err)
	}
	two, err := f.service.UploadMultipartPart(f.ctx, location, id, 2, []byte("last"), owner.ObjectChecksums{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 2, ETag: two.ETag}, {Number: 1, ETag: one.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	multipartCode(t, err, "InvalidPartOrder")
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: one.ETag}, {Number: 2, ETag: two.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	multipartCode(t, err, "EntityTooSmall")
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: "\"wrong\""}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	multipartCode(t, err, "InvalidPart")
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: one.ETag}}, owner.ObjectConditions{IfNoneMatch: "*"}, owner.ObjectChecksums{})
	multipartCode(t, err, "PreconditionFailed")
	data, info, err := f.service.ReadObject(f.ctx, location)
	if err != nil || string(data) != "old" || info.ETag != old.ETag || info.Attributes.CacheControl != "immutable" {
		t.Fatalf("failed completion changed old object: %#v %q %v", info, data, err)
	}
	large := bytes.Repeat([]byte{'x'}, int(owner.MultipartMinimumPartSize))
	replacement, err := f.service.UploadMultipartPart(f.ctx, location, id, 1, large, owner.ObjectChecksums{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: one.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	multipartCode(t, err, "InvalidPart")
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: replacement.ETag}, {Number: 2, ETag: two.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	multipartCode(t, err, "PreconditionFailed")
	_, retained, err := f.service.ListMultipartParts(f.ctx, location, id)
	if err != nil || len(retained) != 2 || retained[0].ETag != replacement.ETag {
		t.Fatalf("write-once rejection changed staged parts: %#v %v", retained, err)
	}
	abortID, err := f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.UploadMultipartPart(f.ctx, location, abortID, 10000, nil, owner.ObjectChecksums{}); err != nil {
		t.Fatal(err)
	}
	if err = f.service.AbortMultipart(f.ctx, location, abortID); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.UploadMultipartPart(f.ctx, location, abortID, 10000, nil, owner.ObjectChecksums{})
	multipartCode(t, err, "NoSuchUpload")
	_, err = f.service.UploadMultipartPart(f.ctx, location, "absent", 10001, nil, owner.ObjectChecksums{})
	multipartCode(t, err, "InvalidArgument")
	_, err = f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{ChecksumAlgorithm: "SHA512"})
	multipartCode(t, err, "NotImplemented")
}

func TestMultipartCRC64ExplicitAndNoInitInference(t *testing.T) {
	for _, algorithm := range []string{"", "CRC64NVME"} {
		t.Run("init="+algorithm, func(t *testing.T) {
			f := newFixture(t, nil)
			table := f.create(t, "crc64")
			location := string(*table.WarehouseLocation) + "/data/native.parquet"
			id, err := f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{ChecksumAlgorithm: algorithm})
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("123456789")
			expected := owner.ObjectChecksums{CRC64NVME: "rosUhgp5mIg="}
			transport := expected
			if algorithm != "" {
				// Explicit FULL_OBJECT CRC64 also works without a transport checksum.
				transport = owner.ObjectChecksums{}
			}
			part, err := f.service.UploadMultipartPart(f.ctx, location, id, 1, data, transport)
			if err != nil || part.Checksums != expected || part.Size != int64(len(data)) {
				t.Fatalf("CRC64 part = %#v, %v", part, err)
			}
			_, err = f.service.UploadMultipartPart(f.ctx, location, id, 1, data, owner.ObjectChecksums{CRC64NVME: "AAAAAAAAAAA="})
			multipartCode(t, err, "BadDigest")
			_, parts, err := f.service.ListMultipartParts(f.ctx, location, id)
			if err != nil || len(parts) != 1 || parts[0] != part {
				t.Fatalf("bad replacement changed retained part: %#v, %v", parts, err)
			}
			completed, err := f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: part.ETag}}, owner.ObjectConditions{ChecksumType: "FULL_OBJECT"}, owner.ObjectChecksums{})
			if err != nil || completed.Attributes.ChecksumAlgorithm != "CRC64NVME" || completed.Attributes.Checksums != expected || completed.ETag != "\"5927c5d64d94a5786f90003aa26d0159-1\"" {
				t.Fatalf("CRC64 native completion = %#v, %v", completed, err)
			}
			actual, info, err := f.service.ReadObject(f.ctx, location)
			if err != nil || !bytes.Equal(actual, data) || info.Attributes.Checksums != expected {
				t.Fatalf("CRC64 native read = %q, %#v, %v", actual, info, err)
			}
		})
	}
}

type multipartRevokingAuthorizer struct {
	calls, denyAt int
	principal     string
}

func (a *multipartRevokingAuthorizer) Authorize(ctx context.Context, r authorization.Request) *awswire.Error {
	if r.Action != "s3tables:PutTableData" {
		return nil
	}
	a.calls++
	if awsctx.FromContext(ctx).PrincipalID != a.principal {
		return &awswire.Error{Code: "AccessDenied", Message: "caller identity lost", StatusCode: 403}
	}
	if a.denyAt != 0 && a.calls >= a.denyAt {
		return &awswire.Error{Code: "AccessDenied", Message: "revoked", StatusCode: 403}
	}
	return nil
}
func TestMultipartPublicationRechecksIAMAndPreservesOldObject(t *testing.T) {
	a := &multipartRevokingAuthorizer{principal: "123456789012"}
	f := newFixture(t, a)
	table := f.create(t, "revoked")
	location := string(*table.WarehouseLocation) + "/data/object"
	old, err := f.service.WriteObject(f.ctx, location, []byte("old"), owner.ObjectAttributes{}, owner.ObjectConditions{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{})
	if err != nil {
		t.Fatal(err)
	}
	part, err := f.service.UploadMultipartPart(f.ctx, location, id, 1, []byte("new"), owner.ObjectChecksums{})
	if err != nil {
		t.Fatal(err)
	}
	a.calls, a.denyAt = 0, 2
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: part.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	multipartCode(t, err, "ForbiddenException")
	data, info, err := f.service.ReadObject(f.ctx, location)
	if err != nil || string(data) != "old" || info.ETag != old.ETag {
		t.Fatalf("denied completion corrupted destination: %#v %q %v", info, data, err)
	}
	_, parts, err := f.service.ListMultipartParts(f.ctx, location, id)
	if err != nil || len(parts) != 1 {
		t.Fatalf("denied completion consumed upload: %#v %v", parts, err)
	}
	a.denyAt = 0
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: part.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	multipartCode(t, err, "PreconditionFailed")
}
func TestMultipartCompleteAbortConcurrencyAndMetadataProtection(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "fenced")
	location := string(*table.WarehouseLocation) + "/data/race"
	id, err := f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{})
	if err != nil {
		t.Fatal(err)
	}
	part, err := f.service.UploadMultipartPart(f.ctx, location, id, 1, []byte("data"), owner.ObjectChecksums{})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: part.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
		results <- err
	}()
	go func() { defer wg.Done(); <-start; results <- f.service.AbortMultipart(f.ctx, location, id) }()
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			multipartCode(t, err, "NoSuchUpload")
		}
	}
	if success != 1 {
		t.Fatalf("complete/abort successes = %d", success)
	}
	metadata := string(*table.MetadataLocation)
	original, old, err := f.service.ReadObject(f.ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.WriteObject(f.ctx, metadata, original, owner.ObjectAttributes{CacheControl: "changed"}, owner.ObjectConditions{})
	multipartCode(t, err, "PreconditionFailed")
	_, err = f.service.WriteObject(f.ctx, metadata, original, owner.ObjectAttributes{}, owner.ObjectConditions{})
	multipartCode(t, err, "PreconditionFailed")
	id, err = f.service.CreateMultipart(f.ctx, metadata, owner.ObjectAttributes{})
	if err != nil {
		t.Fatal(err)
	}
	part, err = f.service.UploadMultipartPart(f.ctx, metadata, id, 1, original, owner.ObjectChecksums{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CompleteMultipart(f.ctx, metadata, id, []owner.CompletedPart{{Number: 1, ETag: part.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	multipartCode(t, err, "PreconditionFailed")
	actual, info, err := f.service.ReadObject(f.ctx, metadata)
	if err != nil || !bytes.Equal(actual, original) || info.ETag != old.ETag {
		t.Fatal("immutable metadata changed")
	}
	if _, rejected := f.service.DeleteTable(f.ctx, &api.DeleteTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("fenced"))}); rejected != nil {
		t.Fatal(rejected)
	}
	if _, err = f.service.UploadMultipartPart(f.ctx, metadata, id, 1, []byte("stale"), owner.ObjectChecksums{}); !errors.Is(err, owner.ErrNotFound) {
		t.Fatalf("deleted table accepted stale part: %v", err)
	}
	job, ok, err := f.service.Next(f.ctx)
	if err != nil || !ok {
		t.Fatalf("cleanup missing: %v", err)
	}
	if err = f.service.Run(f.ctx, job); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.objects.ListMultipartParts(f.ctx, string(*table.WarehouseLocation), old.Key, id)
	multipartCode(t, err, "NoSuchUpload")
}

func TestMultipartEveryMutationRechecksCurrentPutPermission(t *testing.T) {
	a := &multipartRevokingAuthorizer{principal: "123456789012"}
	f := newFixture(t, a)
	table := f.create(t, "every_effect")
	location := string(*table.WarehouseLocation) + "/data/object"
	old, err := f.service.WriteObject(f.ctx, location, []byte("old"), owner.ObjectAttributes{}, owner.ObjectConditions{})
	if err != nil {
		t.Fatal(err)
	}
	a.calls, a.denyAt = 0, 2
	_, err = f.service.WriteObject(f.ctx, location, []byte("denied"), owner.ObjectAttributes{}, owner.ObjectConditions{})
	multipartCode(t, err, "ForbiddenException")
	data, info, err := f.service.ReadObject(f.ctx, location)
	if err != nil || string(data) != "old" || info.ETag != old.ETag {
		t.Fatalf("denied ordinary write changed destination: %q %#v %v", data, info, err)
	}
	a.calls = 0
	id, err := f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{})
	multipartCode(t, err, "ForbiddenException")
	if id != "" {
		t.Fatal("denied initiation exposed an upload ID")
	}
	a.denyAt = 0
	id, err = f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{})
	if err != nil {
		t.Fatal(err)
	}
	part, err := f.service.UploadMultipartPart(f.ctx, location, id, 1, []byte("original part"), owner.ObjectChecksums{})
	if err != nil {
		t.Fatal(err)
	}
	a.calls, a.denyAt = 0, 2
	_, err = f.service.UploadMultipartPart(f.ctx, location, id, 1, []byte("denied replacement"), owner.ObjectChecksums{})
	multipartCode(t, err, "ForbiddenException")
	_, parts, err := f.service.ListMultipartParts(f.ctx, location, id)
	if err != nil || len(parts) != 1 || parts[0].ETag != part.ETag {
		t.Fatalf("denied part replacement changed upload: %#v %v", parts, err)
	}
	a.calls = 0
	err = f.service.AbortMultipart(f.ctx, location, id)
	multipartCode(t, err, "ForbiddenException")
	// ListParts requires GetTableData, not PutTableData. Even a current
	// PutTableData denial cannot hide an otherwise authorized parts read.
	a.calls, a.denyAt = 0, 1
	_, parts, err = f.service.ListMultipartParts(f.ctx, location, id)
	if err != nil || len(parts) != 1 {
		t.Fatalf("ListParts used mutation permission or denied abort consumed upload: %#v %v", parts, err)
	}
}

type multipartBeforePublication struct {
	owner.WarehouseObjects
	before func(context.Context) error
}

func (s multipartBeforePublication) CompleteMultipart(ctx context.Context, warehouse, key, id string, parts []owner.CompletedPart, modified time.Time, conditions owner.ObjectConditions, checksums owner.ObjectChecksums, guard owner.PublicationGuard) (owner.ObjectInfo, error) {
	if err := s.before(ctx); err != nil {
		return owner.ObjectInfo{}, err
	}
	return s.WarehouseObjects.CompleteMultipart(ctx, warehouse, key, id, parts, modified, conditions, checksums, guard)
}
func TestMultipartDeletionBetweenAuthorizationAndPublicationIsFenced(t *testing.T) {
	f := newFixture(t, nil)
	table := f.create(t, "deleted_in_flight")
	warehouse := string(*table.WarehouseLocation)
	location := warehouse + "/data/object"
	old, err := f.service.WriteObject(f.ctx, location, []byte("old"), owner.ObjectAttributes{}, owner.ObjectConditions{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.service.CreateMultipart(f.ctx, location, owner.ObjectAttributes{})
	if err != nil {
		t.Fatal(err)
	}
	part, err := f.service.UploadMultipartPart(f.ctx, location, id, 1, []byte("new"), owner.ObjectChecksums{})
	if err != nil {
		t.Fatal(err)
	}
	objects := multipartBeforePublication{WarehouseObjects: f.objects, before: func(ctx context.Context) error {
		_, rejected := f.service.DeleteTable(ctx, &api.DeleteTableInput{TableBucketARN: f.bucket, Namespace: new(api.NamespaceName("analytics")), Name: new(api.TableName("deleted_in_flight"))})
		if rejected != nil {
			return rejected
		}
		return nil
	}}
	f.service = owner.New(owner.Config{Repository: f.repository, Objects: objects})
	_, err = f.service.CompleteMultipart(f.ctx, location, id, []owner.CompletedPart{{Number: 1, ETag: part.ETag}}, owner.ObjectConditions{}, owner.ObjectChecksums{})
	if !errors.Is(err, owner.ErrNotFound) {
		t.Fatalf("deleted table published completion: %v", err)
	}
	data, info, err := f.objects.ReadObject(f.ctx, warehouse, old.Key)
	if err != nil || string(data) != "old" || info.ETag != old.ETag {
		t.Fatalf("stale completion destroyed prior destination: %q %#v %v", data, info, err)
	}
	_, parts, err := f.objects.ListMultipartParts(f.ctx, warehouse, old.Key, id)
	if err != nil || len(parts) != 1 {
		t.Fatalf("fenced completion inconsistently consumed upload: %#v %v", parts, err)
	}
	replacement := f.create(t, "deleted_in_flight")
	if *replacement.WarehouseLocation == *table.WarehouseLocation {
		t.Fatal("replacement reused deleted warehouse identity")
	}
	if _, err = f.service.UploadMultipartPart(f.ctx, location, id, 1, []byte("late"), owner.ObjectChecksums{}); !errors.Is(err, owner.ErrNotFound) {
		t.Fatalf("recreated table admitted old upload: %v", err)
	}
}

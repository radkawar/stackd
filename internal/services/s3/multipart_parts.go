package s3

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awschecksum"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

const maximumMultipartPartSize int64 = 5 << 30

func multipartPartNumber(input *api.PartNumber) (int32, *awswire.Error) {
	var number int32
	if input != nil {
		number = int32(*input)
	}
	if number < 1 || number > 10000 {
		return number, argumentError("partNumber", strconv.FormatInt(int64(number), 10), "Part number must be an integer between 1 and 10000, inclusive")
	}
	return number, nil
}

func (s *Service) multipartPart(upload MultipartUploadRecord, number int32, body, key []byte, checksum string) (PartRecord, []byte, error) {
	data, err := encryptObject(key, body)
	if err != nil {
		return PartRecord{}, nil, err
	}
	etagBody := body
	if upload.EncryptionAlgorithm == "aws:kms" || upload.CustomerKey != nil {
		etagBody = data
	}
	sum := md5.Sum(etagBody)
	return PartRecord{
		Number: number, Modified: s.clock.Now().UTC().Truncate(time.Second),
		Size: int64(len(body)), ETag: "\"" + hex.EncodeToString(sum[:]) + "\"", Checksum: checksum,
	}, data, nil
}

func readMultipartPartKey(record ObjectRecord, headers customerKeyHeaders) ([]byte, *awswire.Error) {
	key, wire := readCustomerKey(record, headers, false, true)
	if record.CustomerKey != nil && wire != nil {
		if wire.Code == "AccessDenied" {
			wire = failure("InvalidRequest", "The provided encryption parameters did not match the ones used originally.", 400)
		} else if wire.Code == "InvalidRequest" && !headers.supplied {
			wire = failure("InvalidRequest", "The multipart upload initiate requested encryption. Subsequent part requests must include the appropriate encryption parameters.", 400)
		}
	}
	return key, wire
}

func (s *Service) uploadPart(ctx context.Context, in *api.UploadPartInput) (*ObjectResponse[api.UploadPartOutput], *awswire.Error) {
	c := s.multipartCall(ctx, "UploadPart", value(in.Bucket), value(in.Key), value(in.UploadId))
	out := &ObjectResponse[api.UploadPartOutput]{}
	customer := customerHeaders(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5)
	conditions := map[string][]string{}
	requestedEncryption(c, conditions, encryptionHeaders{customer: customer})
	number, wire := multipartPartNumber(in.PartNumber)
	c.params["partNumber"] = strconv.FormatInt(int64(number), 10)
	c.additional["objectSize"] = int64(len(in.Body))
	if wire != nil {
		return out, s.complete(ctx, c, wire)
	}
	var bucket BucketRecord
	var upload MultipartUploadRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		bucket, err = s.bucket(r, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.objectWrite(r.Context(), c, bucket, c.key, "", conditions); wire != nil {
			return wire
		}
		upload, err = multipartUpload(r, MultipartUploadKey{ObjectKey: ObjectKey{bucket.Key, c.key}, UploadID: value(in.UploadId)})
		return err
	})
	if err != nil {
		return out, s.complete(ctx, c, err)
	}
	customerKey, wire := readMultipartPartKey(upload.ObjectRecord, customer)
	if wire != nil {
		return out, s.complete(ctx, c, wire)
	}
	defer clear(customerKey)
	if int64(len(in.Body)) > maximumMultipartPartSize || (in.ContentLength != nil && int64(*in.ContentLength) > maximumMultipartPartSize) {
		return out, s.complete(ctx, c, failure("EntityTooLarge", "Your proposed upload exceeds the maximum allowed size.", 400))
	}
	c.additional["bytesTransferredIn"] = int64(len(in.Body))
	if in.ContentLength != nil && int64(*in.ContentLength) != int64(len(in.Body)) {
		return out, s.complete(ctx, c, failure("IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header.", 400))
	}
	if wire := checkMD5(in.Body, value(in.ContentMD5)); wire != nil {
		return out, s.complete(ctx, c, wire)
	}
	algorithm, sum, stored, wire := uploadPartChecksum(in, upload)
	if wire != nil {
		return out, s.complete(ctx, c, wire)
	}
	effectContext := ctx
	if c.eventID != "" {
		m := awsctx.FromContext(ctx)
		m.ParentEventID = c.eventID
		effectContext = awsctx.WithMetadata(ctx, m)
	}
	key, wire := s.objectDataKey(effectContext, bucket, upload.ObjectRecord, customerKey)
	if wire != nil {
		return out, s.complete(ctx, c, wire)
	}
	defer clear(key)
	part, data, err := s.multipartPart(upload, number, in.Body, key, stored)
	if err != nil {
		return out, s.complete(ctx, c, err)
	}
	wire = s.execute(ctx, c, func(tx Transaction) error {
		currentBucket, err := s.bucket(tx, c, bucket.AccountID)
		if err != nil {
			return err
		}
		if wire := s.objectWrite(tx.Context(), c, currentBucket, c.key, "", conditions); wire != nil {
			return wire
		}
		if upload.CustomerKey != nil {
			if wire := checkCustomerEncryption(currentBucket); wire != nil {
				return wire
			}
		}
		if _, err := multipartUpload(tx, upload.UploadKey()); err != nil {
			return err
		}
		if err := tx.PutMultipartPart(upload.UploadKey(), part, data); err != nil {
			return err
		}
		noteAccessLogObject(tx.Context(), part.Size)
		out.Output.ETag = new(api.ETag(part.ETag))
		out.Output.ServerSideEncryption = sseHeader(upload.ObjectRecord)
		out.Output.SSECustomerAlgorithm = customerAlgorithm(upload.ObjectRecord)
		out.Output.SSECustomerKeyMD5 = customerMD5(upload.ObjectRecord)
		c.response = encryptionResponse(upload.ObjectRecord)
		if upload.KMSKeyARN != "" {
			out.Output.SSEKMSKeyId = new(api.SSEKMSKeyId(upload.KMSKeyARN))
			out.encryptionContext = objectEncryptionContextHeader(upload.EncryptionContext)
		}
		out.Output.SetChecksum(algorithm, sum)
		return nil
	})
	return out, wire
}

// Copy ranges require both inclusive endpoints. Unlike ordinary GET ranges,
// malformed or reversed ranges are InvalidArgument, and out-of-bounds ranges
// are InvalidRequest. Native S3 accepts ranges from sources smaller than 5 MiB.
func multipartCopyRange(input *api.CopySourceRange, size int64) (int64, int64, *awswire.Error) {
	if input == nil {
		return 0, size, nil
	}
	header := value(input)
	rangeValue, ok := strings.CutPrefix(header, "bytes=")
	first, last, separated := strings.Cut(rangeValue, "-")
	start, startErr := strconv.ParseUint(first, 10, 63)
	end, endErr := strconv.ParseUint(last, 10, 63)
	if !ok || !separated || startErr != nil || endErr != nil || start > end {
		return 0, 0, argumentError("x-amz-copy-source-range", header, "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy")
	}
	if int64(start) >= size || int64(end) >= size {
		return 0, 0, failure("InvalidRequest", "The specified copy range is invalid for the source object size", 400)
	}
	return int64(start), int64(end) + 1, nil
}

func (s *Service) uploadPartCopy(ctx context.Context, in *api.UploadPartCopyInput) (*preparedResponse, *awswire.Error) {
	c := s.multipartCall(ctx, "UploadPartCopy", value(in.Bucket), value(in.Key), value(in.UploadId))
	response := &preparedResponse{}
	number, wire := multipartPartNumber(in.PartNumber)
	c.params["partNumber"] = strconv.FormatInt(int64(number), 10)
	c.params["x-amz-copy-source"] = value(in.CopySource)
	for _, header := range []struct{ name, value string }{
		{"x-amz-copy-source-range", value(in.CopySourceRange)},
		{"x-amz-copy-source-if-match", value(in.CopySourceIfMatch)},
		{"x-amz-copy-source-if-none-match", value(in.CopySourceIfNoneMatch)},
	} {
		if header.value != "" {
			c.params[header.name] = header.value
		}
	}
	if wire != nil {
		return response, s.complete(ctx, c, wire)
	}
	m := awsctx.FromContext(ctx)
	source, wire := parseCopySource(value(in.CopySource))
	if wire != nil {
		return response, s.complete(ctx, c, wire)
	}
	sourceCall := call(ctx, "GetObject", source.bucket, source.key)
	sourceCall.copySource = true
	var bucket BucketRecord
	var upload MultipartUploadRecord
	var selected copiedObject
	var encrypted [][]byte
	var start, end int64
	var sourceAttempted bool
	conditions := map[string][]string{"s3:x-amz-copy-source": {value(in.CopySource)}}
	customer := customerHeaders(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5)
	requestedEncryption(c, conditions, encryptionHeaders{customer: customer})
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		bucket, err = s.bucket(r, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		sourceAttempted = true
		selected, err = s.selectCopySource(r, sourceCall, source, value(in.ExpectedSourceBucketOwner))
		if selected.bucket.Key.Name != "" && selected.bucket.Key != bucket.Key {
			c.resources = append(c.resources, journal.APIEventResource{AccountID: selected.bucket.AccountID, Type: "AWS::S3::Bucket", ARN: selected.bucket.Key.ARN()})
		}
		if selected.object.Key.Name != "" && selected.object.Key != (ObjectKey{bucket.Key, c.key}) {
			c.resources = append(c.resources, journal.APIEventResource{Type: "AWS::S3::Object", ARN: selected.object.Key.ARN()})
		}
		if err != nil {
			return err
		}
		if wire := admitAccessPointCopy(r.Context(), c, sourceCall, bucket, selected.bucket); wire != nil {
			return wire
		}
		if wire := readConditions(selected.object, in.CopySourceIfMatch, in.CopySourceIfNoneMatch, in.CopySourceIfModifiedSince, in.CopySourceIfUnmodifiedSince, s.clock.Now()); wire != nil {
			return preconditionFailed("x-amz-copy-source-" + wire.Condition)
		}
		c.additional["objectSize"] = selected.object.Size
		if wire := s.objectWrite(r.Context(), c, bucket, c.key, "", conditions); wire != nil {
			return wire
		}
		upload, err = multipartUpload(r, MultipartUploadKey{ObjectKey: ObjectKey{bucket.Key, c.key}, UploadID: value(in.UploadId)})
		if err != nil {
			return err
		}
		var wire *awswire.Error
		start, end, wire = multipartCopyRange(in.CopySourceRange, selected.object.Size)
		if wire != nil {
			return wire
		}
		if end-start > maximumMultipartPartSize {
			return failure("EntityTooLarge", "Your proposed upload exceeds the maximum allowed size.", 400)
		}
		restore, err := objectRestoreForRead(r, selected.object)
		if err != nil {
			return err
		}
		if wire := objectPayloadError(selected.object, restore, s.clock.Now(), true); wire != nil {
			return wire
		}
		encrypted, err = r.ObjectData(selected.object.VersionKey())
		return err
	})
	effectContext := ctx
	if c.eventID != "" {
		m.ParentEventID = c.eventID
		effectContext = awsctx.WithMetadata(ctx, m)
	}
	finish := func(err error) (*preparedResponse, *awswire.Error) {
		if !sourceAttempted {
			return response, s.complete(ctx, c, err)
		}
		if auditErr := s.recordCopySource(effectContext, c, sourceCall, &selected.object, err); auditErr != nil {
			return response, s.complete(ctx, c, auditErr)
		}
		return response, s.complete(ctx, c, err)
	}
	if err != nil {
		return finish(err)
	}
	customerKey, wire := readMultipartPartKey(upload.ObjectRecord, customer)
	if wire != nil {
		return finish(wire)
	}
	defer clear(customerKey)
	sourceCustomerKey, wire := readCustomerKey(selected.object, customerHeaders(in.CopySourceSSECustomerAlgorithm, in.CopySourceSSECustomerKey, in.CopySourceSSECustomerKeyMD5), true, false)
	if wire != nil {
		return finish(wire)
	}
	defer clear(sourceCustomerKey)
	// Both S3 authorities and the source predicate have admitted this request
	// before either independent KMS operation can disclose a key-policy error.
	sourceKey, wire := s.objectDataKey(effectContext, selected.bucket, selected.object, sourceCustomerKey)
	if wire != nil {
		return finish(wire)
	}
	defer clear(sourceKey)
	key, wire := s.objectDataKey(effectContext, bucket, upload.ObjectRecord, customerKey)
	if wire != nil {
		return finish(wire)
	}
	defer clear(key)
	body, err := decryptObject(sourceKey, encrypted)
	if err != nil {
		return finish(err)
	}
	defer clear(body)
	partBody := body[start:end]
	algorithm := upload.ChecksumAlgorithm
	if algorithm == "" {
		algorithm = "CRC64NVME"
	}
	sum, err := awschecksum.Sum(algorithm, partBody)
	if err != nil {
		return finish(unsupported(err.Error()))
	}
	part, data, err := s.multipartPart(upload, number, partBody, key, sum)
	if err != nil {
		return finish(err)
	}
	// Commit both successful observations with the replacement. On failure the
	// rollback leaves the previous part intact, and finish records the internal
	// source observation with the actual final error (including NoSuchUpload).
	err = s.repository.Update(ctx, func(tx Transaction) error {
		currentBucket, err := s.bucket(tx, c, bucket.AccountID)
		if err != nil {
			return err
		}
		if wire := s.objectWrite(tx.Context(), c, currentBucket, c.key, "", conditions); wire != nil {
			return wire
		}
		if upload.CustomerKey != nil {
			if wire := checkCustomerEncryption(currentBucket); wire != nil {
				return wire
			}
		}
		if _, err := multipartUpload(tx, upload.UploadKey()); err != nil {
			return err
		}
		if err := tx.PutMultipartPart(upload.UploadKey(), part, data); err != nil {
			return err
		}
		out := &api.UploadPartCopyOutput{
			CopyPartResult:       multipartCopyResult(part, upload.ChecksumAlgorithm),
			ServerSideEncryption: sseHeader(upload.ObjectRecord),
			SSECustomerAlgorithm: customerAlgorithm(upload.ObjectRecord),
			SSECustomerKeyMD5:    customerMD5(upload.ObjectRecord),
		}
		c.response = encryptionResponse(upload.ObjectRecord)
		if upload.KMSKeyARN != "" {
			out.SSEKMSKeyId = new(api.SSEKMSKeyId(upload.KMSKeyARN))
		}
		if selected.object.VersionID != "null" || source.version != nil {
			out.CopySourceVersionId = new(api.CopySourceVersionId(selected.object.VersionID))
			c.response["x-amz-copy-source-version-id"] = selected.object.VersionID
		}
		response.encryptionContext = objectEncryptionContextHeader(upload.EncryptionContext)
		if err := response.prepare(c, out); err != nil {
			return err
		}
		c.additional["objectSize"] = part.Size
		noteAccessLogObject(tx.Context(), part.Size)
		if err := s.recordCopySource(tx.Context(), c, sourceCall, &selected.object, nil); err != nil {
			return err
		}
		return s.record(tx.Context(), c, nil)
	})
	if err != nil {
		return finish(err)
	}
	return response, nil
}

func multipartCopyResult(part PartRecord, algorithm string) *api.CopyPartResult {
	out := &api.CopyPartResult{ETag: new(api.ETag(part.ETag)), LastModified: new(part.Modified)}
	out.SetChecksum(algorithm, part.Checksum)
	return out
}

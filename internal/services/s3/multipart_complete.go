package s3

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"net/url"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) completeMultipartUpload(ctx context.Context, in *api.CompleteMultipartUploadInput) (*preparedResponse, *awswire.Error) {
	c := s.multipartCall(ctx, "CompleteMultipartUpload", value(in.Bucket), value(in.Key), value(in.UploadId))
	request, _ := awsapi.FromContext(ctx)
	c.additional["bytesTransferredIn"], c.additional["objectSize"] = len(request.Body), int64(-1)
	response := &preparedResponse{}
	if in.MultipartUpload == nil || len(in.MultipartUpload.Parts) == 0 {
		return response, s.complete(ctx, c, failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", 400))
	}
	parts := in.MultipartUpload.Parts
	var projected any = parts
	if len(parts) == 1 {
		projected = &parts[0]
	}
	document := map[string]any{"Part": projected}
	// The generated decoder has admitted the XML. CloudTrail distinguishes
	// an actual default namespace declaration from an unnamespaced document.
	decoder := xml.NewDecoder(bytes.NewReader(request.Body))
	for token, err := decoder.Token(); err == nil; token, err = decoder.Token() {
		if root, ok := token.(xml.StartElement); ok {
			for _, attribute := range root.Attr {
				if attribute.Name.Space == "" && attribute.Name.Local == "xmlns" {
					document["xmlns"] = attribute.Value
				}
			}
			break
		}
	}
	c.params["CompleteMultipartUpload"] = document
	for _, header := range []struct{ name, value string }{{"If-Match", value(in.IfMatch)}, {"If-None-Match", value(in.IfNoneMatch)}} {
		if header.value != "" {
			c.params[header.name] = header.value
		}
	}
	if value(in.IfMatch) == "*" || (in.IfNoneMatch != nil && (in.IfMatch != nil || value(in.IfNoneMatch) != "*")) {
		return response, s.complete(ctx, c, unsupported("A header you provided implies functionality that is not implemented."))
	}
	customer := customerHeaders(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5)
	conditions := map[string][]string{}
	requestedEncryption(c, conditions, encryptionHeaders{customer: customer})
	var bucket BucketRecord
	var upload MultipartUploadRecord
	var repeated bool
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		bucket, err = s.bucket(r, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.objectWrite(r.Context(), c, bucket, c.key, "", conditions); wire != nil {
			return wire
		}
		key := MultipartUploadKey{ObjectKey: ObjectKey{bucket.Key, c.key}, UploadID: value(in.UploadId)}
		upload, err = r.MultipartUpload(key)
		if errors.Is(err, ErrNotFound) {
			completed, lookupErr := r.CompletedMultipartUpload(key)
			if lookupErr != nil {
				if !errors.Is(lookupErr, ErrNotFound) {
					return lookupErr
				}
				return noSuchMultipartUpload(key.UploadID)
			}
			stored, err := r.ObjectParts(completed.VersionKey())
			if err != nil {
				return err
			}
			if !sameMultipartManifest(parts, stored) {
				return noSuchMultipartUpload(key.UploadID)
			}
			if wire := admitMultipartCompletionKey(completed, customer, completed.MultipartChecksumExplicit); wire != nil {
				return wire
			}
			repeated = true
			response.encryptionContext = objectEncryptionContextHeader(completed.EncryptionContext)
			tags, err := r.ObjectTags(completed.VersionKey())
			if err != nil {
				return err
			}
			out := multipartResult(c, bucket, completed, true)
			out.Expiration, err = lifecycleExpirationHeader(r, bucket, completed, tags)
			if err != nil {
				return err
			}
			return response.prepareMultipartCompletion(c, out, completed, customer)
		}
		if err != nil {
			return err
		}
		c.response = encryptionResponse(upload.ObjectRecord)
		return nil
	})
	if err != nil || repeated {
		return response, s.complete(ctx, c, err)
	}
	if wire := admitMultipartCompletionKey(upload.ObjectRecord, customer, upload.ChecksumAlgorithm != ""); wire != nil {
		return response, s.complete(ctx, c, wire)
	}
	// Explicit-checksum KMS uploads require decrypt admission, but completion
	// adopts ciphertext without reading or re-encrypting it. Ordinary KMS
	// completion remains possible after decrypt authority or the key is disabled.
	if upload.ChecksumAlgorithm != "" && upload.EncryptionAlgorithm == "aws:kms" {
		effectContext := ctx
		if c.eventID != "" {
			m := awsctx.FromContext(ctx)
			m.ParentEventID = c.eventID
			effectContext = awsctx.WithMetadata(ctx, m)
		}
		key, wire := s.objectDataKey(effectContext, bucket, upload.ObjectRecord, nil)
		clear(key)
		if wire != nil {
			return response, s.complete(ctx, c, wire)
		}
	}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		currentBucket, err := s.bucket(tx, c, bucket.AccountID)
		if err != nil {
			return err
		}
		if wire := s.objectWrite(tx.Context(), c, currentBucket, c.key, "", conditions); wire != nil {
			return wire
		}
		current, err := multipartUpload(tx, upload.UploadKey())
		if err != nil {
			return err
		}
		stored, err := tx.MultipartParts(current.UploadKey(), 0, 10000)
		if err != nil {
			return err
		}
		current.VersionID, err = issueVersion(currentBucket.Versioning)
		if err != nil {
			return err
		}
		// Admitted failures can expose this unpublished version in CloudTrail,
		// without returning a version header or creating an object version.
		if currentBucket.Versioning != "" {
			c.response["x-amz-version-id"] = current.VersionID
		}
		record, selected, err := assembleMultipart(current, stored, in)
		if err != nil {
			return err
		}
		record.MultipartChecksumExplicit = current.ChecksumAlgorithm != ""
		initializeObjectTiering(&record, s.clock.Now())
		response.encryptionContext = objectEncryptionContextHeader(record.EncryptionContext)
		out := multipartResult(c, currentBucket, record, false)
		out.Expiration, err = lifecycleExpirationHeader(tx, currentBucket, record, current.Tags)
		if err != nil {
			return err
		}
		if err := response.prepareMultipartCompletion(c, out, record, customer); err != nil {
			return err
		}
		// The admitted completion phase has prepared its 200 headers. S3 can
		// report a final predicate/conflict error inside that successful HTTP
		// envelope; SDKs must inspect the XML body, not just the status code.
		if _, err := writeConditions(tx, record.Key, in.IfMatch, in.IfNoneMatch, true); err != nil {
			return multipartCommitError(err, response)
		}
		if current.Superseded && (in.IfMatch != nil || in.IfNoneMatch != nil) {
			return multipartCommitError(failure("ConditionalRequestConflict", "A conflicting operation occurred during the conditional request.", 409), response)
		}
		retain := currentBucket.Versioning == "Enabled" || !current.Superseded
		record.Sequence, err = tx.CompleteMultipartUpload(current.UploadKey(), record, selected, retain)
		if err != nil {
			return multipartCommitError(err, response)
		}
		c.additional["objectSize"] = record.Size
		s.recordObjectLock(c, record)
		noteAccessLogObject(tx.Context(), record.Size)
		if retain {
			if err := s.enqueueObjectReplication(tx, c, currentBucket, record, ReplicationObject); err != nil {
				return err
			}
		}
		return s.notifyObject(tx, c, currentBucket, record, "ObjectCreated:CompleteMultipartUpload")
	})
	return response, wire
}

func noSuchMultipartUpload(id string) *awswire.Error {
	wire := failure("NoSuchUpload", "The specified multipart upload does not exist.", 404)
	wire.UploadID = id
	return wire
}

func multipartCommitError(err error, response *preparedResponse) *awswire.Error {
	wire := wireError(err)
	wire.StatusCode = 200
	wire.ResponseHeader = response.response.Header
	return wire
}

func multipartResult(c *apiCall, bucket BucketRecord, record ObjectRecord, repeated bool) *api.CompleteMultipartUploadOutput {
	location := url.URL{Scheme: "https", Host: bucket.Key.Name + ".s3.amazonaws.com", Path: "/" + record.Key.Name}
	if c.accessPoint != nil {
		location.Host = c.accessPoint.Key.Name + "-" + c.accessPoint.Key.AccountID + ".s3-accesspoint." + s3RegionDomain(c.accessPoint.Key.Partition, c.accessPoint.Key.Region)
		if strings.HasSuffix(c.accessPointReference, "-s3alias") {
			location.Host = c.accessPointReference + ".s3.amazonaws.com"
		}
	}
	out := &api.CompleteMultipartUploadOutput{
		Bucket: new(api.BucketName(bucket.Key.Name)), Key: new(api.ObjectKey(record.Key.Name)),
		Location: new(api.Location(location.String())), ETag: new(api.ETag(record.ETag)),
		ServerSideEncryption: sseHeader(record),
	}
	c.response = encryptionResponse(record)
	if bucket.Versioning != "" || record.VersionID != "null" {
		out.VersionId = new(api.ObjectVersionId(record.VersionID))
		c.response["x-amz-version-id"] = record.VersionID
	}
	if record.KMSKeyARN != "" {
		out.SSEKMSKeyId = new(api.SSEKMSKeyId(record.KMSKeyARN))
	}
	// Native successful retries return the original identity, but omit the
	// initial completion's checksum fields and do not publish another event.
	if repeated {
		return out
	}
	out.ChecksumType = new(api.ChecksumType(record.ChecksumType))
	out.SetChecksum(record.ChecksumAlgorithm, record.Checksum)
	return out
}

func (r *preparedResponse) prepareMultipartCompletion(c *apiCall, out *api.CompleteMultipartUploadOutput, record ObjectRecord, customer customerKeyHeaders) error {
	if err := r.prepare(c, out); err != nil {
		return err
	}
	if algorithm := customerAlgorithm(record); algorithm != nil {
		r.response.Header.Set("x-amz-server-side-encryption-customer-algorithm", string(*algorithm))
		if customer.supplied {
			r.response.Header.Set("x-amz-server-side-encryption-customer-key-md5", value(customerMD5(record)))
		}
	}
	return nil
}

func admitMultipartCompletionKey(record ObjectRecord, customer customerKeyHeaders, checksums bool) *awswire.Error {
	// Ordinary SSE-C completion only adopts retained ciphertext. A supplied key
	// must still match; explicit checksums additionally require key admission.
	if !customer.supplied && !checksums && record.CustomerKey != nil {
		return nil
	}
	key, wire := readCustomerKey(record, customer, false, false)
	clear(key)
	if record.CustomerKey != nil && wire != nil && (wire.Code == "AccessDenied" || (wire.Code == "InvalidRequest" && !customer.supplied)) {
		return failure("InvalidRequest", "The object was stored using a form of Server Side Encryption. Correct SSE-C request parameters are required for this request when specifying checksums for each part.", 400)
	}
	return wire
}

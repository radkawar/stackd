package s3

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func readConditions[Match, NoneMatch ~string](record ObjectRecord, match *Match, noneMatch *NoneMatch, modifiedSince, unmodifiedSince *time.Time, now time.Time) *awswire.Error {
	if match != nil && !etagMatches(value(match), record.ETag) {
		return preconditionFailed("If-Match")
	}
	if match == nil && unmodifiedSince != nil && record.Modified.After(unmodifiedSince.UTC().Truncate(time.Second)) {
		return preconditionFailed("If-Unmodified-Since")
	}
	if noneMatch != nil && etagMatches(value(noneMatch), record.ETag) {
		return &awswire.Error{Code: "NotModified", Message: "Not Modified", StatusCode: 304, S3ErrorDetails: awswire.S3ErrorDetails{Condition: "If-None-Match"}}
	}
	if noneMatch == nil && modifiedSince != nil && !modifiedSince.After(now) && !record.Modified.After(modifiedSince.UTC().Truncate(time.Second)) {
		return &awswire.Error{Code: "NotModified", Message: "Not Modified", StatusCode: 304, S3ErrorDetails: awswire.S3ErrorDetails{Condition: "If-Modified-Since"}}
	}
	return nil
}

type objectRead struct {
	object       ObjectRecord
	bucket       BucketRecord
	start, end   int64
	tagCount     *api.TagCount
	partsCount   *api.PartsCount
	contentRange bool
	checksum     string
	retention    *api.ObjectLockRetention
	legalHold    *api.ObjectLockLegalHoldStatus
	restore      *api.Restore
	replication  *api.ReplicationStatus
	expiration   *api.Expiration
	customerKey  []byte
}

func (s *Service) readObject(tx Reader, c *apiCall, in *api.GetObjectInput) (objectRead, error) {
	return s.selectObjectRead(tx, c, in, false)
}

func (s *Service) selectObjectRead(tx Reader, c *apiCall, in *api.GetObjectInput, website bool) (objectRead, error) {
	if in.SSECustomerAlgorithm != nil {
		c.params["x-amz-server-side-encryption-customer-algorithm"] = value(in.SSECustomerAlgorithm)
	}
	var read objectRead
	b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
	read.bucket = b
	if err != nil {
		return read, err
	}
	if w := validateKey(c.key); w != nil {
		return read, w
	}
	action := "GetObject"
	tagAction := "GetObjectTagging"
	conditions := map[string][]string{}
	if in.VersionId != nil {
		action = "GetObjectVersion"
		tagAction = "GetObjectVersionTagging"
		version := value(in.VersionId)
		c.params["versionId"] = version
		conditions["s3:VersionId"] = []string{version}
	}
	read.object, err = selectObjectVersion(tx, ObjectKey{b.Key, c.key}, in.VersionId)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return read, err
	}
	record := read.object
	if errors.Is(err, ErrNotFound) {
		record.Key = ObjectKey{b.Key, c.key}
	}
	// Applied native deny controls establish that markers resolve before normal
	// object-read IAM, for both current and explicitly selected versions.
	if err == nil && record.DeleteMarker {
		if in.VersionId != nil {
			return read, failure("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
		}
		return read, noSuchKey(c.key)
	}
	// Native requests under an active GetObject deny still disclose a missing
	// current key when ListBucket permits it. Website reads instead require
	// their anonymous object authority; explicit versions retain version IAM.
	if errors.Is(err, ErrNotFound) && in.VersionId == nil && !website {
		if s.authorize(tx.Context(), c, b, "ListBucket", "", nil) != nil {
			return read, denied()
		}
		return read, noSuchKey(c.key)
	}
	var tags []Tag
	if err == nil {
		var tagErr error
		tags, tagErr = tx.ObjectTags(record.VersionKey())
		if tagErr != nil {
			return read, tagErr
		}
		existingTagConditions(conditions, tags)
	}
	if w := s.authorizeObject(tx.Context(), c, b, record, action, conditions); w != nil {
		return objectRead{bucket: b}, w
	}
	if c.name == "GetObjectAttributes" {
		if w := s.authorizeObject(tx.Context(), c, b, record, action+"Attributes", conditions); w != nil {
			return objectRead{bucket: b}, w
		}
	}
	if err == nil && c.name != "GetObjectAttributes" {
		noteAccessLogObject(tx.Context(), record.Size)
	}
	if in.ChecksumMode != nil && value(in.ChecksumMode) != "ENABLED" {
		return read, invalid("Unsupported checksum mode.")
	}
	if in.PartNumber != nil {
		if in.Range != nil {
			return read, failure("InvalidRequest", "Cannot specify both Range header and partNumber query parameter", 400)
		}
		if _, w := multipartPartNumber(in.PartNumber); w != nil {
			return read, w
		}
	}
	if errors.Is(err, ErrNotFound) {
		if in.VersionId != nil {
			wire := failure("NoSuchVersion", "The specified version does not exist.", 404)
			wire.Key, wire.VersionID = c.key, value(in.VersionId)
			return read, wire
		}
		return read, noSuchKey(c.key)
	}
	headers := customerHeaders(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5)
	var customerError *awswire.Error
	read.customerKey, customerError = readCustomerHeaders(record, headers, false)
	conditional := in.IfMatch != nil || in.IfNoneMatch != nil || in.IfModifiedSince != nil || in.IfUnmodifiedSince != nil
	partial := in.Range != nil || in.PartNumber != nil
	// Conditions and partial reads admit headers before selecting a response.
	// Range validation precedes key proof; only full reads reject unavailable
	// archive payloads before proving an otherwise well-formed customer key.
	if customerError != nil && (headers.supplied || conditional || partial || c.name != "GetObject") {
		return read, customerError
	}
	now := s.clock.Now()
	if w := readConditions(record, in.IfMatch, in.IfNoneMatch, in.IfModifiedSince, in.IfUnmodifiedSince, now); w != nil {
		return read, w
	}
	if err := read.selectRange(tx, in); err != nil {
		return read, err
	}
	var payloadError *awswire.Error
	if c.name != "GetObjectAttributes" {
		restore, err := objectRestoreForRead(tx, record)
		if err != nil {
			return read, err
		}
		if c.name == "GetObject" {
			payloadError = objectPayloadError(record, restore, now, false)
			if payloadError != nil && !partial {
				return read, payloadError
			}
		}
		read.restore = restoreHeader(restore, now)
	}
	if customerError != nil {
		return read, customerError
	}
	if read.customerKey != nil {
		if wire := verifyCustomerKey(record, read.customerKey, false); wire != nil {
			return read, wire
		}
	}
	if payloadError != nil {
		return read, payloadError
	}
	if c.name != "GetObjectAttributes" && len(tags) != 0 && s.authorizeObject(tx.Context(), c, b, record, tagAction, conditions) == nil {
		read.tagCount = new(api.TagCount(len(tags)))
	}
	if !website && c.name != "GetObjectAttributes" {
		if in.VersionId == nil {
			read.expiration, err = lifecycleExpirationHeader(tx, b, record, tags)
			if err != nil {
				return read, err
			}
		}
		status, err := objectReplicationStatus(tx, record)
		if err != nil {
			return read, err
		}
		if status != "" {
			read.replication = new(api.ReplicationStatus(status))
		}
		if record.Retention.Mode != "" && s.authorizeObject(tx.Context(), c, b, record, "GetObjectRetention", conditions) == nil {
			read.retention = retentionOutput(record.Retention, s.clock.Now().UTC().Truncate(time.Millisecond))
		}
		if record.LegalHold != "" && s.authorizeObject(tx.Context(), c, b, record, "GetObjectLegalHold", conditions) == nil {
			read.legalHold = new(api.ObjectLockLegalHoldStatus(record.LegalHold))
		}
	}
	return read, nil
}
func outputMetadata(record ObjectRecord) api.Metadata {
	out := make(api.Metadata, len(record.Metadata))
	for k, v := range record.Metadata {
		out[api.MetadataKey(k)] = api.MetadataValue(v)
	}
	return out
}
func outputExpires(expires *time.Time) *api.Expires {
	if expires == nil {
		return nil
	}
	return new(api.Expires(expires.UTC().Format(http.TimeFormat)))
}

// GetObject reads with caller authority and returns the bucket's actual region
// from the same transaction, without requiring an additional bucket permission.
func (s *Service) GetObject(ctx context.Context, in *api.GetObjectInput) (*ObjectResponse[api.GetObjectOutput], *awswire.Error) {
	c := call(ctx, "GetObject", value(in.Bucket), value(in.Key))
	response := &ObjectResponse[api.GetObjectOutput]{}
	out := &response.Output
	var read objectRead
	err := func() error {
		var encrypted [][]byte
		err := s.repository.View(ctx, func(r Reader) error {
			var err error
			read, err = s.readObject(r, c, in)
			if err != nil {
				return err
			}
			encrypted, err = r.ObjectData(read.object.VersionKey())
			return err
		})
		defer clear(read.customerKey)
		record, b, start, end := read.object, read.bucket, read.start, read.end
		response.Region = b.Region
		if record.DeleteMarker {
			out.DeleteMarker = new(api.DeleteMarker(true))
			out.VersionId = new(api.ObjectVersionId(record.VersionID))
			out.LastModified = new(record.Modified)
		}
		if err != nil {
			return err
		}
		key, rejected := s.objectDataKey(ctx, b, record, read.customerKey)
		if rejected != nil {
			return rejected
		}
		defer clear(key)
		body, err := decryptObject(key, encrypted)
		if err != nil {
			return err
		}
		if int64(len(body)) != record.Size {
			return errors.New("object size does not match encrypted payload")
		}
		out.Body = body[start:end]
		response.BucketAccountID = b.AccountID
		out.TagCount = read.tagCount
		out.Restore = read.restore
		out.ReplicationStatus = read.replication
		out.Expiration = read.expiration
		if record.StorageClass != "" {
			out.StorageClass = new(api.StorageClass(record.StorageClass))
		}
		out.PartsCount = read.partsCount
		out.ObjectLockLegalHoldStatus = read.legalHold
		if retention := read.retention; retention != nil {
			out.ObjectLockMode = (*api.ObjectLockMode)(retention.Mode)
			out.ObjectLockRetainUntilDate = retention.RetainUntilDate
			out.ObjectLockEventHold = retention.EventHold
			if period := retention.EventHoldDuration; period != nil {
				out.ObjectLockEventHoldDurationDays = (*api.ObjectLockEventHoldDurationDays)(period.Days)
				out.ObjectLockEventHoldDurationYears = (*api.ObjectLockEventHoldDurationYears)(period.Years)
			}
		}
		out.ContentLength = new(api.ContentLength(end - start))
		out.ETag = new(api.ETag(record.ETag))
		out.LastModified = new(record.Modified)
		out.ContentType = new(api.ContentType(record.ContentType))
		out.AcceptRanges = new(api.AcceptRanges("bytes"))
		out.ServerSideEncryption = sseHeader(record)
		out.SSECustomerAlgorithm, out.SSECustomerKeyMD5 = customerAlgorithm(record), customerMD5(record)
		if record.KMSKeyARN != "" {
			out.SSEKMSKeyId = new(api.SSEKMSKeyId(record.KMSKeyARN))
			response.encryptionContext = objectEncryptionContextHeader(record.EncryptionContext)
		}
		out.Metadata = outputMetadata(record)
		out.Expires = outputExpires(record.Expires)
		if read.contentRange {
			out.ContentRange = new(api.ContentRange(fmt.Sprintf("bytes %d-%d/%d", start, end-1, record.Size)))
		}
		if record.WebsiteRedirectLocation != "" {
			out.WebsiteRedirectLocation = new(api.WebsiteRedirectLocation(record.WebsiteRedirectLocation))
		}
		if record.CacheControl != "" {
			out.CacheControl = new(api.CacheControl(record.CacheControl))
		}
		if record.ContentDisposition != "" {
			out.ContentDisposition = new(api.ContentDisposition(record.ContentDisposition))
		}
		if record.ContentEncoding != "" {
			out.ContentEncoding = new(api.ContentEncoding(record.ContentEncoding))
		}
		if record.ContentLanguage != "" {
			out.ContentLanguage = new(api.ContentLanguage(record.ContentLanguage))
		}
		if in.ResponseCacheControl != nil {
			out.CacheControl = new(api.CacheControl(*in.ResponseCacheControl))
		}
		if in.ResponseContentDisposition != nil {
			out.ContentDisposition = new(api.ContentDisposition(*in.ResponseContentDisposition))
		}
		if in.ResponseContentEncoding != nil {
			out.ContentEncoding = new(api.ContentEncoding(*in.ResponseContentEncoding))
		}
		if in.ResponseContentLanguage != nil {
			out.ContentLanguage = new(api.ContentLanguage(*in.ResponseContentLanguage))
		}
		if in.ResponseContentType != nil {
			out.ContentType = new(api.ContentType(*in.ResponseContentType))
		}
		if in.ResponseExpires != nil {
			out.Expires = outputExpires(in.ResponseExpires)
		}
		if b.Versioning != "" {
			out.VersionId = new(api.ObjectVersionId(record.VersionID))
		}
		if read.checksum != "" {
			out.SetChecksum(record.ChecksumAlgorithm, read.checksum)
			out.ChecksumType = new(api.ChecksumType(objectChecksumType(record)))
		}
		c.additional = map[string]any{"objectSize": record.Size, "bytesTransferredIn": 0, "bytesTransferredOut": end - start}
		s.recordObjectLock(c, record)
		if read.contentRange {
			c.additional["httpStatusCode"] = 206
		}
		return nil
	}()
	wire := wireError(err)
	if recordErr := s.recordObjectRead(ctx, c, &read.object, wire); recordErr != nil {
		return response, wireError(recordErr)
	}
	return response, wire
}

// HeadObject shares GetObject's authoritative metadata resolution and region.
func (s *Service) HeadObject(ctx context.Context, in *api.HeadObjectInput) (*ObjectResponse[api.HeadObjectOutput], *awswire.Error) {
	c := call(ctx, "HeadObject", value(in.Bucket), value(in.Key))
	response := &ObjectResponse[api.HeadObjectOutput]{}
	out := &response.Output
	err := func() error {
		var read objectRead
		err := s.repository.View(ctx, func(r Reader) error {
			var err error
			read, err = s.readObject(r, c, (*api.GetObjectInput)(in))
			return err
		})
		defer clear(read.customerKey)
		record, b, start, end := read.object, read.bucket, read.start, read.end
		response.Region = b.Region
		if record.DeleteMarker {
			out.DeleteMarker = new(api.DeleteMarker(true))
			out.VersionId = new(api.ObjectVersionId(record.VersionID))
			out.LastModified = new(record.Modified)
		}
		if err != nil {
			return err
		}
		out.ContentLength = new(api.ContentLength(end - start))
		response.BucketAccountID = b.AccountID
		out.TagCount = read.tagCount
		out.Restore = read.restore
		out.ReplicationStatus = read.replication
		out.Expiration = read.expiration
		if record.Tiering != nil && record.Tiering.ArchiveTier != "" {
			out.ArchiveStatus = new(api.ArchiveStatus(record.Tiering.ArchiveTier))
		}
		if record.StorageClass != "" {
			out.StorageClass = new(api.StorageClass(record.StorageClass))
		}
		out.PartsCount = read.partsCount
		out.ObjectLockLegalHoldStatus = read.legalHold
		if retention := read.retention; retention != nil {
			out.ObjectLockMode = (*api.ObjectLockMode)(retention.Mode)
			out.ObjectLockRetainUntilDate = retention.RetainUntilDate
			out.ObjectLockEventHold = retention.EventHold
			if period := retention.EventHoldDuration; period != nil {
				out.ObjectLockEventHoldDurationDays = (*api.ObjectLockEventHoldDurationDays)(period.Days)
				out.ObjectLockEventHoldDurationYears = (*api.ObjectLockEventHoldDurationYears)(period.Years)
			}
		}
		out.ETag = new(api.ETag(record.ETag))
		out.LastModified = new(record.Modified)
		out.ContentType = new(api.ContentType(record.ContentType))
		out.AcceptRanges = new(api.AcceptRanges("bytes"))
		out.ServerSideEncryption = sseHeader(record)
		out.SSECustomerAlgorithm, out.SSECustomerKeyMD5 = customerAlgorithm(record), customerMD5(record)
		if record.KMSKeyARN != "" {
			out.SSEKMSKeyId = new(api.SSEKMSKeyId(record.KMSKeyARN))
			response.encryptionContext = objectEncryptionContextHeader(record.EncryptionContext)
		}
		out.Metadata = outputMetadata(record)
		out.Expires = outputExpires(record.Expires)
		if read.contentRange {
			out.ContentRange = new(api.ContentRange(fmt.Sprintf("bytes %d-%d/%d", start, end-1, record.Size)))
		}
		if record.WebsiteRedirectLocation != "" {
			out.WebsiteRedirectLocation = new(api.WebsiteRedirectLocation(record.WebsiteRedirectLocation))
		}
		if record.CacheControl != "" {
			out.CacheControl = new(api.CacheControl(record.CacheControl))
		}
		if record.ContentDisposition != "" {
			out.ContentDisposition = new(api.ContentDisposition(record.ContentDisposition))
		}
		if record.ContentEncoding != "" {
			out.ContentEncoding = new(api.ContentEncoding(record.ContentEncoding))
		}
		if record.ContentLanguage != "" {
			out.ContentLanguage = new(api.ContentLanguage(record.ContentLanguage))
		}
		if in.ResponseCacheControl != nil {
			out.CacheControl = new(api.CacheControl(*in.ResponseCacheControl))
		}
		if in.ResponseContentDisposition != nil {
			out.ContentDisposition = new(api.ContentDisposition(*in.ResponseContentDisposition))
		}
		if in.ResponseContentEncoding != nil {
			out.ContentEncoding = new(api.ContentEncoding(*in.ResponseContentEncoding))
		}
		if in.ResponseContentLanguage != nil {
			out.ContentLanguage = new(api.ContentLanguage(*in.ResponseContentLanguage))
		}
		if in.ResponseContentType != nil {
			out.ContentType = new(api.ContentType(*in.ResponseContentType))
		}
		if in.ResponseExpires != nil {
			out.Expires = outputExpires(in.ResponseExpires)
		}
		if b.Versioning != "" {
			out.VersionId = new(api.ObjectVersionId(record.VersionID))
		}
		checksum := read.checksum != ""
		if checksum && record.EncryptionAlgorithm == "aws:kms" {
			key, rejected := s.objectDataKey(ctx, b, record, nil)
			clear(key)
			if rejected != nil {
				// Native Head still returns metadata when KMS denies or the key
				// is disabled, but it must not expose the stored checksum.
				if rejected.Code != "AccessDenied" && rejected.Code != "KMS.DisabledException" {
					return rejected
				}
				checksum = false
			}
		}
		if checksum {
			out.SetChecksum(record.ChecksumAlgorithm, read.checksum)
			out.ChecksumType = new(api.ChecksumType(objectChecksumType(record)))
		}
		c.additional = map[string]any{"objectSize": record.Size, "bytesTransferredIn": 0, "bytesTransferredOut": 0}
		s.recordObjectLock(c, record)
		if read.contentRange {
			c.additional["httpStatusCode"] = 206
		}
		return nil
	}()
	return response, s.complete(ctx, c, err)
}

package s3

import (
	"context"
	"encoding/base64"
	"encoding/json"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awschecksum"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

func (s *Service) copyObject(ctx context.Context, in *api.CopyObjectInput) (*preparedResponse, *awswire.Error) {
	c := s.copyCall(ctx, in)
	response := &preparedResponse{}
	storageClass, wire := parseStorageClass(in.StorageClass)
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
	var destination, sourceBucket BucketRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		destination, err = s.bucket(r, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		sourceBucket, err = s.bucket(r, sourceCall, value(in.ExpectedSourceBucketOwner))
		return err
	})
	if err != nil {
		return response, s.complete(ctx, c, err)
	}
	if wire := admitAccessPointCopy(ctx, c, sourceCall, destination, sourceBucket); wire != nil {
		return response, s.complete(ctx, c, wire)
	}
	// KMS effects are independent native API observations, outside the object
	// transaction. Destination key setup precedes source admission/decryption.
	effectContext := ctx
	if c.eventID != "" {
		m.ParentEventID = c.eventID
		effectContext = awsctx.WithMetadata(ctx, m)
	}
	record := ObjectRecord{Key: ObjectKey{Bucket: destination.Key, Name: c.key}, StorageClass: storageClass}
	encryption := encryptionHeaders{
		algorithm: in.ServerSideEncryption, keyID: in.SSEKMSKeyId, context: in.SSEKMSEncryptionContext,
		customer:  customerHeaders(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5),
		bucketKey: in.BucketKeyEnabled != nil && bool(*in.BucketKeyEnabled),
	}
	plainKey, wire := s.prepareEncryption(effectContext, destination, encryption, &record)
	if wire != nil {
		return response, s.complete(ctx, c, wire)
	}
	defer clear(plainKey)
	var admittedSequence int64
	err = s.repository.View(ctx, func(r Reader) error {
		var err error
		admittedSequence, err = writeConditions(r, record.Key, in.IfMatch, in.IfNoneMatch, true)
		return err
	})
	if err != nil {
		return response, s.complete(ctx, c, err)
	}
	if sourceBucket.Key != destination.Key {
		c.resources = append(c.resources, journal.APIEventResource{AccountID: sourceBucket.AccountID, Type: "AWS::S3::Bucket", ARN: sourceBucket.Key.ARN()})
	}
	selected, err := s.readCopySource(effectContext, sourceCall, source, sourceBucket.AccountID, in)
	if auditErr := s.recordCopySource(effectContext, c, sourceCall, &selected.object, err); auditErr != nil {
		return response, s.complete(ctx, c, auditErr)
	}
	if err != nil {
		return response, s.complete(ctx, c, err)
	}
	defer clear(selected.body)
	if selected.object.Key != record.Key {
		c.resources = append(c.resources, journal.APIEventResource{Type: "AWS::S3::Object", ARN: selected.object.Key.ARN()})
	}
	tags := selected.tags
	if value(in.TaggingDirective) == "REPLACE" {
		tags, wire = objectTagsHeader(value(in.Tagging))
		if wire != nil {
			return response, s.complete(ctx, c, wire)
		}
	}
	conditions := requestedTagConditions(tags)
	requestedStorageClass(c, conditions, in.StorageClass)
	conditions["s3:x-amz-copy-source"] = []string{value(in.CopySource)}
	requestedEncryption(c, conditions, encryption)
	if in.MetadataDirective != nil {
		conditions["s3:x-amz-metadata-directive"] = []string{value(in.MetadataDirective)}
	}
	wire = s.execute(ctx, c, func(tx Transaction) error {
		bucket, err := s.bucket(tx, c, destination.AccountID)
		if err != nil {
			return err
		}
		if record.CustomerKey != nil {
			if wire := checkCustomerEncryption(bucket); wire != nil {
				return wire
			}
		}
		requestedRetention := retentionHeaders(in.ObjectLockMode, in.ObjectLockRetainUntilDate, in.ObjectLockEventHold, in.ObjectLockEventHoldDurationDays, in.ObjectLockEventHoldDurationYears)
		if wire := s.prepareObjectLock(tx.Context(), c, bucket, &record, requestedRetention, in.ObjectLockLegalHoldStatus, conditions); wire != nil {
			return wire
		}
		var aclWire *awswire.Error
		record.ACL, aclWire = s.objectCreationACL(tx.Context(), c, bucket, c.key, value(in.ACL), aclHeaders{full: value(in.GrantFullControl), read: value(in.GrantRead), readACP: value(in.GrantReadACP), writeACP: value(in.GrantWriteACP)}, conditions)
		if aclWire != nil {
			return aclWire
		}
		if len(tags) != 0 {
			if wire := s.authorize(tx.Context(), c, bucket, "PutObjectTagging", c.key, conditions); wire != nil {
				return wire
			}
		}
		// Preflight prevents a rejected destination predicate from reading the
		// source. The write transaction owns conflict detection after external
		// key/source work; it must not overwrite an intervening object version.
		sequence, err := writeConditions(tx, record.Key, in.IfMatch, in.IfNoneMatch, true)
		if err != nil {
			wire := wireError(err)
			if wire.Code != "PreconditionFailed" && wire.Code != "NoSuchKey" {
				return err
			}
		}
		if sequence != admittedSequence {
			return failure("ConditionalRequestConflict", "A conflicting operation occurred during the conditional request.", 409)
		}
		if err != nil {
			return err
		}
		if selected.object.Key == record.Key && source.version == nil && value(in.MetadataDirective) != "REPLACE" && in.ServerSideEncryption == nil && !encryption.customer.supplied && in.StorageClass == nil && record.StorageClass == selected.object.StorageClass && in.WebsiteRedirectLocation == nil {
			return failure("InvalidRequest", "This copy request is illegal because it copies an object to itself without changing its metadata, storage class, website redirect location or encryption attributes.", 400)
		}
		if value(in.MetadataDirective) == "REPLACE" {
			if wire := setObjectMetadata(&record, in.Metadata, in.Expires); wire != nil {
				return wire
			}
			record.ContentType, record.ContentEncoding, record.ContentLanguage = value(in.ContentType), value(in.ContentEncoding), value(in.ContentLanguage)
			record.ContentDisposition, record.CacheControl = value(in.ContentDisposition), value(in.CacheControl)
			if record.ContentType == "" {
				record.ContentType = "binary/octet-stream"
			}
		} else {
			record.Metadata, record.Expires = selected.object.Metadata, selected.object.Expires
			record.ContentType, record.ContentEncoding, record.ContentLanguage = selected.object.ContentType, selected.object.ContentEncoding, selected.object.ContentLanguage
			record.ContentDisposition, record.CacheControl = selected.object.ContentDisposition, selected.object.CacheControl
		}
		// Redirects are explicit destination metadata, never inherited by COPY.
		if wire := setObjectRedirect(&record, in.WebsiteRedirectLocation); wire != nil {
			return wire
		}
		record.ChecksumAlgorithm, record.Checksum = selected.object.ChecksumAlgorithm, selected.object.Checksum
		if in.ChecksumAlgorithm != nil || record.ChecksumAlgorithm == "" || selected.object.UploadID != "" {
			if in.ChecksumAlgorithm != nil {
				record.ChecksumAlgorithm = value(in.ChecksumAlgorithm)
			}
			if record.ChecksumAlgorithm == "" {
				record.ChecksumAlgorithm = "CRC64NVME"
			}
			record.Checksum, err = awschecksum.Sum(record.ChecksumAlgorithm, selected.body)
			if err != nil {
				return unsupported(err.Error())
			}
		}
		if err := s.storeObject(tx, bucket, &record, selected.body, plainKey, tags); err != nil {
			return err
		}
		c.requestMetricTags(tags)
		out := &api.CopyObjectOutput{CopyObjectResult: copyResult(record), ServerSideEncryption: sseHeader(record), SSECustomerAlgorithm: customerAlgorithm(record), SSECustomerKeyMD5: customerMD5(record)}
		out.Expiration, err = lifecycleExpirationHeader(tx, bucket, record, tags)
		if err != nil {
			return err
		}
		c.response = encryptionResponse(record)
		if selected.object.VersionID != "null" || source.version != nil {
			out.CopySourceVersionId = new(api.CopySourceVersionId(selected.object.VersionID))
			c.response["x-amz-copy-source-version-id"] = selected.object.VersionID
		}
		if bucket.Versioning != "" {
			out.VersionId = new(api.ObjectVersionId(record.VersionID))
			c.response["x-amz-version-id"] = record.VersionID
		}
		if record.KMSKeyARN != "" {
			out.SSEKMSKeyId = new(api.SSEKMSKeyId(record.KMSKeyARN))
			c.response["x-amz-server-side-encryption-aws-kms-key-id"] = record.KMSKeyARN
		}
		if in.SSEKMSEncryptionContext != nil {
			encoded, err := json.Marshal(record.EncryptionContext)
			if err != nil {
				return err
			}
			out.SSEKMSEncryptionContext = new(api.SSEKMSEncryptionContext(base64.StdEncoding.EncodeToString(encoded)))
		}
		response.storageClass = record.StorageClass
		if err := response.prepare(c, out); err != nil {
			return err
		}
		c.additional["objectSize"] = record.Size
		s.recordObjectLock(c, record)
		noteAccessLogObject(tx.Context(), record.Size)
		c.additional["SSEApplied"] = "Default_SSE_S3"
		if in.ServerSideEncryption != nil {
			c.additional["SSEApplied"] = "SSE_S3"
		}
		if record.EncryptionAlgorithm == "aws:kms" {
			c.additional["SSEApplied"] = "SSE_KMS"
		}
		if record.CustomerKey != nil {
			c.additional["SSEApplied"] = "SSE_C"
		}
		if err := s.enqueueObjectReplication(tx, c, bucket, record, ReplicationObject); err != nil {
			return err
		}
		return s.notifyObject(tx, c, bucket, record, "ObjectCreated:Copy")
	})
	return response, wire
}

func copyResult(record ObjectRecord) *api.CopyObjectResult {
	out := &api.CopyObjectResult{ETag: new(api.ETag(record.ETag)), LastModified: new(record.Modified), ChecksumType: new(api.ChecksumType("FULL_OBJECT"))}
	out.SetChecksum(record.ChecksumAlgorithm, record.Checksum)
	return out
}

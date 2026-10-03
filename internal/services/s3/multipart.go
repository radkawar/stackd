package s3

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) multipartCall(ctx context.Context, name, bucket, key, uploadID string) *apiCall {
	c := s.transferCall(ctx, name, bucket, key)
	if uploadID == "" {
		c.params["uploads"] = ""
	} else {
		c.params["uploadId"] = uploadID
	}
	return c
}

func multipartChecksum(algorithm, kind string) (string, *awswire.Error) {
	if algorithm == "" {
		if kind != "" {
			return "", failure("InvalidRequest", "A checksum algorithm is required with the checksum type.", 400)
		}
		return "", nil
	}
	switch algorithm {
	case "CRC32", "CRC32C", "CRC64NVME", "MD5", "SHA1", "SHA256", "SHA512", "XXHASH64", "XXHASH3", "XXHASH128":
	default:
		return "", unsupported("The requested multipart checksum algorithm is not implemented.")
	}
	if kind == "" {
		kind = "COMPOSITE"
		if algorithm == "CRC64NVME" {
			kind = "FULL_OBJECT"
		}
	}
	if (algorithm == "CRC64NVME" && kind != "FULL_OBJECT") || (kind == "FULL_OBJECT" && algorithm != "CRC32" && algorithm != "CRC32C" && algorithm != "CRC64NVME") {
		return "", failure("InvalidRequest", "The checksum type is not supported for the requested algorithm.", 400)
	}
	return kind, nil
}

func (s *Service) createMultipartUpload(ctx context.Context, in *api.CreateMultipartUploadInput) (*preparedResponse, *awswire.Error) {
	c := s.multipartCall(ctx, "CreateMultipartUpload", value(in.Bucket), value(in.Key), "")
	response := &preparedResponse{}
	storageClass, wire := parseStorageClass(in.StorageClass)
	if wire != nil {
		return response, s.complete(ctx, c, wire)
	}
	tags, wire := objectTagsHeader(value(in.Tagging))
	if wire != nil {
		return response, s.complete(ctx, c, wire)
	}
	conditions := requestedTagConditions(tags)
	requestedStorageClass(c, conditions, in.StorageClass)
	if in.ACL != nil {
		c.params["x-amz-acl"] = value(in.ACL)
	}
	encryption := encryptionHeaders{
		algorithm: in.ServerSideEncryption, keyID: in.SSEKMSKeyId, context: in.SSEKMSEncryptionContext,
		customer:  customerHeaders(in.SSECustomerAlgorithm, in.SSECustomerKey, in.SSECustomerKeyMD5),
		bucketKey: in.BucketKeyEnabled != nil && bool(*in.BucketKeyEnabled),
	}
	requestedEncryption(c, conditions, encryption)
	var admitted BucketRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		admitted, err = s.bucket(r, c, value(in.ExpectedBucketOwner))
		return err
	})
	if err != nil {
		return response, s.complete(ctx, c, err)
	}
	m := awsctx.FromContext(ctx)
	upload := MultipartUploadRecord{ObjectRecord: ObjectRecord{Key: ObjectKey{admitted.Key, c.key}, StorageClass: storageClass}, Initiator: m.PrincipalARN, Tags: tags}
	if strings.HasSuffix(upload.Initiator, ":root") {
		upload.Initiator = canonicalID(m.Partition, m.AccountID)
	}
	effectContext := ctx
	if c.eventID != "" {
		m.ParentEventID = c.eventID
		effectContext = awsctx.WithMetadata(ctx, m)
	}
	plainKey, wire := s.prepareEncryption(effectContext, admitted, encryption, &upload.ObjectRecord)
	if wire != nil {
		return response, s.complete(ctx, c, wire)
	}
	defer clear(plainKey)
	wire = s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, admitted.AccountID)
		if err != nil {
			return err
		}
		if upload.CustomerKey != nil {
			if wire := checkCustomerEncryption(b); wire != nil {
				return wire
			}
		}
		requestedRetention := retentionHeaders(in.ObjectLockMode, in.ObjectLockRetainUntilDate, in.ObjectLockEventHold, in.ObjectLockEventHoldDurationDays, in.ObjectLockEventHoldDurationYears)
		if wire := s.prepareObjectLock(tx.Context(), c, b, &upload.ObjectRecord, requestedRetention, in.ObjectLockLegalHoldStatus, conditions); wire != nil {
			return wire
		}
		var aclWire *awswire.Error
		upload.ACL, aclWire = s.objectCreationACL(tx.Context(), c, b, c.key, value(in.ACL), aclHeaders{full: value(in.GrantFullControl), read: value(in.GrantRead), readACP: value(in.GrantReadACP), writeACP: value(in.GrantWriteACP)}, conditions)
		if aclWire != nil {
			return aclWire
		}
		if len(tags) != 0 {
			if wire := s.authorize(tx.Context(), c, b, "PutObjectTagging", c.key, conditions); wire != nil {
				return wire
			}
		}
		if wire := setObjectMetadata(&upload.ObjectRecord, in.Metadata, in.Expires); wire != nil {
			return wire
		}
		if wire := setObjectRedirect(&upload.ObjectRecord, in.WebsiteRedirectLocation); wire != nil {
			return wire
		}
		upload.ChecksumAlgorithm = value(in.ChecksumAlgorithm)
		var rejected *awswire.Error
		upload.ChecksumType, rejected = multipartChecksum(upload.ChecksumAlgorithm, value(in.ChecksumType))
		if rejected != nil {
			return rejected
		}
		upload.ContentType, upload.ContentEncoding, upload.ContentLanguage = value(in.ContentType), value(in.ContentEncoding), value(in.ContentLanguage)
		upload.ContentDisposition, upload.CacheControl = value(in.ContentDisposition), value(in.CacheControl)
		if upload.ContentType == "" {
			upload.ContentType = "binary/octet-stream"
		}
		upload.Modified = s.clock.Now().UTC().Truncate(time.Second)
		if err := tx.PutMultipartUpload(&upload); err != nil {
			return err
		}
		c.requestMetricTags(upload.Tags)
		out := &api.CreateMultipartUploadOutput{
			Bucket: new(api.BucketName(b.Key.Name)), Key: in.Key, UploadId: new(api.MultipartUploadId(upload.UploadID)),
			ServerSideEncryption: sseHeader(upload.ObjectRecord),
			SSECustomerAlgorithm: customerAlgorithm(upload.ObjectRecord),
			SSECustomerKeyMD5:    customerMD5(upload.ObjectRecord),
		}
		c.response = encryptionResponse(upload.ObjectRecord)
		c.additional["SSEApplied"] = "Default_SSE_S3"
		if in.ServerSideEncryption != nil {
			c.additional["SSEApplied"] = "SSE_S3"
		}
		if upload.KMSKeyARN != "" {
			out.SSEKMSKeyId = new(api.SSEKMSKeyId(upload.KMSKeyARN))
			c.additional["SSEApplied"] = "SSE_KMS"
		}
		if upload.CustomerKey != nil {
			c.additional["SSEApplied"] = "SSE_C"
		}
		if in.SSEKMSEncryptionContext != nil {
			encoded, err := json.Marshal(upload.EncryptionContext)
			if err != nil {
				return err
			}
			out.SSEKMSEncryptionContext = new(api.SSEKMSEncryptionContext(base64.StdEncoding.EncodeToString(encoded)))
		}
		if upload.ChecksumAlgorithm != "" {
			out.ChecksumAlgorithm = new(api.ChecksumAlgorithm(upload.ChecksumAlgorithm))
			out.ChecksumType = new(api.ChecksumType(upload.ChecksumType))
		}
		return response.prepare(c, out)
	})
	return response, wire
}

func (s *Service) abortMultipartUpload(ctx context.Context, in *api.AbortMultipartUploadInput) (*api.AbortMultipartUploadOutput, *awswire.Error) {
	c := s.multipartCall(ctx, "AbortMultipartUpload", value(in.Bucket), value(in.Key), value(in.UploadId))
	out := &api.AbortMultipartUploadOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "AbortMultipartUpload", c.key, nil); wire != nil {
			return wire
		}
		if in.IfMatchInitiatedTime != nil {
			return unsupported("Directory-bucket conditional abort is not implemented.")
		}
		return tx.DeleteMultipartUpload(MultipartUploadKey{ObjectKey: ObjectKey{b.Key, c.key}, UploadID: value(in.UploadId)})
	})
	return out, wire
}

func multipartUpload(r Reader, key MultipartUploadKey) (MultipartUploadRecord, error) {
	upload, err := r.MultipartUpload(key)
	if errors.Is(err, ErrNotFound) {
		return upload, noSuchMultipartUpload(key.UploadID)
	}
	return upload, err
}

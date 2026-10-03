package s3

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func encryptObject(key, body []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize(), gcm.NonceSize()+len(body)+gcm.Overhead())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, body, nil), nil
}
func decryptObject(key []byte, parts [][]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	size := 0
	for _, part := range parts {
		if len(part) < gcm.NonceSize()+gcm.Overhead() {
			return nil, errors.New("invalid encrypted object")
		}
		size += len(part) - gcm.NonceSize() - gcm.Overhead()
	}
	body := make([]byte, 0, size)
	for _, part := range parts {
		body, err = gcm.Open(body, part[:gcm.NonceSize()], part[gcm.NonceSize():], nil)
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}

// CheckPutObject evaluates an object destination without writing a probe object.
func (s *Service) CheckPutObject(ctx context.Context, bucket, key string) *awswire.Error {
	c := call(ctx, "PutObject", bucket, key)
	err := s.repository.View(ctx, func(r Reader) error {
		b, err := s.bucket(r, c, "")
		if err != nil {
			return err
		}
		var conditions map[string][]string
		if b.DefaultRetention.Mode != "" {
			now := s.clock.Now().UTC().Truncate(time.Millisecond)
			conditions = map[string][]string{}
			objectLockConditions(conditions, retentionOutput(defaultObjectRetention(b.DefaultRetention, now), now), nil, now)
		}
		if wire := s.objectWrite(r.Context(), c, b, key, "", conditions); wire != nil {
			return wire
		}
		return nil
	})
	return wireError(err)
}

func (s *Service) PutObject(ctx context.Context, in *api.PutObjectInput) (*api.PutObjectOutput, *awswire.Error) {
	response, wire := s.putObject(ctx, in, nil)
	return &response.Output, wire
}

func (s *Service) putObjectResponse(ctx context.Context, in *api.PutObjectInput) (*ObjectResponse[api.PutObjectOutput], *awswire.Error) {
	return s.putObject(ctx, in, nil)
}

// Log delivery shares object publication and authority, while applying its
// source-owned destination grants atomically with the encrypted object.
func (s *Service) putObject(ctx context.Context, in *api.PutObjectInput, logging *AccessLogDelivery) (*ObjectResponse[api.PutObjectOutput], *awswire.Error) {
	c := call(ctx, "PutObject", value(in.Bucket), value(in.Key))
	response := &ObjectResponse[api.PutObjectOutput]{}
	out := &response.Output
	storageClass, rejected := parseStorageClass(in.StorageClass)
	if rejected != nil {
		return response, s.complete(ctx, c, rejected)
	}
	if in.ACL != nil {
		c.params["x-amz-acl"] = value(in.ACL)
	}
	tags, rejected := objectTagsHeader(value(in.Tagging))
	if rejected != nil {
		return response, s.complete(ctx, c, rejected)
	}
	conditions := requestedTagConditions(tags)
	requestedStorageClass(c, conditions, in.StorageClass)
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
		if err != nil {
			return err
		}
		if logging != nil {
			return accessLogDestination(admitted, logging)
		}
		return nil
	})
	if err != nil {
		return response, s.complete(ctx, c, err)
	}
	record := ObjectRecord{Key: ObjectKey{admitted.Key, c.key}, StorageClass: storageClass}
	plainKey, rejected := s.prepareEncryption(ctx, admitted, encryption, &record)
	if rejected != nil {
		return response, s.complete(ctx, c, rejected)
	}
	defer clear(plainKey)
	wire := s.execute(ctx, c, func(tx Transaction) error {
		// KMS executes before object authorization and checksum/conditional
		// admission, outside the S3 transaction. Resolve current versioning
		// without crossing ownership if the bucket changed during that call.
		b, err := s.bucket(tx, c, admitted.AccountID)
		if err != nil {
			return err
		}
		if record.CustomerKey != nil {
			if wire := checkCustomerEncryption(b); wire != nil {
				return wire
			}
		}
		c.additional = map[string]any{"objectSize": int64(len(in.Body))}
		requestedRetention := retentionHeaders(in.ObjectLockMode, in.ObjectLockRetainUntilDate, in.ObjectLockEventHold, in.ObjectLockEventHoldDurationDays, in.ObjectLockEventHoldDurationYears)
		if wire := s.prepareObjectLock(tx.Context(), c, b, &record, requestedRetention, in.ObjectLockLegalHoldStatus, conditions); wire != nil {
			return wire
		}
		if logging != nil {
			record.ACL, rejected = s.accessLogObjectACL(tx.Context(), c, b, c.key, logging.Destination.Grants, conditions)
		} else {
			record.ACL, rejected = s.objectCreationACL(tx.Context(), c, b, c.key, value(in.ACL), aclHeaders{full: value(in.GrantFullControl), read: value(in.GrantRead), readACP: value(in.GrantReadACP), writeACP: value(in.GrantWriteACP)}, conditions)
		}
		if rejected != nil {
			return rejected
		}
		if len(tags) != 0 {
			if rejected := s.authorize(tx.Context(), c, b, "PutObjectTagging", c.key, conditions); rejected != nil {
				return rejected
			}
		}
		if in.WriteOffsetBytes != nil {
			return unsupported("Append is not implemented.")
		}
		if in.ContentLength != nil && int64(*in.ContentLength) != int64(len(in.Body)) {
			return failure("IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header.", 400)
		}
		if w := checkMD5(in.Body, value(in.ContentMD5)); w != nil {
			return w
		}
		// Required transport digests protect external uploads. Service-owned
		// publications already pass their actual bytes through this typed API.
		request, fromHTTP := awsapi.FromContext(ctx)
		requireChecksum := fromHTTP && request.Operation.Name == "PutObject" && (record.Retention.Mode != "" || record.LegalHold != "")
		algorithm, sum, w := putChecksum(in, requireChecksum)
		if w != nil {
			return w
		}
		if _, err := writeConditions(tx, record.Key, in.IfMatch, in.IfNoneMatch, false); err != nil {
			return err
		}
		if wire := setObjectMetadata(&record, in.Metadata, in.Expires); wire != nil {
			return wire
		}
		if wire := setObjectRedirect(&record, in.WebsiteRedirectLocation); wire != nil {
			return wire
		}
		record.ChecksumAlgorithm, record.Checksum = algorithm, sum
		record.ContentType, record.ContentEncoding, record.ContentLanguage = value(in.ContentType), value(in.ContentEncoding), value(in.ContentLanguage)
		record.ContentDisposition, record.CacheControl = value(in.ContentDisposition), value(in.CacheControl)
		if record.ContentType == "" {
			record.ContentType = "binary/octet-stream"
		}
		if err := s.storeObject(tx, b, &record, in.Body, plainKey, tags); err != nil {
			return err
		}
		c.requestMetricTags(tags)
		out.Expiration, err = lifecycleExpirationHeader(tx, b, record, tags)
		if err != nil {
			return err
		}
		out.ETag = new(api.ETag(record.ETag))
		if b.Versioning == "Enabled" {
			out.VersionId = new(api.ObjectVersionId(record.VersionID))
		}
		out.ServerSideEncryption = sseHeader(record)
		out.SSECustomerAlgorithm, out.SSECustomerKeyMD5 = customerAlgorithm(record), customerMD5(record)
		c.response = encryptionResponse(record)
		if out.VersionId != nil {
			c.response["x-amz-version-id"] = value(out.VersionId)
		}
		if record.KMSKeyARN != "" {
			out.SSEKMSKeyId = new(api.SSEKMSKeyId(record.KMSKeyARN))
			c.response["x-amz-server-side-encryption-aws-kms-key-id"] = record.KMSKeyARN
		}
		if in.SSEKMSEncryptionContext != nil {
			contextJSON, err := json.Marshal(record.EncryptionContext)
			if err != nil {
				return err
			}
			out.SSEKMSEncryptionContext = new(api.SSEKMSEncryptionContext(base64.StdEncoding.EncodeToString(contextJSON)))
		}
		out.SetChecksum(algorithm, sum)
		out.ChecksumType = new(api.ChecksumType("FULL_OBJECT"))
		c.additional["SSEApplied"] = "Default_SSE_S3"
		c.additional["bytesTransferredIn"] = record.Size
		c.additional["bytesTransferredOut"] = 0
		s.recordObjectLock(c, record)
		if in.ServerSideEncryption != nil {
			c.additional["SSEApplied"] = "SSE_S3"
		}
		if record.EncryptionAlgorithm == "aws:kms" {
			c.additional["SSEApplied"] = "SSE_KMS"
		}
		if record.CustomerKey != nil {
			c.additional["SSEApplied"] = "SSE_C"
		}
		// Native private and bucket-owner-full-control writes do not require
		// ACL attribution. Other explicit grants depend on ACL-enabled storage.
		acl := value(in.ACL)
		if logging == nil && ((acl != "" && acl != "private" && acl != "bucket-owner-full-control") || value(in.GrantFullControl) != "" || value(in.GrantRead) != "" || value(in.GrantReadACP) != "" || value(in.GrantWriteACP) != "") {
			c.aclRequired = true
		}
		if err := s.enqueueObjectReplication(tx, c, b, record, ReplicationObject); err != nil {
			return err
		}
		return s.notifyObject(tx, c, b, record, "ObjectCreated:Put")
	})
	if wire == nil {
		response.storageClass = record.StorageClass
		noteAccessLogObject(ctx, record.Size)
	}
	return response, wire
}
func writeConditions(r Reader, key ObjectKey, match *api.IfMatch, noneMatch *api.IfNoneMatch, copying bool) (int64, error) {
	if match == nil && noneMatch == nil {
		return 0, nil
	}
	if copying && noneMatch != nil && (match != nil || value(noneMatch) != "*") {
		return 0, unsupported("A header you provided implies functionality that is not implemented.")
	}
	previous, err := r.Object(key)
	exists := err == nil && !previous.DeleteMarker
	if err != nil && !errors.Is(err, ErrNotFound) {
		return 0, err
	}
	if copying && match != nil && !exists {
		return previous.Sequence, noSuchKey(key.Name)
	}
	if match != nil && (!exists || !etagMatches(value(match), previous.ETag)) {
		return previous.Sequence, preconditionFailed("If-Match")
	}
	if noneMatch != nil {
		if value(noneMatch) != "*" {
			return previous.Sequence, invalid("If-None-Match must be '*'.")
		}
		if exists {
			return previous.Sequence, preconditionFailed("If-None-Match")
		}
	}
	return previous.Sequence, nil
}

func preconditionFailed(condition string) *awswire.Error {
	wire := failure("PreconditionFailed", "At least one of the preconditions you specified did not hold.", 412)
	wire.Condition = condition
	return wire
}

func setObjectRedirect(record *ObjectRecord, location *api.WebsiteRedirectLocation) *awswire.Error {
	if location == nil {
		return nil
	}
	redirect := value(location)
	if !strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "http://") && !strings.HasPrefix(redirect, "https://") {
		return failure("InvalidRedirectLocation", "The website redirect location must begin with '/', 'http://', or 'https://'.", 400)
	}
	record.WebsiteRedirectLocation = redirect
	return nil
}

func setObjectMetadata(record *ObjectRecord, input api.Metadata, expires *api.Expires) *awswire.Error {
	metadata := make(map[string]string, len(input))
	size := 0
	for k, v := range input {
		name := strings.ToLower(string(k))
		size += len(name) + len(v)
		if _, ok := metadata[name]; ok {
			return invalid("Metadata keys collide ignoring case.")
		}
		if strings.ContainsAny(name+string(v), "\r\n") {
			return invalid("Invalid metadata header.")
		}
		metadata[name] = string(v)
	}
	if size > 2048 {
		return failure("MetadataTooLarge", "Your metadata headers exceed the maximum allowed metadata size.", 400)
	}
	if expires != nil {
		parsed, err := http.ParseTime(value(expires))
		if err != nil {
			return invalid("Expires must be a valid HTTP date.")
		}
		record.Expires = &parsed
	}
	record.Metadata = metadata
	return nil
}

// storeObject creates encrypted content, its version and tags in the caller's
// transaction. Both uploads and copies publish only after these writes succeed.
func (s *Service) storeObject(tx Transaction, b BucketRecord, record *ObjectRecord, body, plainKey []byte, tags []Tag) error {
	record.ChecksumType = "FULL_OBJECT"
	data, err := encryptObject(plainKey, body)
	if err != nil {
		return err
	}
	etagBody := body
	if record.EncryptionAlgorithm == "aws:kms" || record.CustomerKey != nil {
		etagBody = data
	}
	sum := md5.Sum(etagBody)
	now := s.clock.Now().UTC()
	record.Modified, record.Size = now.Truncate(time.Second), int64(len(body))
	record.ETag = "\"" + hex.EncodeToString(sum[:]) + "\""
	initializeObjectTiering(record, now)
	record.VersionID, err = issueVersion(b.Versioning)
	if err != nil {
		return err
	}
	record.Sequence, err = tx.PutObject(*record, data)
	record.CreatedOrder = record.Sequence
	if err != nil {
		return err
	}
	if len(tags) != 0 {
		return tx.ReplaceObjectTags(record.VersionKey(), tags)
	}
	return nil
}

func etagMatches(condition, etag string) bool {
	for _, candidate := range strings.Split(condition, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
}

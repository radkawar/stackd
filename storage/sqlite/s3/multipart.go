package s3

import (
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) MultipartUpload(key domain.MultipartUploadKey) (domain.MultipartUploadRecord, error) {
	row, err := r.q.GetMultipartUpload(r.ctx, sqlcgen.GetMultipartUploadParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: key.UploadID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MultipartUploadRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.MultipartUploadRecord{}, err
	}
	out, err := r.multipartUpload(row)
	if err != nil {
		return domain.MultipartUploadRecord{}, err
	}
	encryption, err := r.q.GetMultipartUploadEncryptionMetadata(r.ctx, sqlcgen.GetMultipartUploadEncryptionMetadataParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: key.UploadID,
	})
	if err != nil {
		return domain.MultipartUploadRecord{}, err
	}
	if out.EncryptionAlgorithm == "SSE-C" {
		out.CustomerKey = &domain.CustomerKeyVerifier{
			Salt: encryption.CustomerKeySalt, Hash: encryption.CustomerKeyHash, MD5: encryption.CustomerKeyMd5,
		}
	} else {
		out.EncryptionKey = encryption.EncryptionKey
	}
	return out, nil
}

func (r reader) multipartUpload(row sqlcgen.S3MultipartUpload) (domain.MultipartUploadRecord, error) {
	out := domain.MultipartUploadRecord{
		ObjectRecord: domain.ObjectRecord{
			Key:      domain.ObjectKey{Bucket: domain.BucketKey{Partition: row.Partition, Name: row.BucketName}, Name: row.ObjectName},
			UploadID: row.UploadID, CreatedOrder: row.CreatedOrder, Modified: row.Modified,
			Size: row.Size, ETag: row.Etag, ChecksumAlgorithm: row.ChecksumAlgorithm, Checksum: row.Checksum, ChecksumType: row.ChecksumType,
			StorageClass: row.StorageClass,
			ContentType:  row.ContentType, ContentEncoding: row.ContentEncoding, ContentLanguage: row.ContentLanguage,
			ContentDisposition: row.ContentDisposition, CacheControl: row.CacheControl, Expires: row.Expires,
			WebsiteRedirectLocation: row.WebsiteRedirectLocation,
			EncryptionAlgorithm:     row.EncryptionAlgorithm, KMSKeyARN: row.KmsKeyArn,
			Retention: domain.ObjectRetention{
				Mode: row.RetentionMode, RetainUntil: row.RetainUntil.Time, EventHold: row.EventHold, Modified: row.RetentionModified.Time,
				EventHoldDuration: domain.RetentionPeriod{Days: int32(row.EventHoldDays), Years: int32(row.EventHoldYears)},
			},
			LegalHold: row.LegalHold, LegalHoldModified: row.LegalHoldModified.Time,
		},
		Initiator: row.Initiator, Superseded: row.Superseded,
	}
	acl, err := r.multipartACL(row)
	if err != nil {
		return domain.MultipartUploadRecord{}, err
	}
	out.ACL = acl
	metadata, err := r.q.GetMultipartUploadMetadata(r.ctx, sqlcgen.GetMultipartUploadMetadataParams{
		Partition: row.Partition, BucketName: row.BucketName, ObjectName: row.ObjectName, UploadID: row.UploadID,
	})
	if err != nil {
		return domain.MultipartUploadRecord{}, err
	}
	if len(metadata) > 0 {
		out.Metadata = make(map[string]string, len(metadata))
		for _, entry := range metadata {
			out.Metadata[entry.Key] = entry.Value
		}
	}
	tags, err := r.q.GetMultipartUploadTags(r.ctx, sqlcgen.GetMultipartUploadTagsParams{
		Partition: row.Partition, BucketName: row.BucketName, ObjectName: row.ObjectName, UploadID: row.UploadID,
	})
	if err != nil {
		return domain.MultipartUploadRecord{}, err
	}
	out.Tags = make([]domain.Tag, 0, len(tags))
	for _, tag := range tags {
		out.Tags = append(out.Tags, domain.Tag{Key: tag.Key, Value: tag.Value})
	}
	encryptionContext, err := r.q.GetMultipartUploadEncryptionContext(r.ctx, sqlcgen.GetMultipartUploadEncryptionContextParams{
		Partition: row.Partition, BucketName: row.BucketName, ObjectName: row.ObjectName, UploadID: row.UploadID,
	})
	if err != nil {
		return domain.MultipartUploadRecord{}, err
	}
	if len(encryptionContext) > 0 {
		out.EncryptionContext = make(map[string]string, len(encryptionContext))
		for _, entry := range encryptionContext {
			out.EncryptionContext[entry.Key] = entry.Value
		}
	}
	return out, nil
}

func (r reader) MultipartUploads(query domain.MultipartQuery) ([]domain.MultipartUploadRecord, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if query.Limit <= 0 {
		return []domain.MultipartUploadRecord{}, nil
	}
	var after sql.NullInt64
	if query.AfterOrder != nil {
		after = sql.NullInt64{Int64: *query.AfterOrder, Valid: true}
	}
	rows, err := r.q.ListMultipartUploads(r.ctx, sqlcgen.ListMultipartUploadsParams{
		Partition: query.Bucket.Partition, BucketName: query.Bucket.Name, Prefix: []byte(query.Prefix),
		AfterKey: query.AfterKey, AfterOrder: after, RowLimit: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.MultipartUploadRecord, 0, len(rows))
	for _, row := range rows {
		upload, err := r.multipartUpload(row)
		if err != nil {
			return nil, err
		}
		out = append(out, upload)
	}
	return out, nil
}

func (r reader) MultipartParts(key domain.MultipartUploadKey, after int32, limit int) ([]domain.PartRecord, error) {
	if _, err := r.q.GetMultipartUpload(r.ctx, sqlcgen.GetMultipartUploadParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: key.UploadID,
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	if limit <= 0 {
		return []domain.PartRecord{}, nil
	}
	rows, err := r.q.ListMultipartParts(r.ctx, sqlcgen.ListMultipartPartsParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name,
		UploadID: sql.NullString{String: key.UploadID, Valid: true}, AfterNumber: int64(after), RowLimit: int64(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PartRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.PartRecord{Number: int32(row.Number), Modified: row.Modified, Size: row.Size, ETag: row.Etag, Checksum: row.Checksum})
	}
	return out, nil
}

func (r reader) ObjectParts(key domain.ObjectVersionKey) ([]domain.PartRecord, error) {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	version, err := r.q.GetObjectVersion(r.ctx, sqlcgen.GetObjectVersionParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: key.VersionID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if version.UploadID == "" {
		return []domain.PartRecord{}, nil
	}
	rows, err := r.q.ListObjectParts(r.ctx, sqlcgen.ListObjectPartsParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name,
		VersionID: sql.NullString{String: key.VersionID, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PartRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.PartRecord{Number: int32(row.Number), Modified: row.Modified, Size: row.Size, ETag: row.Etag, Checksum: row.Checksum})
	}
	return out, nil
}

func (r reader) CompletedMultipartUpload(key domain.MultipartUploadKey) (domain.ObjectRecord, error) {
	row, err := r.q.GetCompletedMultipartUpload(r.ctx, sqlcgen.GetCompletedMultipartUploadParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, UploadID: key.UploadID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ObjectRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ObjectRecord{}, err
	}
	return r.objectWithKey(row)
}

func (w writer) PutMultipartUpload(v *domain.MultipartUploadRecord) error {
	key := v.Key
	bucket, err := w.q.GetBucket(w.ctx, sqlcgen.GetBucketParams{Partition: key.Bucket.Partition, Name: key.Bucket.Name})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrNotFound
		}
		return err
	}
	acl := v.ACL
	if acl == nil {
		acl = domain.DefaultACL(key.Bucket.Partition, bucket.AccountID)
	}
	order, err := w.q.NextObjectSequence(w.ctx)
	if err != nil {
		return err
	}
	if err := v.AssignInitiation(order); err != nil {
		return err
	}
	if err := w.q.PutMultipartUpload(w.ctx, sqlcgen.PutMultipartUploadParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: v.UploadID,
		CreatedOrder: order, Modified: v.Modified, Initiator: v.Initiator, Superseded: v.Superseded,
		Size: v.Size, Etag: v.ETag, ChecksumAlgorithm: v.ChecksumAlgorithm, Checksum: v.Checksum, ChecksumType: v.ChecksumType,
		StorageClass: v.StorageClass,
		ContentType:  v.ContentType, ContentEncoding: v.ContentEncoding, ContentLanguage: v.ContentLanguage,
		ContentDisposition: v.ContentDisposition, CacheControl: v.CacheControl, Expires: v.Expires,
		WebsiteRedirectLocation: v.WebsiteRedirectLocation, EncryptionAlgorithm: v.EncryptionAlgorithm, KmsKeyArn: v.KMSKeyARN,
		OwnerAccountID: acl.OwnerAccountID, OwnerID: acl.OwnerID,
		RetentionMode: v.Retention.Mode, RetainUntil: objectLockTime(v.Retention.RetainUntil), EventHold: v.Retention.EventHold,
		EventHoldDays: int64(v.Retention.EventHoldDuration.Days), EventHoldYears: int64(v.Retention.EventHoldDuration.Years),
		LegalHold: v.LegalHold, LegalHoldModified: objectLockTime(v.LegalHoldModified), RetentionModified: objectLockTime(v.Retention.Modified),
	}); err != nil {
		return err
	}
	for position, grant := range acl.Grants {
		if err := w.q.PutMultipartUploadACLGrant(w.ctx, sqlcgen.PutMultipartUploadACLGrantParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: v.UploadID, Position: int64(position),
			GranteeType: grant.Type, GranteeID: grant.ID, GranteeUri: grant.URI, Permission: grant.Permission,
		}); err != nil {
			return err
		}
	}
	for name, value := range v.Metadata {
		if err := w.q.PutMultipartUploadMetadata(w.ctx, sqlcgen.PutMultipartUploadMetadataParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: v.UploadID, Key: name, Value: value,
		}); err != nil {
			return err
		}
	}
	for _, tag := range v.Tags {
		if err := w.q.PutMultipartUploadTag(w.ctx, sqlcgen.PutMultipartUploadTagParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: v.UploadID, Key: tag.Key, Value: tag.Value,
		}); err != nil {
			return err
		}
	}
	for name, value := range v.EncryptionContext {
		if err := w.q.PutMultipartUploadEncryptionContext(w.ctx, sqlcgen.PutMultipartUploadEncryptionContextParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: v.UploadID, Key: name, Value: value,
		}); err != nil {
			return err
		}
	}
	encryptionKey, customerSalt, customerHash, customerMD5 := encryptionMetadata(v.ObjectRecord)
	return w.q.PutMultipartUploadEncryptionMetadata(w.ctx, sqlcgen.PutMultipartUploadEncryptionMetadataParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: v.UploadID, EncryptionKey: encryptionKey,
		CustomerKeySalt: customerSalt, CustomerKeyHash: customerHash, CustomerKeyMd5: customerMD5,
	})
}

func (w writer) PutMultipartPart(key domain.MultipartUploadKey, part domain.PartRecord, data []byte) error {
	if _, err := w.q.GetMultipartUpload(w.ctx, sqlcgen.GetMultipartUploadParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: key.UploadID,
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrNotFound
		}
		return err
	}
	if data == nil {
		data = []byte{}
	}
	return w.q.PutMultipartPart(w.ctx, sqlcgen.PutMultipartPartParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name,
		UploadID: sql.NullString{String: key.UploadID, Valid: true}, Number: int64(part.Number),
		Modified: part.Modified, Size: part.Size, Etag: part.ETag, Checksum: part.Checksum, Ciphertext: data,
	})
}

func (w writer) DeleteMultipartUpload(key domain.MultipartUploadKey) error {
	return w.q.DeleteMultipartUpload(w.ctx, sqlcgen.DeleteMultipartUploadParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: key.UploadID,
	})
}

func (w writer) CompleteMultipartUpload(key domain.MultipartUploadKey, object domain.ObjectRecord, selected []int32, retain bool) (int64, error) {
	upload, err := w.q.GetMultipartUpload(w.ctx, sqlcgen.GetMultipartUploadParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, UploadID: key.UploadID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, domain.ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	object.ACL, err = w.multipartACL(upload)
	if err != nil {
		return 0, err
	}
	if object.VersionID == "" {
		object.VersionID = "null"
	}
	var sequence int64
	if retain {
		object.Key = key.ObjectKey
		object.UploadID = key.UploadID
		object.CreatedOrder = upload.CreatedOrder
		object.Modified = upload.Modified
		object.StorageClass = upload.StorageClass
		// Publication retains the initiation ACL, not the completing caller's ACL.
		// The ordinary data row retains only encryption metadata. Multipart
		// ciphertext stays in place while its ownership moves to this version.
		sequence, err = w.PutObject(object, nil)
		if err != nil {
			return 0, err
		}
		for _, number := range selected {
			count, err := w.q.PublishMultipartPart(w.ctx, sqlcgen.PublishMultipartPartParams{
				Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name,
				UploadID:  sql.NullString{String: key.UploadID, Valid: true},
				VersionID: sql.NullString{String: object.VersionID, Valid: true}, Number: int64(number),
			})
			if err != nil {
				return 0, err
			}
			if count != 1 {
				return 0, domain.ErrNotFound
			}
		}
		if err := w.q.PublishMultipartUploadTags(w.ctx, sqlcgen.PublishMultipartUploadTagsParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name,
			UploadID: key.UploadID, VersionID: object.VersionID,
		}); err != nil {
			return 0, err
		}
	} else {
		sequence, err = w.q.NextObjectSequence(w.ctx)
		if err != nil {
			return 0, err
		}
	}
	// Unselected pending parts cascade; selected published parts no longer
	// reference the upload and survive until their object version is removed.
	return sequence, w.DeleteMultipartUpload(key)
}

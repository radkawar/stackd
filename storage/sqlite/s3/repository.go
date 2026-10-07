// Package s3 persists partition-wide S3 buckets and encrypted object histories.
package s3

import (
	"context"
	"database/sql"
	"errors"

	domain "stackd/storage/s3"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{ctx: ctx, q: sqlcgen.New(tx)})
	})
}

func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: sqlcgen.New(tx)}})
	})
}

func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{ctx: ctx, q: sqlcgen.New(tx)}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}

type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }

func (r reader) AccessPoint(key domain.AccessPointKey) (domain.AccessPointRecord, error) {
	row, err := r.q.GetAccessPoint(r.ctx, sqlcgen.GetAccessPointParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AccessPointRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AccessPointRecord{}, err
	}
	return r.accessPoint(row)
}

func (r reader) AccessPointAlias(partition, alias string) (domain.AccessPointRecord, error) {
	row, err := r.q.GetAccessPointAlias(r.ctx, sqlcgen.GetAccessPointAliasParams{Partition: partition, Alias: alias})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AccessPointRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AccessPointRecord{}, err
	}
	return r.accessPoint(row)
}

func (r reader) accessPoint(row sqlcgen.S3AccessPoint) (domain.AccessPointRecord, error) {
	out := domain.AccessPointRecord{
		Key:   domain.AccessPointKey{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, Name: row.Name},
		Alias: row.Alias, Bucket: domain.BucketKey{Partition: row.BucketPartition, Name: row.BucketName},
		BucketAccountID: row.BucketAccountID, Created: row.Created, VPCID: row.VpcID,
		CloudFormationOwner: row.CloudformationOwner,
		PublicAccess: domain.PublicAccessBlock{
			BlockPublicACLs: row.BlockPublicAcls, IgnorePublicACLs: row.IgnorePublicAcls,
			BlockPublicPolicy: row.BlockPublicPolicy, RestrictPublicBuckets: row.RestrictPublicBuckets,
		},
	}
	out.Policy.Document = row.PolicyDocument
	out.Policy.TrustPolicy = row.PolicyTrust
	principals, err := r.q.GetAccessPointPolicyPrincipals(r.ctx, sqlcgen.GetAccessPointPolicyPrincipalsParams{
		Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, AccessPointName: row.Name,
	})
	if err != nil {
		return domain.AccessPointRecord{}, err
	}
	if len(principals) > 0 {
		out.Policy.PrincipalIDs = make(map[string]string, len(principals))
		for _, principal := range principals {
			out.Policy.PrincipalIDs[principal.Principal] = principal.PrincipalID
		}
	}
	return out, nil
}

func (r reader) AccessPoints(query domain.AccessPointQuery) ([]domain.AccessPointRecord, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if query.Limit <= 0 {
		return []domain.AccessPointRecord{}, nil
	}
	rows, err := r.q.ListAccessPoints(r.ctx, sqlcgen.ListAccessPointsParams{
		Partition: query.Partition, AccountID: query.AccountID, Region: query.Region,
		AfterName: query.After, BucketName: query.Bucket, RowLimit: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AccessPointRecord, 0, len(rows))
	for _, row := range rows {
		point, err := r.accessPoint(row)
		if err != nil {
			return nil, err
		}
		out = append(out, point)
	}
	return out, nil
}

func (r reader) AccessPointCount(partition, accountID, region string) (int, error) {
	count, err := r.q.CountAccessPoints(r.ctx, sqlcgen.CountAccessPointsParams{Partition: partition, AccountID: accountID, Region: region})
	return int(count), err
}

func (r reader) AccessPointTags(key domain.AccessPointKey) ([]domain.Tag, error) {
	if _, err := r.q.GetAccessPoint(r.ctx, sqlcgen.GetAccessPointParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name,
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	rows, err := r.q.GetAccessPointTags(r.ctx, sqlcgen.GetAccessPointTagsParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, AccessPointName: key.Name,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Tag, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.Tag{Key: row.Key, Value: row.Value})
	}
	return out, nil
}

func (w writer) PutAccessPoint(v domain.AccessPointRecord) error {
	key := v.Key
	if err := w.q.PutAccessPoint(w.ctx, sqlcgen.PutAccessPointParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name,
		Alias: v.Alias, BucketPartition: v.Bucket.Partition, BucketName: v.Bucket.Name,
		BucketAccountID: v.BucketAccountID, Created: v.Created, VpcID: v.VPCID,
		BlockPublicAcls: v.PublicAccess.BlockPublicACLs, IgnorePublicAcls: v.PublicAccess.IgnorePublicACLs,
		BlockPublicPolicy: v.PublicAccess.BlockPublicPolicy, RestrictPublicBuckets: v.PublicAccess.RestrictPublicBuckets,
		PolicyDocument: v.Policy.Document, PolicyTrust: v.Policy.TrustPolicy,
		CloudformationOwner: v.CloudFormationOwner,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteAccessPointPolicyPrincipals(w.ctx, sqlcgen.DeleteAccessPointPolicyPrincipalsParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, AccessPointName: key.Name,
	}); err != nil {
		return err
	}
	for principal, id := range v.Policy.PrincipalIDs {
		if err := w.q.PutAccessPointPolicyPrincipal(w.ctx, sqlcgen.PutAccessPointPolicyPrincipalParams{
			Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, AccessPointName: key.Name,
			Principal: principal, PrincipalID: id,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteAccessPoint(key domain.AccessPointKey) error {
	count, err := w.q.DeleteAccessPoint(w.ctx, sqlcgen.DeleteAccessPointParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (w writer) PutAccessPointTags(key domain.AccessPointKey, tags []domain.Tag) error {
	if _, err := w.q.GetAccessPoint(w.ctx, sqlcgen.GetAccessPointParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, Name: key.Name,
	}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrNotFound
		}
		return err
	}
	if err := w.q.DeleteAccessPointTags(w.ctx, sqlcgen.DeleteAccessPointTagsParams{
		Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, AccessPointName: key.Name,
	}); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := w.q.PutAccessPointTag(w.ctx, sqlcgen.PutAccessPointTagParams{
			Partition: key.Partition, AccountID: key.AccountID, Region: key.Region, AccessPointName: key.Name,
			Key: tag.Key, Value: tag.Value,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) AccountPublicAccessBlock(partition, accountID string) (*domain.PublicAccessBlock, error) {
	row, err := r.q.GetAccountPublicAccessBlock(r.ctx, sqlcgen.GetAccountPublicAccessBlockParams{Partition: partition, AccountID: accountID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &domain.PublicAccessBlock{
		BlockPublicACLs: row.BlockPublicAcls, IgnorePublicACLs: row.IgnorePublicAcls,
		BlockPublicPolicy: row.BlockPublicPolicy, RestrictPublicBuckets: row.RestrictPublicBuckets,
	}, nil
}

func (w writer) PutAccountPublicAccessBlock(partition, accountID string, block domain.PublicAccessBlock) error {
	return w.q.PutAccountPublicAccessBlock(w.ctx, sqlcgen.PutAccountPublicAccessBlockParams{
		Partition: partition, AccountID: accountID,
		BlockPublicAcls: block.BlockPublicACLs, IgnorePublicAcls: block.IgnorePublicACLs,
		BlockPublicPolicy: block.BlockPublicPolicy, RestrictPublicBuckets: block.RestrictPublicBuckets,
	})
}

func (w writer) DeleteAccountPublicAccessBlock(partition, accountID string) error {
	return w.q.DeleteAccountPublicAccessBlock(w.ctx, sqlcgen.DeleteAccountPublicAccessBlockParams{Partition: partition, AccountID: accountID})
}

func (r reader) Bucket(key domain.BucketKey) (domain.BucketRecord, error) {
	row, err := r.q.GetBucket(r.ctx, sqlcgen.GetBucketParams{Partition: key.Partition, Name: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.BucketRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.BucketRecord{}, err
	}
	return r.bucket(row)
}

func (r reader) bucket(row sqlcgen.S3Bucket) (domain.BucketRecord, error) {
	out := domain.BucketRecord{
		Key:       domain.BucketKey{Partition: row.Partition, Name: row.Name},
		AccountID: row.AccountID, Region: row.Region, Created: row.Created, Ownership: row.Ownership, Versioning: row.Versioning,
		Incarnation:         row.Incarnation,
		CloudFormationOwner: row.CloudformationOwner, PolicyOwner: row.PolicyOwner,
		EncryptionAlgorithm: row.EncryptionAlgorithm, KMSKeyID: row.KmsKeyID,
		BucketKeyEnabled:   row.BucketKeyEnabled,
		SSECustomerBlocked: row.SseCustomerBlocked,
		RequesterPays:      row.RequesterPays,
		ABACEnabled:        row.AbacEnabled,
		AccelerationStatus: row.AccelerationStatus,
		ObjectLockEnabled:  row.ObjectLockEnabled,
		DefaultRetention: domain.DefaultRetention{
			Mode:      row.DefaultRetentionMode,
			Period:    domain.RetentionPeriod{Days: int32(row.DefaultRetentionDays), Years: int32(row.DefaultRetentionYears)},
			EventHold: domain.RetentionPeriod{Days: int32(row.DefaultEventHoldDays), Years: int32(row.DefaultEventHoldYears)},
		},
	}
	acl, err := r.bucketACL(row)
	if err != nil {
		return domain.BucketRecord{}, err
	}
	out.ACL = acl
	out.Policy.Document = row.PolicyDocument
	out.Policy.TrustPolicy = row.PolicyTrust
	principals, err := r.q.GetBucketPolicyPrincipals(r.ctx, sqlcgen.GetBucketPolicyPrincipalsParams{Partition: row.Partition, BucketName: row.Name})
	if err != nil {
		return domain.BucketRecord{}, err
	}
	if len(principals) > 0 {
		out.Policy.PrincipalIDs = make(map[string]string, len(principals))
		for _, principal := range principals {
			out.Policy.PrincipalIDs[principal.Principal] = principal.PrincipalID
		}
	}
	access, err := r.q.GetBucketPublicAccess(r.ctx, sqlcgen.GetBucketPublicAccessParams{Partition: row.Partition, BucketName: row.Name})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return domain.BucketRecord{}, err
	}
	if err == nil {
		out.PublicAccess = &domain.PublicAccessBlock{
			BlockPublicACLs: access.BlockPublicAcls, IgnorePublicACLs: access.IgnorePublicAcls,
			BlockPublicPolicy: access.BlockPublicPolicy, RestrictPublicBuckets: access.RestrictPublicBuckets,
		}
	}
	return out, nil
}

func (r reader) Buckets(partition, accountID string) ([]domain.BucketRecord, error) {
	rows, err := r.q.ListBuckets(r.ctx, sqlcgen.ListBucketsParams{Partition: partition, AccountID: accountID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.BucketRecord, 0, len(rows))
	for _, row := range rows {
		bucket, err := r.bucket(row)
		if err != nil {
			return nil, err
		}
		out = append(out, bucket)
	}
	return out, nil
}

func (r reader) BucketTags(key domain.BucketKey) ([]domain.Tag, error) {
	rows, err := r.q.GetBucketTags(r.ctx, sqlcgen.GetBucketTagsParams{Partition: key.Partition, BucketName: key.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Tag, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.Tag{Key: row.Key, Value: row.Value})
	}
	return out, nil
}

func (w writer) ReplaceBucketTags(key domain.BucketKey, tags []domain.Tag) error {
	if err := w.q.DeleteBucketTags(w.ctx, sqlcgen.DeleteBucketTagsParams{Partition: key.Partition, BucketName: key.Name}); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := w.q.PutBucketTag(w.ctx, sqlcgen.PutBucketTagParams{
			Partition: key.Partition, BucketName: key.Name, Key: tag.Key, Value: tag.Value,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) Object(key domain.ObjectKey) (domain.ObjectRecord, error) {
	row, err := r.q.GetObject(r.ctx, sqlcgen.GetObjectParams{Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ObjectRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ObjectRecord{}, err
	}
	return r.objectWithKey(row)
}

func (r reader) ObjectVersion(key domain.ObjectVersionKey) (domain.ObjectRecord, error) {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	row, err := r.q.GetObjectVersion(r.ctx, sqlcgen.GetObjectVersionParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: key.VersionID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ObjectRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ObjectRecord{}, err
	}
	return r.objectWithKey(row)
}

func (r reader) objectWithKey(row sqlcgen.S3ObjectVersion) (domain.ObjectRecord, error) {
	out, err := r.object(row)
	if err != nil {
		return domain.ObjectRecord{}, err
	}
	encryption, err := r.q.GetObjectVersionEncryptionMetadata(r.ctx, sqlcgen.GetObjectVersionEncryptionMetadataParams{
		Partition: row.Partition, BucketName: row.BucketName, ObjectName: row.Name, VersionID: row.VersionID,
	})
	if err != nil {
		return domain.ObjectRecord{}, err
	}
	if row.EncryptionAlgorithm == "SSE-C" {
		out.CustomerKey = &domain.CustomerKeyVerifier{
			Salt: encryption.CustomerKeySalt, Hash: encryption.CustomerKeyHash, MD5: encryption.CustomerKeyMd5,
		}
	} else {
		out.EncryptionKey = encryption.EncryptionKey
	}
	if row.EncryptionAlgorithm != "aws:kms" {
		return out, nil
	}
	encryptionContext, err := r.q.GetObjectVersionEncryptionContext(r.ctx, sqlcgen.GetObjectVersionEncryptionContextParams{
		Partition: row.Partition, BucketName: row.BucketName, ObjectName: row.Name, VersionID: row.VersionID,
	})
	if err != nil {
		return domain.ObjectRecord{}, err
	}
	if len(encryptionContext) > 0 {
		out.EncryptionContext = make(map[string]string, len(encryptionContext))
		for _, entry := range encryptionContext {
			out.EncryptionContext[entry.Key] = entry.Value
		}
	}
	return out, nil
}

func (r reader) object(row sqlcgen.S3ObjectVersion) (domain.ObjectRecord, error) {
	out := domain.ObjectRecord{
		Key:       domain.ObjectKey{Bucket: domain.BucketKey{Partition: row.Partition, Name: row.BucketName}, Name: row.Name},
		VersionID: row.VersionID, Sequence: row.Sequence, CreatedOrder: row.CreatedOrder, UploadID: row.UploadID, DeleteMarker: row.DeleteMarker,
		Modified: row.Modified, Size: row.Size, ETag: row.Etag, ChecksumAlgorithm: row.ChecksumAlgorithm, Checksum: row.Checksum, ChecksumType: row.ChecksumType,
		MultipartChecksumExplicit: row.MultipartChecksumExplicit,
		StorageClass:              row.StorageClass,
		Replica:                   row.Replica,
		ContentType:               row.ContentType, ContentEncoding: row.ContentEncoding, ContentLanguage: row.ContentLanguage,
		ContentDisposition: row.ContentDisposition, CacheControl: row.CacheControl, Expires: row.Expires,
		WebsiteRedirectLocation: row.WebsiteRedirectLocation,
		EncryptionAlgorithm:     row.EncryptionAlgorithm, KMSKeyARN: row.KmsKeyArn,
		Retention: domain.ObjectRetention{
			Mode: row.RetentionMode, RetainUntil: row.RetainUntil.Time, EventHold: row.EventHold, Modified: row.RetentionModified.Time,
			EventHoldDuration: domain.RetentionPeriod{Days: int32(row.EventHoldDays), Years: int32(row.EventHoldYears)},
		},
		LegalHold: row.LegalHold, LegalHoldModified: row.LegalHoldModified.Time,
	}
	if row.TieringAccessed != nil {
		out.Tiering = &domain.ObjectTiering{Accessed: *row.TieringAccessed, ArchiveTier: domain.AccessTier(row.ArchiveTier)}
	}
	acl, err := r.objectACL(row)
	if err != nil {
		return domain.ObjectRecord{}, err
	}
	out.ACL = acl
	metadata, err := r.q.GetObjectVersionMetadata(r.ctx, sqlcgen.GetObjectVersionMetadataParams{Partition: row.Partition, BucketName: row.BucketName, ObjectName: row.Name, VersionID: row.VersionID})
	if err != nil {
		return domain.ObjectRecord{}, err
	}
	if len(metadata) > 0 {
		out.Metadata = make(map[string]string, len(metadata))
		for _, header := range metadata {
			out.Metadata[header.Key] = header.Value
		}
	}
	return out, nil
}

func (r reader) Objects(query domain.ObjectQuery) ([]domain.ObjectRecord, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if query.Limit <= 0 {
		return []domain.ObjectRecord{}, nil
	}
	rows, err := r.q.ListObjects(r.ctx, sqlcgen.ListObjectsParams{
		Partition: query.Bucket.Partition, BucketName: query.Bucket.Name,
		AfterKey: query.After, Prefix: []byte(query.Prefix), RowLimit: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ObjectRecord, 0, len(rows))
	for _, row := range rows {
		object, err := r.object(row)
		if err != nil {
			return nil, err
		}
		out = append(out, object)
	}
	return out, nil
}

func (r reader) ObjectVersions(query domain.VersionQuery) ([]domain.ObjectRecord, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if query.Limit <= 0 {
		return []domain.ObjectRecord{}, nil
	}
	var after sql.NullInt64
	if query.AfterOrder != nil {
		after = sql.NullInt64{Int64: *query.AfterOrder, Valid: true}
	}
	rows, err := r.q.ListObjectVersions(r.ctx, sqlcgen.ListObjectVersionsParams{
		Partition: query.Bucket.Partition, BucketName: query.Bucket.Name,
		AfterKey: query.AfterKey, AfterVersion: query.AfterVersion, Prefix: []byte(query.Prefix), RowLimit: int64(query.Limit),
		AfterOrder: after,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ObjectRecord, 0, len(rows))
	for _, row := range rows {
		object, err := r.object(row)
		if err != nil {
			return nil, err
		}
		out = append(out, object)
	}
	return out, nil
}

func (r reader) ObjectData(key domain.ObjectVersionKey) ([][]byte, error) {
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
	if version.UploadID != "" {
		return r.q.GetMultipartObjectData(r.ctx, sqlcgen.GetMultipartObjectDataParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name,
			VersionID: sql.NullString{String: key.VersionID, Valid: true},
		})
	}
	out, err := r.q.GetObjectVersionData(r.ctx, sqlcgen.GetObjectVersionDataParams{Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return [][]byte{out}, nil
}

func (w writer) PutBucket(v domain.BucketRecord) error {
	key := v.Key
	acl := v.ACL
	if acl == nil {
		acl = domain.DefaultACL(key.Partition, v.AccountID)
	}
	if err := w.q.PutBucket(w.ctx, sqlcgen.PutBucketParams{
		Partition: key.Partition, Name: key.Name, AccountID: v.AccountID, Region: v.Region,
		Incarnation: v.Incarnation, CloudformationOwner: v.CloudFormationOwner, PolicyOwner: v.PolicyOwner,
		Created: v.Created, PolicyDocument: v.Policy.Document, PolicyTrust: v.Policy.TrustPolicy, Ownership: v.Ownership, Versioning: v.Versioning,
		EncryptionAlgorithm: v.EncryptionAlgorithm, KmsKeyID: v.KMSKeyID,
		BucketKeyEnabled:   v.BucketKeyEnabled,
		SseCustomerBlocked: v.SSECustomerBlocked,
		RequesterPays:      v.RequesterPays,
		AbacEnabled:        v.ABACEnabled,
		AccelerationStatus: v.AccelerationStatus,
		OwnerAccountID:     acl.OwnerAccountID, OwnerID: acl.OwnerID,
		ObjectLockEnabled: v.ObjectLockEnabled, DefaultRetentionMode: v.DefaultRetention.Mode,
		DefaultRetentionDays: int64(v.DefaultRetention.Period.Days), DefaultRetentionYears: int64(v.DefaultRetention.Period.Years),
		DefaultEventHoldDays: int64(v.DefaultRetention.EventHold.Days), DefaultEventHoldYears: int64(v.DefaultRetention.EventHold.Years),
	}); err != nil {
		return err
	}
	if err := w.putBucketACLGrants(key, *acl); err != nil {
		return err
	}
	if err := w.q.DeleteBucketPolicyPrincipals(w.ctx, sqlcgen.DeleteBucketPolicyPrincipalsParams{Partition: key.Partition, BucketName: key.Name}); err != nil {
		return err
	}
	for principal, id := range v.Policy.PrincipalIDs {
		if err := w.q.PutBucketPolicyPrincipal(w.ctx, sqlcgen.PutBucketPolicyPrincipalParams{Partition: key.Partition, BucketName: key.Name, Principal: principal, PrincipalID: id}); err != nil {
			return err
		}
	}
	if v.PublicAccess == nil {
		return w.q.DeleteBucketPublicAccess(w.ctx, sqlcgen.DeleteBucketPublicAccessParams{Partition: key.Partition, BucketName: key.Name})
	}
	return w.q.PutBucketPublicAccess(w.ctx, sqlcgen.PutBucketPublicAccessParams{
		Partition: key.Partition, BucketName: key.Name, BlockPublicAcls: v.PublicAccess.BlockPublicACLs,
		IgnorePublicAcls: v.PublicAccess.IgnorePublicACLs, BlockPublicPolicy: v.PublicAccess.BlockPublicPolicy,
		RestrictPublicBuckets: v.PublicAccess.RestrictPublicBuckets,
	})
}

func (w writer) DeleteBucket(key domain.BucketKey) error {
	if err := w.ReplaceReplicationMetricSchedules(key, nil); err != nil {
		return err
	}
	return w.q.DeleteBucket(w.ctx, sqlcgen.DeleteBucketParams{Partition: key.Partition, Name: key.Name})
}

func (w writer) PutObject(v domain.ObjectRecord, data []byte) (int64, error) {
	key := v.Key
	bucket, err := w.q.GetBucket(w.ctx, sqlcgen.GetBucketParams{Partition: key.Bucket.Partition, Name: key.Bucket.Name})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, domain.ErrNotFound
		}
		return 0, err
	}
	acl := v.ACL
	if acl == nil {
		acl = domain.DefaultACL(key.Bucket.Partition, bucket.AccountID)
	}
	if v.VersionID == "" {
		v.VersionID = "null"
	}
	if v.VersionID == "null" {
		if err := w.q.DeleteObjectVersion(w.ctx, sqlcgen.DeleteObjectVersionParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: v.VersionID,
		}); err != nil {
			return 0, err
		}
	}
	sequence, err := w.q.NextObjectSequence(w.ctx)
	if err != nil {
		return 0, err
	}
	if v.CreatedOrder == 0 {
		v.CreatedOrder = sequence
	}
	v.Sequence = sequence
	if err := w.putObjectVersion(v, *acl); err != nil {
		return 0, err
	}
	encryptionKey, customerSalt, customerHash, customerMD5 := encryptionMetadata(v)
	if data == nil {
		data = []byte{}
	}
	return sequence, w.q.PutObjectVersionData(w.ctx, sqlcgen.PutObjectVersionDataParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name,
		VersionID: v.VersionID, EncryptionKey: encryptionKey, Ciphertext: data,
		CustomerKeySalt: customerSalt, CustomerKeyHash: customerHash, CustomerKeyMd5: customerMD5,
	})
}

func encryptionMetadata(v domain.ObjectRecord) (key, salt, hash []byte, md5 string) {
	key = v.EncryptionKey
	if key == nil {
		key = []byte{}
	}
	salt, hash = []byte{}, []byte{}
	if v.CustomerKey != nil {
		salt, hash = v.CustomerKey.Salt, v.CustomerKey.Hash
		md5 = v.CustomerKey.MD5
	}
	return
}

func (w writer) putObjectVersion(v domain.ObjectRecord, acl domain.AccessControlList) error {
	key := v.Key
	row := sqlcgen.PutObjectVersionParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name,
		VersionID: v.VersionID, Sequence: v.Sequence, CreatedOrder: v.CreatedOrder, UploadID: v.UploadID, DeleteMarker: v.DeleteMarker,
		Modified: v.Modified, Size: v.Size, Etag: v.ETag, ChecksumAlgorithm: v.ChecksumAlgorithm, Checksum: v.Checksum, ChecksumType: v.ChecksumType,
		MultipartChecksumExplicit: v.MultipartChecksumExplicit,
		StorageClass:              v.StorageClass, Replica: v.Replica,
		ContentType: v.ContentType, ContentEncoding: v.ContentEncoding, ContentLanguage: v.ContentLanguage,
		ContentDisposition: v.ContentDisposition, CacheControl: v.CacheControl, Expires: v.Expires,
		WebsiteRedirectLocation: v.WebsiteRedirectLocation,
		EncryptionAlgorithm:     v.EncryptionAlgorithm, KmsKeyArn: v.KMSKeyARN,
		OwnerAccountID: acl.OwnerAccountID, OwnerID: acl.OwnerID,
		RetentionMode: v.Retention.Mode, RetainUntil: objectLockTime(v.Retention.RetainUntil), EventHold: v.Retention.EventHold,
		EventHoldDays: int64(v.Retention.EventHoldDuration.Days), EventHoldYears: int64(v.Retention.EventHoldDuration.Years),
		LegalHold: v.LegalHold, LegalHoldModified: objectLockTime(v.LegalHoldModified), RetentionModified: objectLockTime(v.Retention.Modified),
	}
	if v.Tiering != nil {
		row.TieringAccessed = new(v.Tiering.Accessed.UTC())
		row.ArchiveTier = string(v.Tiering.ArchiveTier)
	}
	if err := w.q.PutObjectVersion(w.ctx, row); err != nil {
		return err
	}
	if err := w.putObjectACLGrants(domain.ObjectVersionKey{ObjectKey: key, VersionID: v.VersionID}, acl); err != nil {
		return err
	}
	for name, value := range v.Metadata {
		if err := w.q.PutObjectVersionMetadata(w.ctx, sqlcgen.PutObjectVersionMetadataParams{Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: v.VersionID, Key: name, Value: value}); err != nil {
			return err
		}
	}
	for name, value := range v.EncryptionContext {
		if err := w.q.PutObjectVersionEncryptionContext(w.ctx, sqlcgen.PutObjectVersionEncryptionContextParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: v.VersionID,
			Key: name, Value: value,
		}); err != nil {
			return err
		}
	}
	return w.q.SupersedeOlderMultipartUploads(w.ctx, sqlcgen.SupersedeOlderMultipartUploadsParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, CreatedOrder: v.CreatedOrder,
	})
}

func (w writer) DeleteObject(key domain.ObjectVersionKey) (int64, error) {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	if err := w.q.SupersedeDeletedMultipartUploads(w.ctx, sqlcgen.SupersedeDeletedMultipartUploadsParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	}); err != nil {
		return 0, err
	}
	if err := w.q.DeleteObjectVersion(w.ctx, sqlcgen.DeleteObjectVersionParams{Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: key.VersionID}); err != nil {
		return 0, err
	}
	return w.q.NextObjectSequence(w.ctx)
}

var _ domain.Repository = (*Repository)(nil)
var _ domain.Transaction = writer{}

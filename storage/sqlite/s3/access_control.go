package s3

import (
	domain "stackd/storage/s3"
	"stackd/storage/sqlite/s3/internal/sqlcgen"
)

func (r reader) bucketACL(row sqlcgen.S3Bucket) (*domain.AccessControlList, error) {
	if row.AclLegacy {
		return domain.DefaultACL(row.Partition, row.OwnerAccountID), nil
	}
	rows, err := r.q.GetBucketACLGrants(r.ctx, sqlcgen.GetBucketACLGrantsParams{Partition: row.Partition, BucketName: row.Name})
	if err != nil {
		return nil, err
	}
	acl := &domain.AccessControlList{OwnerAccountID: row.OwnerAccountID, OwnerID: row.OwnerID, Grants: make([]domain.ACLGrant, 0, len(rows))}
	for _, grant := range rows {
		acl.Grants = append(acl.Grants, domain.ACLGrant{Type: grant.GranteeType, ID: grant.GranteeID, URI: grant.GranteeUri, Permission: grant.Permission})
	}
	return acl, nil
}

func (r reader) objectACL(row sqlcgen.S3ObjectVersion) (*domain.AccessControlList, error) {
	if row.AclLegacy {
		return domain.DefaultACL(row.Partition, row.OwnerAccountID), nil
	}
	rows, err := r.q.GetObjectVersionACLGrants(r.ctx, sqlcgen.GetObjectVersionACLGrantsParams{
		Partition: row.Partition, BucketName: row.BucketName, ObjectName: row.Name, VersionID: row.VersionID,
	})
	if err != nil {
		return nil, err
	}
	acl := &domain.AccessControlList{OwnerAccountID: row.OwnerAccountID, OwnerID: row.OwnerID, Grants: make([]domain.ACLGrant, 0, len(rows))}
	for _, grant := range rows {
		acl.Grants = append(acl.Grants, domain.ACLGrant{Type: grant.GranteeType, ID: grant.GranteeID, URI: grant.GranteeUri, Permission: grant.Permission})
	}
	return acl, nil
}

func (r reader) multipartACL(row sqlcgen.S3MultipartUpload) (*domain.AccessControlList, error) {
	if row.AclLegacy {
		return domain.DefaultACL(row.Partition, row.OwnerAccountID), nil
	}
	rows, err := r.q.GetMultipartUploadACLGrants(r.ctx, sqlcgen.GetMultipartUploadACLGrantsParams{
		Partition: row.Partition, BucketName: row.BucketName, ObjectName: row.ObjectName, UploadID: row.UploadID,
	})
	if err != nil {
		return nil, err
	}
	acl := &domain.AccessControlList{OwnerAccountID: row.OwnerAccountID, OwnerID: row.OwnerID, Grants: make([]domain.ACLGrant, 0, len(rows))}
	for _, grant := range rows {
		acl.Grants = append(acl.Grants, domain.ACLGrant{Type: grant.GranteeType, ID: grant.GranteeID, URI: grant.GranteeUri, Permission: grant.Permission})
	}
	return acl, nil
}

func (w writer) putBucketACLGrants(key domain.BucketKey, acl domain.AccessControlList) error {
	if err := w.q.DeleteBucketACLGrants(w.ctx, sqlcgen.DeleteBucketACLGrantsParams{Partition: key.Partition, BucketName: key.Name}); err != nil {
		return err
	}
	for position, grant := range acl.Grants {
		if err := w.q.PutBucketACLGrant(w.ctx, sqlcgen.PutBucketACLGrantParams{
			Partition: key.Partition, BucketName: key.Name, Position: int64(position),
			GranteeType: grant.Type, GranteeID: grant.ID, GranteeUri: grant.URI, Permission: grant.Permission,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) putObjectACLGrants(key domain.ObjectVersionKey, acl domain.AccessControlList) error {
	for position, grant := range acl.Grants {
		if err := w.q.PutObjectVersionACLGrant(w.ctx, sqlcgen.PutObjectVersionACLGrantParams{
			Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID, Position: int64(position),
			GranteeType: grant.Type, GranteeID: grant.ID, GranteeUri: grant.URI, Permission: grant.Permission,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) ReplaceObjectACL(key domain.ObjectVersionKey, acl domain.AccessControlList) error {
	if key.VersionID == "" {
		key.VersionID = "null"
	}
	count, err := w.q.ReplaceObjectVersionACLOwner(w.ctx, sqlcgen.ReplaceObjectVersionACLOwnerParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, Name: key.Name, VersionID: key.VersionID,
		OwnerAccountID: acl.OwnerAccountID, OwnerID: acl.OwnerID,
	})
	if err != nil {
		return err
	}
	if count == 0 {
		return domain.ErrNotFound
	}
	if err := w.q.DeleteObjectVersionACLGrants(w.ctx, sqlcgen.DeleteObjectVersionACLGrantsParams{
		Partition: key.Bucket.Partition, BucketName: key.Bucket.Name, ObjectName: key.Name, VersionID: key.VersionID,
	}); err != nil {
		return err
	}
	return w.putObjectACLGrants(key, acl)
}

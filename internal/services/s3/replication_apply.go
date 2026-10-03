package s3

import (
	"errors"
	"maps"
	"time"
)

func (s *Service) applyReplica(tx Transaction, a *replicationAttempt) error {
	operation := a.job.Operation
	bucket := a.destinationBucket
	if operation == ReplicationObject && bucket.SSECustomerBlocked && a.source.EncryptionAlgorithm == "SSE-C" {
		a.rejectDestination(operation, "DstPutObjectNotPermitted", denied())
		return nil
	}
	if !bucket.ObjectLockEnabled && (a.source.Retention.Mode != "" || a.source.LegalHold != "") && (operation == ReplicationObject || operation == ReplicationRetention || operation == ReplicationLegalHold) {
		a.rejectDestination(operation, "DstBucketObjectLockConfigMissing", invalid("The destination bucket does not have Object Lock enabled."))
		return nil
	}
	if operation != ReplicationObject && operation != ReplicationDelete {
		object, err := tx.ObjectVersion(a.replica.VersionKey())
		if errors.Is(err, ErrNotFound) {
			a.rejectDestination(operation, "DstVersionNotFound", failure("NoSuchVersion", "The specified version does not exist.", 404))
			return nil
		}
		if err != nil {
			return err
		}
		a.replica = object
	}
	notification := ""
	switch operation {
	case ReplicationObject, ReplicationDelete:
		a.replica.ACL = effectiveACL(a.sourceBucket, a.source.ACL, false)
		if a.job.Destination.OwnerOverride || bucket.Ownership == "BucketOwnerEnforced" {
			a.replica.ACL = DefaultACL(bucket.Key.Partition, bucket.AccountID)
		}
		if operation == ReplicationObject {
			if a.job.Destination.StorageClass != "" {
				a.replica.StorageClass = a.job.Destination.StorageClass
				if a.replica.StorageClass == "STANDARD" {
					a.replica.StorageClass = ""
				}
			}
			if a.replica.Retention.Mode == "" && a.replica.LegalHold == "" {
				a.replica.Retention = defaultObjectRetention(bucket.DefaultRetention, a.job.Due.UTC().Truncate(time.Millisecond))
			}
		}
		initializeObjectTiering(&a.replica, a.job.Due)
		if err := tx.PutReplica(a.job.Source, a.replica); err != nil {
			return err
		}
		if a.failure == nil && len(a.tags) != 0 {
			if err := tx.ReplaceObjectTags(a.replica.VersionKey(), a.tags); err != nil {
				return err
			}
		}
		notification = "ObjectCreated:Put"
		if operation == ReplicationDelete {
			notification = "ObjectRemoved:DeleteMarkerCreated"
		}
	case ReplicationTags:
		if err := tx.ReplaceObjectTags(a.replica.VersionKey(), a.tags); err != nil {
			return err
		}
		notification = "ObjectTagging:Put"
	case ReplicationACL:
		// Ownership override stops source ACL changes from changing replica
		// ownership. BOE likewise retains the destination owner's authority.
		if !a.job.Destination.OwnerOverride && bucket.Ownership != "BucketOwnerEnforced" {
			acl := effectiveACL(a.sourceBucket, a.source.ACL, false)
			if !equalACL(originalACL(bucket, a.replica.ACL), acl) {
				notification = "ObjectAcl:Put"
			}
			a.replica.ACL = acl
			if err := tx.ReplaceObjectACL(a.replica.VersionKey(), *a.replica.ACL); err != nil {
				return err
			}
		}
	case ReplicationRetention:
		now := a.job.Due.UTC().Truncate(time.Millisecond)
		candidate := a.source.Retention
		candidate.RetainUntil = candidate.until(now)
		if !retentionChangeAllowed(a.replica.Retention, candidate, now, true) {
			a.rejectDestination(operation, "DstPutRetentionNotPermitted", objectLockDenied())
			return nil
		}
		a.replica.Retention = a.source.Retention
		if err := tx.ReplaceObjectRetention(a.replica.VersionKey(), a.replica.Retention); err != nil {
			return err
		}
		notification = "ObjectRetention:Put"
	case ReplicationLegalHold:
		a.replica.LegalHold, a.replica.LegalHoldModified = a.source.LegalHold, a.source.LegalHoldModified
		if err := tx.ReplaceObjectLegalHold(a.replica.VersionKey(), a.replica.LegalHold, a.replica.LegalHoldModified); err != nil {
			return err
		}
	}
	c := a.destinationCall
	if operation == ReplicationObject || operation == ReplicationTags {
		var tags []Tag
		if a.failure == nil {
			tags = a.tags
		}
		c.requestMetricTags(tags)
	}
	c.response = map[string]any{"x-amz-version-id": a.replica.VersionID}
	if operation == ReplicationObject {
		c.additional["objectSize"] = a.replica.Size
		c.additional["bytesTransferredIn"] = a.replica.Size
		maps.Copy(c.response, encryptionResponse(a.replica))
	}
	if operation == ReplicationDelete {
		c.response["x-amz-delete-marker"] = "true"
	}
	s.recordObjectLock(c, a.replica)
	a.results = append(a.results, replicationAPIResult{call: c})
	if notification != "" {
		return s.notifyObjectEvent(tx, c, bucket, a.replica, notification, nil, nil, a.job.Due)
	}
	return nil
}

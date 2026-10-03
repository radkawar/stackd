package s3

import (
	"context"
	"errors"
	"maps"

	"github.com/google/uuid"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type replicationFailure struct {
	operation ReplicationOperation
	reason    string
}

type replicationAPIResult struct {
	call *apiCall
	wire *awswire.Error
}

// replicationAttempt owns an authorized snapshot across the external KMS phase.
// Its source version remains immutable; the final transaction fences the job and
// destination ownership before adopting bytes and publishing the S3 outcomes.
type replicationAttempt struct {
	job                             ReplicationJob
	sourceBucket, destinationBucket BucketRecord
	source, replica                 ObjectRecord
	sourceAccess                    PublicAccessBlock
	tags                            []Tag
	results                         []replicationAPIResult
	destinationCall                 *apiCall
	failure                         *replicationFailure
}

func (s *Service) replicationCall(ctx context.Context, bucket BucketRecord, object ObjectRecord, name string) *apiCall {
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID, metadata.Region = uuid.NewString(), bucket.Region
	c := s.transferCall(awsctx.WithMetadata(ctx, metadata), name, bucket.Key.Name, object.Key.Name)
	c.account, c.region, c.requestID = bucket.AccountID, bucket.Region, metadata.RequestID
	if name != "PutObject" && name != "DeleteObject" {
		c.params["versionId"] = object.VersionID
	} else {
		c.params["x-amz-version-id"] = object.VersionID
	}
	switch name {
	case "GetObjectAcl", "PutObjectAcl":
		c.params["acl"] = ""
	case "GetObjectTagging", "PutObjectTagging":
		c.params["tagging"] = ""
	case "GetObjectRetention", "PutObjectRetention":
		c.params["retention"] = ""
	case "GetObjectLegalHold", "PutObjectLegalHold":
		c.params["legal-hold"] = ""
	}
	return c
}

func (a *replicationAttempt) sourcePermission(s *Service, reader Reader, name, action, reason string, component ReplicationOperation) bool {
	c := s.replicationCall(reader.Context(), a.sourceBucket, a.source, name)
	c.publicAccess = a.sourceAccess
	s.captureRequestCommand(reader, c, a.sourceBucket)
	conditions := map[string][]string{"s3:VersionId": {a.source.VersionID}}
	existingTagConditions(conditions, a.tags)
	var wire *awswire.Error
	if action == "GetObjectVersionForReplication" {
		wire = s.replicationReadPermission(reader.Context(), c, a.sourceBucket, a.source, conditions)
	} else {
		wire = s.authorizeObject(reader.Context(), c, a.sourceBucket, a.source, action, conditions)
	}
	if wire == nil && (name == "GetObject" || name == "HeadObject") {
		c.additional["objectSize"] = a.source.Size
	}
	if name == "GetObject" && wire == nil {
		c.additional["bytesTransferredOut"] = a.source.Size
	}
	a.results = append(a.results, replicationAPIResult{call: c, wire: wire})
	if wire != nil {
		a.failure = &replicationFailure{operation: component, reason: reason}
		return false
	}
	return true
}

func (s *Service) prepareReplication(reader Reader, job ReplicationJob) (*replicationAttempt, error) {
	a := &replicationAttempt{job: job}
	var err error
	a.source, err = reader.ObjectVersion(job.Source)
	if err != nil {
		return nil, err
	}
	a.sourceBucket, err = reader.Bucket(job.Source.Bucket)
	if err != nil {
		return nil, err
	}
	a.sourceAccess, err = s.bucketPublicAccess(reader, a.sourceBucket)
	if err != nil {
		return nil, err
	}
	a.tags, err = reader.ObjectTags(job.Source)
	if err != nil {
		return nil, err
	}
	if job.Operation != ReplicationDelete {
		name, reason := "HeadObject", "SrcHeadObjectNotPermitted"
		if job.Operation == ReplicationObject {
			name, reason = "GetObject", "SrcGetObjectNotPermitted"
		}
		if !a.sourcePermission(s, reader, name, "GetObjectVersionForReplication", reason, job.Operation) {
			return a, nil
		}
	} else {
		// Like a versioned public HEAD, reading the delete marker returns
		// 405 before object IAM. The marker itself is still replicated.
		c := s.replicationCall(reader.Context(), a.sourceBucket, a.source, "HeadObject")
		s.captureRequestCommand(reader, c, a.sourceBucket)
		a.results = append(a.results, replicationAPIResult{
			call: c,
			wire: failure("MethodNotAllowed", "The specified method is not allowed against this resource.", 405),
		})
	}
	if job.Operation == ReplicationObject || job.Operation == ReplicationACL {
		if !a.sourcePermission(s, reader, "GetObjectAcl", "GetObjectVersionAcl", "SrcGetAclNotPermitted", job.Operation) {
			return a, nil
		}
	}
	if job.Operation == ReplicationRetention || job.Operation == ReplicationObject && a.sourceBucket.ObjectLockEnabled {
		if !a.sourcePermission(s, reader, "GetObjectRetention", "GetObjectRetention", "SrcGetRetentionNotPermitted", job.Operation) {
			return a, nil
		}
	}
	if job.Operation == ReplicationLegalHold || job.Operation == ReplicationObject && a.sourceBucket.ObjectLockEnabled {
		if !a.sourcePermission(s, reader, "GetObjectLegalHold", "GetObjectLegalHold", "SrcGetLegalHoldNotPermitted", job.Operation) {
			return a, nil
		}
	}
	a.destinationBucket, err = reader.Bucket(job.Destination.Bucket)
	if errors.Is(err, ErrNotFound) {
		a.failure = &replicationFailure{operation: job.Operation, reason: "DstBucketNotFound"}
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	a.replica = a.source
	a.replica.Key.Bucket, a.replica.Replica = job.Destination.Bucket, true
	name, action, reason := "PutObject", "ReplicateObject", "DstPutObjectNotPermitted"
	switch job.Operation {
	case ReplicationDelete:
		name, action, reason = "DeleteObject", "ReplicateDelete", "DstDelObjNotPermitted"
	case ReplicationTags:
		name, reason = "PutObjectTagging", "DstPutTaggingNotPermitted"
	case ReplicationACL:
		name, reason = "PutObjectAcl", "DstPutAclNotPermitted"
	case ReplicationRetention:
		name, reason = "PutObjectRetention", "DstPutRetentionNotPermitted"
	case ReplicationLegalHold:
		name, reason = "PutObjectLegalHold", "DstPutLegalHoldNotPermitted"
	}
	metadata := awsctx.FromContext(reader.Context())
	metadata.Region = a.destinationBucket.Region
	destinationContext := awsctx.WithMetadata(reader.Context(), metadata)
	c := s.replicationCall(destinationContext, a.destinationBucket, a.replica, name)
	a.destinationCall = c
	s.captureRequestCommand(reader, c, a.destinationBucket)
	c.publicAccess, err = s.bucketPublicAccess(reader, a.destinationBucket)
	if err != nil {
		return nil, err
	}
	if job.Destination.AccountID != "" && job.Destination.AccountID != a.destinationBucket.AccountID {
		a.rejectDestination(job.Operation, reason, denied())
		return a, nil
	}
	conditions := requestedTagConditions(a.tags)
	conditions["s3:VersionId"] = []string{a.source.VersionID}
	var wire *awswire.Error
	if job.Operation == ReplicationTags {
		if !a.sourcePermission(s, reader, "GetObjectTagging", "GetObjectVersionTagging", "SrcGetTaggingNotPermitted", ReplicationTags) {
			return a, nil
		}
		wire = s.replicationTagPermission(destinationContext, c, a.destinationBucket, a.replica.Key.Name, conditions)
	} else {
		wire = s.authorize(destinationContext, c, a.destinationBucket, action, a.replica.Key.Name, conditions)
	}
	if wire == nil && job.Destination.OwnerOverride && job.Operation == ReplicationObject {
		wire = s.authorize(destinationContext, c, a.destinationBucket, "ObjectOwnerOverrideToBucketOwner", a.replica.Key.Name, conditions)
	}
	if wire != nil {
		a.rejectDestination(job.Operation, reason, wire)
		return a, nil
	}
	if job.Operation == ReplicationObject && len(a.tags) != 0 {
		if !a.sourcePermission(s, reader, "GetObjectTagging", "GetObjectVersionTagging", "SrcGetTaggingNotPermitted", ReplicationTags) {
			return a, nil
		}
		if wire := s.replicationTagPermission(destinationContext, c, a.destinationBucket, a.replica.Key.Name, conditions); wire != nil {
			a.failure = &replicationFailure{operation: ReplicationTags, reason: "DstPutTaggingNotPermitted"}
		}
	}
	return a, nil
}

func (a *replicationAttempt) rejectDestination(operation ReplicationOperation, reason string, wire *awswire.Error) {
	a.failure = &replicationFailure{operation: operation, reason: reason}
	a.results = append(a.results, replicationAPIResult{call: a.destinationCall, wire: wire})
	a.destinationCall = nil
}

func (a *replicationAttempt) copiesObject() bool {
	return a.job.Operation == ReplicationObject && (a.failure == nil || a.failure.operation == ReplicationTags)
}

func (s *Service) replicationEncryption(ctx context.Context, a *replicationAttempt) *awswire.Error {
	if !a.copiesObject() || a.source.EncryptionAlgorithm != "aws:kms" {
		return nil
	}
	plain, wire := s.objectDataKey(ctx, a.sourceBucket, a.source, nil)
	if wire != nil {
		a.failure = &replicationFailure{operation: ReplicationObject, reason: "SrcGetObjectNotPermitted"}
		a.results[0].wire = wire
		delete(a.results[0].call.additional, "bytesTransferredOut")
		delete(a.results[0].call.additional, "objectSize")
		if wire.Code == "KMS.DisabledException" || wire.Code == "KMS.KMSInvalidStateException" {
			a.failure.reason = "SrcKmsKeyInvalidState"
		}
		return wire
	}
	defer clear(plain)
	ec := maps.Clone(a.source.EncryptionContext)
	ec["aws:s3:arn"] = a.replica.Key.ARN()
	key, arn, wire := s.keys.Encrypt(objectKMSContext(ctx, a.destinationBucket), a.job.Destination.KMSKeyID, plain, ec)
	if wire != nil {
		reason := "DstPutObjectNotPermitted"
		switch wire.Code {
		case "NotFoundException":
			reason = "DstKmsKeyNotFound"
		case "DisabledException", "KMSInvalidStateException":
			reason = "DstKmsKeyInvalidState"
		}
		a.rejectDestination(ReplicationObject, reason, objectKeyError(wire))
		return wire
	}
	a.replica.EncryptionKey, a.replica.KMSKeyARN, a.replica.EncryptionContext = key, arn, ec
	return nil
}

func replicationContext(ctx context.Context, job ReplicationJob, bucket BucketRecord) context.Context {
	m := awsctx.FromContext(ctx)
	m.Partition, m.AccountID, m.Region = bucket.Key.Partition, bucket.AccountID, bucket.Region
	m.ParentEventID = job.ParentEventID
	return awsctx.WithMetadata(ctx, m)
}

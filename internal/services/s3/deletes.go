package s3

import (
	"context"
	"errors"
	"time"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

type objectRemoval struct {
	size, sequence  int64
	existed, marker bool
	version         string
}

func (s *Service) removeObject(tx Transaction, c *apiCall, b BucketRecord, key string, version *api.ObjectVersionId, match *string, bypass bool) (objectRemoval, error) {
	result := objectRemoval{}
	if w := validateKey(key); w != nil {
		return result, w
	}
	// Native S3 rejects a conditional explicit-version selection before any
	// read authority or ETag evaluation; it does not compare historical ETags.
	if version != nil && match != nil {
		wire := unsupported("A header you provided implies functionality that is not implemented")
		wire.Header = "If-Match"
		wire.AdditionalMessage = "Conditional delete operations are not allowed when a version ID is included in the request parameters."
		return result, wire
	}
	action := "DeleteObject"
	conditions := map[string][]string{}
	if match != nil {
		conditions["s3:if-match"] = []string{*match}
	}
	if version != nil {
		action = "DeleteObjectVersion"
		conditions["s3:VersionId"] = []string{value(version)}
	}
	if w := s.authorize(tx.Context(), c, b, action, key, conditions); w != nil {
		return result, w
	}
	if bypass {
		if wire := s.authorize(tx.Context(), c, b, "BypassGovernanceRetention", key, conditions); wire != nil {
			return result, wire
		}
	}
	var record ObjectRecord
	var err error
	if version != nil {
		if w := validateVersion(value(version)); w != nil {
			return result, w
		}
		result.version = value(version)
		record, err = tx.ObjectVersion(ObjectVersionKey{ObjectKey{b.Key, key}, result.version})
	} else {
		record, err = tx.Object(ObjectKey{b.Key, key})
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return result, err
	}
	if match != nil && *match != "*" {
		record.Key = ObjectKey{b.Key, key}
		if w := s.authorizeObject(tx.Context(), c, b, record, "GetObject", conditions); w != nil {
			return result, w
		}
	}
	result.existed = err == nil && !record.DeleteMarker
	result.size = record.Size
	if match != nil {
		if !result.existed {
			return result, noSuchKey(key)
		}
		if !etagMatches(*match, record.ETag) {
			return result, failure("PreconditionFailed", "At least one of the preconditions you specified did not hold.", 412)
		}
	}
	if version != nil || b.Versioning == "" {
		result.marker = err == nil && record.DeleteMarker
		if !record.DeleteMarker && (record.LegalHold == "ON" || record.Retention.protected(s.clock.Now()) && (record.Retention.Mode == "COMPLIANCE" || !bypass)) {
			return result, objectLockDenied()
		}
		if err == nil {
			if err := s.abandonObjectReplication(tx, c, b, record); err != nil {
				return result, err
			}
		}
		// Native S3 emits removal events even when the selected object or
		// explicit version does not exist.
		result.sequence, err = tx.DeleteObject(ObjectVersionKey{ObjectKey{b.Key, key}, result.version})
		return result, err
	}
	result.version, err = issueVersion(b.Versioning)
	if err != nil {
		return result, err
	}
	result.marker = true
	marker := ObjectRecord{Key: ObjectKey{b.Key, key}, VersionID: result.version, DeleteMarker: true, Modified: s.clock.Now().UTC().Truncate(time.Second)}
	result.sequence, err = tx.PutObject(marker, nil)
	if err == nil {
		err = s.enqueueObjectReplication(tx, c, b, marker, ReplicationDelete)
	}
	return result, err
}
func (s *Service) deleteObject(ctx context.Context, in *api.DeleteObjectInput) (*api.DeleteObjectOutput, *awswire.Error) {
	c := call(ctx, "DeleteObject", value(in.Bucket), value(in.Key))
	out := &api.DeleteObjectOutput{}
	if in.VersionId != nil {
		c.params["versionId"] = value(in.VersionId)
	}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if in.MFA != nil || in.IfMatchLastModifiedTime != nil || in.IfMatchSize != nil {
			return unsupported("MFA and directory-bucket conditions are not implemented.")
		}
		if wire := retentionBypassRequest(b, in.BypassGovernanceRetention); wire != nil {
			return wire
		}
		result, err := s.removeObject(tx, c, b, c.key, in.VersionId, (*string)(in.IfMatch), in.BypassGovernanceRetention != nil && bool(*in.BypassGovernanceRetention))
		c.additional = map[string]any{"bytesTransferredIn": 0, "bytesTransferredOut": 0}
		if result.existed && err == nil {
			c.additional["objectSize"] = result.size
		}
		if err != nil {
			return err
		}
		if in.VersionId != nil && result.existed {
			noteAccessLogObject(tx.Context(), result.size)
		}
		if result.version != "" {
			out.VersionId = new(api.ObjectVersionId(result.version))
		}
		if result.marker {
			out.DeleteMarker = new(api.DeleteMarker(true))
		}
		return s.notifyRemoval(tx, c, b, c.key, in.VersionId != nil, result)
	})
	return out, wire
}
func (s *Service) deleteObjects(ctx context.Context, in *api.DeleteObjectsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteObjects", value(in.Bucket), "", "delete")
	response := &preparedResponse{}
	out := &api.DeleteObjectsOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if in.Delete == nil || len(in.Delete.Objects) == 0 || len(in.Delete.Objects) > 1000 {
			return failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", 400)
		}
		if in.MFA != nil {
			return unsupported("MFA delete is not implemented.")
		}
		if wire := retentionBypassRequest(b, in.BypassGovernanceRetention); wire != nil {
			return wire
		}
		for _, object := range in.Delete.Objects {
			if object.LastModifiedTime != nil || object.Size != nil {
				return unsupported("Directory-bucket conditional deletion is not implemented.")
			}
		}
		// Each member has its own access-log outcome, but the existing batch
		// command remains the sole CloudTrail and notification owner.
		member := call(ctx, "DeleteObject", c.bucket, "")
		member.eventID = c.eventID
		member.account, member.region = c.account, c.region
		member.publicAccess = c.publicAccess
		member.accessPoint, member.accessPointReference = c.accessPoint, c.accessPointReference
		member.accessLogOperation = "BATCH.DELETE.OBJECT"
		s.captureRequestCommand(tx, member, b)
		for _, object := range in.Delete.Objects {
			key := value(object.Key)
			child := *member
			child.key = key
			result, err := s.removeObject(tx, &child, b, key, object.VersionId, (*string)(object.ETag), in.BypassGovernanceRetention != nil && bool(*in.BypassGovernanceRetention))
			c.aclRequired = c.aclRequired || child.aclRequired
			if err != nil {
				var wire *awswire.Error
				if !errors.As(err, &wire) {
					return err
				}
				if err := s.recordRequestCommand(tx.Context(), &child, wire); err != nil {
					return err
				}
				message := wire.Message
				if wire.Code == "NotImplemented" && wire.Header == "If-Match" {
					message = "A form field you provided implies functionality that is not implemented"
				} else if wire.Code == "PreconditionFailed" {
					message = "At least one of the pre-conditions you specified did not hold"
				}
				out.Errors = append(out.Errors, api.Error{Key: object.Key, VersionId: object.VersionId, Code: new(api.Code(wire.Code)), Message: new(api.Message(message))})
				continue
			}
			if err := s.notifyRemoval(tx, c, b, key, object.VersionId != nil, result); err != nil {
				return err
			}
			if err := s.recordRequestCommand(tx.Context(), &child, nil); err != nil {
				return err
			}
			if in.Delete.Quiet == nil || !bool(*in.Delete.Quiet) {
				deleted := api.DeletedObject{Key: object.Key, VersionId: object.VersionId}
				if result.marker {
					deleted.DeleteMarker = new(api.DeleteMarker(true))
					deleted.DeleteMarkerVersionId = new(api.DeleteMarkerVersionId(result.version))
				}
				out.Deleted = append(out.Deleted, deleted)
			}
		}
		if err := response.prepare(c, out); err != nil {
			return err
		}
		// Native batch audit describes the request as one operation and does
		// not account for its XML transfer as per-object payload traffic.
		c.additional["bytesTransferredIn"], c.additional["bytesTransferredOut"] = 0, 0
		return nil
	})
	return response, wire
}

func retentionBypassRequest(bucket BucketRecord, bypass *api.BypassGovernanceRetention) *awswire.Error {
	if bypass != nil && !bucket.ObjectLockEnabled {
		return argumentError("x-amz-bypass-governance-retention", "", "x-amz-bypass-governance-retention is only applicable to Object Lock enabled buckets.")
	}
	return nil
}

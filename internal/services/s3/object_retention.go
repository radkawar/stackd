package s3

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) protectedObject(tx Reader, c *apiCall, expected string, version *api.ObjectVersionId, conditions map[string][]string, prepare func(ObjectRecord) *awswire.Error) (BucketRecord, ObjectRecord, error) {
	bucket, err := s.bucket(tx, c, expected)
	if err != nil {
		return bucket, ObjectRecord{}, err
	}
	if wire := validateKey(c.key); wire != nil {
		return bucket, ObjectRecord{}, wire
	}
	if version != nil {
		c.params["versionId"] = value(version)
		conditions["s3:VersionId"] = []string{value(version)}
	}
	object, err := selectObjectVersion(tx, ObjectKey{bucket.Key, c.key}, version)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return bucket, object, err
	}
	if err == nil && object.DeleteMarker {
		wire := failure("MethodNotAllowed", "The specified method is not allowed against this resource.", http.StatusMethodNotAllowed)
		wire.Method, wire.ResourceType = http.MethodPut, "DeleteMarker"
		if strings.HasPrefix(c.name, "Get") {
			wire.Method = http.MethodGet
		}
		selectedVersion := "null"
		if version != nil {
			selectedVersion = value(version)
		}
		wire.ResponseHeader = http.Header{
			"X-Amz-Delete-Marker": {"true"},
			"X-Amz-Version-Id":    {selectedVersion},
		}
		return bucket, object, wire
	}
	if errors.Is(err, ErrNotFound) {
		object.Key = ObjectKey{bucket.Key, c.key}
	}
	if err == nil && prepare != nil {
		if wire := prepare(object); wire != nil {
			return bucket, object, wire
		}
	}
	if wire := s.authorizeObject(tx.Context(), c, bucket, object, c.name, conditions); wire != nil {
		return bucket, object, wire
	}
	if !bucket.ObjectLockEnabled {
		return bucket, object, failure("InvalidRequest", "Bucket is missing Object Lock Configuration", http.StatusBadRequest)
	}
	if errors.Is(err, ErrNotFound) {
		if version != nil {
			return bucket, object, failure("NoSuchVersion", "The specified version does not exist.", http.StatusNotFound)
		}
		if wire := s.authorize(tx.Context(), c, bucket, "ListBucket", "", nil); wire != nil {
			return bucket, object, wire
		}
		return bucket, object, noSuchKey(c.key)
	}
	return bucket, object, nil
}

func (s *Service) getObjectRetention(ctx context.Context, in *api.GetObjectRetentionInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetObjectRetention", value(in.Bucket), value(in.Key), "retention")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		_, object, err := s.protectedObject(tx, c, value(in.ExpectedBucketOwner), in.VersionId, map[string][]string{}, nil)
		if err != nil {
			return err
		}
		if object.Retention.Mode == "" {
			return noObjectLock()
		}
		c.additional["objectSize"] = object.Size
		s.recordObjectLock(c, object)
		out := &api.GetObjectRetentionOutput{Retention: retentionOutput(object.Retention, s.clock.Now().UTC().Truncate(time.Millisecond))}
		return response.prepare(c, out)
	})
	return response, wire
}

func (s *Service) getObjectLegalHold(ctx context.Context, in *api.GetObjectLegalHoldInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetObjectLegalHold", value(in.Bucket), value(in.Key), "legal-hold")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		_, object, err := s.protectedObject(tx, c, value(in.ExpectedBucketOwner), in.VersionId, map[string][]string{}, nil)
		if err != nil {
			return err
		}
		if object.LegalHold == "" {
			return noObjectLock()
		}
		c.additional["objectSize"] = object.Size
		s.recordObjectLock(c, object)
		return response.prepare(c, &api.GetObjectLegalHoldOutput{LegalHold: &api.ObjectLockLegalHold{Status: new(api.ObjectLockLegalHoldStatus(object.LegalHold))}})
	})
	return response, wire
}

func (s *Service) putObjectLegalHold(ctx context.Context, in *api.PutObjectLegalHoldInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutObjectLegalHold", value(in.Bucket), value(in.Key), "legal-hold")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		if in.LegalHold == nil || in.LegalHold.Status == nil {
			return malformedXML()
		}
		conditions := map[string][]string{"s3:object-lock-legal-hold": {value(in.LegalHold.Status)}}
		bucket, object, err := s.protectedObject(tx, c, value(in.ExpectedBucketOwner), in.VersionId, conditions, nil)
		if err != nil {
			return err
		}
		object.LegalHold = value(in.LegalHold.Status)
		object.LegalHoldModified = s.clock.Now().UTC().Truncate(time.Millisecond)
		if err := tx.ReplaceObjectLegalHold(object.VersionKey(), object.LegalHold, object.LegalHoldModified); err != nil {
			return err
		}
		c.additional["objectSize"] = object.Size
		s.recordObjectLock(c, object)
		if err := response.prepare(c, &api.PutObjectLegalHoldOutput{}); err != nil {
			return err
		}
		response.response.Header.Set("x-amz-version-id", object.VersionID)
		c.response = map[string]any{"x-amz-version-id": object.VersionID}
		return s.enqueueObjectReplication(tx, c, bucket, object, ReplicationLegalHold)
	})
	return response, wire
}

func (s *Service) putObjectRetention(ctx context.Context, in *api.PutObjectRetentionInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutObjectRetention", value(in.Bucket), value(in.Key), "retention")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		now := s.clock.Now().UTC().Truncate(time.Millisecond)
		bypass := in.BypassGovernanceRetention != nil && bool(*in.BypassGovernanceRetention)
		conditions := map[string][]string{}
		objectLockConditions(conditions, in.Retention, nil, now)
		var retention ObjectRetention
		// IAM sees the proposed effective deadline, including a variable hold
		// without a supplied fixed date, resolved from the selected version.
		bucket, object, err := s.protectedObject(tx, c, value(in.ExpectedBucketOwner), in.VersionId, conditions, func(object ObjectRecord) *awswire.Error {
			var wire *awswire.Error
			retention, wire = replacementRetention(in.Retention, object.Retention, now, bypass)
			if wire == nil && retention.Mode != "" {
				objectLockConditions(conditions, retentionOutput(retention, now), nil, now)
			}
			return wire
		})
		if err != nil {
			return err
		}
		if bypass {
			if wire := s.authorizeObject(tx.Context(), c, bucket, object, "BypassGovernanceRetention", conditions); wire != nil {
				return wire
			}
		}
		// Supplying a shorter date requires bypass even when an omitted
		// EventHold preserves the existing moving period.
		if !retentionChangeAllowed(object.Retention, retention, now, bypass) {
			return objectLockDenied()
		}
		if err := tx.ReplaceObjectRetention(object.VersionKey(), retention); err != nil {
			return err
		}
		object.Retention = retention
		s.recordObjectLock(c, object)
		if err := response.prepare(c, &api.PutObjectRetentionOutput{}); err != nil {
			return err
		}
		response.response.Header.Set("x-amz-version-id", object.VersionID)
		c.response = map[string]any{"x-amz-version-id": object.VersionID}
		if err := s.enqueueObjectReplication(tx, c, bucket, object, ReplicationRetention); err != nil {
			return err
		}
		return s.notifyObject(tx, c, bucket, object, "ObjectRetention:Put")
	})
	return response, wire
}

func retentionChangeAllowed(current, next ObjectRetention, now time.Time, bypass bool) bool {
	if current.protected(now) && (next.Mode != current.Mode || next.RetainUntil.Before(current.until(now))) {
		return current.Mode != "COMPLIANCE" && bypass
	}
	return true
}

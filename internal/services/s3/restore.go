package s3

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) restoreObject(ctx context.Context, in *api.RestoreObjectInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "RestoreObject", value(in.Bucket), value(in.Key), "restore")
	request, _ := awsapi.FromContext(ctx)
	xmlAuditParameters(c, request.Body)
	if c.eventID == "" {
		c.eventID = uuid.NewString()
	}
	response := &preparedResponse{statusCode: http.StatusAccepted}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		bucket, object, err := s.restoreObjectVersion(tx, c, in)
		if err != nil {
			return err
		}
		c.additional["objectSize"] = object.Size
		noteAccessLogObject(tx.Context(), object.Size)
		archiveClass := objectArchiveClass(&object)
		if archiveClass == "" {
			return invalidRestoreState()
		}
		days, tier, wire := parseRestoreRequest(in.RestoreRequest, object.StorageClass)
		if wire != nil {
			return wire
		}
		if value(in.RestoreRequest.Type) == "SELECT" {
			return failure("MethodNotAllowed", "The specific method for Select type jobs is not allowed against this resource.", http.StatusMethodNotAllowed)
		}
		if archiveClass == "DEEP_ARCHIVE" && tier == "Expedited" {
			return failure("InvalidTier", "Retrieval option is not supported by this storage class.", http.StatusForbidden)
		}
		now := s.clock.Now().UTC()
		state, err := tx.ObjectRestore(object.VersionKey())
		if err != nil {
			return err
		}
		if state != nil && state.Ongoing {
			// An in-flight restore may only be accelerated, not have its
			// retention period changed or be restarted at an equal/slower tier.
			if days != state.Days || restoreDelay(archiveClass, tier) >= restoreDelay(archiveClass, state.Tier) {
				return failure("RestoreAlreadyInProgress", "Object restore is already in progress", http.StatusConflict)
			}
			if due := now.Add(restoreDelay(archiveClass, tier)); due.Before(state.Due) {
				state.Due = due
			}
			state.Tier = tier
		} else if objectRestored(state, now) {
			response.statusCode = http.StatusOK
			state.Days, state.Tier, state.Due = days, tier, objectDayDeadline(now, days)
		} else {
			if state != nil {
				// A request can arrive before the worker consumes an expired
				// cache. Preserve that expiration's publication before replacing it.
				if err := s.expireObjectRestore(tx, bucket, object, state); err != nil {
					return err
				}
			}
			state = &ObjectRestore{Key: object.VersionKey(), Ongoing: true, Days: days, Tier: tier, Due: now.Add(restoreDelay(archiveClass, tier))}
		}
		state.ParentEventID = c.eventID
		if err := tx.PutObjectRestore(*state); err != nil {
			return err
		}
		if object.Tiering != nil {
			tiering := *object.Tiering
			tiering.Accessed = now
			if err := tx.SetObjectTiering(object.VersionKey(), object.CreatedOrder, &tiering); err != nil {
				return err
			}
		}
		if err := response.prepare(c, &api.RestoreObjectOutput{}); err != nil {
			return err
		}
		if bucket.Versioning != "" {
			response.response.Header.Set("x-amz-version-id", object.VersionID)
		}
		return s.notifyObjectEvent(tx, c, bucket, object, "ObjectRestore:Post", state, nil, now)
	})
	if wire == nil {
		s.jobs.Wake()
	}
	return response, wire
}

// Restore uses its own permission, even for explicitly selected versions. It
// must not borrow GetObject admission: a restore-only principal cannot read the
// restored payload, and a get-only principal cannot initiate this mutation.
func (s *Service) restoreObjectVersion(tx Reader, c *apiCall, in *api.RestoreObjectInput) (BucketRecord, ObjectRecord, error) {
	bucket, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
	if err != nil {
		return bucket, ObjectRecord{}, err
	}
	if wire := validateKey(c.key); wire != nil {
		return bucket, ObjectRecord{}, wire
	}
	conditions := map[string][]string{}
	if in.VersionId != nil {
		c.params["versionId"] = value(in.VersionId)
		conditions["s3:VersionId"] = []string{value(in.VersionId)}
	}
	object, err := selectObjectVersion(tx, ObjectKey{bucket.Key, c.key}, in.VersionId)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return bucket, object, err
	}
	if err == nil && object.DeleteMarker {
		if in.VersionId == nil {
			return bucket, object, noSuchKey(c.key)
		}
		wire := failure("MethodNotAllowed", "The specified method is not allowed against this resource.", http.StatusMethodNotAllowed)
		wire.Method, wire.ResourceType = http.MethodPost, "DeleteMarker"
		wire.ResponseHeader = http.Header{"Allow": {http.MethodDelete}, "X-Amz-Delete-Marker": {"true"}, "X-Amz-Version-Id": {object.VersionID}}
		return bucket, object, wire
	}
	if errors.Is(err, ErrNotFound) {
		object.Key = ObjectKey{bucket.Key, c.key}
	} else {
		tags, tagErr := tx.ObjectTags(object.VersionKey())
		if tagErr != nil {
			return bucket, object, tagErr
		}
		existingTagConditions(conditions, tags)
	}
	if wire := s.authorizeObject(tx.Context(), c, bucket, object, "RestoreObject", conditions); wire != nil {
		return bucket, object, wire
	}
	if errors.Is(err, ErrNotFound) {
		if in.VersionId != nil {
			wire := failure("NoSuchVersion", "The specified version does not exist.", http.StatusNotFound)
			wire.Key, wire.VersionID = c.key, value(in.VersionId)
			return bucket, object, wire
		}
		if wire := s.authorize(tx.Context(), c, bucket, "ListBucket", "", nil); wire != nil {
			return bucket, object, wire
		}
		return bucket, object, noSuchKey(c.key)
	}
	return bucket, object, nil
}

func parseRestoreRequest(in *api.RestoreRequest, storageClass string) (int32, string, *awswire.Error) {
	if in == nil {
		return 0, "", malformedXML()
	}
	if in.Type != nil {
		if value(in.Type) != "SELECT" {
			return 0, "", malformedXML()
		}
		// SELECT is rejected against the selected storage class by the command;
		// never accept a query without performing it or require regular Days.
		return 0, "", nil
	}
	if in.Tier != nil || in.OutputLocation != nil || in.SelectParameters != nil {
		return 0, "", malformedXML()
	}
	var days int32
	if storageClass == "INTELLIGENT_TIERING" {
		if in.Days != nil {
			return 0, "", failure("InvalidRequest", "Days cannot be specified for objects in the INTELLIGENT_TIERING storage class.", http.StatusBadRequest)
		}
	} else {
		if in.Days == nil {
			return 0, "", malformedXML()
		}
		days = int32(*in.Days)
		if days < 1 {
			return 0, "", argumentError("Days", strconv.FormatInt(int64(days), 10), "restoration days should be at least 1")
		}
	}
	tier := "Standard"
	if in.GlacierJobParameters != nil {
		tier = value(in.GlacierJobParameters.Tier)
	}
	switch tier {
	case "Expedited", "Standard", "Bulk":
		return days, tier, nil
	default:
		return 0, "", malformedXML()
	}
}

func invalidRestoreState() *awswire.Error {
	return failure("InvalidObjectState", "Restore is not allowed for the object's current storage class", http.StatusForbidden)
}

func restoreRequestError(name string, err error) *awswire.Error {
	if name != "RestoreObject" {
		return nil
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) && (validation.Path == "" || validation.Path == "RestoreRequest" || strings.HasPrefix(validation.Path, "RestoreRequest.")) {
		return malformedXML()
	}
	return nil
}

// These are deterministic local service-time delays within the documented
// retrieval ranges, not promises about AWS latency or provisioned capacity.
func restoreDelay(storageClass, tier string) time.Duration {
	if storageClass == "DEEP_ARCHIVE" {
		if tier == "Bulk" {
			return 48 * time.Hour
		}
		return 12 * time.Hour
	}
	switch tier {
	case "Expedited":
		return 5 * time.Minute
	case "Bulk":
		return 12 * time.Hour
	default:
		return 4 * time.Hour
	}
}

func objectRestored(state *ObjectRestore, now time.Time) bool {
	return state != nil && !state.Ongoing && now.Before(state.Due)
}

func restoreHeader(state *ObjectRestore, now time.Time) *api.Restore {
	if state == nil {
		return nil
	}
	if state.Ongoing {
		return new(api.Restore(`ongoing-request="true"`))
	}
	if !objectRestored(state, now) {
		return nil
	}
	return new(api.Restore(`ongoing-request="false", expiry-date="` + state.Due.UTC().Format(http.TimeFormat) + `"`))
}

func restoreStatus(state *ObjectRestore, now time.Time) *api.RestoreStatus {
	if state == nil || !state.Ongoing && !objectRestored(state, now) {
		return nil
	}
	out := &api.RestoreStatus{IsRestoreInProgress: new(api.IsRestoreInProgress(state.Ongoing))}
	if !state.Ongoing {
		out.RestoreExpiryDate = new(state.Due.UTC())
	}
	return out
}

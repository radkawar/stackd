package s3

import (
	"context"
	"errors"
	"strconv"
	"time"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// RetentionPeriod preserves the configured unit; years are not a fixed day count.
type RetentionPeriod struct {
	Days, Years int32
}

// DefaultRetention applies to new versions, never to existing object history.
// Period is a fixed minimum; EventHold starts a variable retention period.
type DefaultRetention struct {
	Mode      string
	Period    RetentionPeriod
	EventHold RetentionPeriod
}

// ObjectRetention belongs to one version. RetainUntil is the fixed deadline or
// the minimum deadline while an event hold is active. Reading an active hold
// computes its effective deadline from service time without mutating storage.
type ObjectRetention struct {
	Mode              string
	RetainUntil       time.Time
	Modified          time.Time
	EventHold         string
	EventHoldDuration RetentionPeriod
}

func (p RetentionPeriod) until(at time.Time) time.Time {
	return at.AddDate(int(p.Years), 0, int(p.Days))
}

func (r ObjectRetention) until(at time.Time) time.Time {
	if r.EventHold == "ON" {
		if moving := r.EventHoldDuration.until(at); moving.After(r.RetainUntil) {
			return moving
		}
	}
	return r.RetainUntil
}

func retentionHeaders(mode *api.ObjectLockMode, until *api.ObjectLockRetainUntilDate, event *api.ObjectLockEventHold, days *api.ObjectLockEventHoldDurationDays, years *api.ObjectLockEventHoldDurationYears) *api.ObjectLockRetention {
	if mode == nil && until == nil && event == nil && days == nil && years == nil {
		return nil
	}
	out := &api.ObjectLockRetention{
		Mode: (*api.ObjectLockRetentionMode)(mode), RetainUntilDate: until, EventHold: event,
	}
	if days != nil || years != nil {
		out.EventHoldDuration = &api.EventHoldDuration{Days: (*api.Days)(days), Years: (*api.Years)(years)}
	}
	return out
}

func retentionOutput(retention ObjectRetention, now time.Time) *api.ObjectLockRetention {
	out := &api.ObjectLockRetention{Mode: new(api.ObjectLockRetentionMode(retention.Mode))}
	if until := retention.until(now); !until.IsZero() {
		out.RetainUntilDate = new(until)
	}
	if retention.EventHold != "" {
		out.EventHold = new(api.ObjectLockEventHold(retention.EventHold))
	}
	if period := retention.EventHoldDuration; period != (RetentionPeriod{}) {
		out.EventHoldDuration = &api.EventHoldDuration{}
		if period.Days != 0 {
			out.EventHoldDuration.Days = new(api.Days(period.Days))
		}
		if period.Years != 0 {
			out.EventHoldDuration.Years = new(api.Years(period.Years))
		}
	}
	return out
}

// Admission uses the effective lock, including bucket defaults. Native IAM
// converts event-hold years to 365-day years independently of the calendar
// arithmetic used for the actual retention deadline.
func objectLockConditions(conditions map[string][]string, retention *api.ObjectLockRetention, legal *api.ObjectLockLegalHoldStatus, now time.Time) {
	if legal != nil {
		conditions["s3:object-lock-legal-hold"] = []string{value(legal)}
	}
	if retention == nil {
		return
	}
	if retention.Mode != nil {
		conditions["s3:object-lock-mode"] = []string{value(retention.Mode)}
	}
	if retention.RetainUntilDate != nil {
		until := retention.RetainUntilDate.UTC()
		conditions["s3:object-lock-retain-until-date"] = []string{until.Format(time.RFC3339Nano)}
		conditions["s3:object-lock-remaining-retention-days"] = []string{strconv.FormatInt(int64(until.Sub(now)/(24*time.Hour)), 10)}
	}
	if retention.EventHold != nil {
		conditions["s3:object-lock-event-hold"] = []string{value(retention.EventHold)}
	}
	if period := retention.EventHoldDuration; period != nil {
		var days int64
		if period.Days != nil {
			days = int64(*period.Days)
		} else if period.Years != nil {
			days = 365 * int64(*period.Years)
		}
		conditions["s3:object-lock-event-hold-duration-days"] = []string{strconv.FormatInt(days, 10)}
	}
}

func defaultObjectRetention(config DefaultRetention, now time.Time) ObjectRetention {
	if config.Mode == "" {
		return ObjectRetention{}
	}
	retention := ObjectRetention{Mode: config.Mode, Modified: now}
	if config.Period != (RetentionPeriod{}) {
		retention.RetainUntil = config.Period.until(now)
	}
	if config.EventHold != (RetentionPeriod{}) {
		retention.EventHold, retention.EventHoldDuration = "ON", config.EventHold
	}
	return retention
}

func objectLockDenied() *awswire.Error {
	return failure("AccessDenied", "Access Denied because object protected by object lock.", 403)
}

func noObjectLock() *awswire.Error {
	return failure("NoSuchObjectLockConfiguration", "The specified object does not have an ObjectLock configuration", 404)
}

func (r ObjectRetention) protected(now time.Time) bool {
	return r.EventHold == "ON" || r.RetainUntil.After(now)
}

// Object creation replaces all lock settings: an explicit legal-hold status,
// including OFF, suppresses bucket default retention. Implicit defaults affect
// PutObject conditions but do not require additional retention permissions.
func (s *Service) prepareObjectLock(ctx context.Context, c *apiCall, bucket BucketRecord, record *ObjectRecord, requested *api.ObjectLockRetention, legal *api.ObjectLockLegalHoldStatus, conditions map[string][]string) *awswire.Error {
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	if requested == nil && legal == nil {
		record.Retention = defaultObjectRetention(bucket.DefaultRetention, now)
	} else {
		if !bucket.ObjectLockEnabled {
			return failure("InvalidRequest", "Bucket is missing Object Lock Configuration", 400)
		}
		if requested != nil {
			if requested.Mode == nil && requested.EventHold != nil {
				return failure("InvalidRequest", "x-amz-object-lock-mode is required when x-amz-object-lock-event-hold is supplied.", 400)
			}
			if requested.EventHold == nil {
				if requested.EventHoldDuration != nil {
					return failure("InvalidRequest", "Event hold duration requires x-amz-object-lock-event-hold:ON.", 400)
				}
				if requested.Mode == nil || requested.RetainUntilDate == nil {
					header := "x-amz-object-lock-retain-until-date"
					if requested.Mode == nil {
						header = "x-amz-object-lock-mode"
					}
					return argumentError(header, "", "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied")
				}
			} else if value(requested.EventHold) == "OFF" && requested.RetainUntilDate == nil {
				return failure("InvalidRequest", "x-amz-object-lock-retain-until-date is required when x-amz-object-lock-event-hold is OFF.", 400)
			}
			var wire *awswire.Error
			record.Retention, wire = replacementRetention(requested, ObjectRetention{}, now, false)
			if wire != nil {
				return wire
			}
		}
		record.LegalHold = value(legal)
		if legal != nil {
			record.LegalHoldModified = now
		}
	}
	var effective *api.ObjectLockRetention
	if record.Retention.Mode != "" {
		effective = retentionOutput(record.Retention, now)
	}
	objectLockConditions(conditions, effective, legal, now)
	if requested != nil {
		if wire := s.authorize(ctx, c, bucket, "PutObjectRetention", record.Key.Name, conditions); wire != nil {
			return wire
		}
	}
	if legal != nil {
		if wire := s.authorize(ctx, c, bucket, "PutObjectLegalHold", record.Key.Name, conditions); wire != nil {
			return wire
		}
	}
	return nil
}

func objectLockRequestError(name string, err error) *awswire.Error {
	if name != "PutObject" && name != "CopyObject" && name != "CreateMultipartUpload" {
		return nil
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) && validation.Constraint == "enum" {
		switch validation.Path {
		case "ObjectLockLegalHoldStatus":
			return argumentError("x-amz-object-lock-legal-hold", validation.EnumValue, "Legal Hold must be either of 'ON' or 'OFF'")
		case "ObjectLockMode":
			return argumentError("x-amz-object-lock-mode", validation.EnumValue, "Unknown wormMode directive.")
		case "ObjectLockEventHold":
			return argumentError("x-amz-object-lock-event-hold", validation.EnumValue, "Event hold must be either of 'ON' or 'OFF'")
		}
	}
	return nil
}

package s3

import (
	"strconv"
	"time"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// replacementRetention resolves the requested version metadata. Authorization
// against the old protected period is owned by the command, not this parser.
func replacementRetention(in *api.ObjectLockRetention, current ObjectRetention, now time.Time, bypass bool) (ObjectRetention, *awswire.Error) {
	if in == nil {
		return ObjectRetention{}, malformedXML()
	}
	if in.Mode == nil && in.RetainUntilDate == nil && in.EventHold == nil && in.EventHoldDuration == nil {
		return ObjectRetention{}, nil
	}
	if in.Mode == nil {
		return ObjectRetention{}, malformedXML()
	}
	out := ObjectRetention{Mode: value(in.Mode), Modified: now}
	if in.RetainUntilDate != nil {
		out.RetainUntil = in.RetainUntilDate.UTC().Truncate(time.Millisecond)
		if !out.RetainUntil.After(now) {
			location, err := time.LoadLocation("America/Los_Angeles")
			if err != nil {
				return ObjectRetention{}, failure("InternalError", err.Error(), 500)
			}
			return ObjectRetention{}, argumentError("RetainUntilDate", out.RetainUntil.In(location).Format("Mon Jan 02 15:04:05 MST 2006"), "The retain until date must be in the future!")
		}
	}
	if in.EventHold == nil {
		if in.EventHoldDuration != nil || in.RetainUntilDate == nil {
			return ObjectRetention{}, malformedXML()
		}
		out.EventHold, out.EventHoldDuration = current.EventHold, current.EventHoldDuration
		if current.EventHold == "ON" && bypass && out.RetainUntil.Before(current.until(now)) {
			return ObjectRetention{}, failure("InvalidRequest", "Using the governance mode bypass to shorten the retain-until-date of a retention period in governance mode with an ON event hold requires the providing of a new ON event hold or a new OFF event hold.", 400)
		}
		return out, nil
	}
	out.EventHold = value(in.EventHold)
	if out.EventHold == "OFF" {
		if in.EventHoldDuration != nil {
			return ObjectRetention{}, failure("InvalidRequest", "EventHoldDuration must not be supplied with EventHold:OFF.", 400)
		}
		if in.RetainUntilDate == nil {
			if !current.until(now).After(now) {
				return ObjectRetention{}, failure("InvalidRequest", "To turn off an event hold, either provide a retain-until-date in the future in the request or the object version must already have a retain-until-date in the future.", 400)
			}
			out.RetainUntil = current.until(now)
		}
		return out, nil
	}
	if in.EventHoldDuration == nil {
		return ObjectRetention{}, failure("InvalidRequest", "EventHold:ON must be supplied with an EventHoldDuration.", 400)
	}
	period, wire := objectEventHoldDuration(in.EventHoldDuration)
	if wire != nil {
		return ObjectRetention{}, wire
	}
	out.EventHoldDuration = period
	if in.RetainUntilDate != nil {
		if out.RetainUntil.Before(period.until(now)) {
			return ObjectRetention{}, argumentError("RetainUntilDate", out.RetainUntil.Format("2006-01-02T15:04:05.000Z"), "The retain until date must be equal to or later than the current time plus the event hold duration.")
		}
	} else {
		// A duration-only change freezes the previous effective deadline at the
		// mutation time. Neither reading nor restarting can move that floor.
		out.RetainUntil = current.until(now)
	}
	return out, nil
}

func objectEventHoldDuration(in *api.EventHoldDuration) (RetentionPeriod, *awswire.Error) {
	if (in.Days == nil) == (in.Years == nil) {
		return RetentionPeriod{}, malformedXML()
	}
	if in.Days != nil {
		days := int32(*in.Days)
		if days <= 0 {
			return RetentionPeriod{}, argumentError("Days", strconv.FormatInt(int64(days), 10), "Event hold duration must be a positive integer value.")
		}
		if days > 36500 {
			return RetentionPeriod{}, argumentError("Days", strconv.FormatInt(int64(days), 10), "Event hold duration must be at most 36500 days.")
		}
		return RetentionPeriod{Days: days}, nil
	}
	years := int32(*in.Years)
	if years <= 0 {
		return RetentionPeriod{}, argumentError("Years", strconv.FormatInt(int64(years), 10), "Event hold duration must be a positive integer value.")
	}
	if years > 100 {
		return RetentionPeriod{}, argumentError("Years", strconv.FormatInt(int64(years), 10), "Event hold duration must be at most 100 years.")
	}
	return RetentionPeriod{Years: years}, nil
}

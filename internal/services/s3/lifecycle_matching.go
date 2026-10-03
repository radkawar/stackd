package s3

import (
	"net/http"
	"strings"
	"time"

	api "stackd/internal/awsapi/s3"
)

func (when LifecycleWhen) deadline(created time.Time) (time.Time, bool) {
	if when.Date != nil {
		return *when.Date, true
	}
	if when.Days != nil {
		return objectDayDeadline(created, *when.Days), true
	}
	return time.Time{}, false
}

// lifecycleExpirationHeader is disclosure, not lifecycle authorization. Native
// object reads expose it without GetLifecycleConfiguration permission; callers
// omit it for explicit version selections, including the current/null version.
func lifecycleExpirationHeader(reader Reader, bucket BucketRecord, object ObjectRecord, tags []Tag) (*api.Expiration, error) {
	config, err := reader.BucketLifecycle(bucket.Key)
	if err != nil || config == nil {
		return nil, err
	}
	expires, id, found := lifecycleVersionExpiration(config, object, tags, true, time.Time{}, 0)
	if !found {
		return nil, nil
	}
	return new(api.Expiration(`expiry-date="` + expires.UTC().Format(http.TimeFormat) + `", rule-id="` + lifecycleHeaderRuleID(id) + `"`)), nil
}

// lifecycleVersionExpiration selects the earliest applicable timed expiration.
// Noncurrent age starts at the successor, not at the object's own creation.
// Marker cleanup has no fixed timestamp and is deliberately not synthesized.
func lifecycleVersionExpiration(config *LifecycleConfiguration, object ObjectRecord, tags []Tag, current bool, successor time.Time, newer int32) (time.Time, string, bool) {
	var expires time.Time
	var id string
	found := false
	if config == nil {
		return expires, id, found
	}
	for _, rule := range config.Rules {
		if !rule.Enabled || !objectFilterMatches(rule.Filter, object, tags) {
			continue
		}
		var deadline time.Time
		var timed bool
		if current && rule.Expiration != nil {
			deadline, timed = rule.Expiration.deadline(object.Modified)
		} else if !current && rule.NoncurrentExpiration != nil {
			deadline = objectDayDeadline(successor, rule.NoncurrentExpiration.Days)
			timed = lifecycleNoncurrentDue(*rule.NoncurrentExpiration, successor, newer, deadline)
		}
		if timed && (!found || deadline.Before(expires)) {
			expires, id, found = deadline, rule.ID, true
		}
	}
	return expires, id, found
}

func lifecycleHeaderRuleID(id string) string {
	const hex = "0123456789abcdef"
	var escaped strings.Builder
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c < 32 || c >= 127 || c == '"' || c == '%' {
			if escaped.Len() == 0 {
				escaped.Grow(len(id) + 2)
				escaped.WriteString(id[:i])
			}
			escaped.WriteByte('%')
			escaped.WriteByte(hex[c>>4])
			escaped.WriteByte(hex[c&15])
		} else if escaped.Len() != 0 {
			escaped.WriteByte(c)
		}
	}
	if escaped.Len() == 0 {
		return id
	}
	return escaped.String()
}

func lifecycleTransitionAllowed(source, destination string) bool {
	if source == destination {
		return false
	}
	switch source {
	case "", "REDUCED_REDUNDANCY":
		return true
	case "STANDARD_IA":
		return destination != "STANDARD_IA"
	case "INTELLIGENT_TIERING":
		return destination != "STANDARD_IA" && destination != "INTELLIGENT_TIERING"
	case "ONEZONE_IA", "GLACIER_IR":
		return destination == "GLACIER" || destination == "DEEP_ARCHIVE"
	case "GLACIER":
		return destination == "DEEP_ARCHIVE"
	default:
		return false
	}
}

func lifecycleObjectTransitionAllowed(object ObjectRecord, destination string, at time.Time) bool {
	if object.Tiering != nil {
		switch object.Tiering.ArchiveTier {
		case DeepArchiveAccessTier:
			return destination == "DEEP_ARCHIVE"
		case ArchiveAccessTier:
			return destination == "GLACIER" || destination == "DEEP_ARCHIVE"
		default:
			// The automatic Archive Instant tier needs no separate stored
			// state, but after 90 idle days it excludes One Zone-IA.
			if destination == "ONEZONE_IA" && !at.Before(object.Tiering.Accessed.AddDate(0, 0, 90)) {
				return false
			}
		}
	}
	return lifecycleTransitionAllowed(object.StorageClass, destination)
}

func lifecycleTransitionSize(config *LifecycleConfiguration, filter ObjectFilter, object ObjectRecord, destination string) bool {
	if filter.ObjectSizeGreaterThan != nil || filter.ObjectSizeLessThan != nil || object.Size >= 128*1024 {
		return true
	}
	return config.MinimumObjectSize == "varies_by_storage_class" && isArchivedStorageClass(destination)
}

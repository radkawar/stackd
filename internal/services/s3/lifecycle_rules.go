package s3

import (
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func parseLifecycleConfiguration(in *api.BucketLifecycleConfiguration) (*LifecycleConfiguration, error) {
	if in == nil || len(in.Rules) == 0 || len(in.Rules) > 1000 {
		return nil, malformedXML()
	}
	out := &LifecycleConfiguration{Rules: make([]LifecycleRule, 0, len(in.Rules))}
	ids := make(map[string]struct{}, len(in.Rules))
	legacy, modern := false, false
	for _, rule := range in.Rules {
		if value(rule.Status) != "Enabled" && value(rule.Status) != "Disabled" {
			return nil, malformedXML()
		}
		filter, wire := parseLifecycleFilter(rule)
		if wire != nil {
			return nil, wire
		}
		legacy = legacy || filter.Kind == "legacy"
		modern = modern || filter.Kind != "legacy"
		if legacy && modern {
			return nil, failure("InvalidRequest", "Filter element can only be used in Lifecycle V2.", 400)
		}
		stored := LifecycleRule{ID: value(rule.ID), Enabled: value(rule.Status) == "Enabled", Filter: filter}
		if len(stored.ID) > 255 {
			return nil, argumentError("ID", stored.ID, "ID length should not exceed allowed limit of 255")
		}
		if stored.ID == "" {
			id, err := uuid.NewRandom()
			if err != nil {
				return nil, err
			}
			stored.ID = id.String()
		}
		if _, duplicate := ids[stored.ID]; duplicate {
			return nil, argumentError("ID", stored.ID, "Rule ID must be unique. Found same ID for more than one rule")
		}
		ids[stored.ID] = struct{}{}
		if wire := parseLifecycleActions(rule, &stored); wire != nil {
			return nil, wire
		}
		out.Rules = append(out.Rules, stored)
	}
	return out, nil
}

func parseLifecycleFilter(rule api.LifecycleRule) (ObjectFilter, *awswire.Error) {
	if rule.Filter == nil {
		if rule.Prefix == nil {
			return ObjectFilter{}, malformedXML()
		}
		return ObjectFilter{Kind: "legacy", Prefix: new(value(rule.Prefix))}, nil
	}
	if rule.Prefix != nil {
		return ObjectFilter{}, malformedXML()
	}
	in := rule.Filter
	out := ObjectFilter{Kind: "empty"}
	members := 0
	var tags api.TagSet
	if in.Prefix != nil {
		members++
		out.Kind, out.Prefix = "prefix", new(value(in.Prefix))
	}
	if in.Tag != nil {
		members++
		out.Kind, tags = "tag", api.TagSet{*in.Tag}
	}
	if in.ObjectSizeGreaterThan != nil {
		members++
		out.Kind, out.ObjectSizeGreaterThan = "greater", new(int64(*in.ObjectSizeGreaterThan))
	}
	if in.ObjectSizeLessThan != nil {
		members++
		out.Kind, out.ObjectSizeLessThan = "less", new(int64(*in.ObjectSizeLessThan))
	}
	if in.And != nil {
		members++
		out.Kind, tags = "and", in.And.Tags
		predicates := len(tags)
		if in.And.Prefix != nil {
			predicates++
			out.Prefix = new(value(in.And.Prefix))
		}
		if in.And.ObjectSizeGreaterThan != nil {
			predicates++
			out.ObjectSizeGreaterThan = new(int64(*in.And.ObjectSizeGreaterThan))
		}
		if in.And.ObjectSizeLessThan != nil {
			predicates++
			out.ObjectSizeLessThan = new(int64(*in.And.ObjectSizeLessThan))
		}
		if predicates < 2 {
			return ObjectFilter{}, malformedXML()
		}
	}
	if members > 1 {
		return ObjectFilter{}, malformedXML()
	}
	const maxSize = 1099511627776000
	if out.ObjectSizeGreaterThan != nil && (*out.ObjectSizeGreaterThan < 0 || *out.ObjectSizeGreaterThan > maxSize) {
		return ObjectFilter{}, failure("InvalidRequest", "'ObjectSizeGreaterThan' should be between 0 and 1099511627776000.", 400)
	}
	if out.ObjectSizeLessThan != nil && (*out.ObjectSizeLessThan < 1 || *out.ObjectSizeLessThan > maxSize) {
		return ObjectFilter{}, failure("InvalidRequest", "'ObjectSizeLessThan' should be between 1 and 1099511627776000.", 400)
	}
	if out.ObjectSizeGreaterThan != nil && out.ObjectSizeLessThan != nil && *out.ObjectSizeGreaterThan >= *out.ObjectSizeLessThan {
		return ObjectFilter{}, failure("InvalidRequest", "'ObjectSizeLessThan' has to be a value greater than 'ObjectSizeGreaterThan'.", 400)
	}
	if len(tags) != 0 {
		var wire *awswire.Error
		out.Tags, wire = validateTags(&api.Tagging{TagSet: tags}, false)
		if wire != nil {
			if wire.Code == "InvalidTag" {
				switch wire.Message {
				case "Cannot provide multiple Tags with the same key":
					return ObjectFilter{}, failure("InvalidRequest", "Duplicate Tag Keys are not allowed.", 400)
				case "The TagKey you have provided is invalid":
					return ObjectFilter{}, failure("InvalidRequest", "A Tag's Key must be a length between 1 and 128.", 400)
				case "The TagValue you have provided is invalid":
					return ObjectFilter{}, failure("InvalidRequest", "A Tag's Value must be a length between 0 and 256.", 400)
				}
			}
			return ObjectFilter{}, wire
		}
	}
	return out, nil
}

func parseLifecycleActions(in api.LifecycleRule, out *LifecycleRule) *awswire.Error {
	if in.Expiration == nil && len(in.Transitions) == 0 && in.NoncurrentVersionExpiration == nil && len(in.NoncurrentVersionTransitions) == 0 && in.AbortIncompleteMultipartUpload == nil {
		return failure("InvalidRequest", "At least one action needs to be specified in a rule", 400)
	}
	if expiration := in.Expiration; expiration != nil {
		out.Expiration = &LifecycleExpiration{}
		if expiration.ExpiredObjectDeleteMarker != nil {
			if expiration.Date != nil || expiration.Days != nil {
				return malformedXML()
			}
			if wire := lifecycleUnfilteredAction(out.Filter, "ExpiredObjectDeleteMarker"); wire != nil {
				return wire
			}
			out.Expiration.ExpiredObjectDeleteMarker = new(bool(*expiration.ExpiredObjectDeleteMarker))
		} else {
			when, wire := parseLifecycleWhen(expiration.Date, expiration.Days, "Expiration")
			if wire != nil {
				return wire
			}
			out.Expiration.LifecycleWhen = when
		}
	}
	if len(in.Transitions) != 0 {
		out.Transitions = make([]LifecycleTransition, 0, len(in.Transitions))
	}
	for _, transition := range in.Transitions {
		when, wire := parseLifecycleWhen(transition.Date, transition.Days, "Transition")
		if wire != nil {
			return wire
		}
		class := value(transition.StorageClass)
		if wire := lifecycleAdmissionClass(class); wire != nil {
			return wire
		}
		out.Transitions = append(out.Transitions, LifecycleTransition{LifecycleWhen: when, StorageClass: class})
	}
	if expiration := in.NoncurrentVersionExpiration; expiration != nil {
		parsed, wire := parseLifecycleNoncurrent(expiration.NoncurrentDays, expiration.NewerNoncurrentVersions, out.Filter.Kind == "legacy", "NoncurrentVersionExpiration")
		if wire != nil {
			return wire
		}
		out.NoncurrentExpiration = &parsed
	}
	if len(in.NoncurrentVersionTransitions) != 0 {
		out.NoncurrentTransitions = make([]LifecycleNoncurrentTransition, 0, len(in.NoncurrentVersionTransitions))
	}
	for _, transition := range in.NoncurrentVersionTransitions {
		parsed, wire := parseLifecycleNoncurrent(transition.NoncurrentDays, transition.NewerNoncurrentVersions, out.Filter.Kind == "legacy", "NoncurrentVersionTransition")
		if wire != nil {
			return wire
		}
		class := value(transition.StorageClass)
		if wire := lifecycleAdmissionClass(class); wire != nil {
			return wire
		}
		out.NoncurrentTransitions = append(out.NoncurrentTransitions, LifecycleNoncurrentTransition{LifecycleNoncurrentExpiration: parsed, StorageClass: class})
	}
	if abort := in.AbortIncompleteMultipartUpload; abort != nil {
		if abort.DaysAfterInitiation == nil {
			return malformedXML()
		}
		days := int32(*abort.DaysAfterInitiation)
		if days <= 0 {
			return lifecyclePositiveInteger("DaysAfterInitiation", "AbortIncompleteMultipartUpload", days)
		}
		if wire := lifecycleUnfilteredAction(out.Filter, "AbortIncompleteMultipartUpload"); wire != nil {
			return wire
		}
		out.AbortIncompleteDays = &days
	}
	return validateLifecycleActionOrder(out)
}

func lifecycleUnfilteredAction(filter ObjectFilter, action string) *awswire.Error {
	if len(filter.Tags) != 0 {
		return failure("InvalidRequest", action+" cannot be specified with Tags.", 400)
	}
	if filter.ObjectSizeGreaterThan != nil || filter.ObjectSizeLessThan != nil {
		return failure("InvalidRequest", action+" cannot be specified with Object Size.", 400)
	}
	return nil
}

func parseLifecycleWhen(date *api.Date, days *api.Days, action string) (LifecycleWhen, *awswire.Error) {
	if (date == nil) == (days == nil) {
		return LifecycleWhen{}, malformedXML()
	}
	if date != nil {
		utc := date.UTC()
		if utc.Hour() != 0 || utc.Minute() != 0 || utc.Second() != 0 || utc.Nanosecond() != 0 {
			return LifecycleWhen{}, lifecycleDateArgument(utc, "'Date' must be at midnight GMT")
		}
		return LifecycleWhen{Date: &utc}, nil
	}
	value := int32(*days)
	if action == "Expiration" && value <= 0 {
		return LifecycleWhen{}, lifecyclePositiveInteger("Days", action, value)
	}
	if value < 0 {
		return LifecycleWhen{}, argumentError("Days", strconv.FormatInt(int64(value), 10), "'Days' in Transition action must be nonnegative")
	}
	return LifecycleWhen{Days: &value}, nil
}

func parseLifecycleNoncurrent(days *api.Days, newer *api.VersionCount, legacy bool, action string) (LifecycleNoncurrentExpiration, *awswire.Error) {
	if days == nil {
		return LifecycleNoncurrentExpiration{}, malformedXML()
	}
	out := LifecycleNoncurrentExpiration{Days: int32(*days)}
	if action == "NoncurrentVersionExpiration" && out.Days <= 0 {
		return out, lifecyclePositiveInteger("NoncurrentDays", action, out.Days)
	}
	if out.Days < 0 {
		return out, argumentError("NoncurrentDays", strconv.FormatInt(int64(out.Days), 10), "'NoncurrentDays' in NoncurrentVersionTransition action must be nonnegative")
	}
	if newer != nil {
		if legacy {
			return out, failure("InvalidRequest", "NewerNoncurrentVersions element can only be used in Lifecycle V2.", 400)
		}
		count := int32(*newer)
		if count <= 0 {
			return out, lifecyclePositiveInteger("NewerNoncurrentVersions", action, count)
		}
		out.NewerNoncurrentVersions = &count
	}
	return out, nil
}

func lifecyclePositiveInteger(field, action string, value int32) *awswire.Error {
	return argumentError(field, strconv.FormatInt(int64(value), 10), "'"+field+"' for "+action+" action must be a positive integer")
}

func lifecycleDateArgument(date time.Time, message string) *awswire.Error {
	location, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		return failure("InternalError", err.Error(), 500)
	}
	return argumentError("Date", date.In(location).Format("Mon Jan 02 15:04:05 MST 2006"), message)
}

func lifecycleAdmissionClass(class string) *awswire.Error {
	switch class {
	case "STANDARD_IA", "INTELLIGENT_TIERING", "ONEZONE_IA", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE":
		return nil
	case "STANDARD", "REDUCED_REDUNDANCY":
		return argumentError("StorageClass", class, "Invalid target Storage class for Transition action")
	default:
		return malformedXML()
	}
}

func validateLifecycleActionOrder(rule *LifecycleRule) *awswire.Error {
	for i, transition := range rule.Transitions {
		for _, previous := range rule.Transitions[:i] {
			if wire := lifecycleTransitionOrder(previous, transition, false); wire != nil {
				return wire
			}
		}
		if expiration := rule.Expiration; expiration != nil && expiration.ExpiredObjectDeleteMarker == nil {
			if wire := lifecycleExpirationOrder(expiration.LifecycleWhen, transition.LifecycleWhen, false); wire != nil {
				return wire
			}
		}
	}
	for i, transition := range rule.NoncurrentTransitions {
		current := LifecycleTransition{LifecycleWhen: LifecycleWhen{Days: &transition.Days}, StorageClass: transition.StorageClass}
		for _, previous := range rule.NoncurrentTransitions[:i] {
			prior := LifecycleTransition{LifecycleWhen: LifecycleWhen{Days: &previous.Days}, StorageClass: previous.StorageClass}
			if wire := lifecycleTransitionOrder(prior, current, true); wire != nil {
				return wire
			}
		}
		if expiration := rule.NoncurrentExpiration; expiration != nil {
			if wire := lifecycleExpirationOrder(LifecycleWhen{Days: &expiration.Days}, current.LifecycleWhen, true); wire != nil {
				return wire
			}
		}
	}
	return nil
}

func lifecycleTransitionOrder(first, second LifecycleTransition, noncurrent bool) *awswire.Error {
	action, field := "Transition", "Days"
	if noncurrent {
		action, field = "NoncurrentVersionTransition", "NoncurrentDays"
	}
	if first.StorageClass == second.StorageClass {
		return failure("InvalidRequest", "'StorageClass' must be different for '"+action+"' actions in same 'Rule' with filter '()'", 400)
	}
	if (first.Date == nil) != (second.Date == nil) {
		return failure("InvalidRequest", "Found mixed 'Date' and 'Days' based Transition actions in lifecycle rule for filter '()'", 400)
	}
	// Validate the shared waterfall without sorting the retained wire order.
	warm, cold := first, second
	if lifecycleTransitionAllowed(second.StorageClass, first.StorageClass) {
		warm, cold = second, first
	}
	var gap int64
	if warm.Date != nil {
		field = "Date"
		gap = (cold.Date.Unix() - warm.Date.Unix()) / 86400
	} else {
		gap = int64(*cold.Days) - int64(*warm.Days)
	}
	if gap <= 0 || !lifecycleTransitionAllowed(warm.StorageClass, cold.StorageClass) {
		message := fmt.Sprintf("'%s' in the '%s' action for StorageClass '%s' for filter '()' must be greater than '%s' in the '%s' action for StorageClass '%s' for filter '()'", field, action, cold.StorageClass, field, action, warm.StorageClass)
		return lifecycleWhenArgument(second.LifecycleWhen, field, message)
	}
	minimum := int64(0)
	switch warm.StorageClass {
	case "STANDARD_IA", "ONEZONE_IA":
		minimum = 30
	case "GLACIER_IR", "GLACIER":
		minimum = 90
	}
	if gap < minimum {
		message := fmt.Sprintf("'%s' in the '%s' action for StorageClass '%s' for filter '()' must be %d days more than 'filter '()'' in the '%s' action for StorageClass '%s'", field, action, cold.StorageClass, minimum, action, warm.StorageClass)
		return lifecycleWhenArgument(second.LifecycleWhen, field, message)
	}
	return nil
}

func lifecycleExpirationOrder(expiration, transition LifecycleWhen, noncurrent bool) *awswire.Error {
	action, transitionAction, field := "Expiration", "Transition", "Days"
	if noncurrent {
		action, transitionAction, field = "NoncurrentVersionExpiration", "NoncurrentVersionTransition", "NoncurrentDays"
	}
	if (expiration.Date == nil) != (transition.Date == nil) {
		return failure("InvalidRequest", "Found mixed 'Date' and 'Days' based Expiration and Transition actions in lifecycle rule for filter '()'", 400)
	}
	if expiration.Date != nil {
		field = "Date"
		if expiration.Date.After(*transition.Date) {
			return nil
		}
	} else if *expiration.Days > *transition.Days {
		return nil
	}
	message := fmt.Sprintf("'%s' in the %s action for filter '()' must be greater than '%s' in the %s action", field, action, field, transitionAction)
	return lifecycleWhenArgument(expiration, field, message)
}

func lifecycleWhenArgument(when LifecycleWhen, field, message string) *awswire.Error {
	if when.Date != nil {
		return lifecycleDateArgument(*when.Date, message)
	}
	return argumentError(field, strconv.FormatInt(int64(*when.Days), 10), message)
}

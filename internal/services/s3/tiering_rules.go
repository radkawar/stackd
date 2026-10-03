package s3

import (
	"strconv"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// Generated binding owns required members, enums and tag-key length. The
// command owns the cross-field predicates and native configuration limits.
func parseTieringConfiguration(id string, in *api.IntelligentTieringConfiguration) (*TieringConfiguration, *awswire.Error) {
	if len(in.Tierings) == 0 {
		return nil, malformedXML()
	}
	configurationID := value(in.Id)
	if wire := validateConfigurationID(configurationID); wire != nil {
		return nil, wire
	}
	if id != configurationID {
		return nil, malformedXML()
	}
	filter, wire := parseTieringFilter(in.Filter)
	if wire != nil {
		return nil, wire
	}
	out := &TieringConfiguration{ID: configurationID, Enabled: value(in.Status) == "Enabled", Filter: filter, Tierings: make([]TieringRule, 0, len(in.Tierings))}
	var archiveDays, deepArchiveDays int32
	for _, tier := range in.Tierings {
		accessTier, days := AccessTier(*tier.AccessTier), int32(*tier.Days)
		previous, minimum := &archiveDays, int32(90)
		if accessTier == DeepArchiveAccessTier {
			previous, minimum = &deepArchiveDays, 180
		}
		if *previous != 0 {
			return nil, failure("InvalidAccessTier", "All Access Tiers in a configuration must be unique. Found duplicate entry for "+string(accessTier)+".", 400)
		}
		if days < minimum {
			return nil, failure("InvalidAccessTier", "Days specified in "+string(accessTier)+" tier should not be less than "+strconv.Itoa(int(minimum))+".", 400)
		}
		if days > 730 {
			return nil, failure("InvalidAccessTier", "Days specified in "+string(accessTier)+" tier should not be more than 730.", 400)
		}
		*previous = days
		out.Tierings = append(out.Tierings, TieringRule{AccessTier: accessTier, Days: days})
	}
	if archiveDays != 0 && deepArchiveDays != 0 && deepArchiveDays <= archiveDays {
		return nil, failure("InvalidAccessTier", "Days specified in DEEP_ARCHIVE_ACCESS should be greater than days specified in ARCHIVE_ACCESS", 400)
	}
	return out, nil
}

func parseTieringFilter(in *api.IntelligentTieringFilter) (*ObjectFilter, *awswire.Error) {
	if in == nil {
		return nil, nil
	}
	members := 0
	if in.Prefix != nil {
		members++
	}
	if in.Tag != nil {
		members++
	}
	if in.And != nil {
		members++
	}
	if members != 1 {
		return nil, malformedXML()
	}
	out := &ObjectFilter{}
	var tags api.TagSet
	switch {
	case in.Prefix != nil:
		out.Kind, out.Prefix = "prefix", new(value(in.Prefix))
	case in.Tag != nil:
		out.Kind, tags = "tag", api.TagSet{*in.Tag}
	case in.And != nil:
		out.Kind, tags = "and", in.And.Tags
		predicates := len(tags)
		if in.And.Prefix != nil {
			predicates++
			out.Prefix = new(value(in.And.Prefix))
		}
		if predicates < 2 {
			return nil, failure("InvalidAnd", "Number of Prefixes and Tags combined cannot be less than 2. And cannot contain less than 2 elements.", 400)
		}
	}
	if out.Prefix != nil && *out.Prefix == "" {
		return nil, failure("InvalidPrefix", "Filter Prefix should be set to a valid non-empty value or not set at all.", 400)
	}
	if len(tags) != 0 {
		out.Tags = make([]Tag, 0, len(tags))
		keys := make(map[string]struct{}, len(tags))
		for _, tag := range tags {
			key := value(tag.Key)
			if _, duplicate := keys[key]; duplicate {
				return nil, failure("InvalidAnd", "All Tag Keys in an And must be unique. Found duplicate entry for "+key+".", 400)
			}
			keys[key] = struct{}{}
			out.Tags = append(out.Tags, Tag{Key: key, Value: value(tag.Value)})
		}
	}
	return out, nil
}

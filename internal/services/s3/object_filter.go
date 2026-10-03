package s3

import (
	"slices"
	"strings"
)

// ObjectFilter preserves a bucket rule's admitted form and matching predicate.
// Kind is legacy, empty, prefix, tag, and, greater or less. Each command admits
// only its supported forms. Supplied size bounds are exclusive.
type ObjectFilter struct {
	Kind                  string
	Prefix                *string
	Tags                  []Tag
	ObjectSizeGreaterThan *int64
	ObjectSizeLessThan    *int64
}

func objectFilterMatches(filter ObjectFilter, object ObjectRecord, tags []Tag) bool {
	if filter.Prefix != nil && !strings.HasPrefix(object.Key.Name, *filter.Prefix) {
		return false
	}
	// Delete markers have neither an object payload size nor object tags.
	if object.DeleteMarker && (len(filter.Tags) != 0 || filter.ObjectSizeGreaterThan != nil || filter.ObjectSizeLessThan != nil) {
		return false
	}
	if filter.ObjectSizeGreaterThan != nil && object.Size <= *filter.ObjectSizeGreaterThan || filter.ObjectSizeLessThan != nil && object.Size >= *filter.ObjectSizeLessThan {
		return false
	}
	for _, required := range filter.Tags {
		if !slices.Contains(tags, required) {
			return false
		}
	}
	return true
}

func cloneObjectFilter(filter ObjectFilter) ObjectFilter {
	filter.Prefix = copyOptional(filter.Prefix)
	filter.Tags = slices.Clone(filter.Tags)
	filter.ObjectSizeGreaterThan = copyOptional(filter.ObjectSizeGreaterThan)
	filter.ObjectSizeLessThan = copyOptional(filter.ObjectSizeLessThan)
	return filter
}

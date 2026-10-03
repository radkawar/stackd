package cloudformation

import (
	"fmt"
	"maps"
	"slices"
	"unicode/utf8"
)

// ValidateResourceStringLengths checks captured registry bounds on resolved
// properties. Providers call it during resource admission, not template parsing:
// native model validation failures belong to the resource operation/rollback.
// Non-string values remain subject to each provider's type/coercion checks.
func ValidateResourceStringLengths(typeName string, properties Properties) error {
	bounds := resourceSchemas[typeName].StringLengths
	for _, path := range slices.Sorted(maps.Keys(bounds)) {
		limit := bounds[path]
		for _, value := range resourcePathValues(properties, resourcePathParts(path)) {
			text, ok := value.(string)
			if !ok {
				continue
			}
			length := utf8.RuneCountInString(text)
			if length < limit.Min {
				return fmt.Errorf("resource property %s%s requires minLength %d", typeName, path, limit.Min)
			}
			if limit.Max >= 0 && length > limit.Max {
				return fmt.Errorf("resource property %s%s exceeds maxLength %d", typeName, path, limit.Max)
			}
		}
	}
	return nil
}

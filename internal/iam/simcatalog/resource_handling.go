package simcatalog

import (
	"slices"
	"strings"
)

// SupportsResourceHandling reports the action's AWS-captured simulator options.
// SAR resource types and API operation names are separate contracts.
func SupportsResourceHandling(action, option string) bool {
	return slices.Contains(resourceHandlingOptions[strings.ToLower(action)], option)
}

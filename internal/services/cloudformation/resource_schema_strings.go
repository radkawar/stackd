package cloudformation

import "fmt"

// ValidateResourceStringLengths checks captured registry bounds on resolved
// properties. Providers call it during resource admission, not template parsing:
// native model validation failures belong to the resource operation/rollback.
// Non-string values remain subject to each provider's type/coercion checks.
func ValidateResourceStringLengths(typeName string, properties Properties) error {
	if err := validateCompiledResourceSchema(typeName, properties, true); err != nil {
		return fmt.Errorf("resource string limits: %w", err)
	}
	return nil
}

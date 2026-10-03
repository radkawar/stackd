package policy

import (
	"fmt"
	"strings"
)

// ParseResourceControl compiles a customer RCP. The caller supplies AWS's
// supported service catalogue; action names may be unknown or use wildcards.
// AWS's built-in RCPFullAWSAccess uses the ordinary resource-policy parser.
func ParseResourceControl(data []byte, supportsService func(string) bool) (*Document, error) {
	doc, err := ParseResource(data)
	if err != nil {
		return nil, err
	}
	for _, st := range doc.statements {
		if st.effect != ExplicitDeny || st.notAction || st.notPrincipal {
			return nil, fmt.Errorf("%w: customer RCPs require Deny, Action and Principal", ErrInvalidPolicy)
		}
		for _, principal := range st.principals {
			if principal.kind != "AWS" || principal.value != "*" {
				return nil, fmt.Errorf("%w: RCP Principal must select everyone", ErrInvalidPolicy)
			}
		}
		for _, action := range st.actions {
			service, _, ok := strings.Cut(action, ":")
			if !ok || !supportsService(service) {
				return nil, fmt.Errorf("%w: RCP action requires a supported service", ErrInvalidPolicy)
			}
		}
	}
	return doc, nil
}

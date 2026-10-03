package policy

import (
	"fmt"
	"strings"
)

// UnsupportedDelegationAction identifies a pattern that selects no known action
// or includes an action outside the service's delegation permissions.
type UnsupportedDelegationAction struct{ Action string }

func (e *UnsupportedDelegationAction) Error() string {
	return "unsupported delegation action: " + e.Action
}

// ParseDelegation compiles an Organizations delegation policy and normalizes
// numeric AWS account principals for storage. Actions contains every modeled
// service action and whether it is delegatable; wildcards must select only
// supported actions. The service must separately verify account membership.
// Negated selectors are not accepted by the current Organizations contract.
func ParseDelegation(data []byte, partition string, actions map[string]bool) (*Document, []byte, error) {
	doc, err := ParseResource(data)
	if err != nil {
		return nil, nil, err
	}
	for _, st := range doc.statements {
		if st.notAction || st.notResource || st.notPrincipal {
			return nil, nil, fmt.Errorf("%w: delegation policies require positive selectors", ErrInvalidPolicy)
		}
		for _, pattern := range st.actions {
			matched := false
			for action, supported := range actions {
				if !wildcardMatch(strings.ToLower(pattern), strings.ToLower(action), false) {
					continue
				}
				if !supported {
					return nil, nil, &UnsupportedDelegationAction{Action: pattern}
				}
				matched = true
			}
			if !matched {
				return nil, nil, &UnsupportedDelegationAction{Action: pattern}
			}
		}
	}
	if len(doc.FederatedPrincipals()) != 0 {
		return nil, nil, fmt.Errorf("%w: delegation principals must identify AWS accounts or services", ErrInvalidPolicy)
	}
	replacements := map[string]string{}
	for _, principal := range doc.AWSPrincipals() {
		if principal == "*" {
			continue
		}
		if accountPattern.MatchString(principal) {
			replacements[principal] = "arn:" + partition + ":iam::" + principal + ":root"
			continue
		}
		parts := strings.SplitN(principal, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] != partition || parts[2] != "iam" || parts[3] != "" || !accountPattern.MatchString(parts[4]) || parts[5] != "root" {
			return nil, nil, fmt.Errorf("%w: delegation AWS principals must identify accounts", ErrInvalidPolicy)
		}
	}
	canonical, err := rewritePrincipals(data, replacements)
	return doc, canonical, err
}

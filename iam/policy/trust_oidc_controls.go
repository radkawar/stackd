package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ValidateOIDCTrustControls applies IAM's required provider conditions when a
// role trust policy is created or replaced. It must not be called when rendering
// or evaluating persisted policies: AWS does not retroactively apply these
// write controls to preexisting trust documents.
func ValidateOIDCTrustControls(data []byte) error {
	resource, err := TrustResourcePolicy(data)
	if err != nil {
		return err
	}
	document, err := ParseResource(resource)
	if err != nil {
		return err
	}
	rawDocument, _ := object(data)
	rawStatements, _ := scalarOrArray(rawDocument["Statement"])
	for index, statement := range document.statements {
		if statement.effect != Allow || matchesAny(statement.actions, "sts:assumerolewithwebidentity", true, false) == statement.notAction {
			continue
		}
		for _, principal := range statement.principals {
			if principal.kind != "Federated" {
				continue
			}
			issuer := principal.value
			if _, suffix, ok := strings.Cut(issuer, ":oidc-provider/"); ok {
				issuer = suffix
			}
			if keys := builtinOIDCTrustKeys(issuer); len(keys) != 0 {
				fields, _ := object(rawStatements[index])
				if !hasBuiltinOIDCTrustControl(fields["Condition"], keys) {
					return fmt.Errorf("%w: Policy trusting %s requires a StringEquals condition on an application id", ErrInvalidPolicy, issuer)
				}
				continue
			}
			claim, shared := sharedOIDCTrustClaims[issuer]
			github := strings.HasPrefix(issuer, "token.actions.githubusercontent.com")
			if github {
				claim, shared = issuer+":sub", true
			}
			if !shared {
				continue
			}
			claims := []string{claim}
			if github {
				claims = append(claims, issuer+":job_workflow_ref")
			}
			if !hasSharedOIDCTrustControl(statement.conditions, claims, github) {
				return fmt.Errorf("%w: Trust policy with trusted principal %s must evaluate, using StringEquals, StringLike or StringEqualsIgnoreCase, %s which is not scoped to all", ErrInvalidPolicy, principal.value, strings.Join(claims, " or "))
			}
		}
	}
	return nil
}

func hasSharedOIDCTrustControl(conditions []condition, claims []string, github bool) bool {
	type controlGroup struct{ present, invalid bool }
	groups := make(map[string]controlGroup)
	for _, condition := range conditions {
		if !positiveOIDCStringOperator(condition.op, true) {
			continue
		}
		matched := false
		for _, claim := range claims {
			matched = matched || strings.EqualFold(claim, condition.key)
		}
		if !matched {
			continue
		}
		group := groups[condition.name]
		group.present = true
		for _, value := range condition.values {
			// AWS tests values, not semantic satisfiability. Empty arrays qualify;
			// generic controls reject literal "*" while GitHub also rejects its
			// observed leading-star patterns and blank values.
			if value.text == "*" || github && (strings.TrimSpace(value.text) == "" || strings.HasPrefix(value.text, "*")) {
				group.invalid = true
				break
			}
		}
		groups[condition.name] = group
	}
	for _, group := range groups {
		// Alternative claims in one operator block must all be scoped. A
		// separate positive operator block can independently provide a control.
		if group.present && !group.invalid {
			return true
		}
	}
	return false
}

func positiveOIDCStringOperator(op operator, allowLike bool) bool {
	return op.kind == stringKind && !op.negated && !op.ifExists && (op.comparison == equal || op.comparison == equalFold || allowLike && op.comparison == like)
}

func builtinOIDCTrustKeys(issuer string) []string {
	switch issuer {
	case "accounts.google.com":
		return []string{issuer + ":aud", issuer + ":oaud", issuer + ":sub"}
	case "www.amazon.com", "graph.facebook.com":
		return []string{issuer + ":app_id", issuer + ":sub"}
	default:
		return nil
	}
}

func hasBuiltinOIDCTrustControl(raw json.RawMessage, claims []string) bool {
	conditions, _ := object(raw)
	for name, rawKeys := range conditions {
		op, err := parseOperator(name)
		if err != nil || !positiveOIDCStringOperator(op, false) {
			continue
		}
		keys, _ := object(rawKeys)
		for _, claim := range claims {
			// Legacy built-in controls use exact condition-key spelling, unlike
			// ordinary IAM condition evaluation and newer shared-provider checks.
			if _, exists := keys[claim]; exists {
				return true
			}
		}
	}
	return false
}

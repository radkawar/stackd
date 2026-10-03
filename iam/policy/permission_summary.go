package policy

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
)

// PermissionSummary retains the selectors needed for potential-permission
// reports. Such reports intentionally ignore conditions; they cannot establish
// that an actual request is authorized. The stored source document must have
// passed the IAM policy storage boundary's validation.
type PermissionSummary struct {
	statements []permissionStatement
}

type permissionStatement struct {
	effect      Decision
	actions     []string
	notAction   bool
	resources   []string
	notResource bool
	conditional bool
}

// ParsePermissionSummary reads action/resource selectors without invoking the
// enforcement compiler's condition checks. Valid stored policies can contain
// condition values that require request context or are not meaningful to this
// reporting operation. Returned summaries retain no mutable input bytes.
func ParsePermissionSummary(data []byte) (*PermissionSummary, error) {
	obj, err := object(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	statements, err := scalarOrArray(obj["Statement"])
	if err != nil || len(statements) == 0 {
		return nil, fmt.Errorf("%w: Statement must contain at least one statement", ErrInvalidPolicy)
	}
	result := &PermissionSummary{}
	for _, raw := range statements {
		fields, err := object(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: statement must be an object", ErrInvalidPolicy)
		}
		effect, err := stringValue(fields["Effect"])
		if err != nil || effect != "Allow" && effect != "Deny" {
			return nil, fmt.Errorf("%w: Effect must be Allow or Deny", ErrInvalidPolicy)
		}
		statement := permissionStatement{effect: Allow}
		if condition, present := fields["Condition"]; present {
			values, err := object(condition)
			if err != nil {
				return nil, fmt.Errorf("%w: Condition must be an object", ErrInvalidPolicy)
			}
			statement.conditional = len(values) > 0
		}
		if effect == "Deny" {
			statement.effect = ExplicitDeny
		}
		statement.actions, statement.notAction, err = alternatives(fields, "Action", "NotAction")
		if err != nil {
			return nil, err
		}
		for i, action := range statement.actions {
			statement.actions[i] = strings.ToLower(action)
		}
		statement.resources, statement.notResource, err = alternatives(fields, "Resource", "NotResource")
		if err != nil {
			return nil, err
		}
		result.statements = append(result.statements, statement)
	}
	return result, nil
}

// GrantsService implements the coarse, per-document discovery used by IAM's
// ListPoliciesGrantingServiceAccess. Conditional grants are potential grants;
// only unconditional whole-service denies on all resources suppress a service.
// resourceTemplates are the service's SAR ARN templates, not concrete ARNs.
func (p *PermissionSummary) GrantsService(ctx context.Context, namespace string, resourceTemplates []string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if p == nil {
		return false, nil
	}
	var grants []permissionStatement
	for _, statement := range p.statements {
		selects, whole := statement.serviceActions(namespace)
		if statement.effect == ExplicitDeny {
			if !statement.conditional && whole && !statement.notResource && slices.Contains(statement.resources, "*") {
				return false, nil
			}
		} else if selects {
			grants = append(grants, statement)
		}
	}
	return potentialResource(ctx, resourceTemplates, [][]permissionStatement{grants}, 0)
}
func (s permissionStatement) serviceActions(namespace string) (some, all bool) {
	namespace = strings.ToLower(namespace)
	for _, pattern := range s.actions {
		if pattern == "*" {
			some, all = true, true
			break
		}
		prefix, action, found := strings.Cut(strings.ToLower(pattern), ":")
		if found && prefix == namespace {
			some = true
			if action != "" && strings.Trim(action, "*") == "" {
				all = true
			}
		}
	}
	if s.notAction {
		return !all, !some
	}
	return some, all
}

// PotentialActions combines the policy levels used by permission reports. Allows
// are unioned within each level, then intersected across levels at the same
// resource. Any unconditional deny prevails. Conditional allows remain potential
// permissions and conditional denies are ignored; this is not authorization.
// Zero levels impose no restrictions; an empty level permits nothing. Identity
// reports pass one level, and Organizations reports pass the SCP hierarchy.
// The map associates concrete canonical SAR action names with their resource
// templates; a nil template list denotes an action with only the global resource.
func PotentialActions(ctx context.Context, levels [][]*PermissionSummary, resourcesByAction map[string][]string) ([]string, error) {
	return potentialActions(ctx, levels, resourcesByAction, nil)
}

// PotentialActionsWithResourceLimits is PotentialActions with an optional upper
// bound on each action's resource ARN length in UTF-8 bytes. Missing or zero
// bounds retain the unbounded report semantics; negative bounds are invalid.
// Bounded searches admit only valid Unicode strings within that byte limit.
// Conditions retain PotentialActions' reporting semantics, not authorization.
func PotentialActionsWithResourceLimits(ctx context.Context, levels [][]*PermissionSummary, resourcesByAction map[string][]string, maxResourceBytesByAction map[string]int) ([]string, error) {
	for _, maxBytes := range maxResourceBytesByAction {
		if maxBytes < 0 {
			return nil, fmt.Errorf("resource byte limit must not be negative")
		}
	}
	return potentialActions(ctx, levels, resourcesByAction, maxResourceBytesByAction)
}

func potentialActions(ctx context.Context, levels [][]*PermissionSummary, resourcesByAction map[string][]string, maxResourceBytesByAction map[string]int) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	statements := make([][]permissionStatement, len(levels))
	for i, level := range levels {
		for _, summary := range level {
			if summary != nil {
				statements[i] = append(statements[i], summary.statements...)
			}
		}
	}
	result := make([]string, 0)
	decisions := make(map[string]bool)
	// A large hierarchy commonly contains service-specific restrictions. Do
	// not re-scan those restrictions for every unrelated catalog action.
	candidates := make(map[string][][]int)
	actions := make([]string, 0, len(resourcesByAction))
	for action := range resourcesByAction {
		actions = append(actions, action)
	}
	slices.Sort(actions)
	for _, action := range actions {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resourceTemplates := resourcesByAction[action]
		maxBytes := maxResourceBytesByAction[action]
		normalizedAction := strings.ToLower(action)
		namespace, _, _ := strings.Cut(normalizedAction, ":")
		selected, prepared := candidates[namespace]
		if !prepared {
			selected = make([][]int, len(statements))
			for level, entries := range statements {
				for i, statement := range entries {
					if statement.effect == ExplicitDeny && statement.conditional {
						continue
					}
					if some, _ := statement.serviceActions(namespace); some {
						selected[level] = append(selected[level], i)
					}
				}
			}
			candidates[namespace] = selected
		}
		applicable := make([][]permissionStatement, len(levels))
		var signature []byte
		if maxResourceBytesByAction != nil {
			signature = binary.AppendUvarint(signature, uint64(maxBytes))
		}
		for level, indexes := range selected {
			for _, i := range indexes {
				statement := statements[level][i]
				matches := matchesAny(statement.actions, normalizedAction, false, false)
				if matches == statement.notAction {
					continue
				}
				applicable[level] = append(applicable[level], statement)
				signature = binary.AppendUvarint(signature, uint64(i+1))
			}
			signature = append(signature, 0)
		}
		// Length prefixes keep arbitrary literal resource text from colliding with
		// the selector signature or another template's boundary.
		for _, template := range resourceTemplates {
			signature = binary.AppendUvarint(signature, uint64(len(template)))
			signature = append(signature, template...)
		}
		key := string(signature)
		allowed, exists := decisions[key]
		if !exists {
			var err error
			allowed, err = potentialResource(ctx, resourceTemplates, applicable, maxBytes)
			if err != nil {
				return nil, err
			}
			decisions[key] = allowed
		}
		if allowed {
			result = append(result, action)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

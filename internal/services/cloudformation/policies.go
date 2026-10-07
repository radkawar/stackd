package cloudformation

import "fmt"

// ResourcePolicies is admitted intent, frozen into each ResourceRecord before
// provisioning so deletion and rollback never reevaluate customer expressions.
type ResourcePolicies struct {
	DeletionPolicy, UpdateReplacePolicy string
}

func validResourcePolicy(policy, value string) bool {
	return value == "Delete" || value == "Retain" || value == "Snapshot" || policy == "DeletionPolicy" && value == "RetainExceptOnCreate"
}

// RFC0011 permits only Ref, FindInMap and If, and only AccountId, Region and
// Partition pseudo parameters. Conditions are checked transitively, including
// inactive branches, rather than opening a path to stack/resource references.
func (t *Template) validatePolicyExpression(value any, policy string, result, condition bool, visited map[string]bool) error {
	if text, ok := value.(string); ok {
		if err := templateDynamicReference(text); err != nil {
			return err
		}
		if result && !validResourcePolicy(policy, text) {
			return fmt.Errorf("unsupported policy %q", text)
		}
		return nil
	}
	if condition && !result {
		switch value.(type) {
		case bool, float64, nil:
			return nil
		}
	}
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("requires a policy string or permitted intrinsic expression")
	}
	name, argument, intrinsic, err := templateFunction(object)
	if err != nil {
		return err
	}
	if !intrinsic {
		return fmt.Errorf("requires a permitted intrinsic expression")
	}
	switch name {
	case "Ref":
		ref, ok := argument.(string)
		if !ok {
			return fmt.Errorf("lifecycle policy Ref requires a literal parameter name")
		}
		if _, ok := t.Parameters[ref]; ok {
			return nil
		}
		if ref == "AWS::AccountId" || ref == "AWS::Region" || ref == "AWS::Partition" {
			return nil
		}
		return fmt.Errorf("lifecycle policy Ref %s is not permitted", ref)
	case "Fn::If":
		args, err := templateArguments(argument, 3, 3)
		if err != nil {
			return err
		}
		name, ok := args[0].(string)
		if !ok {
			return fmt.Errorf("Fn::If requires a literal condition name")
		}
		if err := t.validatePolicyCondition(name, policy, visited); err != nil {
			return err
		}
		for _, branch := range args[1:] {
			if err := t.validatePolicyExpression(branch, policy, result, condition, visited); err != nil {
				return err
			}
		}
		return nil
	case "Fn::FindInMap":
		args, err := templateArguments(argument, 3, 3)
		if err != nil {
			return err
		}
		if err := t.validateFunction(name, argument, false, condition); err != nil {
			return err
		}
		for _, key := range args {
			if err := t.validatePolicyExpression(key, policy, false, condition, visited); err != nil {
				return err
			}
		}
		return nil
	case "Condition":
		if condition {
			name, ok := argument.(string)
			if !ok {
				return fmt.Errorf("requires a literal condition name")
			}
			return t.validatePolicyCondition(name, policy, visited)
		}
	case "Fn::Equals", "Fn::And", "Fn::Or", "Fn::Not":
		if condition {
			if err := t.validateFunction(name, argument, false, true); err != nil {
				return err
			}
			for _, arg := range argument.([]any) {
				if err := t.validatePolicyExpression(arg, policy, false, true, visited); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return fmt.Errorf("%s is not permitted in lifecycle policies", name)
}

func (t *Template) validatePolicyCondition(name, policy string, visited map[string]bool) error {
	if err := t.validateConditionName(name, false); err != nil {
		return err
	}
	if visited[name] {
		return nil
	}
	visited[name] = true
	return t.validatePolicyExpression(t.Conditions[name], policy, false, true, visited)
}

func (t *Template) ResolvePolicies(input Evaluation) (map[string]ResourcePolicies, error) {
	e := t.evaluator(input)
	out := make(map[string]ResourcePolicies, len(t.Resources))
	for _, id := range templateKeys(t.Resources) {
		resource := t.Resources[id]
		policies := ResourcePolicies{}
		for _, entry := range []struct {
			name   string
			raw    any
			target *string
		}{
			{"DeletionPolicy", resource.DeletionPolicy, &policies.DeletionPolicy},
			{"UpdateReplacePolicy", resource.UpdateReplacePolicy, &policies.UpdateReplacePolicy},
		} {
			if entry.raw == nil {
				continue
			}
			value, err := e.resolve(entry.raw)
			if err != nil {
				return nil, fmt.Errorf("resource %s %s: %w", id, entry.name, err)
			}
			text, ok := value.(string)
			if !ok || !validResourcePolicy(entry.name, text) {
				return nil, fmt.Errorf("resource %s %s resolved to unsupported policy %v", id, entry.name, value)
			}
			*entry.target = text
		}
		out[id] = policies
	}
	return out, nil
}

func (t *Template) validateResolvedPolicies(input Evaluation, handlers map[string]ResourceHandler) error {
	policies, err := t.ResolvePolicies(input)
	if err != nil {
		return err
	}
	for _, id := range templateKeys(policies) {
		handler := handlers[t.Resources[id].Type]
		for _, policy := range []string{policies[id].DeletionPolicy, policies[id].UpdateReplacePolicy} {
			if validator, ok := handler.(ResourceDeletionPolicyValidator); ok {
				if err := validator.ValidateDeletionPolicy(policy); err != nil {
					return fmt.Errorf("resource %s: %w", id, err)
				}
			} else if policy == "Snapshot" {
				return fmt.Errorf("resource %s does not support Snapshot deletion", id)
			}
		}
	}
	return nil
}

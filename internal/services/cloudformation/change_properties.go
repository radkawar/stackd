package cloudformation

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	api "stackd/internal/awsapi/cloudformation"
)

func changeContext(properties Properties) string {
	raw, _ := json.Marshal(map[string]any{"Properties": contextValue(properties)})
	return string(raw)
}
func contextValue(v any) any {
	switch x := v.(type) {
	case Properties:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = contextValue(v)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = contextValue(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = contextValue(v)
		}
		return out
	case nil:
		return nil
	default:
		return fmt.Sprint(v)
	}
}
func referencesChanged(v any, affected map[string]bool) bool {
	switch x := v.(type) {
	case Properties:
		for _, v := range x {
			if referencesChanged(v, affected) {
				return true
			}
		}
	case map[string]any:
		if name, ok := x["Ref"].(string); ok && affected[name] {
			return true
		}
		if att, ok := x["Fn::GetAtt"].([]any); ok && len(att) > 0 {
			if name, ok := att[0].(string); ok && affected[name] {
				return true
			}
		}
		if name, ok := x["Fn::GetAtt"].(string); ok {
			prefix, _, _ := strings.Cut(name, ".")
			if affected[prefix] {
				return true
			}
		}
		for k, v := range x {
			if k == "Fn::Sub" {
				raw, _ := json.Marshal(v)
				for name := range affected {
					if strings.Contains(string(raw), "${"+name+"}") || strings.Contains(string(raw), "${"+name+".") {
						return true
					}
				}
			}
			if referencesChanged(v, affected) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if referencesChanged(v, affected) {
				return true
			}
		}
	}
	return false
}
func propertyText(v any) string {
	if x, ok := v.(string); ok {
		return x
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}
func changeProperties(change ChangeRecord, includeValues bool, handler ResourceHandler, scope Scope) *api.ResourceChange {
	out := &api.ResourceChange{LogicalResourceId: new(api.LogicalResourceId(change.LogicalID)), ResourceType: new(api.ResourceType(change.Type)), Action: new(api.ChangeAction(change.Action))}
	if change.PhysicalID != "" {
		out.PhysicalResourceId = new(api.PhysicalResourceId(change.PhysicalID))
	}
	if change.Replacement != "" {
		out.Replacement = new(api.Replacement(change.Replacement))
		out.Scope = api.Scope{api.ResourceAttribute("Properties")}
	}
	if change.Replacement == "True" {
		out.PolicyAction = new(api.PolicyAction("ReplaceAndDelete"))
	}
	if includeValues {
		if change.BeforeContext != "" {
			out.BeforeContext = new(api.BeforeContext(change.BeforeContext))
		}
		if change.AfterContext != "" {
			out.AfterContext = new(api.AfterContext(change.AfterContext))
		}
	}
	if change.Action != "Modify" {
		return out
	}
	var before, after struct{ Properties Properties }
	_ = json.Unmarshal([]byte(change.BeforeContext), &before)
	_ = json.Unmarshal([]byte(change.AfterContext), &after)
	keys := map[string]bool{}
	for k := range before.Properties {
		keys[k] = true
	}
	for k := range after.Properties {
		keys[k] = true
	}
	out.Details = api.ResourceChangeDetails{}
	for _, key := range slices.Sorted(maps.Keys(keys)) {
		old, had := before.Properties[key]
		next, has := after.Properties[key]
		if reflect.DeepEqual(old, next) && had == has {
			continue
		}
		kind := "Modify"
		if !had {
			kind = "Add"
		} else if !has {
			kind = "Remove"
		}
		requires := "Never"
		if handler != nil {
			probe := maps.Clone(before.Properties)
			if has {
				probe[key] = next
			} else {
				delete(probe, key)
			}
			replacement, e := resourceReplacementPlan(handler, scope, before.Properties, probe)
			if e != nil || replacement == "Conditional" {
				requires = "Conditionally"
			} else if replacement == "True" {
				requires = "Always"
			}
		}
		target := &api.ResourceTargetDefinition{Attribute: new(api.ResourceAttribute("Properties")), Name: new(api.PropertyName(key)), RequiresRecreation: new(api.RequiresRecreation(requires))}
		if includeValues {
			target.Path = new(api.ResourcePropertyPath("/Properties/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")))
			target.AttributeChangeType = new(api.AttributeChangeType(kind))
			if had {
				target.BeforeValue = new(api.BeforeValue(propertyText(old)))
			}
			if has {
				target.AfterValue = new(api.AfterValue(propertyText(next)))
			}
		}
		out.Details = append(out.Details, api.ResourceChangeDetail{Target: target, Evaluation: new(api.EvaluationType("Static")), ChangeSource: new(api.ChangeSource("DirectModification"))})
	}
	return out
}

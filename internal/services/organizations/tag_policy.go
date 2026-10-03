package organizations

import (
	"fmt"
	"strings"
)

const (
	tagEnforcement uint8 = 1 << iota
	tagRequiredReporting
)

func tagPolicy(n *managementNode) error {
	if len(n.children) != 1 || n.children["tags"] == nil || n.assigned || n.append != nil || n.remove != nil {
		return fmt.Errorf("tag policies require a tags object")
	}
	tags := n.children["tags"]
	keys := make(map[string]bool, len(tags.children))
	for key, tag := range tags.children {
		if key == "" || tag.assigned || tag.append != nil || tag.remove != nil {
			return fmt.Errorf("invalid tag policy key")
		}
		for field, setting := range tag.children {
			if len(setting.children) > 0 {
				return fmt.Errorf("invalid tag setting")
			}
			switch field {
			case "tag_key":
				if setting.append != nil || setting.remove != nil {
					return fmt.Errorf("tag keys only support assignment")
				}
				if setting.assigned {
					value, ok := setting.assign.(string)
					if !ok || !strings.EqualFold(value, key) {
						return fmt.Errorf("tag key must match its policy key")
					}
				}
			case "tag_value", "enforced_for", "report_required_tag_for":
				values, ok := setting.assign.([]any)
				if setting.assigned && !ok {
					return fmt.Errorf("tag setting requires an array")
				}
				for _, group := range [][]any{values, setting.append, setting.remove} {
					for _, item := range group {
						value, ok := item.(string)
						if field == "tag_value" {
							value, ok = managementScalar(item)
							if !ok {
								return fmt.Errorf("tag values must be scalar")
							}
							if strings.Count(value, "*") > 1 {
								return fmt.Errorf("invalid tag value wildcard")
							}
						} else {
							mode := tagEnforcement
							if field == "report_required_tag_for" {
								mode = tagRequiredReporting
							}
							if !ok || tagPolicyResourceModes[value]&mode == 0 {
								return fmt.Errorf("unsupported tag-policy resource")
							}
						}
					}
				}
			default:
				return fmt.Errorf("unknown tag setting %q", field)
			}
		}
		canonical := strings.ToLower(key)
		if keys[canonical] {
			return fmt.Errorf("duplicate tag policy key")
		}
		keys[canonical] = true
	}
	return nil
}

func completeEffectiveTags(doc map[string]any) {
	tags, _ := doc["tags"].(map[string]any)
	for key, raw := range tags {
		tag, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := tag["tag_key"]; !ok {
			tag["tag_key"] = key
		}
		if _, ok := tag["tag_value"]; !ok {
			tag["tag_value"] = []any{"*"}
		}
	}
}

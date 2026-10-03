package appconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/amazon-ion/ion-go/ion"
)

// agentContent emits the Agent's native Ion rule program, not an evaluation.
// The official Agent accepts standard named Ion symbols as well as AWS's shared
// symbol tables; the native fixture and unmodified Agent replay cover both.
func (s *Service) agentContent(profileType string, content []byte) ([]byte, error) {
	if profileType != "AWS.AppConfig.FeatureFlags" {
		return content, nil
	}
	root, err := parseFeatureFlags(content)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w := ion.NewBinaryWriter(&out)
	for _, key := range flagKeys(flagObject(root["values"])) {
		flag := flagObject(flagObject(root["values"])[key])
		_ = w.Annotation(ion.NewSymbolTokenFromString(key))
		_ = w.BeginList()
		if variants, ok := flag["_variants"].([]any); ok {
			for _, raw := range variants {
				v := flagObject(raw)
				name, _ := v["name"].(string)
				rule, _ := v["rule"].(string)
				payload := map[string]any{"_variant": name, "enabled": v["enabled"]}
				if enabled, _ := v["enabled"].(bool); enabled {
					for k, a := range flagObject(v["attributeValues"]) {
						payload[k] = a
					}
				}
				encoded, e := json.Marshal(payload)
				if e != nil {
					return nil, e
				}
				if rule != "" {
					node, e := parseVariantRule(rule)
					if e != nil {
						return nil, e
					}
					_ = w.Annotation(ion.NewSymbolTokenFromString(name))
					_ = w.BeginList()
					if e = writeAgentRule(w, node); e != nil {
						return nil, e
					}
					_ = w.WriteString(string(encoded))
					_ = w.EndList()
				} else {
					_ = w.WriteString(string(encoded))
				}
			}
		} else {
			payload := map[string]any{"enabled": flag["enabled"]}
			if enabled, _ := flag["enabled"].(bool); enabled {
				for k, v := range flag {
					if !strings.HasPrefix(k, "_") && k != "enabled" {
						payload[k] = v
					}
				}
			}
			encoded, e := json.Marshal(payload)
			if e != nil {
				return nil, e
			}
			_ = w.WriteString(string(encoded))
		}
		_ = w.EndList()
	}
	if err = w.Finish(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func writeAgentRule(w ion.Writer, n variantRuleNode) error {
	switch n.Kind {
	case "expression":
		_ = w.BeginSexp()
		_ = w.WriteSymbolFromString(n.Text)
		for _, v := range n.Children {
			if err := writeAgentRule(w, v); err != nil {
				return err
			}
		}
		return w.EndSexp()
	case "list":
		_ = w.BeginList()
		for _, v := range n.Children {
			if err := writeAgentRule(w, v); err != nil {
				return err
			}
		}
		return w.EndList()
	case "named":
		_ = w.Annotation(ion.NewSymbolTokenFromString(n.Text))
		return writeAgentRule(w, n.Children[0])
	case "context":
		return w.WriteSymbolFromString("$" + n.Text)
	case "string":
		return w.WriteString(n.Text)
	case "bool":
		return w.WriteBool(n.Text == "true")
	case "number":
		if i, e := strconv.ParseInt(n.Text, 10, 64); e == nil {
			return w.WriteInt(i)
		}
		d, e := ion.ParseDecimal(n.Text)
		if e != nil {
			return e
		}
		return w.WriteDecimal(d)
	case "timestamp":
		t, e := ion.ParseTimestamp(n.Text)
		if e != nil {
			return e
		}
		return w.WriteTimestamp(t)
	default:
		return fmt.Errorf("unsupported parsed feature flag rule node %q", n.Kind)
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
)

// Reads omit write-only values. An update model may preserve those native values
// without resupplying them; creation still uses the complete required contract.
func updateStructure(raw json.RawMessage, writeOnly []string) (string, error) {
	if len(writeOnly) == 0 {
		return "", nil
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return "", err
	}
	root := document
	for _, path := range writeOnly {
		if !strings.HasPrefix(path, "/properties/") {
			return "", fmt.Errorf("invalid write-only property path %q", path)
		}
		parts := strings.Split(strings.TrimPrefix(path, "/properties/"), "/")
		for i := range parts {
			parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "~1", "/"), "~0", "~")
		}
		var err error
		document, err = relaxWriteOnlyRequired(root, document, parts)
		if err != nil {
			return "", err
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	return structuralSchema(encoded, false)
}

func relaxWriteOnlyRequired(root, original map[string]any, parts []string) (map[string]any, error) {
	node := maps.Clone(original)
	for depth := 0; ; depth++ {
		reference, ok := node["$ref"].(string)
		if !ok {
			break
		}
		if depth >= 64 || !strings.HasPrefix(reference, "#/") {
			return nil, fmt.Errorf("invalid or cyclic local schema reference %q", reference)
		}
		var target any = root
		for _, part := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
			fields, ok := target.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid schema reference %q", reference)
			}
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			target = fields[part]
		}
		fields, ok := target.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("missing schema reference %q", reference)
		}
		resolved := maps.Clone(fields)
		for key, value := range node {
			if key != "$ref" {
				resolved[key] = value
			}
		}
		node = resolved
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		branches, ok := node[keyword].([]any)
		if !ok {
			continue
		}
		updated := make([]any, len(branches))
		for i, branch := range branches {
			fields, ok := branch.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid %s schema branch", keyword)
			}
			var err error
			updated[i], err = relaxWriteOnlyRequired(root, fields, parts)
			if err != nil {
				return nil, err
			}
		}
		node[keyword] = updated
	}
	if len(parts) == 1 {
		if required, ok := node["required"].([]any); ok {
			updated := make([]any, 0, len(required))
			for _, field := range required {
				if field != parts[0] {
					updated = append(updated, field)
				}
			}
			node["required"] = updated
		}
		return node, nil
	}
	if parts[0] == "*" {
		if items, ok := node["items"].(map[string]any); ok {
			updated, err := relaxWriteOnlyRequired(root, items, parts[1:])
			if err != nil {
				return nil, err
			}
			node["items"] = updated
		}
	} else if properties, ok := node["properties"].(map[string]any); ok {
		if child, ok := properties[parts[0]].(map[string]any); ok {
			updated, err := relaxWriteOnlyRequired(root, child, parts[1:])
			if err != nil {
				return nil, err
			}
			properties = maps.Clone(properties)
			properties[parts[0]] = updated
			node["properties"] = properties
		}
	}
	return node, nil
}

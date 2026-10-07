package cloudformation

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func cloneOwnerProperties(properties Properties) (Properties, error) {
	if !requiresJSONProjection(properties) {
		return cloneResourceValue(properties).(Properties), nil
	}
	// Only typed owner DTOs need serialization. Ordinary JSON request models
	// retain the cheaper recursive clone and exact number representation.
	body, err := json.Marshal(properties)
	if err != nil {
		return nil, fmt.Errorf("cannot project owner resource properties: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var out Properties
	if err := decoder.Decode(&out); err != nil {
		return nil, fmt.Errorf("cannot decode owner resource properties: %w", err)
	}
	return out, nil
}

func requiresJSONProjection(value any) bool {
	switch value := value.(type) {
	case nil, bool, string, json.Number, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return false
	case Properties:
		for _, child := range value {
			if requiresJSONProjection(child) {
				return true
			}
		}
		return false
	case map[string]any:
		for _, child := range value {
			if requiresJSONProjection(child) {
				return true
			}
		}
		return false
	case []any:
		for _, child := range value {
			if requiresJSONProjection(child) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// A parent is pruned only when removing a modeled read-only observation made
// it empty. Deliberately empty customer maps/arrays remain valid desired state.
func removeResourcePath(value any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return nil, true
	}
	if parts[0] == "*" {
		list, ok := value.([]any)
		if !ok {
			return value, false
		}
		kept := list[:0]
		removed := false
		for _, item := range list {
			next, changed := removeResourcePath(item, parts[1:])
			removed = removed || changed
			if changed && emptyResourceContainer(next) {
				continue
			}
			kept = append(kept, next)
		}
		clear(list[len(kept):])
		return kept, removed
	}
	var fields map[string]any
	switch value := value.(type) {
	case Properties:
		fields = value
	case map[string]any:
		fields = value
	default:
		return value, false
	}
	child, exists := fields[parts[0]]
	if !exists {
		return value, false
	}
	if len(parts) == 1 {
		delete(fields, parts[0])
		return value, true
	}
	next, changed := removeResourcePath(child, parts[1:])
	if changed {
		if emptyResourceContainer(next) {
			delete(fields, parts[0])
		} else {
			fields[parts[0]] = next
		}
	}
	return value, changed
}

func emptyResourceContainer(value any) bool {
	switch value := value.(type) {
	case nil:
		return true
	case Properties:
		return len(value) == 0
	case map[string]any:
		return len(value) == 0
	case []any:
		return len(value) == 0
	default:
		return false
	}
}

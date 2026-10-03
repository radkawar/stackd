package configservice

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
)

// configurationDiff compares immutable owner observations; delivery never reads
// the resource again or derives its change from the triggering API request.
func configurationDiff(previous *Item, current Item) (map[string]any, error) {
	if previous == nil || previous.Status == "ResourceDeleted" {
		return map[string]any{"changedProperties": map[string]any{}, "changeType": "CREATE"}, nil
	}
	before := map[string]any{}
	after := map[string]any{}
	fields := func(item Item, target map[string]any) error {
		if item.Configuration != "" && item.Configuration != "null" {
			var configuration map[string]any
			if err := json.Unmarshal([]byte(item.Configuration), &configuration); err != nil {
				return err
			}
			for k, v := range configuration {
				target["Configuration."+k] = v
			}
		}
		for k, v := range item.Tags {
			target["Tags."+k] = v
		}
		for k, v := range item.Supplementary {
			var value any
			if err := json.Unmarshal([]byte(v), &value); err != nil {
				return err
			}
			target["SupplementaryConfiguration."+k] = value
		}
		return nil
	}
	if previous != nil && previous.Status != "ResourceDeleted" {
		if err := fields(*previous, before); err != nil {
			return nil, err
		}
	}
	if current.Status != "ResourceDeleted" {
		if err := fields(current, after); err != nil {
			return nil, err
		}
	}
	keys := maps.Clone(before)
	maps.Copy(keys, after)
	changed := map[string]any{}
	for _, key := range slices.Sorted(maps.Keys(keys)) {
		old, existed := before[key]
		value, present := after[key]
		if existed && present && reflect.DeepEqual(old, value) {
			continue
		}
		kind := "UPDATE"
		if !existed {
			kind = "CREATE"
		} else if !present {
			kind = "DELETE"
		}
		property := map[string]any{"changeType": kind}
		if existed {
			property["previousValue"] = old
		}
		if present {
			property["updatedValue"] = value
		}
		changed[key] = property
	}
	kind := "UPDATE"
	if previous == nil || previous.Status == "ResourceDeleted" {
		kind = "CREATE"
	}
	if current.Status == "ResourceDeleted" {
		kind = "DELETE"
	}
	return map[string]any{"changedProperties": changed, "changeType": kind}, nil
}

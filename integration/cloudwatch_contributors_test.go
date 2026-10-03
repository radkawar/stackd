package stackd_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

// Native contributor IDs are opaque, but their equality across displacement,
// deletion, recreation, current discovery and retained history is observable.
type alarmContributorBindings map[string]string

func (bindings alarmContributorBindings) request(input any) {
	if history, ok := input.(*cloudwatch.DescribeAlarmHistoryInput); ok && history.AlarmContributorId != nil {
		if local, exists := bindings[*history.AlarmContributorId]; exists {
			history.AlarmContributorId = new(local)
		}
	}
}

func (bindings alarmContributorBindings) bind(t *testing.T, got, want map[string]any) {
	t.Helper()
	bind := func(actual, expected map[string]any, idKey, attributesKey string) {
		t.Helper()
		native, exists := expected[idKey].(string)
		if !exists {
			return
		}
		local, ok := actual[idKey].(string)
		if !ok || !reflect.DeepEqual(actual[attributesKey], expected[attributesKey]) {
			t.Fatalf("contributor identity/attributes: got %v, native %v", actual, expected)
		}
		if previous, exists := bindings[native]; exists && previous != local {
			t.Fatalf("contributor %s changed from %s to %s", native, previous, local)
		}
		for other, value := range bindings {
			if other != native && value == local {
				t.Fatalf("distinct native contributors %s and %s collapsed into %s", other, native, local)
			}
		}
		bindings[native] = local
		expected[idKey] = local
	}
	if expected, ok := want["AlarmContributors"].([]any); ok {
		actual, _ := got["AlarmContributors"].([]any)
		if len(actual) != len(expected) {
			t.Fatalf("active contributors: got %v, native %v", actual, expected)
		}
		byAttributes := map[string]map[string]any{}
		for _, raw := range actual {
			item := raw.(map[string]any)
			key, _ := json.Marshal(item["ContributorAttributes"])
			byAttributes[string(key)] = item
		}
		for _, raw := range expected {
			item := raw.(map[string]any)
			key, _ := json.Marshal(item["ContributorAttributes"])
			bind(byAttributes[string(key)], item, "ContributorId", "ContributorAttributes")
		}
	}
	if expected, ok := want["AlarmHistoryItems"].([]any); ok {
		actual, _ := got["AlarmHistoryItems"].([]any)
		for i, raw := range expected {
			item := raw.(map[string]any)
			if _, exists := item["AlarmContributorId"].(string); !exists {
				continue
			}
			if i >= len(actual) {
				t.Fatalf("contributor history missing native transition %v", item)
			}
			bind(actual[i].(map[string]any), item, "AlarmContributorId", "AlarmContributorAttributes")
		}
	}
}

func alarmContributorProjection(t *testing.T, object map[string]any, mode string) map[string]any {
	t.Helper()
	key := "AlarmContributors"
	if mode == "contributor-history" {
		key = "AlarmHistoryItems"
	}
	items := []any{}
	rows, _ := object[key].([]any)
	for _, raw := range rows {
		row := raw.(map[string]any)
		if mode == "contributors" {
			items = append(items, alarmControlFields(row, "ContributorId ContributorAttributes StateTransitionedTimestamp"))
			continue
		}
		item := alarmControlFields(row, "AlarmName AlarmType Timestamp HistoryItemType AlarmContributorId AlarmContributorAttributes")
		var payload map[string]any
		if err := json.Unmarshal([]byte(row["HistoryData"].(string)), &payload); err != nil {
			t.Fatal(err)
		}
		if state, ok := payload["newState"].(map[string]any); ok {
			_, present := state["stateReason"]
			state["hasReason"] = present
			delete(state, "stateReason") // Generated prose is not a transition contract.
		}
		item["data"] = payload
		items = append(items, item)
	}
	if mode == "contributors" {
		alarmControlSort(items, "ContributorId")
	}
	return map[string]any{key: items, "NextToken": object["NextToken"]}
}

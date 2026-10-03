package cloudtrail

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	api "stackd/internal/awsapi/cloudtrail"
	"stackd/journal"
)

type selectorFixture struct {
	Observations []struct {
		Label     string          `json:"label"`
		Operation string          `json:"operation"`
		Input     json.RawMessage `json:"input"`
		Result    struct {
			Code string `json:"code"`
		} `json:"result"`
	} `json:"observations"`
	DeliveredLogs []struct {
		Records []struct {
			EventName     string                     `json:"eventName"`
			EventSource   string                     `json:"eventSource"`
			EventCategory journal.APICallCategory    `json:"eventCategory"`
			ReadOnly      bool                       `json:"readOnly"`
			Resources     []journal.APIEventResource `json:"resources"`
			UserIdentity  struct {
				ARN string `json:"arn"`
			} `json:"userIdentity"`
		} `json:"Records"`
	} `json:"delivered_logs"`
}

func readSelectorFixture(t *testing.T, name string) selectorFixture {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/aws/cloudtrail/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var fixture selectorFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func nativeSelectorEvents(t *testing.T) map[string]journal.Event {
	t.Helper()
	fixture := readSelectorFixture(t, "owned_s3_delivery.json")
	events := map[string]journal.Event{}
	for _, log := range fixture.DeliveredLogs {
		for _, record := range log.Records {
			events[record.EventName] = journal.Event{
				Envelope: journal.Envelope{ActorARN: record.UserIdentity.ARN},
				APICallCompleted: &journal.APICallCompleted{
					EventName: record.EventName, EventSource: record.EventSource,
					Category: record.EventCategory, ReadOnly: record.ReadOnly, EventResources: record.Resources,
				},
			}
		}
	}
	for _, name := range []string{"PutObject", "DeleteObject"} {
		if _, ok := events[name]; !ok {
			t.Fatalf("native delivery fixture lacks %s", name)
		}
	}
	return events
}

func selectionFromJSON(t *testing.T, raw string) Selection {
	t.Helper()
	var input api.PutEventSelectorsInput
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatal(err)
	}
	selection, err := decodeSelection(&input)
	if err != nil {
		t.Fatal(err)
	}
	return selection
}

func TestNativeSelectorAdmissionAndDeliveredEvents(t *testing.T) {
	events := nativeSelectorEvents(t)
	for _, name := range []string{"owned_s3_delivery.json", "owned_selector_resource_types.json", "lambda_resource_arns.json"} {
		fixture := readSelectorFixture(t, name)
		for _, observation := range fixture.Observations {
			if observation.Operation != "PutEventSelectors" {
				continue
			}
			t.Run(name+"/"+observation.Label, func(t *testing.T) {
				var input api.PutEventSelectorsInput
				if err := json.Unmarshal(observation.Input, &input); err != nil {
					t.Fatal(err)
				}
				selection, err := decodeSelection(&input)
				if observation.Result.Code != "Success" {
					if err == nil || err.Code != observation.Result.Code {
						t.Fatalf("admission error = %v, native code = %s", err, observation.Result.Code)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if name != "owned_s3_delivery.json" {
					return
				}
				for _, eventName := range []string{"PutObject", "DeleteObject"} {
					event := events[eventName]
					if !matchesSelection(selection, event) {
						t.Errorf("native %s delivery excluded by its recorded selector", eventName)
					}
					call := *event.APICallCompleted
					call.EventResources = nil
					// History search terms must never substitute for native resources.
					for _, resource := range event.APICallCompleted.EventResources {
						call.Resources = append(call.Resources, journal.APIResource{Type: resource.Type, Name: resource.ARN})
					}
					event.APICallCompleted = &call
					if matchesSelection(selection, event) {
						t.Error("history-only resources incorrectly admitted a data event")
					}
				}
			})
		}
	}
}

func TestAdvancedSelectorPositiveNegativeGroups(t *testing.T) {
	// Derived from the delivered native records. The extra conditions exercise
	// the documented positive-OR/negative-AND rule, not additional AWS captures.
	selection := selectionFromJSON(t, `{"AdvancedEventSelectors":[{"FieldSelectors":[
		{"Field":"eventCategory","Equals":["Data"]},
		{"Field":"resources.type","Equals":["AWS::S3::Object"]},
		{"Field":"eventName","Equals":["PutObject"],"StartsWith":["Delete"],"NotEquals":["DeleteObject","GetObject"],"NotEndsWith":["Bucket"]},
		{"Field":"eventSource","Equals":["s3.amazonaws.com"]}
	]}]}`)
	events := nativeSelectorEvents(t)
	if !matchesSelection(selection, events["PutObject"]) {
		t.Fatal("Equals match wrongly required StartsWith to match as well")
	}
	if matchesSelection(selection, events["DeleteObject"]) {
		t.Fatal("positive StartsWith incorrectly overrode a negative Equals value")
	}
	event := events["PutObject"]
	call := *event.APICallCompleted
	event.APICallCompleted = &call
	call.EventName = "DeleteMarker"
	if !matchesSelection(selection, event) {
		t.Error("StartsWith alternative did not admit the event")
	}
	call.EventName = "DeleteBucket"
	if matchesSelection(selection, event) {
		t.Error("negative suffix did not veto the positive prefix")
	}
	call.EventName = "PutObject"
	call.EventSource = "other.amazonaws.com"
	if matchesSelection(selection, event) {
		t.Error("advanced fields were ORed instead of ANDed")
	}
	selection.Advanced = append(selection.Advanced, AdvancedSelector{Fields: []FieldSelector{{Field: "eventCategory", Tests: []FieldTest{{Operator: "Equals", Values: []string{"Data"}}}}, {Field: "resources.type", Tests: []FieldTest{{Operator: "Equals", Values: []string{"AWS::S3::Object"}}}}}})
	if !matchesSelection(selection, event) {
		t.Error("separate advanced selectors were ANDed instead of ORed")
	}
}

func TestAdvancedResourceExclusionAndARNPrefix(t *testing.T) {
	selection := selectionFromJSON(t, `{"AdvancedEventSelectors":[{"FieldSelectors":[
		{"Field":"eventCategory","Equals":["Data"]},
		{"Field":"resources.type","Equals":["AWS::S3::Object"]},
		{"Field":"resources.ARN","StartsWith":["arn:aws:s3:::source/"],"NotStartsWith":["arn:aws:s3:::source/private/"]}
	]}]}`)
	event := journal.Event{APICallCompleted: &journal.APICallCompleted{Category: journal.CategoryData, EventResources: []journal.APIEventResource{
		{Type: "AWS::S3::Bucket", ARN: "arn:aws:s3:::source"},
		{Type: "AWS::S3::Object", ARN: "arn:aws:s3:::source/private/secret"},
	}}}
	if matchesSelection(selection, event) {
		t.Error("nonexcluded bucket resource bypassed an excluded object resource")
	}
	event.APICallCompleted.EventResources[1] = journal.APIEventResource{Type: "AWS::S3::Object", ARNPrefix: "arn:aws:s3:::source/public/"}
	if !matchesSelection(selection, event) {
		t.Error("native ARNPrefix resource did not match")
	}
	event.APICallCompleted.EventResources[1].Type = "AWS::S3::Bucket"
	if matchesSelection(selection, event) {
		t.Error("matching ARN admitted a different resource type")
	}
}

func TestBasicManagementReadModeAndExactLambdaARN(t *testing.T) {
	selection := selectionFromJSON(t, `{"EventSelectors":[{"ReadWriteType":"ReadOnly","ExcludeManagementEventSources":["kms.amazonaws.com"],"DataResources":[{"Type":"AWS::Lambda::Function","Values":["arn:aws:lambda:us-east-1:111111111111:function:one"]}]}]}`)
	event := journal.Event{APICallCompleted: &journal.APICallCompleted{Category: journal.CategoryManagement, EventSource: "iam.amazonaws.com", ReadOnly: true}}
	if !matchesSelection(selection, event) {
		t.Error("omitted management inclusion should admit management reads")
	}
	event.APICallCompleted.EventSource = "kms.amazonaws.com"
	if matchesSelection(selection, event) {
		t.Error("excluded management source was admitted")
	}
	event.APICallCompleted.Category = journal.CategoryData
	event.APICallCompleted.EventResources = []journal.APIEventResource{{Type: "AWS::Lambda::Function", ARN: "arn:aws:lambda:us-east-1:111111111111:function:one"}}
	if !matchesSelection(selection, event) {
		t.Error("management exclusion incorrectly suppressed data activity")
	}
	event.APICallCompleted.EventResources[0].ARN += "-other"
	if matchesSelection(selection, event) {
		t.Error("Lambda selector incorrectly matched an ARN prefix")
	}
	event.APICallCompleted.EventResources[0].ARN = "arn:aws:lambda:us-east-1:111111111111:function:one"
	event.APICallCompleted.ReadOnly = false
	if matchesSelection(selection, event) {
		t.Error("ReadOnly selector admitted a write")
	}
	if matchesSelection(defaultSelection(), event) {
		t.Error("default selection admitted a data event")
	}
	event.APICallCompleted.Category = journal.CategoryManagement
	if !matchesSelection(defaultSelection(), event) {
		t.Error("default selection excluded a management write")
	}
}

func TestSelectorQuotaBoundaries(t *testing.T) {
	input := api.PutEventSelectorsInput{EventSelectors: api.EventSelectors{{DataResources: api.DataResources{{Type: str("AWS::S3::Object")}}}, {DataResources: api.DataResources{{Type: str("AWS::S3::Object")}}}}}
	for i := range 250 {
		index := i % 2
		input.EventSelectors[index].DataResources[0].Values = append(input.EventSelectors[index].DataResources[0].Values, api.String(fmt.Sprintf("arn:aws:s3:::source/object-%d", i)))
	}
	selection, err := decodeSelection(&input)
	if err != nil {
		t.Fatal(err)
	}
	event := journal.Event{APICallCompleted: &journal.APICallCompleted{Category: journal.CategoryData, EventResources: []journal.APIEventResource{{Type: "AWS::S3::Object", ARN: "arn:aws:s3:::source/object-249"}}}}
	if !matchesSelection(selection, event) {
		t.Error("resource at shared basic quota boundary was not selected")
	}
	input.EventSelectors[1].DataResources[0].Values = append(input.EventSelectors[1].DataResources[0].Values, "arn:aws:s3:::source/overflow")
	if _, err := decodeSelection(&input); err == nil || err.Code != "InvalidEventSelectorsException" {
		t.Fatalf("cross-selector resource quota not enforced: %v", err)
	}
	category, resourceType, eventName := api.SelectorField("eventCategory"), api.SelectorField("resources.type"), api.SelectorField("eventName")
	input = api.PutEventSelectorsInput{AdvancedEventSelectors: api.AdvancedEventSelectors{{FieldSelectors: api.AdvancedFieldSelectors{
		{Field: &category, Equals: api.Operator{"Data"}}, {Field: &resourceType, Equals: api.Operator{"AWS::S3::Object"}}, {Field: &eventName, Equals: api.Operator{"PutObject"}},
	}}}}
	for i := range 497 {
		input.AdvancedEventSelectors[0].FieldSelectors[2].Equals = append(input.AdvancedEventSelectors[0].FieldSelectors[2].Equals, api.OperatorValue(fmt.Sprintf("OtherEvent%d", i)))
	}
	selection, err = decodeSelection(&input)
	if err != nil {
		t.Fatal(err)
	}
	event.APICallCompleted.EventName = "PutObject"
	if !matchesSelection(selection, event) {
		t.Error("advanced event at 500 condition values was not selected")
	}
	input.AdvancedEventSelectors[0].FieldSelectors[2].NotEquals = api.Operator{"Overflow"}
	if _, err := decodeSelection(&input); err == nil || err.Code != "InvalidEventSelectorsException" {
		t.Fatalf("all-operator advanced quota not enforced: %v", err)
	}
}

func TestSelectorCategoryAndOperatorValidation(t *testing.T) {
	for _, test := range []struct{ name, raw, code string }{
		{"network unsupported", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["NetworkActivity"]},{"Field":"eventSource","Equals":["kms.amazonaws.com"]}]}]}`, "UnsupportedOperationException"},
		{"insights unsupported", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Insight"]}]}]}`, "UnsupportedOperationException"},
		{"unknown category invalid", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Unknown"]}]}]}`, "InvalidEventSelectorsException"},
		{"management fields differ from Lake", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]},{"Field":"eventName","Equals":["CreateUser"]}]}]}`, "InvalidEventSelectorsException"},
		{"management source inclusion invalid", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]},{"Field":"eventSource","Equals":["kms.amazonaws.com"]}]}]}`, "InvalidEventSelectorsException"},
		{"data requires type", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Data"]}]}]}`, "InvalidEventSelectorsException"},
		{"category negative invalid", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","NotEquals":["Management"]}]}]}`, "InvalidEventSelectorsException"},
		{"duplicate field invalid", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]},{"Field":"eventCategory","Equals":["Management"]}]}]}`, "InvalidEventSelectorsException"},
		{"unknown field invalid", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Management"]},{"Field":"mystery","Equals":["value"]}]}]}`, "InvalidEventSelectorsException"},
		{"console unsupported", `{"AdvancedEventSelectors":[{"FieldSelectors":[{"Field":"eventCategory","Equals":["Data"]},{"Field":"resources.type","Equals":["AWS::S3::Object"]},{"Field":"sessionCredentialFromConsole","NotEquals":["true"]}]}]}`, "UnsupportedOperationException"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var input api.PutEventSelectorsInput
			if err := json.Unmarshal([]byte(test.raw), &input); err != nil {
				t.Fatal(err)
			}
			if _, err := decodeSelection(&input); err == nil || err.Code != test.code {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestGlobalTrailRegionSelection(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/cloudtrail/region_selection.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name          string          `json:"name"`
			Source        string          `json:"source"`
			EventRegion   string          `json:"event_region"`
			TrailRegion   string          `json:"trail_region"`
			IncludeGlobal bool            `json:"include_global"`
			MultiRegion   bool            `json:"multi_region"`
			Additional    json.RawMessage `json:"additional"`
			Match         bool            `json:"match"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Cases {
		t.Run(row.Name, func(t *testing.T) {
			call := journal.APICallCompleted{EventSource: row.Source, AdditionalEventData: row.Additional}
			global, err := globalServiceEvent(call)
			if err != nil {
				t.Fatal(err)
			}
			trail := TrailRecord{Key: TrailKey{Scope: Scope{Region: row.TrailRegion}}, IncludeGlobal: row.IncludeGlobal, MultiRegion: row.MultiRegion}
			event := journal.Event{Envelope: journal.Envelope{Region: row.EventRegion}, APICallCompleted: &call}
			if got := trailRegionMatches(trail, event, global); got != row.Match {
				t.Fatalf("trail admission = %t, want %t", got, row.Match)
			}
		})
	}
}

package appconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"stackd/internal/awswire"
)

type featureFlagsCapture struct {
	Calls []struct {
		Label     string `json:"label"`
		Operation string `json:"operation"`
		Input     struct {
			Content                string
			ConfigurationProfileID string `json:"ConfigurationProfileId"`
		} `json:"input"`
		Response struct {
			ID      string `json:"Id"`
			Content string
		} `json:"response"`
		Error *struct {
			Error  struct{ Code string }
			Reason string
		} `json:"error"`
	} `json:"calls"`
	Served []struct{ Name, Hosted, Served string } `json:"served_fixtures"`
}

func readFeatureFlagsCapture(t *testing.T) featureFlagsCapture {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/appconfig/feature_flags_native.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture featureFlagsCapture
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	return capture
}

func TestFeatureFlagsNativeAdmission(t *testing.T) {
	capture := readFeatureFlagsCapture(t)
	selected := map[string]bool{
		"missing-version": true, "wrong-version": true,
		"required-missing": true, "enum-invalid": true, "minimum-invalid": true,
		"maximum-invalid": true, "number-type": true, "array-pattern": true,
		"array-mixed": true, "unknown-attribute": true, "undefined-flag": true,
		"missing-value": true, "missing-enabled": true, "disabled-required-missing": true,
		"disabled-invalid-value": true, "variant-no-default": true,
		"variant-invalid-rule": true, "variant-duplicate-name": true,
		"enabled-coercion-true": true, "enabled-coercion-FALSE": true,
		"enabled-coercion-invalid": true, "enabled-coercion-1": true,
		"enabled-coercion-None": true, "unknown-top": true,
		"unknown-flag-property": true, "undefined-flag-attr": true,
		"array-empty": true, "variant-empty": true, "variant-first-no-rule": true,
		"variant-default-enabled": true, "rule-bad-operator": true,
		"rule-missing-argument": true, "rule-boolean-literal": true,
		"rule-context-literal": true, "rule-boolean-operand": true,
		"rule-split": true, "rule-in": true, "rule-date": true,
		"rule-exists": true, "variant-too-many": true,
	}
	for _, call := range capture.Calls {
		if call.Operation != "create_hosted_configuration_version" || !selected[call.Label] {
			continue
		}
		t.Run(call.Label, func(t *testing.T) {
			err := validateFeatureFlags([]byte(call.Input.Content))
			if call.Error == nil {
				if err != nil {
					t.Fatalf("native accepted content: %v", err)
				}
				return
			}
			var rejected *awswire.Error
			if !errors.As(err, &rejected) || rejected.Code != call.Error.Error.Code || rejected.Reason != call.Error.Reason {
				t.Fatalf("native rejected with %s/%s; got %v", call.Error.Error.Code, call.Error.Reason, err)
			}
		})
	}
}

func TestFeatureFlagsNativeServing(t *testing.T) {
	for _, fixture := range readFeatureFlagsCapture(t).Served {
		t.Run(fixture.Name, func(t *testing.T) {
			got, err := (*Service)(nil).servedContent("AWS.AppConfig.FeatureFlags", []byte(fixture.Hosted))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != fixture.Served {
				t.Fatalf("served %s; native served %s", got, fixture.Served)
			}
		})
	}
}

func TestFeatureFlagsNativeHostedVersionTransitions(t *testing.T) {
	capture := readFeatureFlagsCapture(t)
	var profileID string
	var previous []byte
	selected := map[string]bool{"boolean-enabled-disabled": true, "variant-document": true, "variant-identical-repeat": true, "variant-value-change": true, "missing-value-serving": true, "empty-variant-serving": true, "user-valid-timestamps": true}
	for _, call := range capture.Calls {
		if call.Label == "setup-profile" {
			profileID = call.Response.ID
		}
		if call.Operation != "create_hosted_configuration_version" || call.Input.ConfigurationProfileID != profileID || call.Error != nil {
			continue
		}
		if selected[call.Label] {
			t.Run(call.Label, func(t *testing.T) {
				var hosted map[string]any
				if err := json.Unmarshal([]byte(call.Response.Content), &hosted); err != nil {
					t.Fatal(err)
				}
				var now time.Time
				for _, section := range []string{"flags", "values"} {
					for _, raw := range flagObject(hosted[section]) {
						stamp, _ := flagObject(raw)["_updatedAt"].(string)
						at, err := time.Parse(time.RFC3339Nano, stamp)
						if err != nil {
							t.Fatal(err)
						}
						if at.After(now) {
							now = at
						}
					}
				}
				got, err := normalizeFeatureFlags([]byte(call.Input.Content), previous, now)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != call.Response.Content {
					t.Fatalf("hosted %s; native hosted %s", got, call.Response.Content)
				}
			})
		}
		previous = []byte(call.Response.Content)
	}
}

func TestAppConfigDraft4Validation(t *testing.T) {
	for _, fixture := range []struct {
		name, schema, content string
		rejected              bool
	}{
		{"local-reference-valid", `{"definitions":{"positive":{"type":"integer","minimum":1}},"$ref":"#/definitions/positive"}`, `2`, false},
		{"local-reference-invalid", `{"definitions":{"positive":{"type":"integer","minimum":1}},"$ref":"#/definitions/positive"}`, `0`, true},
		{"later-draft-ignored", `{"$schema":"http://json-schema.org/draft-07/schema#","const":"x"}`, `"y"`, false},
		{"draft4-exclusive-bound", `{"type":"number","minimum":1,"exclusiveMinimum":true}`, `1`, true},
		{"later-draft-bound-rejected", `{"$schema":"http://json-schema.org/draft-07/schema#","exclusiveMinimum":3}`, `2`, true},
		{"boolean-schema-rejected", `false`, `{}`, true},
		{"required", `{"type":"object","required":["count"]}`, `{}`, true},
		{"external-http-reference", `{"$ref":"http://127.0.0.1:1/schema"}`, `{}`, true},
		{"external-file-reference", `{"$ref":"file:///etc/passwd"}`, `{}`, true},
		{"non-json-content", `{"type":"object"}`, `not json`, true},
		{"trailing-json", `{"type":"object"}`, `{} {}`, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			profile := Profile{Type: "AWS.Freeform", Validators: []Validator{{Type: "JSON_SCHEMA", Content: fixture.schema}}}
			err := (&Service{}).validateContent(context.Background(), profile, "1", []byte(fixture.content))
			if (err != nil) != fixture.rejected {
				t.Fatalf("rejected=%v, got %v", fixture.rejected, err)
			}
		})
	}
}

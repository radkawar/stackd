package inputtransform_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"stackd/internal/services/eventbridge/inputtransform"
)

func TestNativeTargetInputs(t *testing.T) {
	data, err := os.ReadFile("../../../../testdata/aws/eventbridge/inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case            string
			Definition      inputtransform.Definition `json:"target_input"`
			ValidationOwner string                    `json:"validation_owner"`
			Context         inputtransform.Context
			Event           json.RawMessage
			Admission       struct{ Code string }
			Delivery        struct {
				Kind, Body string
				Attributes map[string]struct{ StringValue string }
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Observations {
		t.Run(row.Case, func(t *testing.T) {
			t.Parallel()
			if row.ValidationOwner == "generated-model" {
				t.Skip("model constraints are checked by the generated frontend")
			}
			projection, err := inputtransform.Compile(row.Definition)
			if row.Admission.Code != "Success" {
				if err == nil {
					t.Fatalf("Compile succeeded; AWS returned %s", row.Admission.Code)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if row.Delivery.Kind == "unobserved" {
				t.Log("native bounded capture has no target or DLQ outcome; admission only")
				return
			}
			var event bytes.Buffer
			if err := json.Compact(&event, row.Event); err != nil {
				t.Fatal(err)
			}
			body, err := projection.Apply(event.Bytes(), row.Context)
			if row.Delivery.Attributes["ERROR_CODE"].StringValue == "INVALID_JSON" {
				if !errors.Is(err, inputtransform.ErrInvalidJSON) {
					t.Fatalf("Apply error = %v; AWS returned INVALID_JSON", err)
				}
			} else if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if string(body) != row.Delivery.Body {
				t.Fatalf("body differs from AWS:\n got %q\nwant %q", body, row.Delivery.Body)
			}
		})
	}
}

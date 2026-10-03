package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"stackd/internal/awsschema"
	"stackd/internal/smithy"
)

func correctionFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	data, _ := fixture(t)
	correction := modelCorrection{ID: "demo-optional-name", Service: "demo", Shape: "example.demo#CreateThingRequest", Member: "Name", Trait: "smithy.api#required", Expected: json.RawMessage(`{}`), Replacement: json.RawMessage(`null`)}
	correction.Evidence.Path, correction.Evidence.Case = "testdata/aws/demo.json", "optional_name"
	correction.Evidence.Code = "Success"
	manifest, err := json.Marshal(struct {
		Version     int               `json:"version"`
		Corrections []modelCorrection `json:"corrections"`
	}{1, []modelCorrection{correction}})
	if err != nil {
		t.Fatal(err)
	}
	return data, manifest
}

func TestModelCorrectionChangesGeneratedRequiredMember(t *testing.T) {
	data, manifest := correctionFixture(t)
	corrected, err := parseModelWithCorrections("demo", data, awsschema.Source{}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range corrected.Shapes {
		if shape.ID == "example.demo#CreateThingRequest" {
			for _, member := range shape.Members {
				if member.Name == "Name" && member.Required {
					t.Fatal("corrected required trait remained in generated contract")
				}
			}
		}
	}
	dir := t.TempDir()
	files, err := generate([]contract{corrected}, filepath.Join(dir, "catalog"), filepath.Join(dir, "api"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeGenerated(files, false); err != nil {
		t.Fatal(err)
	}
	uncorrected, err := parseModelWithCorrections("demo", data, awsschema.Source{}, []byte(`{"version":1,"corrections":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	uncorrectedFiles, err := generate([]contract{uncorrected}, filepath.Join(dir, "catalog"), filepath.Join(dir, "api"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeGenerated(uncorrectedFiles, true); err == nil {
		t.Fatal("check mode missed removal of a model correction")
	}
	if err := writeGenerated(files, true); err != nil {
		t.Fatal("check mode changed corrected output:", err)
	}
}

func TestModelCorrectionsRejectChangedTarget(t *testing.T) {
	data, manifest := correctionFixture(t)
	for _, scenario := range []string{"shape removed", "member removed", "trait removed", "trait changed"} {
		t.Run(scenario, func(t *testing.T) {
			var model map[string]any
			if err := json.Unmarshal(data, &model); err != nil {
				t.Fatal(err)
			}
			shapes := model["shapes"].(map[string]any)
			request := shapes["example.demo#CreateThingRequest"].(map[string]any)
			members := request["members"].(map[string]any)
			traits := members["Name"].(map[string]any)["traits"].(map[string]any)
			switch scenario {
			case "shape removed":
				delete(shapes, "example.demo#CreateThingRequest")
			case "member removed":
				delete(members, "Name")
			case "trait removed":
				delete(traits, "smithy.api#required")
			case "trait changed":
				traits["smithy.api#required"] = true
			}
			changed, err := json.Marshal(model)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseModelWithCorrections("demo", changed, awsschema.Source{}, manifest); err == nil || !strings.Contains(err.Error(), "model correction") {
				t.Fatalf("stale correction accepted or failed opaquely: %v", err)
			}
		})
	}
}

func TestModelCorrectionCanReplaceAShapePattern(t *testing.T) {
	data, manifest := correctionFixture(t)
	var file struct {
		Version     int               `json:"version"`
		Corrections []modelCorrection `json:"corrections"`
	}
	if err := json.Unmarshal(manifest, &file); err != nil {
		t.Fatal(err)
	}
	correction := &file.Corrections[0]
	correction.Shape, correction.Member, correction.Trait = "example.demo#Name", "", "smithy.api#pattern"
	correction.Expected, correction.Replacement = json.RawMessage(`"^[a-z]+$"`), json.RawMessage(`".*[a-z]+.*"`)
	manifest, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	result, err := parseModelWithCorrections("demo", data, awsschema.Source{}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range result.Shapes {
		if shape.ID != "example.demo#Name" {
			continue
		}
		if shape.Constraints.Pattern != ".*[a-z]+.*" || shape.Constraints.Length.Min.Value != "1" || shape.Constraints.Length.Max.Value != "64" {
			t.Fatalf("pattern correction changed unrelated constraints: %+v", shape.Constraints)
		}
		pattern, err := regexp.Compile(shape.Constraints.Pattern)
		if err != nil {
			t.Fatal(err)
		}
		if !pattern.MatchString("name*") || !pattern.MatchString("na?e") || pattern.MatchString("*") {
			t.Fatal("corrected pattern lost meaningful-name requirement")
		}
		return
	}
	t.Fatal("corrected shape is absent")
}

func TestModelCorrectionManifestValidation(t *testing.T) {
	_, valid := correctionFixture(t)
	for _, scenario := range []string{"unknown field", "unknown version", "duplicate ID", "duplicate target", "missing expected", "no-op", "missing evidence", "client-only evidence", "unsupported trait", "invalid replacement", "inherited required", "inherited shape override", "inherited removal", "trailing JSON"} {
		t.Run(scenario, func(t *testing.T) {
			var file map[string]any
			if err := json.Unmarshal(valid, &file); err != nil {
				t.Fatal(err)
			}
			list := file["corrections"].([]any)
			correction := list[0].(map[string]any)
			switch scenario {
			case "unknown field":
				correction["silent_override"] = true
			case "unknown version":
				file["version"] = 2
			case "duplicate ID":
				file["corrections"] = append(list, correction)
			case "duplicate target":
				copy := make(map[string]any)
				for key, value := range correction {
					copy[key] = value
				}
				copy["id"] = "another-correction"
				file["corrections"] = append(list, copy)
			case "missing expected":
				delete(correction, "expected")
			case "no-op":
				correction["replacement"] = map[string]any{}
			case "missing evidence":
				delete(correction, "evidence")
			case "client-only evidence":
				correction["evidence"].(map[string]any)["code"] = "CLIValidationError"
			case "unsupported trait":
				correction["trait"] = "aws.auth#sigv4"
			case "invalid replacement":
				correction["replacement"] = false
			case "inherited required":
				correction["inherited_from"] = "example.demo#Name"
			case "inherited shape override", "inherited removal":
				correction["inherited_from"] = "example.demo#Name"
				correction["trait"], correction["expected"] = "smithy.api#pattern", "^[a-z]+$"
				if scenario == "inherited shape override" {
					delete(correction, "member")
					correction["replacement"] = ".*[a-z]+.*"
				}
			}
			invalid, err := json.Marshal(file)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "trailing JSON" {
				invalid = append(invalid, []byte(" {}")...)
			}
			if _, err := parseModelCorrections(invalid); err == nil {
				t.Fatal("invalid correction manifest accepted")
			}
		})
	}
}

func TestModelCorrectionOverridesOnlyTheInheritedMemberConstraint(t *testing.T) {
	data, originalManifest := correctionFixture(t)
	var file struct {
		Version     int               `json:"version"`
		Corrections []modelCorrection `json:"corrections"`
	}
	if err := json.Unmarshal(originalManifest, &file); err != nil {
		t.Fatal(err)
	}
	correction := &file.Corrections[0]
	correction.InheritedFrom, correction.Trait = "example.demo#Name", "smithy.api#pattern"
	correction.Expected, correction.Replacement = json.RawMessage(`"^[a-z]+$"`), json.RawMessage(`".*[a-z]+.*"`)
	manifest, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	result, err := parseModelWithCorrections("demo", data, awsschema.Source{}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	memberFound, targetFound := false, false
	for _, shape := range result.Shapes {
		if shape.ID == "example.demo#Name" {
			targetFound = true
			if shape.Constraints.Pattern != "^[a-z]+$" || shape.Constraints.Length.Min.Value != "1" || shape.Constraints.Length.Max.Value != "64" {
				t.Fatalf("member override changed the shared target: %+v", shape.Constraints)
			}
		}
		if shape.ID == "example.demo#CreateThingRequest" {
			for _, member := range shape.Members {
				if member.Name != "Name" {
					continue
				}
				memberFound = true
				if member.Constraints.Pattern != ".*[a-z]+.*" || !member.Required || member.Target != "example.demo#Name" {
					t.Fatalf("member override lost target or unrelated constraints: %+v", member)
				}
			}
		}
	}
	if !memberFound || !targetFound {
		t.Fatal("corrected member or shared target was omitted")
	}
	for _, scenario := range []string{"local override added", "target changed", "inherited shape removed", "inherited trait removed", "inherited trait changed"} {
		t.Run(scenario, func(t *testing.T) {
			var model smithy.Model
			if err := json.Unmarshal(data, &model); err != nil {
				t.Fatal(err)
			}
			request := model.Shapes[correction.Shape]
			member := request.Members[correction.Member]
			inherited := model.Shapes[correction.InheritedFrom]
			switch scenario {
			case "local override added":
				member.Traits[correction.Trait] = bytes.Clone(correction.Expected)
			case "target changed":
				member.Target = "example.demo#DifferentName"
				request.Members[correction.Member] = member
			case "inherited shape removed":
				delete(model.Shapes, correction.InheritedFrom)
			case "inherited trait removed":
				delete(inherited.Traits, correction.Trait)
			case "inherited trait changed":
				inherited.Traits[correction.Trait] = json.RawMessage(`"^.+$"`)
			}
			source := awsschema.Source{}
			if err := applyModelCorrections("demo", &model, &source, manifest); err == nil || !strings.Contains(err.Error(), "model correction") {
				t.Fatalf("stale inherited correction accepted or failed opaquely: %v", err)
			}
		})
	}
}

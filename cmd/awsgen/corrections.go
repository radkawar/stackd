package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"reflect"
	"strings"

	"stackd/internal/awsschema"
	"stackd/internal/smithy"
)

const modelCorrectionsPath = "cmd/awsgen/model_corrections.json"
const jsonIntegerCoercionTrait = "stackd.api#jsonIntegerCoercion"
const openEnumTrait = "stackd.api#openEnum"
const jsonResponseNullTrait = "stackd.api#jsonResponseNull"

// Corrections are explicit, reviewed model inputs. Each target's expected trait
// must still match so changes to that constraint require reviewing the correction.
//
//go:embed model_corrections.json
var modelCorrectionsJSON []byte

type modelCorrection struct {
	ID            string          `json:"id"`
	Service       string          `json:"service"`
	Shape         string          `json:"shape"`
	Member        string          `json:"member,omitempty"`
	InheritedFrom string          `json:"inherited_from,omitempty"`
	Trait         string          `json:"trait,omitempty"`
	Expected      json.RawMessage `json:"expected"`
	Replacement   json.RawMessage `json:"replacement"`
	Evidence      struct {
		Path string `json:"path"`
		Case string `json:"case"`
		Code string `json:"code"`
	} `json:"evidence"`
}

func parseModelCorrections(data []byte) ([]modelCorrection, error) {
	var file struct {
		Version     int               `json:"version"`
		Corrections []modelCorrection `json:"corrections"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode model corrections: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("model corrections must contain one JSON document")
	}
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported model corrections version %d", file.Version)
	}
	ids, targets := make(map[string]bool), make(map[string]bool)
	for _, correction := range file.Corrections {
		if correction.ID == "" || correction.Service == "" || !strings.Contains(correction.Shape, "#") {
			return nil, fmt.Errorf("model correction %q has invalid target metadata", correction.ID)
		}
		target := correction.Service + "\x00" + correction.Shape + "\x00" + correction.Member + "\x00" + correction.Trait
		if ids[correction.ID] || targets[target] {
			return nil, fmt.Errorf("duplicate model correction %q or target", correction.ID)
		}
		ids[correction.ID], targets[target] = true, true
		memberAddition := correction.Trait == "" && correction.Member != ""
		memberAnnotation := correction.Trait == jsonResponseNullTrait
		nativeAnnotation := correction.Trait == jsonIntegerCoercionTrait || correction.Trait == openEnumTrait || memberAnnotation
		if correction.Trait != "smithy.api#required" && correction.Trait != "smithy.api#pattern" && correction.Trait != "smithy.api#length" && correction.Trait != "smithy.api#range" && correction.Trait != "smithy.api#http" && correction.Trait != "smithy.api#httpError" && correction.Trait != "aws.api#service" && correction.Trait != "aws.protocols#httpChecksum" && !nativeAnnotation && !memberAddition {
			return nil, fmt.Errorf("model correction %q targets unsupported trait %q", correction.ID, correction.Trait)
		}
		if correction.InheritedFrom != "" && (correction.Member == "" || !strings.Contains(correction.InheritedFrom, "#") || correction.Trait != "smithy.api#pattern" && correction.Trait != "smithy.api#range" || jsonEqual(correction.Replacement, []byte("null"))) {
			return nil, fmt.Errorf("model correction %q requires a member constraint replacement for an inherited trait", correction.ID)
		}
		if !json.Valid(correction.Expected) || !json.Valid(correction.Replacement) || (jsonEqual(correction.Expected, []byte("null")) && !nativeAnnotation && !memberAddition) || jsonEqual(correction.Expected, correction.Replacement) {
			return nil, fmt.Errorf("model correction %q requires an expected trait and a different replacement", correction.ID)
		}
		if memberAddition && !jsonEqual(correction.Expected, []byte("null")) {
			return nil, fmt.Errorf("model correction %q must add an absent member", correction.ID)
		}
		if nativeAnnotation && ((correction.Member != "") != memberAnnotation || !jsonEqual(correction.Expected, []byte("null")) || !jsonEqual(correction.Replacement, []byte("{}"))) {
			return nil, fmt.Errorf("model correction %q must add a native behavior annotation to its supported shape or member target", correction.ID)
		}
		if correction.Trait == "smithy.api#required" {
			if !jsonEqual(correction.Expected, []byte("{}")) || !jsonEqual(correction.Replacement, []byte("null")) {
				return nil, fmt.Errorf("model correction %q may only remove an expected empty required trait", correction.ID)
			}
		} else if correction.Trait == "smithy.api#pattern" {
			var pattern string
			if json.Unmarshal(correction.Expected, &pattern) != nil || (!jsonEqual(correction.Replacement, []byte("null")) && json.Unmarshal(correction.Replacement, &pattern) != nil) {
				return nil, fmt.Errorf("model correction %q requires string pattern traits", correction.ID)
			}
		}
		if !strings.HasPrefix(correction.Evidence.Path, "testdata/aws/") || path.Clean(correction.Evidence.Path) != correction.Evidence.Path || correction.Evidence.Case == "" || correction.Evidence.Code == "" || correction.Evidence.Code == "CLIValidationError" {
			return nil, fmt.Errorf("model correction %q requires an AWS fixture path and case", correction.ID)
		}
	}
	return file.Corrections, nil
}

func applyModelCorrections(name string, model *smithy.Model, source *awsschema.Source, data []byte) error {
	corrections, err := parseModelCorrections(data)
	if err != nil {
		return err
	}
	source.CorrectionsPath, source.CorrectionsSHA256 = "", ""
	for _, correction := range corrections {
		if correction.Service != name {
			continue
		}
		shape, exists := model.Shapes[correction.Shape]
		if !exists {
			return fmt.Errorf("model correction %q: shape %s is absent", correction.ID, correction.Shape)
		}
		checksum := sha256.Sum256(data)
		source.CorrectionsPath, source.CorrectionsSHA256 = modelCorrectionsPath, hex.EncodeToString(checksum[:])
		if correction.Trait == "" {
			if shape.Type != "structure" && shape.Type != "union" {
				return fmt.Errorf("model correction %q requires an aggregate member", correction.ID)
			}
			if _, exists := shape.Members[correction.Member]; exists {
				return fmt.Errorf("model correction %q: member %s already exists", correction.ID, correction.Member)
			}
			var member smithy.Reference
			if err := json.Unmarshal(correction.Replacement, &member); err != nil {
				return fmt.Errorf("model correction %q: %w", correction.ID, err)
			}
			if shape.Members == nil {
				shape.Members = make(map[string]smithy.Reference)
			}
			shape.Members[correction.Member] = member
			model.Shapes[correction.Shape] = shape
			continue
		}
		if correction.Trait == jsonIntegerCoercionTrait && shape.Type != "integer" {
			return fmt.Errorf("model correction %q requires an integer shape", correction.ID)
		}
		if correction.Trait == openEnumTrait && shape.Type != "enum" {
			return fmt.Errorf("model correction %q requires a string enum shape", correction.ID)
		}
		if correction.Trait == jsonResponseNullTrait && shape.Type != "structure" && shape.Type != "union" {
			return fmt.Errorf("model correction %q requires an aggregate member", correction.ID)
		}
		target := shape.Traits
		var inheritedTraits map[string]json.RawMessage
		if correction.Member != "" {
			member, exists := shape.Members[correction.Member]
			if !exists {
				return fmt.Errorf("model correction %q: member %s is absent", correction.ID, correction.Member)
			}
			target = member.Traits
			if correction.InheritedFrom != "" {
				// A member override changes only this use of the shared target.
				// Require both the absence of a local trait and the exact
				// inherited constraint; upstream changes must be reviewed.
				if _, exists := target[correction.Trait]; exists || string(member.Target) != correction.InheritedFrom {
					return fmt.Errorf("model correction %q: member must inherit %s from %s without a local override", correction.ID, correction.Trait, correction.InheritedFrom)
				}
				inherited, exists := model.Shapes[correction.InheritedFrom]
				if !exists {
					return fmt.Errorf("model correction %q: inherited target %s is absent", correction.ID, correction.InheritedFrom)
				}
				inheritedTraits = inherited.Traits
				if target == nil {
					target = make(map[string]json.RawMessage)
					member.Traits = target
					shape.Members[correction.Member] = member
				}
			}
		}
		actual, exists := target[correction.Trait]
		if correction.InheritedFrom != "" {
			actual, exists = inheritedTraits[correction.Trait]
		}
		if !exists {
			actual = json.RawMessage("null")
		}
		if !jsonEqual(actual, correction.Expected) {
			return fmt.Errorf("model correction %q: expected trait %s=%s, found %s", correction.ID, correction.Trait, correction.Expected, actual)
		}
		if jsonEqual(correction.Replacement, []byte("null")) {
			delete(target, correction.Trait)
		} else {
			if target == nil {
				target = make(map[string]json.RawMessage)
				if correction.Member != "" {
					member := shape.Members[correction.Member]
					member.Traits = target
					shape.Members[correction.Member] = member
				} else {
					shape.Traits = target
				}
				model.Shapes[correction.Shape] = shape
			}
			target[correction.Trait] = bytes.Clone(correction.Replacement)
		}
	}
	return nil
}

func jsonEqual(a, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

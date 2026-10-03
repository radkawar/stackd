package iam_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"stackd/internal/services/iam"
)

// Replay the exact owned-resource AWS observations through SDK inputs and
// decoded outputs. Only account IDs, generated IDs and clock values are mapped.
func TestFederationAWSReplay(t *testing.T) {
	paths, err := filepath.Glob("testdata/federation/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Source, Endpoint, Region string
				Scenarios                []struct {
					Operation  string
					Input      map[string]any
					Output     map[string]any
					ExitCode   int `json:"exit_code"`
					Error      string
					ObservedAt string `json:"observed_at"`
				}
			}
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			if fixture.Source == "" || fixture.Endpoint != "https://iam.amazonaws.com" || len(fixture.Scenarios) == 0 {
				t.Fatal("missing live AWS provenance")
			}
			client := reflect.ValueOf(clientFor(t, iam.New(), "123456789012", "us-east-1"))
			methods := map[string]reflect.Value{}
			for i := 0; i < client.NumMethod(); i++ {
				methods[strings.ToLower(client.Type().Method(i).Name)] = client.Method(i)
			}
			ids := map[string]string{}
			for i, row := range fixture.Scenarios {
				if _, err := time.Parse(time.RFC3339Nano, row.ObservedAt); err != nil {
					t.Fatal(err)
				}
				method := methods[strings.ReplaceAll(row.Operation, "-", "")]
				if !method.IsValid() {
					t.Fatalf("unknown operation %s", row.Operation)
				}
				input := map[string]any{}
				for key, value := range row.Input {
					if stringValue, ok := value.(string); ok {
						value := stringValue
						value = strings.ReplaceAll(value, "<source-account>", "123456789012")
						if mapped, ok := ids[value]; ok {
							value = mapped
						}
						if strings.HasPrefix(value, "<fixture:") {
							raw, err := os.ReadFile(filepath.Join("testdata/federation", strings.TrimSuffix(strings.TrimPrefix(value, "<fixture:"), ">")))
							if err != nil {
								t.Fatal(err)
							}
							value = string(raw)
						}
						input[key] = value
					} else {
						input[key] = value
					}
				}
				encoded, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				argument := reflect.New(method.Type().In(1).Elem())
				if err := json.Unmarshal(encoded, argument.Interface()); err != nil {
					t.Fatal(err)
				}
				out := method.Call([]reflect.Value{reflect.ValueOf(context.Background()), argument})
				label := fmt.Sprintf("scenario %d %s", i, row.Operation)
				if row.ExitCode != 0 {
					match := regexp.MustCompile(`error occurred \(([^)]+)\)`).FindStringSubmatch(row.Error)
					if len(match) != 2 {
						t.Fatalf("%s invalid error fixture: %s", label, row.Error)
					}
					if out[1].IsNil() {
						t.Fatalf("%s unexpectedly succeeded", label)
					}
					requireCode(t, out[1].Interface().(error), match[1])
					continue
				}
				if !out[1].IsNil() {
					t.Fatalf("%s: %v", label, out[1].Interface())
				}
				encoded, err = json.Marshal(out[0].Interface())
				if err != nil {
					t.Fatal(err)
				}
				var got map[string]any
				if err := json.Unmarshal(encoded, &got); err != nil {
					t.Fatal(err)
				}
				compareFederationReplay(t, label, "", row.Output, got, ids)
			}
		})
	}
}

func compareFederationReplay(t *testing.T, label, path string, want, got any, ids map[string]string) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("%s %s expected object, got %v", label, path, got)
		}
		for key, value := range expected {
			compareFederationReplay(t, label, path+"/"+key, value, actual[key], ids)
		}
	case []any:
		actual, ok := got.([]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s %s expected %d entries, got %v", label, path, len(expected), got)
		}
		for i, value := range expected {
			compareFederationReplay(t, label, fmt.Sprintf("%s/%d", path, i), value, actual[i], ids)
		}
	case string:
		actual, ok := got.(string)
		if !ok {
			t.Fatalf("%s %s expected string, got %v", label, path, got)
		}
		if strings.HasSuffix(path, "/CreateDate") || strings.HasSuffix(path, "/ValidUntil") || strings.HasSuffix(path, "/Timestamp") {
			if _, err := time.Parse(time.RFC3339Nano, actual); err != nil {
				t.Fatalf("%s invalid timestamp: %v", label, err)
			}
			return
		}
		if strings.HasSuffix(path, "/SAMLProviderUUID") || strings.HasSuffix(path, "/KeyId") {
			if old, ok := ids[expected]; ok && old != actual {
				t.Fatalf("%s %s changed identifier", label, path)
			}
			if len(expected) != len(actual) {
				t.Fatalf("%s invalid identifier %s", label, actual)
			}
			ids[expected] = actual
			return
		}
		expected = strings.ReplaceAll(expected, "<source-account>", "123456789012")
		if expected != actual {
			t.Fatalf("%s %s got %q, want %q", label, path, actual, expected)
		}
	default:
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s %s got %v, want %v", label, path, got, want)
		}
	}
}

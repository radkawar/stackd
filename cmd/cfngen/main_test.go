package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRegistryGenerationRetainsCapturedSchemaMetadataAndAbsence(t *testing.T) {
	root := t.TempDir()
	source, metadata := filepath.Join(root, "source.json"), filepath.Join(root, "metadata.json")
	publicData, err := os.ReadFile("../../testdata/aws/cloudformation/resource_schemas_public.json")
	if err != nil {
		t.Fatal(err)
	}
	nativeData, err := os.ReadFile("../../testdata/aws/cloudformation/resource_schemas.json")
	if err != nil {
		t.Fatal(err)
	}
	var public, native registry
	if err := json.Unmarshal(publicData, &public); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(nativeData, &native); err != nil {
		t.Fatal(err)
	}
	public.Types = map[string]registryEntry{"AWS::SSM::Parameter": public.Types["AWS::SSM::Parameter"]}
	native.Types = map[string]registryEntry{"AWS::SSM::Parameter": native.Types["AWS::SSM::Parameter"]}
	writeRegistryFixture(t, source, public)
	writeRegistryFixture(t, metadata, native)
	output := filepath.Join(root, "generated.go")
	if err := run(source, metadata, output, false); err != nil {
		t.Fatal(err)
	}
	generated, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), output, generated, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"Registry: resourceRegistryContract{", "DeprecatedStatus: \"LIVE\"", "Visibility: \"PUBLIC\"", "ProvisioningType: \"FULLY_MUTABLE\"", "Version: \"\"", "TimeCreated: time.Unix(", "Metadata: " + metadata} {
		if !strings.Contains(string(generated), fragment) {
			t.Fatalf("generated contract omitted %q", fragment)
		}
	}
	// Raw schema retains the read-only ARN, original descriptions and write-only
	// properties; the simplified admission schema must not replace it.
	var compact bytes.Buffer
	if err := json.Compact(&compact, public.Types["AWS::SSM::Parameter"].Schema); err != nil {
		t.Fatal(err)
	}
	foundSchema := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		field, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := field.Key.(*ast.Ident)
		if !ok || key.Name != "Schema" {
			return true
		}
		value, ok := field.Value.(*ast.BasicLit)
		if !ok || value.Kind != token.STRING {
			t.Fatal("registry schema is not a constant string")
		}
		raw, err := strconv.Unquote(value.Value)
		if err != nil || raw != compact.String() {
			t.Fatalf("complete captured schema differs: %v", err)
		}
		foundSchema = true
		return true
	})
	if !foundSchema {
		t.Fatal("complete captured schema was not retained")
	}
	if err := run(source, metadata, output, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, append(generated, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(source, metadata, output, true); err == nil {
		t.Fatal("check mode did not reject changed generated output")
	}
}

func TestRegistryGenerationDoesNotInventUnobservedTimestamps(t *testing.T) {
	root := t.TempDir()
	source, metadata, output := filepath.Join(root, "source.json"), filepath.Join(root, "metadata.json"), filepath.Join(root, "generated.go")
	capture := registry{Region: "us-east-1", Types: map[string]registryEntry{
		"AWS::Example::Resource": {Schema: json.RawMessage(`{"typeName":"AWS::Example::Resource","properties":{"Name":{"type":"string"}},"primaryIdentifier":["/properties/Name"],"handlers":{"create":{},"update":{}}}`)},
	}}
	writeRegistryFixture(t, source, capture)
	writeRegistryFixture(t, metadata, registry{Region: "us-east-1", Types: map[string]registryEntry{"AWS::Example::Resource": {}}})
	if err := run(source, metadata, output, false); err != nil {
		t.Fatal(err)
	}
	generated, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(generated), `import "time"`) || strings.Contains(string(generated), "TimeCreated:") {
		t.Fatal("unobserved creation timestamp was generated")
	}
	if !strings.Contains(string(generated), `ProvisioningType: "NON_PROVISIONABLE"`) {
		t.Fatal("a type without read/delete handlers was called provisionable")
	}
}

func writeRegistryFixture(t *testing.T, path string, value registry) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

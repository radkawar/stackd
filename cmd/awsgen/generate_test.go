package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"stackd/internal/awsschema"
)

func fixture(t *testing.T) ([]byte, contract) {
	t.Helper()
	data, err := os.ReadFile("testdata/service.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseModel("demo", data, awsschema.Source{Repository: "https://example.test/sdk", Revision: strings.Repeat("a", 40), Path: "models/demo.json"})
	if err != nil {
		t.Fatal(err)
	}
	return data, c
}

func TestModelContractsPreserveRelationshipsAndConstraints(t *testing.T) {
	data, c := fixture(t)
	checksum := sha256.Sum256(data)
	if c.Info.Protocol != awsschema.AWSJSON11 || c.Info.SigningName != "demo" || c.Info.Version != "2025-01-01" || c.Info.Source.SHA256 != hex.EncodeToString(checksum[:]) {
		t.Fatalf("unexpected metadata: %+v", c.Info)
	}
	if len(c.Operations) != 1 {
		t.Fatalf("operations: %+v", c.Operations)
	}
	op := c.Operations[0]
	if op.Input != "example.demo#CreateThingRequest" || op.Output != "example.demo#CreateThingResponse" || len(op.Errors) != 1 || op.Errors[0] != "example.demo#RejectedException" || !op.Idempotent || op.Pagination.PageSize != "Count" {
		t.Fatalf("operation relationship lost: %+v", op)
	}
	shapes := map[awsschema.ShapeID]awsschema.Shape{}
	for _, shape := range c.Shapes {
		shapes[shape.ID] = shape
	}
	name := shapes["example.demo#Name"]
	if !name.Constraints.Length.Min.Set || name.Constraints.Length.Min.Value != "1" || name.Constraints.Length.Max.Value != "64" || name.Constraints.Pattern != "^[a-z]+$" || !name.Sensitive {
		t.Fatalf("constraints lost: %+v", name)
	}
	request := shapes[op.Input]
	members := map[string]awsschema.Member{}
	for _, member := range request.Members {
		members[member.Name] = member
	}
	if !members["Name"].Required || members["Count"].Default != "1" {
		t.Fatalf("member traits lost: %+v", request)
	}
	if shapes["example.demo#Labels"].Key.Target != name.ID || shapes["example.demo#Labels"].Value.Target != name.ID || shapes["example.demo#Items"].Member.Target != name.ID || !shapes["example.demo#Items"].Constraints.UniqueItems {
		t.Fatal("collection targets or constraints lost")
	}
	if len(shapes["example.demo#State"].Enum) != 2 || shapes["example.demo#RejectedException"].Error.Code != "Rejected" || shapes["example.demo#RejectedException"].Error.HTTPStatus != 409 {
		t.Fatal("enum or modeled error metadata lost")
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	data, c := fixture(t)
	first, err := generate([]contract{c}, "catalog", "api")
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		reparsed, err := parseModel("demo", data, c.Info.Source)
		if err != nil {
			t.Fatal(err)
		}
		again, err := generate([]contract{reparsed}, "catalog", "api")
		if err != nil {
			t.Fatal(err)
		}
		for path, content := range first {
			if !bytes.Equal(content, again[path]) {
				t.Fatalf("generation is nondeterministic for %s", path)
			}
		}
	}
	for path, content := range first {
		if _, err := parser.ParseFile(token.NewFileSet(), path, content, parser.AllErrors); err != nil {
			t.Fatalf("invalid generated Go %s: %v", path, err)
		}
	}
}

func TestCheckModeDetectsDriftWithoutWrites(t *testing.T) {
	_, c := fixture(t)
	root := t.TempDir()
	files, err := generate([]contract{c}, filepath.Join(root, "catalog"), filepath.Join(root, "api"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeGenerated(files, true); err == nil {
		t.Fatal("check accepted missing outputs")
	}
	if _, err := os.Stat(filepath.Join(root, "catalog")); !os.IsNotExist(err) {
		t.Fatalf("check created directory: %v", err)
	}
	if err := writeGenerated(files, false); err != nil {
		t.Fatal(err)
	}
	if err := writeGenerated(files, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "catalog", "generated.go")
	changed := []byte("// user-modified output\n")
	if err := os.WriteFile(path, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeGenerated(files, true); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("check error=%v, want changed path", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, changed) {
		t.Fatal("check rewrote stale output")
	}
}

func TestMalformedModelFailsExplicitly(t *testing.T) {
	data, _ := fixture(t)
	for _, tt := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown version", func(model map[string]any) { model["smithy"] = "9.0" }},
		{"missing service", func(model map[string]any) { delete(model["shapes"].(map[string]any), "example.demo#Demo") }},
		{"unresolved input", func(model map[string]any) {
			model["shapes"].(map[string]any)["example.demo#CreateThing"].(map[string]any)["input"] = map[string]any{"target": "example.demo#Missing"}
		}},
		{"unknown shape kind", func(model map[string]any) {
			model["shapes"].(map[string]any)["example.demo#Name"].(map[string]any)["type"] = "unknown"
		}},
		{"missing protocol", func(model map[string]any) {
			delete(model["shapes"].(map[string]any)["example.demo#Demo"].(map[string]any)["traits"].(map[string]any), "aws.protocols#awsJson1_1")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var model map[string]any
			if err := json.Unmarshal(data, &model); err != nil {
				t.Fatal(err)
			}
			tt.mutate(model)
			changed, err := json.Marshal(model)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseModel("demo", changed, awsschema.Source{}); err == nil {
				t.Fatal("invalid model accepted")
			}
		})
	}
}

func TestEquivalentScalarNamesCompileWithoutMergingKinds(t *testing.T) {
	_, c := fixture(t)
	c.Shapes = append(c.Shapes,
		awsschema.Shape{ID: "example.demo#String", Kind: "string", Constraints: awsschema.Constraints{
			Length: awsschema.Bounds{Min: awsschema.Bound{Set: true, Value: "1"}}}},
		awsschema.Shape{ID: "smithy.api#String", Kind: "string"},
		awsschema.Shape{ID: "example.demo#Pair", Kind: "structure", Members: []awsschema.Member{
			{Name: "Constrained", Target: "example.demo#String"},
			{Name: "Unconstrained", Target: "smithy.api#String"},
		}},
	)
	if err := validateContract(c); err != nil {
		t.Fatal(err)
	}
	generated, err := renderTypes(c)
	if err != nil {
		t.Fatal(err)
	}
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, "types.go", generated, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := new(types.Config).Check("demo", files, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pair := pkg.Scope().Lookup("Pair").Type().Underlying().(*types.Struct)
	if !types.Identical(pair.Field(0).Type(), pair.Field(1).Type()) {
		t.Fatal("equivalent scalar references do not share their Go representation")
	}
	c.Shapes[len(c.Shapes)-2].Kind = "integer"
	if err := validateContract(c); err == nil {
		t.Fatal("different scalar representations shared a Go type")
	}
}

func TestCheckoutConsistency(t *testing.T) {
	sdk := os.Getenv("STACKD_AWS_SDK_PATH")
	if sdk == "" {
		t.Skip("set STACKD_AWS_SDK_PATH to verify generated output against a local checkout")
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := run(options{SDK: sdk, Services: "iam,organizations,sts", CatalogOut: filepath.Join(repoRoot, "internal", "awscatalog"), APIOut: filepath.Join(repoRoot, "internal", "awsapi"), Check: true}); err != nil {
		t.Fatal(err)
	}
}

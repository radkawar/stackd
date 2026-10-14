package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestRegistrationsPreserveAliasesAndSplitFrameworkMethods(t *testing.T) {
	fixtures := []struct{ path, code string }{
		{"service_package_gen.go", `package example
import sdk "github.com/aws/aws-sdk-go-v2/service/sfn"
func (p *servicePackage) SDKResources() any { return []*Registration{
 {Factory: resourceLoadBalancer, TypeName: "aws_alb"},
 {Factory: resourceLoadBalancer, TypeName: "aws_lb"},
} }
func (p *servicePackage) SDKDataSources() any { return []*Registration{
 {Factory: dataSourceLoadBalancer, TypeName: "aws_lb"},
} }
func (p *servicePackage) FrameworkResources() any { return []*Registration{
 {Factory: newStateMachine, TypeName: "aws_sfn_state_machine"},
} }
func (p *servicePackage) SDKListResources() any { return []*Registration{
 {Factory: listLoadBalancer, TypeName: "aws_lb"},
} }
func (p *servicePackage) NewClient() (*sdk.Client, error) { return nil, nil }
`},
		{"load_balancer.go", `package example
func resourceLoadBalancer() any { return &schema.Resource{} }
func dataSourceLoadBalancer() any { return &schema.Resource{} }
`},
		{"state_machine_factory.go", `package example
func newStateMachine() (any, error) { return &stateMachine{}, nil }
`},
		{"state_machine_methods.go", `package example
func (r *stateMachine) Create() {}
func (r stateMachine) Read() {}
`},
		{"unrelated.go", `package example
func helper() {}
`},
	}
	sources := []parsedSource{}
	for _, fixture := range fixtures {
		path := "internal/service/sfn/" + fixture.path
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, fixture.code, 0)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, parsedSource{path, file, fset})
	}
	apis := []requirement{
		{SDKService: "sfn", StackdService: "stepfunctions", Operation: "CreateStateMachine", Status: "registered-partial", Callsites: []callsite{{Path: "internal/service/sfn/state_machine_methods.go", Line: 2}}},
		{SDKService: "kms", StackdService: "kms", Operation: "DescribeKey", Status: "unimplemented", Callsites: []callsite{{Path: "internal/service/sfn/state_machine_methods.go", Line: 3}}},
		{SDKService: "sfn", Operation: "Unrelated", Status: "unimplemented", Callsites: []callsite{{Path: "internal/service/sfn/unrelated.go", Line: 2}}},
	}
	items, err := registeredItems("sfn", sources, apis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 {
		t.Fatalf("aliases or data source lost: %+v", items)
	}
	r := report{Services: []service{{Name: "sfn", SDKService: packageSDK(sources), Requirements: apis}}, Lifecycle: lifecycleInventory{Items: items}}
	var inventory retained
	inventory.Services = append(inventory.Services, struct {
		ID         string                          `json:"id"`
		Operations []struct{ Name, Status string } `json:"operations"`
	}{ID: "stepfunctions", Operations: []struct{ Name, Status string }{{"CreateStateMachine", "partial"}}})
	refreshLifecycle(&r, inventory)
	if r.Lifecycle.Totals.Resources != 3 || r.Lifecycle.Totals.DataSources != 1 {
		t.Fatalf("counts: %+v", r.Lifecycle.Totals)
	}
	for _, item := range r.Lifecycle.Items {
		if item.StackdService != "stepfunctions" || item.Lifecycle != "unverified" || item.Engine != "unverified" {
			t.Fatalf("identity/evidence: %+v", item)
		}
		if item.Type != "aws_sfn_state_machine" {
			continue
		}
		if len(item.SourceFiles) != 2 || len(item.APIs) != 2 || len(item.Gaps) != 1 || len(item.Dependencies) != 1 || item.Dependencies[0] != "kms" {
			t.Fatalf("split files or API context: %+v", item)
		}
	}
}

func TestNonliteralRegistrationFailsInsteadOfOmittingType(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "service_package_gen.go", `package example
func (p *servicePackage) SDKResources() any { return []*Registration{{Factory: resourceExample, TypeName: computedName}} }
func resourceExample() any { return nil }
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registeredItems("example", []parsedSource{{"internal/service/example/service_package_gen.go", file, fset}}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "nonliteral TypeName") {
		t.Fatalf("unexpected result: %v", err)
	}
}

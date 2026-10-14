package main

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestASTEvidenceAndLexicalScope(t *testing.T) {
	const fixture = `package example
import (
 sdk "github.com/aws/aws-sdk-go-v2/service/ec2"
 other "github.com/aws/aws-sdk-go-v2/service/rds"
 connections "github.com/hashicorp/terraform-provider-aws/internal/conns"
)
var initialize = func(client *sdk.Client) { client.DescribeAddresses(nil, nil) }
func refresh(ctx any, conn *sdk.Client, input *sdk.DescribeAddressesAttributeInput) {
 pages := sdk.NewDescribeAddressesAttributePaginator(conn, input)
 pages.NextPage(ctx)
 conn.DescribeAddressesAttribute(ctx, input)
 conn.PurchaseReservedInstancesOffering(ctx, nil)
 operation := conn.DescribeAddressesAttribute
 operation(ctx, input)
 helper(ctx, input)
 { conn := unknown(); conn.DescribeAddresses(ctx, nil) }
 rdsInput := &other.CreateDBInstanceInput{}
 unknownConnection.CreateDBInstance(ctx, rdsInput)
 conn.Options()
}
func helper(ctx any, input *sdk.DescribeAddressesAttributeInput) {}
func factory(ctx any, meta any) {
 conn := meta.(*connections.AWSClient).EC2Client(ctx)
 conn.DescribeAddresses(ctx, nil)
 impostorClient := unrelated.EC2Client(ctx)
 impostorClient.DescribeAddresses(ctx, nil)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/service/example/fixture.go", fixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	a := analyzer{fset: fset, file: file, path: "internal/service/example/fixture.go", imports: sdkImports(file), operations: map[string]map[string]bool{"ec2": {"DescribeAddresses": true}, "rds": {"CreateDBInstance": true}}}
	resolved := map[string][]callsite{}
	unresolvedCalls := []unresolved{}
	a.scan(func(sdk, op string, site callsite) { resolved[sdk+"/"+op] = append(resolved[sdk+"/"+op], site) }, func(u unresolved) { unresolvedCalls = append(unresolvedCalls, u) })
	if len(resolved["ec2/DescribeAddressesAttribute"]) != 2 {
		t.Fatalf("paginator and direct Input evidence: %+v", resolved)
	}
	if resolved["ec2/DescribeAddressesAttribute"][0].Evidence != "sdk_paginator_constructor" {
		t.Fatalf("missing paginator evidence: %+v", resolved)
	}
	if len(resolved["ec2/DescribeAddresses"]) != 2 {
		t.Fatalf("package closure and genuine factory only: %+v", resolved)
	}
	if len(resolved["ec2/PurchaseReservedInstancesOffering"]) != 1 {
		t.Fatalf("typed SDK receivers must not require a verb whitelist: %+v", resolved)
	}
	if len(resolved["rds/CreateDBInstance"]) != 1 {
		t.Fatalf("cross-service Input alias: %+v", resolved)
	}
	if _, found := resolved["ec2/Options"]; found {
		t.Fatal("SDK configuration is not an AWS operation")
	}
	reasons := map[string]int{}
	for _, u := range unresolvedCalls {
		reasons[u.Callsite.Evidence]++
	}
	if reasons["sdk_method_reference"] != 1 || reasons["indirect_input_typed_call"] != 1 || reasons["unresolved_receiver"] != 2 {
		t.Fatalf("unresolved scope/dynamic calls: %+v", unresolvedCalls)
	}
}

func TestSDKServiceAliases(t *testing.T) {
	for id, want := range map[string]string{"elbv2": "elasticloadbalancingv2", "elb": "elasticloadbalancing", "logs": "cloudwatchlogs", "ce": "costexplorer", "es": "elasticsearchservice", "cognitoidp": "cognitoidentityprovider", "stepfunctions": "sfn", "serverlessrepo": "serverlessapplicationrepository", "iot-data": "iotdataplane", "bedrock-agentcore-control": "bedrockagentcorecontrol"} {
		if got := sdkID(id); got != want {
			t.Errorf("sdkID(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestGenerationDeterminismCheckAndClassification(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required for provider revision metadata")
	}
	root := t.TempDir()
	provider := filepath.Join(root, "provider")
	put := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put(filepath.Join(provider, "version", "VERSION"), pinnedVersion+"\n")
	put(filepath.Join(provider, "internal", "service", "ec2", "find.go"), `package ec2
import sdk "github.com/aws/aws-sdk-go-v2/service/ec2"
func read(conn *sdk.Client) {
 sdk.NewDescribeAddressesAttributePaginator(conn, nil)
 conn.DescribeAddresses(nil, nil)
 conn.DescribeFutureFeature(nil, nil)
}
`)
	put(filepath.Join(provider, "internal", "service", "outside", "create.go"), `package outside
import sdk "github.com/aws/aws-sdk-go-v2/service/future"
func create(conn *sdk.Client) { conn.CreateThing(nil, nil) }
`)
	put(filepath.Join(provider, "internal", "service", "empty", "service_package.go"), "package empty\n")
	put(filepath.Join(provider, "internal", "service", "ec2", "read_test.go"), "not parsed\n")
	put(filepath.Join(provider, "internal", "service", "ec2", "sweep.go"), "not parsed\n")
	put(filepath.Join(provider, "internal", "service", "ec2", "testdata", "fixture.go"), "not parsed\n")
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", provider}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=Inventory Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Inventory Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("init", "-q")
	runGit("add", ".")
	runGit("-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
	inventoryPath := filepath.Join(root, "services.json")
	put(inventoryPath, `{"source":{"revision":"fixture"},"services":[{"id":"ec2","operations":[{"name":"DescribeAddresses","status":"partial"},{"name":"DescribeAddressesAttribute","status":"unimplemented"}]}],"additional_registered":[{"service":"future","operations":[{"name":"CreateThing","status":"partial"}]}]}`)
	o := options{Provider: provider, Inventory: inventoryPath, Out: filepath.Join(root, "apis.json"), Revision: runGit("rev-parse", "HEAD"), Version: pinnedVersion}
	first, err := generate(o)
	if err != nil {
		t.Fatal(err)
	}
	second, err := generate(o)
	if err != nil {
		t.Fatal(err)
	}
	one, _ := json.Marshal(first)
	two, _ := json.Marshal(second)
	if !bytes.Equal(one, two) {
		t.Fatal("generation is not deterministic")
	}
	if first.Totals.Services != 3 || first.Totals.Files != 3 || first.Totals.Partial != 1 || first.Totals.Unimplemented != 1 || first.Totals.Outside != 1 || first.Totals.Unknown != 1 || first.Totals.Paginators != 1 {
		t.Fatalf("totals: %+v", first.Totals)
	}
	if first.Priorities[0].Service != "ec2" || first.Services[0].ExcludedFiles != 2 {
		t.Fatalf("priority/exclusions: %+v", first)
	}
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	o.Check = true
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	// Missing checkout mode must reproduce the same bytes, but it must not
	// claim that retained source evidence verifies provider source drift.
	originalProvider := o.Provider
	o.Provider = filepath.Join(root, "missing-provider")
	if err := run(o); err != nil {
		t.Fatalf("retained-source deterministic check: %v", err)
	}
	o.Provider = originalProvider
	put(o.Out, "stale\n")
	if err := run(o); err == nil || !strings.Contains(err.Error(), "generated inventory differs") {
		t.Fatalf("stale check: %v", err)
	}
	stale, err := os.ReadFile(o.Out)
	if err != nil || string(stale) != "stale\n" {
		t.Fatalf("check modified output: %q %v", stale, err)
	}
	put(filepath.Join(provider, "internal", "service", "empty", "service_package.go"), "package changed\n")
	if _, err := generate(o); err == nil || !strings.Contains(err.Error(), "local changes") {
		t.Fatalf("dirty revision source: %v", err)
	}
}

package integrations

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/apigatewayv2"
	"stackd/internal/services/cloudformation"
)

type cfnGatewayV2Fixture struct {
	ctx      context.Context
	scope    cloudformation.Scope
	handlers map[string]cloudformation.ResourceHandler
}

func newCFNGatewayV2Fixture(t *testing.T) cfnGatewayV2Fixture {
	t.Helper()
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	owner := apigatewayv2.New(apigatewayv2.Config{Clock: clock.NewManual(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))})
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"apigatewayv2": owner})
	return cfnGatewayV2Fixture{ctx: ctx, scope: cloudformation.Scope{Partition: "aws", Region: "us-east-1", Account: "111111111111"}, handlers: CloudFormationAPIGatewayV2Handlers(commands)}
}

func (f cfnGatewayV2Fixture) request(typeName, logical, token string, p cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "arn:aws:cloudformation:us-east-1:111111111111:stack/guard/1", StackName: "guard", LogicalID: logical, Type: typeName, Token: token, Scope: f.scope, Properties: p}
}

func (f cfnGatewayV2Fixture) create(t *testing.T, typeName, logical string, p cloudformation.Properties) cloudformation.ResourceResult {
	t.Helper()
	result, err := f.handlers[typeName].Create(f.ctx, f.request(typeName, logical, logical+"-1", p))
	if err != nil {
		t.Fatalf("create %s: %v", typeName, err)
	}
	return result
}

func (f cfnGatewayV2Fixture) read(t *testing.T, typeName, physical string) cloudformation.Properties {
	t.Helper()
	p, err := f.handlers[typeName].(cloudformation.ResourceReader).Read(f.ctx, cloudformation.ResourceRequest{Type: typeName, PhysicalID: physical, Scope: f.scope, CloudControl: true})
	if err != nil {
		t.Fatalf("read %s: %v", typeName, err)
	}
	return p
}

// The V2 UpdateStage command merges stage variables; a CloudFormation update
// that omits a variable must remove it from the deployed stage.
func TestCloudFormationGatewayV2StageUpdateRemovesOmittedVariables(t *testing.T) {
	f := newCFNGatewayV2Fixture(t)
	api := f.create(t, "AWS::ApiGatewayV2::Api", "Api", cloudformation.Properties{"Name": "api", "ProtocolType": "HTTP"})
	before := cloudformation.Properties{"ApiId": api.Ref, "StageName": "dev", "StageVariables": map[string]any{"keep": "one", "drop": "two"}}
	stage := f.create(t, "AWS::ApiGatewayV2::Stage", "Stage", before)
	if stage.PhysicalID != api.Ref+"|dev" || stage.Ref != "dev" {
		t.Fatalf("stage identity = %q ref %q", stage.PhysicalID, stage.Ref)
	}
	after := cloudformation.Properties{"ApiId": api.Ref, "StageName": "dev", "StageVariables": map[string]any{"keep": "one"}}
	update := f.request("AWS::ApiGatewayV2::Stage", "Stage", "Stage-1", after)
	update.PhysicalID, update.Previous = stage.PhysicalID, before
	if _, err := f.handlers["AWS::ApiGatewayV2::Stage"].Update(f.ctx, update); err != nil {
		t.Fatal(err)
	}
	variables, _ := f.read(t, "AWS::ApiGatewayV2::Stage", stage.PhysicalID)["StageVariables"].(map[string]any)
	if len(variables) != 1 || variables["keep"] != "one" {
		t.Fatalf("stage variables = %#v", variables)
	}
}

// Removing a WebSocket integration timeout restores the protocol default
// instead of retaining the previously declared value.
func TestCloudFormationGatewayV2IntegrationRemovalRestoresProtocolDefault(t *testing.T) {
	f := newCFNGatewayV2Fixture(t)
	api := f.create(t, "AWS::ApiGatewayV2::Api", "Socket", cloudformation.Properties{"Name": "socket", "ProtocolType": "WEBSOCKET", "RouteSelectionExpression": "$request.body.action"})
	uri := "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:111111111111:function:handler/invocations"
	before := cloudformation.Properties{"ApiId": api.Ref, "IntegrationType": "AWS_PROXY", "IntegrationUri": uri, "TimeoutInMillis": "1000"}
	integration := f.create(t, "AWS::ApiGatewayV2::Integration", "Integration", before)
	if got := f.read(t, "AWS::ApiGatewayV2::Integration", integration.PhysicalID)["TimeoutInMillis"]; got != float64(1000) {
		t.Fatalf("created timeout = %#v", got)
	}
	after := cloudformation.Properties{"ApiId": api.Ref, "IntegrationType": "AWS_PROXY", "IntegrationUri": uri}
	update := f.request("AWS::ApiGatewayV2::Integration", "Integration", "Integration-1", after)
	update.PhysicalID, update.Previous = integration.PhysicalID, before
	if _, err := f.handlers["AWS::ApiGatewayV2::Integration"].Update(f.ctx, update); err != nil {
		t.Fatal(err)
	}
	if got := f.read(t, "AWS::ApiGatewayV2::Integration", integration.PhysicalID)["TimeoutInMillis"]; got != float64(29000) {
		t.Fatalf("timeout after removal = %#v", got)
	}
}

// Authorizer identifiers follow the schema's primaryIdentifier order.
func TestCloudFormationGatewayV2AuthorizerIdentifierOrder(t *testing.T) {
	f := newCFNGatewayV2Fixture(t)
	api := f.create(t, "AWS::ApiGatewayV2::Api", "Api", cloudformation.Properties{"Name": "api", "ProtocolType": "HTTP"})
	authorizer := f.create(t, "AWS::ApiGatewayV2::Authorizer", "Jwt", cloudformation.Properties{"ApiId": api.Ref, "AuthorizerType": "JWT", "Name": "jwt",
		"IdentitySource": []any{"$request.header.Authorization"}, "JwtConfiguration": map[string]any{"Audience": []any{"client"}, "Issuer": "https://issuer.example.com"}})
	if authorizer.PhysicalID != authorizer.Ref+"|"+api.Ref || authorizer.Attributes["AuthorizerId"] != authorizer.Ref {
		t.Fatalf("authorizer result = %#v", authorizer)
	}
	if got := f.read(t, "AWS::ApiGatewayV2::Authorizer", authorizer.PhysicalID)["Name"]; got != "jwt" {
		t.Fatalf("authorizer name = %#v", got)
	}
}

// Members the owner cannot clear through an update force replacement.
func TestCloudFormationGatewayV2RemovalReplacement(t *testing.T) {
	h := CloudFormationAPIGatewayV2Handlers(StepFunctionsCommands{})["AWS::ApiGatewayV2::Route"]
	before := cloudformation.Properties{"ApiId": "a1", "RouteKey": "GET /", "AuthorizationType": "JWT", "AuthorizerId": "z9", "AuthorizationScopes": []any{"read"}, "OperationName": "get"}
	clearable := cloudformation.Properties{"ApiId": "a1", "RouteKey": "GET /", "AuthorizationType": "JWT", "AuthorizerId": "z9", "AuthorizationScopes": []any{"read"}}
	if replace, err := h.Replacement(before, clearable); err != nil || replace {
		t.Fatalf("operation name removal replace=%v err=%v", replace, err)
	}
	unclearable := cloudformation.Properties{"ApiId": "a1", "RouteKey": "GET /", "AuthorizationType": "JWT", "AuthorizerId": "z9", "OperationName": "get"}
	if replace, err := h.Replacement(before, unclearable); err != nil || !replace {
		t.Fatalf("scope removal replace=%v err=%v", replace, err)
	}
}

// Recovery with the same incarnation returns the original API; a different
// incarnation cannot delete it.
func TestCloudFormationGatewayV2IncarnationOwnership(t *testing.T) {
	f := newCFNGatewayV2Fixture(t)
	p := cloudformation.Properties{"Name": "api", "ProtocolType": "HTTP"}
	first := f.create(t, "AWS::ApiGatewayV2::Api", "Api", p)
	recovered := f.create(t, "AWS::ApiGatewayV2::Api", "Api", p)
	if recovered.PhysicalID != first.PhysicalID {
		t.Fatalf("recovery minted %q, want %q", recovered.PhysicalID, first.PhysicalID)
	}
	other := f.request("AWS::ApiGatewayV2::Api", "Api", "Api-2", p)
	other.PhysicalID = first.PhysicalID
	if err := f.handlers["AWS::ApiGatewayV2::Api"].Delete(f.ctx, other); err == nil {
		t.Fatal("another incarnation deleted the API")
	}
	f.read(t, "AWS::ApiGatewayV2::Api", first.PhysicalID)
}

func TestCloudFormationGatewayV2NoopUpdateChecksPrivateIncarnation(t *testing.T) {
	f := newCFNGatewayV2Fixture(t)
	api := f.create(t, "AWS::ApiGatewayV2::Api", "Api", cloudformation.Properties{"Name": "owned", "ProtocolType": "HTTP"})
	properties := cloudformation.Properties{"ApiId": api.Ref, "RouteKey": "GET /owned", "AuthorizationType": "NONE"}
	created := f.create(t, "AWS::ApiGatewayV2::Route", "Route", properties)
	r := f.request("AWS::ApiGatewayV2::Route", "Route", "Route-1", properties)
	r.PhysicalID, r.Previous = created.PhysicalID, properties
	h := f.handlers[r.Type]
	foreign := r
	foreign.Token = "other-incarnation"
	var conflict *awswire.Error
	if _, err := h.Update(f.ctx, foreign); !errors.As(err, &conflict) || conflict.Code != "ConflictException" {
		t.Fatalf("no-op update accepted another private incarnation: %v", err)
	}
	denied := awsctx.WithMetadata(t.Context(), awsctx.Metadata{
		Partition: f.scope.Partition, AccountID: f.scope.Account, Region: f.scope.Region,
		PrincipalARN: "arn:aws:iam::111111111111:user/denied", PrincipalID: "denied",
	})
	var rejection *awswire.Error
	if _, err := h.Update(denied, r); !errors.As(err, &rejection) || rejection.StatusCode != 403 {
		t.Fatalf("no-op observation bypassed current IAM: %v", err)
	}
	// Ordinary Cloud Control changes keep, but cannot grant, the native claim.
	native := foreign
	native.CloudControl = true
	native.Properties = cloudformation.Properties{"ApiId": api.Ref, "RouteKey": "GET /native", "AuthorizationType": "NONE"}
	if _, err := h.Update(f.ctx, native); err != nil {
		t.Fatal(err)
	}
	if model := f.read(t, r.Type, r.PhysicalID); model["RouteKey"] != "GET /native" {
		t.Fatalf("ordinary caller update did not reach the native route: %+v", model)
	}
	r.Properties = cloudformation.Properties{"ApiId": api.Ref, "RouteKey": "GET /stack", "AuthorizationType": "NONE"}
	if _, err := h.Update(f.ctx, r); err != nil {
		t.Fatal(err)
	}
	if model := f.read(t, r.Type, r.PhysicalID); model["RouteKey"] != "GET /stack" {
		t.Fatalf("ordinary update discarded the stack's private claim: %+v", model)
	}
}

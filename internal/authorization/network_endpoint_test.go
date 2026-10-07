package authorization_test

import (
	"context"
	"net/http"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type endpointPolicyGuard struct {
	document  *policy.Document
	called    bool
	principal policy.Principal
}

func (g *endpointPolicyGuard) Context(context.Context, authorization.Request) (map[string][]string, *awswire.Error) {
	return map[string][]string{"aws:sourcevpce": {"vpce-authoritative"}, "aws:sourcevpc": {"vpc-authoritative"}, "aws:vpcsourceip": {"10.91.1.10"}}, nil
}

func (g *endpointPolicyGuard) Authorize(_ context.Context, request authorization.Request, principal policy.Principal) *awswire.Error {
	g.called, g.principal = true, principal
	decision, err := policy.EvaluateResource(g.document, policy.Request{Action: request.Action, ActionAliases: request.PolicyActionAliases, Resource: request.ResourceARN, Context: request.Context, ContextTypes: request.ContextTypes}, principal)
	if err != nil || decision.Decision != policy.Allow {
		return &awswire.Error{Code: "AccessDenied", Message: "Endpoint policy denied", StatusCode: http.StatusForbidden}
	}
	return nil
}

func TestNetworkEndpointPolicyIsIntersectionNeverAnIAMGrant(t *testing.T) {
	for _, test := range []struct {
		name, identity, endpoint string
		allowed, guardCalled     bool
	}{
		{"both-allow", allow, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"*"}}`, true, true},
		{"endpoint-deny", allow, `{"Statement":{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"}}`, false, true},
		{"endpoint-wrong-action", allow, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage","Resource":"*"}}`, false, true},
		{"endpoint-cannot-grant-IAM", other, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`, false, false},
		{"IAM-explicit-deny", deny, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`, false, false},
		{"wrong-vpc", allow, `{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpc":"vpc-other"}}}}`, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc, err := policy.ParseResource([]byte(test.endpoint))
			if err != nil {
				t.Fatal(err)
			}
			guard := &endpointPolicyGuard{document: doc}
			ctx := authorization.WithNetworkEndpointGuard(awsctx.WithMetadata(t.Context(), metadata(false)), guard)
			evaluator := authorization.New(identitySource{set: authorization.PolicySet{Identity: []policy.Policy{{Document: test.identity}}}}, nil)
			errWire := evaluator.Authorize(ctx, authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN})
			if (errWire == nil) != test.allowed || guard.called != test.guardCalled {
				t.Fatalf("endpoint intersection allowed=%t called=%t error=%v", errWire == nil, guard.called, errWire)
			}
		})
	}
}

func TestNetworkEndpointContextParticipatesInNormalIAMAndRetainsBoundaryPrincipal(t *testing.T) {
	doc, err := policy.ParseResource([]byte(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`))
	if err != nil {
		t.Fatal(err)
	}
	guard := &endpointPolicyGuard{document: doc}
	ctx := authorization.WithNetworkEndpointGuard(awsctx.WithMetadata(t.Context(), metadata(false)), guard)
	identity := `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-authoritative"},"IpAddress":{"aws:VpcSourceIp":"10.91.1.0/24"}}}}`
	evaluator := authorization.New(identitySource{set: authorization.PolicySet{Identity: []policy.Policy{{Document: identity}}, HasBoundary: true, Boundary: []policy.Policy{{Document: allow}}}}, nil)
	if rejected := evaluator.Authorize(ctx, authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN}); rejected != nil {
		t.Fatal(rejected)
	}
	if !guard.principal.HasBoundary || guard.principal.ARN != userARN || guard.principal.ID != "AIDAEXAMPLE" {
		t.Fatal("endpoint guard did not receive the actual authenticated principal and boundary")
	}
	plain := authorization.WithoutNetworkEndpointGuard(ctx)
	if rejected := evaluator.Authorize(plain, authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN}); rejected == nil {
		t.Fatal("removing the trusted endpoint context fabricated IAM condition keys")
	}
}

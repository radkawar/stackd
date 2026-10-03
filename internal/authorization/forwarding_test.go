package authorization_test

import (
	"context"
	"fmt"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func TestForwardedCallerConditionsAndPolicyRestrictions(t *testing.T) {
	m := metadata(false)
	m.TransportKnown, m.SourceIP = true, "192.0.2.1"
	direct := awsctx.WithMetadata(t.Context(), m)
	forwarded := awsctx.WithViaService(direct, "sqs.amazonaws.com")
	for _, tc := range []struct {
		name, condition   string
		direct, forwarded bool
	}{
		{"via service", `"Bool":{"aws:ViaAWSService":"true"}`, false, true},
		{"direct service", `"Bool":{"aws:ViaAWSService":"false"}`, true, false},
		{"caller remains IAM", `"Bool":{"aws:PrincipalIsAWSService":"false"}`, true, true},
		{"service principal cannot be claimed", `"Bool":{"aws:PrincipalIsAWSService":"true"}`, false, false},
		{"last service", `"StringEquals":{"aws:CalledViaLast":"sqs.amazonaws.com"}`, false, true},
		{"first service", `"StringEquals":{"aws:CalledViaFirst":"sqs.amazonaws.com"}`, false, true},
		{"service chain", `"ForAnyValue:StringEquals":{"aws:CalledVia":"sqs.amazonaws.com"}`, false, true},
		{"direct chain absent", `"Null":{"aws:CalledVia":"true","aws:CalledViaFirst":"true","aws:CalledViaLast":"true"}`, true, false},
		{"public source address retained", `"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{%s}}}`, tc.condition)
			e := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: doc}}}}, nil)
			for _, request := range []struct {
				name    string
				ctx     context.Context
				allowed bool
			}{{"direct", direct, tc.direct}, {"forwarded", forwarded, tc.forwarded}} {
				if err := e.Authorize(request.ctx, authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN}); (err == nil) != request.allowed {
					t.Fatalf("%s authorization=%v, want allowed=%t", request.name, err, request.allowed)
				}
			}
		})
	}
	// Forwarding changes the request path, not the caller's policy ceilings.
	for _, restriction := range []string{"identity", "boundary", "session", "scp", "resource"} {
		t.Run(restriction, func(t *testing.T) {
			set := authorization.PolicySet{Identity: policyDocuments(allow)}
			request := authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN}
			caller := awsctx.FromContext(forwarded)
			var controls controlSource
			switch restriction {
			case "identity":
				set.Identity = append(set.Identity, iampolicy.Policy{Document: deny})
			case "boundary":
				set.HasBoundary, set.Boundary = true, policyDocuments(other)
			case "session":
				caller.HasSessionPolicy, caller.SessionPolicies = true, []string{other}
			case "scp":
				controls = controlSource{{Documents: policyDocuments(other)}}
			case "resource":
				request.ResourcePolicies = []authorization.BoundPolicy{{Document: resourceDeny}}
			}
			e := authorization.New(identitySource{set: set}, controls)
			if e.Authorize(awsctx.WithMetadata(t.Context(), caller), request) == nil {
				t.Fatal("forwarding bypassed the caller's restriction")
			}
		})
	}
}

func TestForwardingContextCannotBeSuppliedAsPolicyContext(t *testing.T) {
	e := authorization.New(identitySource{set: authorization.PolicySet{Identity: policyDocuments(allow)}}, nil)
	ctx := awsctx.WithMetadata(t.Context(), metadata(false))
	for key, values := range map[string][]string{
		"aws:ViaAWSService": {"true"}, "aws:CalledVia": {"sqs.amazonaws.com"},
		"aws:CalledViaFirst": {"sqs.amazonaws.com"}, "aws:CalledViaLast": {"sqs.amazonaws.com"},
		"aws:PrincipalIsAWSService": {"true"},
	} {
		if e.Authorize(ctx, authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, Context: map[string][]string{key: values}}) == nil {
			t.Fatalf("policy context fabricated %s", key)
		}
	}
}

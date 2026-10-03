package authorization_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

const (
	account      = "123456789012"
	userARN      = "arn:aws:iam::123456789012:user/app"
	queueARN     = "arn:aws:sqs:us-east-1:123456789012:work"
	allow        = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*"}}`
	deny         = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`
	other        = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"*"}}`
	direct       = `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/app"},"Action":"sqs:*","Resource":"*"}}`
	delegation   = `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sqs:*","Resource":"*"}}`
	resourceDeny = `{"Statement":{"Effect":"Deny","Principal":"*","Action":"sqs:SendMessage","Resource":"*"}}`
)

type identitySource struct {
	set authorization.PolicySet
	err error
}

func (s identitySource) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return s.set, s.err
}

type controlSource []iampolicy.PolicyLevel

func (s controlSource) ServiceControlPolicies(context.Context) ([]iampolicy.PolicyLevel, error) {
	return s, nil
}

func metadata(root bool) awsctx.Metadata {
	m := awsctx.Metadata{AccountID: account, Region: "us-east-1", Partition: "aws", PrincipalARN: userARN, PrincipalID: "AIDAEXAMPLE", UserName: "app"}
	if root {
		m.PrincipalARN = "arn:aws:iam::" + account + ":root"
		m.PrincipalID, m.UserName = account, ""
	}
	return m
}

func TestPolicyComposition(t *testing.T) {
	cases := []struct {
		name            string
		root            bool
		identity        []string
		boundary        []string
		hasBoundary     bool
		resource        string
		requireResource bool
		cross           bool
		controls        controlSource
		wantAllow       bool
	}{
		{name: "root default", root: true, wantAllow: true},
		{name: "implicit deny"},
		{name: "identity allow", identity: []string{allow}, wantAllow: true},
		{name: "identity explicit deny", identity: []string{allow, deny}},
		{name: "resource direct grant", resource: direct, wantAllow: true},
		{name: "resource cannot override identity explicit deny", identity: []string{deny}, resource: direct},
		{name: "account grant delegates only", resource: delegation},
		{name: "account delegation with identity", resource: delegation, identity: []string{allow}, wantAllow: true},
		{name: "account delegation with root", root: true, resource: delegation, wantAllow: true},
		{name: "resource explicit deny", identity: []string{allow}, resource: resourceDeny},
		{name: "root resource explicit deny", root: true, resource: resourceDeny},
		{name: "boundary implicit deny", identity: []string{allow}, boundary: []string{other}, hasBoundary: true},
		{name: "empty boundary denies", identity: []string{allow}, hasBoundary: true},
		{name: "boundary intersection", identity: []string{allow}, boundary: []string{allow}, hasBoundary: true, wantAllow: true},
		{name: "direct user bypasses implicit boundary", resource: direct, boundary: []string{other}, hasBoundary: true, wantAllow: true},
		{name: "direct user cannot bypass explicit boundary", resource: direct, boundary: []string{deny}, hasBoundary: true},
		{name: "delegation cannot bypass implicit boundary", resource: delegation, identity: []string{allow}, boundary: []string{other}, hasBoundary: true},
		{name: "key policy required", identity: []string{allow}, requireResource: true},
		{name: "key policy required for root", root: true, requireResource: true},
		{name: "key direct grant", resource: direct, requireResource: true, wantAllow: true},
		{name: "key delegation", resource: delegation, identity: []string{allow}, requireResource: true, wantAllow: true},
		{name: "key unrelated policy", resource: strings.ReplaceAll(direct, userARN, "arn:aws:iam::123456789012:user/other"), identity: []string{allow}, requireResource: true},
		{name: "cross-account missing resource", identity: []string{allow}, cross: true},
		{name: "cross-account missing identity", resource: direct, cross: true},
		{name: "cross-account requires both", resource: direct, identity: []string{allow}, cross: true, wantAllow: true},
		{name: "cross-account boundary still applies", resource: direct, identity: []string{allow}, boundary: []string{other}, hasBoundary: true, cross: true},
		{name: "cross-account root still needs resource", root: true, cross: true},
		{name: "root member SCP deny", root: true, controls: controlSource{{Documents: []iampolicy.Policy{{Document: allow}, {Document: deny}}}}},
		{name: "SCP each level permits", identity: []string{allow}, controls: controlSource{{Documents: []iampolicy.Policy{{Document: allow}}}, {Documents: []iampolicy.Policy{{Document: allow}}}}, wantAllow: true},
		{name: "SCP one level implicit deny", identity: []string{allow}, controls: controlSource{{Documents: []iampolicy.Policy{{Document: allow}}}, {Documents: []iampolicy.Policy{{Document: other}}}}},
		{name: "SCP empty level denies", root: true, controls: controlSource{{Documents: []iampolicy.Policy{{Document: allow}}}, {}}},
		{name: "SCP union within level", identity: []string{allow}, controls: controlSource{{Documents: []iampolicy.Policy{{Document: other}, {Document: allow}}}}, wantAllow: true},
		{name: "SCP restricts direct resource grant", resource: direct, controls: controlSource{{Documents: []iampolicy.Policy{{Document: other}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := identitySource{set: authorization.PolicySet{Identity: policyDocuments(tc.identity...), Boundary: policyDocuments(tc.boundary...), HasBoundary: tc.hasBoundary}}
			evaluator := authorization.New(source, tc.controls)
			resourceARN := queueARN
			if tc.cross {
				resourceARN = strings.ReplaceAll(queueARN, account, "999999999999")
			}
			err := evaluator.Authorize(awsctx.WithMetadata(context.Background(), metadata(tc.root)), authorization.Request{Action: "sqs:SendMessage", ResourceARN: resourceARN, ResourcePolicies: []authorization.BoundPolicy{{Document: tc.resource}}, RequireResourcePolicy: tc.requireResource})
			if (err == nil) != tc.wantAllow {
				t.Fatalf("Authorize error = %v; want allow %v", err, tc.wantAllow)
			}
			if err != nil && (err.Code != "AccessDenied" || err.StatusCode != 403) {
				t.Fatalf("wrong access denied: %+v", err)
			}
		})
	}
}

func TestNotPrincipalBoundaryRule(t *testing.T) {
	resource := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:*","Resource":"*"},{"Effect":"Deny","NotPrincipal":{"AWS":"` + userARN + `"},"Action":"sqs:*","Resource":"*"}]}`
	for _, hasBoundary := range []bool{false, true} {
		e := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}, HasBoundary: hasBoundary, Boundary: []iampolicy.Policy{{Document: allow}}}}, nil)
		err := e.Authorize(awsctx.WithMetadata(context.Background(), metadata(false)), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, ResourcePolicies: []authorization.BoundPolicy{{Document: resource}}})
		if (err != nil) != hasBoundary {
			t.Fatalf("boundary=%v error=%v", hasBoundary, err)
		}
	}
}

func TestTrustedContextAndFailureClosed(t *testing.T) {
	condition := `{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"app","aws:RequestedRegion":"us-east-1","sqs:ResourceTag/env":"prod"}}}}`
	source := identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: condition}}, PrincipalTags: map[string]string{"team": "app"}}}
	e := authorization.New(source, nil)
	ctx := awsctx.WithMetadata(context.Background(), metadata(false))
	req := authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, Context: map[string][]string{"sqs:ResourceTag/env": {"prod"}}}
	if err := e.Authorize(ctx, req); err != nil {
		t.Fatal(err)
	}
	req.Context["aws:PrincipalArn"] = []string{"arn:aws:iam::123456789012:root"}
	if err := e.Authorize(ctx, req); err == nil {
		t.Fatal("spoofed principal context accepted")
	}
	delete(req.Context, "aws:PrincipalArn")
	req.Context["aws:PrincipalTag/missing"] = []string{"spoofed"}
	if err := e.Authorize(ctx, req); err == nil {
		t.Fatal("spoofed principal tag accepted")
	}
	req.Context = nil
	unsupported := `{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"UnsupportedOperator":{"aws:username":"app"}}}}`
	e = authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}, {Document: unsupported}}}}, nil)
	if err := e.Authorize(ctx, req); err == nil || !strings.Contains(err.Message, "Policy evaluation failed") {
		t.Fatalf("unsupported policy did not fail closed: %v", err)
	}
	e = authorization.New(identitySource{err: errors.New("deleted principal")}, nil)
	req.ResourcePolicies = []authorization.BoundPolicy{{Document: direct}}
	if err := e.Authorize(ctx, req); err == nil {
		t.Fatal("failed identity resolution accepted")
	}
	if err := authorization.New(nil, nil).Authorize(ctx, req); err == nil {
		t.Fatal("nonroot accepted without identity source")
	}
	if err := authorization.New(nil, nil).Authorize(context.Background(), req); err == nil {
		t.Fatal("missing verified metadata accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := e.Authorize(canceled, req); err == nil {
		t.Fatal("canceled authorization accepted")
	}
}

func TestGetCallerIdentityExemptionAndPartitionIsolation(t *testing.T) {
	ctx := awsctx.WithMetadata(context.Background(), metadata(false))
	e := authorization.New(nil, controlSource{{Documents: []iampolicy.Policy{{Document: deny}}}})
	if err := e.Authorize(ctx, authorization.Request{Action: "sts:GetCallerIdentity", ResourceARN: "*"}); err != nil {
		t.Fatal(err)
	}
	ctx = awsctx.WithMetadata(context.Background(), metadata(true))
	if err := authorization.New(nil, nil).Authorize(ctx, authorization.Request{Action: "sqs:SendMessage", ResourceARN: strings.Replace(queueARN, "arn:aws:", "arn:aws-cn:", 1)}); err == nil {
		t.Fatal("cross-partition request accepted")
	}
	m := metadata(false)
	m.PrincipalARN = "arn:aws:sts::123456789012:assumed-role/app/session"
	if err := e.Authorize(awsctx.WithMetadata(context.Background(), m), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN}); err == nil {
		t.Fatal("unimplemented session policy composition accepted")
	}
}

func policyDocuments(documents ...string) []iampolicy.Policy {
	result := make([]iampolicy.Policy, 0, len(documents))
	for _, document := range documents {
		result = append(result, iampolicy.Policy{Document: document})
	}
	return result
}

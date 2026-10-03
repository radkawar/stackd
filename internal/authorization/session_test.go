package authorization_test

import (
	"context"
	"strings"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func roleMetadata() awsctx.Metadata {
	m := metadata(false)
	m.PrincipalARN = "arn:aws:sts::123456789012:assumed-role/worker/session"
	m.PrincipalID = "AROAEXAMPLE:session"
	m.IssuerARN = "arn:aws:iam::123456789012:role/worker"
	m.IssuerID = "AROAEXAMPLE"
	m.UserName = ""
	m.SessionType = "AssumeRole"
	return m
}

func TestRoleSessionPolicyComposition(t *testing.T) {
	roleGrant := strings.ReplaceAll(direct, userARN, roleMetadata().IssuerARN)
	sessionGrant := strings.ReplaceAll(direct, userARN, roleMetadata().PrincipalARN)
	cases := []struct {
		name, resource                string
		identity, boundary, session   []string
		hasBoundary, hasSession, want bool
	}{
		{name: "role identity allow", identity: []string{allow}, want: true},
		{name: "session intersection", identity: []string{allow}, session: []string{other}, hasSession: true},
		{name: "session cannot grant alone", session: []string{allow}, hasSession: true},
		{name: "role grant allows without identity", resource: roleGrant, want: true},
		{name: "role grant constrained by session", resource: roleGrant, session: []string{other}, hasSession: true},
		{name: "role grant constrained by boundary", resource: roleGrant, boundary: []string{other}, hasBoundary: true},
		{name: "direct session bypasses implicit limits", resource: sessionGrant, session: []string{other}, hasSession: true, boundary: []string{other}, hasBoundary: true, want: true},
		{name: "direct session cannot bypass explicit session deny", resource: sessionGrant, session: []string{deny}, hasSession: true},
		{name: "direct session cannot bypass explicit boundary deny", resource: sessionGrant, boundary: []string{deny}, hasBoundary: true},
		{name: "direct session cannot bypass identity explicit deny", resource: sessionGrant, identity: []string{deny}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := roleMetadata()
			m.SessionPolicies = tc.session
			m.HasSessionPolicy = tc.hasSession
			e := authorization.New(identitySource{set: authorization.PolicySet{Identity: policyDocuments(tc.identity...), Boundary: policyDocuments(tc.boundary...), HasBoundary: tc.hasBoundary}}, nil)
			err := e.Authorize(awsctx.WithMetadata(context.Background(), m), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, ResourcePolicies: []authorization.BoundPolicy{{Document: tc.resource}}})
			if (err == nil) != tc.want {
				t.Fatalf("error=%v want allow=%v", err, tc.want)
			}
		})
	}
}

func TestSessionTrustedContext(t *testing.T) {
	m := roleMetadata()
	m.SessionTags = map[string]string{"TEAM": "payments"}
	m.SourceIdentity = "original-user"
	policy := `{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalArn":"` + m.IssuerARN + `","aws:PrincipalTag/team":"payments","aws:SourceIdentity":"original-user","aws:userid":"AROAEXAMPLE:session"},"Bool":{"aws:MultiFactorAuthPresent":"false"},"Null":{"aws:username":"true"}}}}`
	e := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: policy}}, PrincipalTags: map[string]string{"team": "original"}}}, nil)
	if err := e.Authorize(awsctx.WithMetadata(context.Background(), m), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN}); err != nil {
		t.Fatal(err)
	}
}

func TestTrustPoliciesAlwaysRequireTrustGrant(t *testing.T) {
	ctx := awsctx.WithMetadata(context.Background(), metadata(true))
	req := authorization.Request{Action: "sts:AssumeRole", ResourceARN: "arn:aws:iam::123456789012:role/worker", ResourcePolicies: []authorization.BoundPolicy{{TrustPolicy: true}}}
	e := authorization.New(nil, nil)
	if err := e.Authorize(ctx, req); err == nil {
		t.Fatal("root assumed role without trust grant")
	}
	req.ResourcePolicies[0].Document = `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`
	if err := e.Authorize(ctx, req); err != nil {
		t.Fatal(err)
	}
}

func TestKMSGrantsRespectPolicyLimitsAndCrossAccountTrust(t *testing.T) {
	ctx := awsctx.WithMetadata(context.Background(), metadata(false))
	req := authorization.Request{Action: "kms:Encrypt", ResourceARN: "arn:aws:kms:us-east-1:123456789012:key/one", RequireResourcePolicy: true, Grants: iampolicy.GrantPermissions{Direct: true}}
	e := authorization.New(identitySource{}, nil)
	if err := e.Authorize(ctx, req); err != nil {
		t.Fatal(err)
	}
	req.ResourceARN = "arn:aws:kms:us-east-1:999999999999:key/one"
	if err := e.Authorize(ctx, req); err == nil {
		t.Fatal("cross-account grant implicitly trusted")
	}
	req.Grants.TrustedDirect = true
	if err := e.Authorize(ctx, req); err != nil {
		t.Fatal(err)
	}
	req.ResourcePolicies = []authorization.BoundPolicy{{Document: strings.ReplaceAll(resourceDeny, "sqs:SendMessage", "kms:Encrypt")}}
	if err := e.Authorize(ctx, req); err == nil {
		t.Fatal("grant bypassed explicit key deny")
	}
	req.ResourcePolicies = nil
	e = authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: strings.ReplaceAll(deny, "sqs:SendMessage", "kms:Encrypt")}}}}, nil)
	if err := e.Authorize(ctx, req); err == nil {
		t.Fatal("grant bypassed explicit IAM deny")
	}
}

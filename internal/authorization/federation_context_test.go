package authorization

import (
	"testing"
	"time"

	"stackd/internal/awsctx"
)

func TestFederationContextRequiresVerifiedSessionClaims(t *testing.T) {
	m := awsctx.Metadata{AccountID: "123456789012", Partition: "aws", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/role/session", PrincipalID: "AROATEST:session", IssuerARN: "arn:aws:iam::123456789012:role/role", SessionType: "AssumeRole", SessionContext: map[string][]string{"idp.example:sub": {"verified"}}}
	request := Request{Action: "sqs:SendMessage", ResourceARN: "arn:aws:sqs:us-east-1:123456789012:queue"}
	context, _, err := evaluationContext(m, "AssumedRole", nil, request, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC))
	if err != nil || context["idp.example:sub"][0] != "verified" {
		t.Fatalf("verified claim missing: %v %v", context, err)
	}
	context["idp.example:sub"][0] = "changed"
	if m.SessionContext["idp.example:sub"][0] != "verified" {
		t.Fatal("session context is mutable through evaluator")
	}
	for _, supplied := range []map[string][]string{{"idp.example:sub": {"forged"}}, {"idp.example:aud": {"invented"}}, {"saml:sub": {"invented"}}} {
		request.Context = supplied
		if _, _, err := evaluationContext(m, "AssumedRole", nil, request, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)); err == nil {
			t.Fatalf("unverified context accepted: %v", supplied)
		}
	}
	request.Context = map[string][]string{"idp.example:sub": {"verified"}}
	if _, _, err := evaluationContext(m, "AssumedRole", nil, request, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	m.SessionContext = map[string][]string{"aws:PrincipalArn": {"forged"}}
	if _, _, err := evaluationContext(m, "AssumedRole", nil, request, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("federation metadata overrode AWS identity")
	}
}

func TestAbsentSessionAttributesCannotBeInvented(t *testing.T) {
	user := awsctx.Metadata{AccountID: "123456789012", Partition: "aws", PrincipalARN: "arn:aws:iam::123456789012:user/alice", PrincipalID: "AIDATEST", UserName: "alice"}
	request := Request{Action: "sqs:SendMessage", ResourceARN: "arn:aws:sqs:us-east-1:123456789012:queue"}
	for key, value := range map[string]string{
		"aws:SourceIdentity": "forged", "aws:TokenIssueTime": "2026-09-11T00:00:00Z",
		"aws:MultiFactorAuthPresent": "true", "aws:MultiFactorAuthAge": "0",
		"ec2:SourceInstanceARN":    "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
		"aws:Ec2InstanceSourceVpc": "vpc-0123456789abcdef0", "aws:Ec2InstanceSourcePrivateIPv4": "10.0.1.10",
	} {
		t.Run(key, func(t *testing.T) {
			request.Context = map[string][]string{key: {value}}
			if _, _, err := evaluationContext(user, "User", nil, request, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)); err == nil {
				t.Fatal("service invented an absent session attribute")
			}
		})
	}
	request.Context = nil
	values, _, err := evaluationContext(user, "User", nil, request, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"aws:sourceidentity", "aws:tokenissuetime", "aws:multifactorauthpresent", "aws:multifactorauthage"} {
		if _, exists := values[key]; exists {
			t.Fatalf("absent attribute synthesized: %s", key)
		}
	}
	user.SessionType, user.SourceIdentity = "AssumeRole", "verified"
	user.TokenIssueTime = time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	request.Context = map[string][]string{"aws:SourceIdentity": {"verified"}, "aws:TokenIssueTime": {"2026-09-11T00:00:00Z"}, "aws:MultiFactorAuthPresent": {"false"}}
	if _, _, err := evaluationContext(user, "AssumedRole", nil, request, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("matching verified attributes rejected: %v", err)
	}
	request.Context["aws:MultiFactorAuthAge"] = []string{"0"}
	if _, _, err := evaluationContext(user, "AssumedRole", nil, request, time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("non-MFA session acquired an authentication age")
	}
}

func TestVerifiedSessionAttributesAtZeroTime(t *testing.T) {
	m := awsctx.Metadata{AccountID: "123456789012", Partition: "aws", PrincipalARN: "arn:aws:iam::123456789012:user/alice", PrincipalID: "AIDATEST", UserName: "alice", SessionType: "GetSessionToken", MFAPresent: true}
	request := Request{Action: "sqs:SendMessage", ResourceARN: "arn:aws:sqs:us-east-1:123456789012:queue"}
	values, _, err := evaluationContext(m, "User", nil, request, time.Time{}.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"aws:tokenissuetime": "0001-01-01T00:00:00Z", "aws:multifactorauthpresent": "true", "aws:multifactorauthage": "60"} {
		if got := values[key]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want %s", key, got, want)
		}
	}
}

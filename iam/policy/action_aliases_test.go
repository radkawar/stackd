package policy_test

import (
	"fmt"
	"testing"

	"stackd/iam/policy"
)

func TestActionAliasesPreservePolicyIntersections(t *testing.T) {
	const modern = "es:DescribeDomain"
	const legacy = "es:DescribeElasticsearchDomain"
	statement := func(effect, action string) policy.Policy {
		return policy.Policy{Document: fmt.Sprintf(`{"Statement":{"Effect":%q,"Action":%q,"Resource":"*"}}`, effect, action)}
	}
	resource := func(effect, action string) policy.Policy {
		return policy.Policy{Document: fmt.Sprintf(`{"Statement":{"Effect":%q,"Principal":"*","Action":%q,"Resource":"*"}}`, effect, action)}
	}
	request := policy.Request{Action: modern, ActionAliases: []string{legacy}, Resource: "arn:aws:es:us-east-1:123456789012:domain/example"}
	base := func() policy.Authorization {
		return policy.Authorization{Principal: policy.Principal{ARN: "arn:aws:iam::123456789012:user/app", AccountID: "123456789012", Partition: "aws"}, Identity: []policy.Policy{statement("Allow", legacy)}}
	}
	tests := []struct {
		name   string
		modify func(*policy.Authorization)
		want   policy.Decision
	}{
		{"legacy grant", func(*policy.Authorization) {}, policy.Allow},
		{"modern grant", func(s *policy.Authorization) { s.Identity = []policy.Policy{statement("Allow", modern)} }, policy.Allow},
		{"legacy deny beats modern", func(s *policy.Authorization) {
			s.Identity = []policy.Policy{statement("Allow", modern), statement("Deny", legacy)}
		}, policy.ExplicitDeny},
		{"modern deny beats legacy", func(s *policy.Authorization) { s.Identity = append(s.Identity, statement("Deny", modern)) }, policy.ExplicitDeny},
		{"mixed boundary and session", func(s *policy.Authorization) {
			s.Principal.HasBoundary = true
			s.Boundary = []policy.Policy{statement("Allow", modern)}
			s.HasSessionPolicy = true
			s.Session = []policy.Policy{statement("Allow", legacy)}
		}, policy.Allow},
		{"session remains an intersection", func(s *policy.Authorization) {
			s.HasSessionPolicy = true
			s.Session = []policy.Policy{statement("Allow", "es:ListDomainNames")}
		}, policy.ImplicitDeny},
		{"boundary alias deny", func(s *policy.Authorization) {
			s.Principal.HasBoundary = true
			s.Boundary = []policy.Policy{statement("Allow", modern), statement("Deny", legacy)}
		}, policy.ExplicitDeny},
		{"session alias deny", func(s *policy.Authorization) {
			s.HasSessionPolicy = true
			s.Session = []policy.Policy{statement("Allow", modern), statement("Deny", legacy)}
		}, policy.ExplicitDeny},
		{"resource alias grant", func(s *policy.Authorization) {
			s.Identity = nil
			s.Resource = []policy.Policy{resource("Allow", legacy)}
		}, policy.Allow},
		{"resource alias deny", func(s *policy.Authorization) { s.Resource = []policy.Policy{resource("Deny", legacy)} }, policy.ExplicitDeny},
		{"SCP legacy grant is insufficient", func(s *policy.Authorization) {
			s.ServiceControls = []policy.PolicyLevel{{Documents: []policy.Policy{statement("Allow", legacy)}}}
		}, policy.ImplicitDeny},
		{"SCP modern grant and legacy deny", func(s *policy.Authorization) {
			s.ServiceControls = []policy.PolicyLevel{{Documents: []policy.Policy{statement("Allow", modern), statement("Deny", legacy)}}}
		}, policy.Allow},
		{"SCP modern deny", func(s *policy.Authorization) {
			s.ServiceControls = []policy.PolicyLevel{{Documents: []policy.Policy{statement("Allow", "*"), statement("Deny", modern)}}}
		}, policy.ExplicitDeny},
		{"RCP legacy grant is insufficient", func(s *policy.Authorization) {
			s.ResourceControls = []policy.PolicyLevel{{Documents: []policy.Policy{resource("Allow", legacy)}}}
		}, policy.ImplicitDeny},
		{"RCP modern grant and legacy deny", func(s *policy.Authorization) {
			s.ResourceControls = []policy.PolicyLevel{{Documents: []policy.Policy{resource("Allow", modern), resource("Deny", legacy)}}}
		}, policy.Allow},
		{"NotAction excludes equivalent legacy name", func(s *policy.Authorization) {
			s.Identity = []policy.Policy{{Document: `{"Statement":{"Effect":"Allow","NotAction":"es:DescribeElasticsearchDomain","Resource":"*"}}`}}
		}, policy.ImplicitDeny},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := base()
			test.modify(&s)
			got, err := policy.Authorize(request, s)
			if err != nil || got.Decision != test.want {
				t.Fatalf("decision=%s error=%v want=%s (%s)", got.Decision, err, test.want, got.Reason)
			}
		})
	}
	withoutAliases := request
	withoutAliases.ActionAliases = nil
	got, err := policy.Authorize(withoutAliases, base())
	if err != nil || got.Decision != policy.ImplicitDeny {
		t.Fatalf("unrelated caller acquired alias: %+v %v", got, err)
	}
}

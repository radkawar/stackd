package authorization_test

import (
	"context"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func TestServiceLinkedRoleExemptsOnlyOrganizationControls(t *testing.T) {
	m := metadata(false)
	m.PrincipalARN = "arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForExample/session"
	m.PrincipalID = "AROASERVICELINKED:session"
	m.IssuerARN = "arn:aws:iam::123456789012:role/aws-service-role/example.amazonaws.com/AWSServiceRoleForExample"
	m.IssuerID = "AROASERVICELINKED"
	for _, tc := range []struct {
		name      string
		set       authorization.PolicySet
		resource  string
		session   bool
		wantAllow bool
	}{
		{name: "trusted role exempts SCP", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}, ServiceLinkedRole: true}, wantAllow: true},
		{name: "path does not exempt ordinary role", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}}},
		{name: "exemption grants no identity permission", set: authorization.PolicySet{ServiceLinkedRole: true}},
		{name: "identity explicit deny retained", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}, {Document: deny}}, ServiceLinkedRole: true}},
		{name: "resource explicit deny retained", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}, ServiceLinkedRole: true}, resource: resourceDeny},
		{name: "session restriction retained", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}, ServiceLinkedRole: true}, session: true},
		{name: "boundary restriction retained", set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: allow}}, ServiceLinkedRole: true, HasBoundary: true, Boundary: []iampolicy.Policy{{Document: other}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requestMetadata := m
			requestMetadata.HasSessionPolicy = tc.session
			requestMetadata.SessionPolicies = []string{other}
			e := authorization.New(identitySource{set: tc.set}, controlSource{{Documents: []iampolicy.Policy{{Document: deny}}}})
			err := e.Authorize(awsctx.WithMetadata(context.Background(), requestMetadata), authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueARN, ResourcePolicies: []authorization.BoundPolicy{{Document: tc.resource}}})
			if (err == nil) != tc.wantAllow {
				t.Fatalf("Authorize = %v; want allowed %v", err, tc.wantAllow)
			}
		})
	}
}

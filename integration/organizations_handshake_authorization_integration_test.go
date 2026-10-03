package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestOrganizationsHandshakeReceivedListOwnershipReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../testdata/aws/iam/organizations_handshakes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Observations []struct{ Case, Code string } }
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{}
	for _, row := range fixture.Observations {
		expected[row.Case] = row.Code
	}
	f := newOrganizationReportFixture(t, nil)
	member := f.account(t, f.rootID, "recipient")
	for _, test := range []struct{ name, operator, value string }{{"management-owner", "StringEquals", "000000000000"}, {"member-owner", "StringEquals", member}, {"owner-absent", "Null", "true"}} {
		t.Run(test.name, func(t *testing.T) {
			policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"organizations:ListHandshakesForAccount","Resource":"*","Condition":{%q:{"aws:ResourceAccount":%q}}}}`, test.operator, test.value)
			session, err := f.cloud.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole"), RoleSessionName: aws.String("handshake-reader"), Policy: &policy})
			if err != nil {
				t.Fatal(err)
			}
			_, err = delegationSessionClient(f.cloud, session.Credentials).ListHandshakesForAccount(t.Context(), &organizations.ListHandshakesForAccountInput{})
			code, ok := expected[test.name]
			if !ok {
				t.Fatal("missing AWS evidence")
			}
			if code == "Success" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				assertAPIError(t, err, code)
			}
		})
	}
	// An existing member may inspect its own incoming handshake, but cannot
	// cancel it or borrow another recipient's access through a matching IAM ARN.
	invited, err := f.org.InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeEmail, Id: aws.String("recipient@example.test")}})
	if err != nil {
		t.Fatal(err)
	}
	_, key, secret := f.cloud.user(t, "test", "inviter")
	putUserPolicy(t, f.iam, "inviter", allow(`"organizations:InviteAccountToOrganization"`, "*"))
	_, err = f.cloud.organizations(key, secret).InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: aws.String("333333333333")}, Tags: []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("blue")}}})
	assertAPIError(t, err, "AccessDeniedException")
	_, otherKey, otherSecret := f.cloud.user(t, "444444444444", "outsider")
	putUserPolicy(t, f.cloud.iam("444444444444", "test", ""), "outsider", allow(`"organizations:*"`, "*"))
	outsider := f.cloud.organizations(otherKey, otherSecret)
	_, err = outsider.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: invited.Handshake.Id})
	assertAPIError(t, err, "AccessDeniedException")
	_, err = outsider.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: invited.Handshake.Id})
	assertAPIError(t, err, "AccessDeniedException")
	memberIAM := f.cloud.iam(member, "test", "")
	_, memberKey, memberSecret := f.cloud.user(t, member, "receiver")
	putUserPolicy(t, memberIAM, "receiver", allow(`"organizations:DescribeHandshake"`, *invited.Handshake.Arn))
	receiver := f.cloud.organizations(memberKey, memberSecret)
	if _, err := receiver.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: invited.Handshake.Id}); err != nil {
		t.Fatal(err)
	}
	denyID := f.policy(t, "deny-received-read", `{"Statement":{"Effect":"Deny","Action":"organizations:DescribeHandshake","Resource":"*"}}`, member)
	_, err = receiver.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: invited.Handshake.Id})
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := f.org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{TargetId: &member, PolicyId: &denyID}); err != nil {
		t.Fatal(err)
	}
	if _, err := memberIAM.DeleteUserPolicy(t.Context(), &iam.DeleteUserPolicyInput{UserName: aws.String("receiver"), PolicyName: aws.String("access")}); err != nil {
		t.Fatal(err)
	}
	_, err = receiver.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: invited.Handshake.Id})
	assertAPIError(t, err, "AccessDeniedException")
}

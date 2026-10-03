package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd/clock"
)

func TestOrganizationsDelegationAuthorityReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../testdata/aws/iam/organizations_delegation_authority.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Observations []struct{ Case, Code string } }
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{}
	for _, row := range fixture.Observations {
		expected[row.Case] = row.Code
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			check := func(name string, err error) {
				t.Helper()
				code, ok := expected[name]
				if !ok {
					t.Fatal("missing AWS capture", name)
				}
				if code == "Success" {
					if err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					return
				}
				assertAPIError(t, err, code)
			}
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			start := retainedDelegationCloud(t, backend, source)
			c, close := start()
			f := organizationFixture(t, c, source)
			org := f.org
			member := f.account(t, f.rootID, "authority")
			targetID := f.policy(t, "OWNED_NAME", allow(`"*"`, "*"), "")
			target, err := org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			if err != nil {
				t.Fatal(err)
			}
			roleARN := "arn:aws:iam::" + member + ":role/OWNED_NAME"
			permissions := allow(`["organizations:DescribePolicy","organizations:ListAccounts","organizations:DescribeResourcePolicy","organizations:DescribeOrganization","organizations:UpdatePolicy","organizations:DeleteResourcePolicy"]`, "*")
			for _, owner := range []string{"000000000000", member} {
				root := c.iam(owner, "test", "")
				if _, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("OWNED_NAME"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)}); err != nil {
					t.Fatal(err)
				}
				putRolePolicy(t, root, "OWNED_NAME", permissions)
			}
			assume := func(owner string, policy *string) *ststypes.Credentials {
				t.Helper()
				out, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: aws.String("arn:aws:iam::" + owner + ":role/OWNED_NAME"), RoleSessionName: aws.String("authority"), Policy: policy, DurationSeconds: aws.Int32(900)})
				if err != nil {
					t.Fatal(err)
				}
				return out.Credentials
			}
			actorCredentials := assume(member, nil)
			actor := delegationSessionClient(c, actorCredentials)
			describePolicy := func(name string, client *organizations.Client, id string) {
				t.Helper()
				out, err := client.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &id})
				check(name, err)
				if err == nil && (out.Policy == nil || out.Policy.PolicySummary == nil || aws.ToString(out.Policy.PolicySummary.Id) != id || aws.ToString(out.Policy.Content) == "") {
					t.Fatalf("%s: missing policy state: %+v", name, out)
				}
			}
			describeOrg := func(name string, client *organizations.Client) {
				t.Helper()
				out, err := client.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
				check(name, err)
				if err == nil && (out.Organization == nil || aws.ToString(out.Organization.MasterAccountId) != "000000000000") {
					t.Fatalf("%s: missing organization: %+v", name, out)
				}
			}
			list := func(name string, client *organizations.Client) {
				t.Helper()
				out, err := client.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
				check(name, err)
				if err == nil && len(out.Accounts) != 2 {
					t.Fatalf("%s: missing members: %+v", name, out)
				}
			}
			describeResource := func(name string) {
				t.Helper()
				out, err := actor.DescribeResourcePolicy(t.Context(), &organizations.DescribeResourcePolicyInput{})
				check(name, err)
				if err == nil && (out.ResourcePolicy == nil || out.ResourcePolicy.Content == nil || out.ResourcePolicy.ResourcePolicySummary == nil) {
					t.Fatalf("%s: missing delegation: %+v", name, out)
				}
			}
			ownerConditions := func(caller, owner, action string, awsPolicy bool) {
				t.Helper()
				cases := []struct{ label, operator, value string }{{"management-owner", "StringEquals", "000000000000"}, {"member-owner", "StringEquals", member}}
				if awsPolicy {
					cases = append(cases, struct{ label, operator, value string }{"aws-owner", "StringEquals", "aws"})
				}
				cases = append(cases, struct{ label, operator, value string }{"owner-absent", "Null", "true"})
				for _, condition := range cases {
					policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":%q,"Resource":"*","Condition":{%q:{"aws:ResourceAccount":%q}}}}`, "organizations:"+action, condition.operator, condition.value)
					client := delegationSessionClient(c, assume(owner, &policy))
					name := caller + "-"
					switch action {
					case "DescribeOrganization":
						describeOrg(name+"describe-org-"+condition.label, client)
					case "ListAccounts":
						list(name+"list-"+condition.label, client)
					case "DescribePolicy":
						describePolicy(name+"aws-policy-"+condition.label, client, "p-FullAWSAccess")
					}
				}
			}
			describePolicy("member-without-delegation", actor, targetID)
			describeOrg("ordinary-member-describe-organization", actor)
			ownerConditions("member", member, "DescribeOrganization", false)
			ownerConditions("management", "000000000000", "DescribeOrganization", false)
			service := "account.amazonaws.com"
			if _, err := org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: &service}); err != nil {
				t.Fatal(err)
			}
			if _, err := org.RegisterDelegatedAdministrator(t.Context(), &organizations.RegisterDelegatedAdministratorInput{AccountId: &member, ServicePrincipal: &service}); err != nil {
				t.Fatal(err)
			}
			describePolicy("trusted-without-resource-policy", actor, targetID)
			list("trusted-list-without-resource-policy", actor)
			describeResource("trusted-describe-absent-resource-policy")
			ownerConditions("trusted-member", member, "ListAccounts", false)
			ownerConditions("management", "000000000000", "ListAccounts", false)
			describePolicy("trusted-aws-managed-policy", actor, "p-FullAWSAccess")
			ownerConditions("trusted-member", member, "DescribePolicy", true)
			ownerConditions("management", "000000000000", "DescribePolicy", true)
			statement := map[string]any{"Effect": "Deny", "Principal": map[string]string{"AWS": member}, "Action": []string{"organizations:DescribePolicy", "organizations:ListAccounts", "organizations:DescribeResourcePolicy", "organizations:DescribeOrganization"}, "Resource": "*", "Condition": map[string]any{"ArnEquals": map[string]string{"aws:PrincipalArn": roleARN}}}
			put := func(statements ...map[string]any) {
				t.Helper()
				raw, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := org.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: aws.String(string(raw))}); err != nil {
					t.Fatal(err)
				}
			}
			put(statement)
			describePolicy("trusted-resource-policy-denies-read", actor, targetID)
			describePolicy("trusted-resource-policy-denies-aws-policy", actor, "p-FullAWSAccess")
			list("trusted-resource-policy-denies-list", actor)
			describeResource("trusted-resource-policy-denies-own-description")
			describeOrg("trusted-resource-policy-denies-organization-description", actor)
			_, err = actor.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &targetID, Name: aws.String("ungranted")})
			check("trusted-without-write-delegation", err)
			write := map[string]any{"Effect": "Allow", "Principal": map[string]string{"AWS": member}, "Action": "organizations:UpdatePolicy", "Resource": *target.Policy.PolicySummary.Arn, "Condition": map[string]any{"ArnEquals": map[string]string{"aws:PrincipalArn": roleARN}}}
			put(statement, write)
			_, err = actor.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &targetID, Name: aws.String("delegated")})
			check("trusted-with-write-delegation", err)
			// Recovered account grants must retain the current policy's explicit deny.
			close()
			c, close = start()
			org, actor = c.organizations("test", "test"), delegationSessionClient(c, actorCredentials)
			describePolicy("trusted-resource-policy-denies-read", actor, targetID)
			describeOrg("trusted-resource-policy-denies-organization-description", actor)
			if _, err := org.DeregisterDelegatedAdministrator(t.Context(), &organizations.DeregisterDelegatedAdministratorInput{AccountId: &member, ServicePrincipal: &service}); err != nil {
				t.Fatal(err)
			}
			describePolicy("deregistered-resource-policy-denies-read", actor, targetID)
			describeOrg("ordinary-member-resource-policy-denies-description", actor)
			_, err = actor.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: &targetID, Name: aws.String("policy-only")})
			check("deregistered-resource-policy-allows-write", err)
			for i := 1; i <= 3; i++ {
				statement["Effect"] = "Allow"
				put(statement)
				describePolicy(fmt.Sprintf("grant-%d", i), actor, targetID)
				statement["Effect"] = "Deny"
				put(statement)
				describePolicy(fmt.Sprintf("revoke-%d", i), actor, targetID)
			}
			statement["Effect"] = "Allow"
			put(statement)
			describeResource("resource-delegate-describes-policy")
			describePolicy("resource-delegate-describes-aws-policy", actor, "p-FullAWSAccess")
			for _, condition := range []struct{ label, operator, value string }{{"management-owner", "StringEquals", "000000000000"}, {"member-owner", "StringEquals", member}, {"owner-absent", "Null", "true"}} {
				put(statement)
				policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"organizations:DeleteResourcePolicy","Resource":"*","Condition":{%q:{"aws:ResourceAccount":%q}}}}`, condition.operator, condition.value)
				client := delegationSessionClient(c, assume("000000000000", &policy))
				_, err := client.DeleteResourcePolicy(t.Context(), &organizations.DeleteResourcePolicyInput{})
				check("management-delete-resource-policy-"+condition.label, err)
			}
			put(statement)
			if _, err := org.DeleteResourcePolicy(t.Context(), &organizations.DeleteResourcePolicyInput{}); err != nil {
				t.Fatal(err)
			}
			describePolicy("resource-policy-deleted", actor, targetID)
			// Membership's description grant survives removal of both delegation paths.
			describeOrg("ordinary-member-describe-organization", actor)
			close()
			c, _ = start()
			org, actor = c.organizations("test", "test"), delegationSessionClient(c, actorCredentials)
			describePolicy("resource-policy-deleted", actor, targetID)
			describeOrg("ordinary-member-describe-organization", actor)
		})
	}
}

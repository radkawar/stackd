package stackd_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func TestOrganizationsDelegationIAMReplayAndRecovery(t *testing.T) {
	raw, err := os.ReadFile("../testdata/aws/iam/organizations_resource_policy.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct{ Enforcement []struct{ Case, Code string } }
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{}
	for _, row := range capture.Enforcement {
		expected[row.Case] = row.Code
	}
	check := func(t *testing.T, name string, err error) {
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
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			start := retainedDelegationCloud(t, backend, source)
			c, close := start()
			f := organizationFixture(t, c, source)
			member := f.account(t, f.rootID, "delegated")
			targetID := f.policy(t, "OWNED_NAME", allow(`"*"`, "*"), "")
			target, err := f.org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			if err != nil {
				t.Fatal(err)
			}
			targetARN := aws.ToString(target.Policy.PolicySummary.Arn)
			memberIAM := c.iam(member, "test", "")
			role, err := memberIAM.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("OWNED_NAME"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			assume := func(sessionPolicy *string) *ststypes.Credentials {
				t.Helper()
				out, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("delegated"), Policy: sessionPolicy, DurationSeconds: aws.Int32(900)})
				if err != nil {
					t.Fatal(err)
				}
				return out.Credentials
			}
			actorCredentials := assume(nil)
			actor := delegationSessionClient(c, actorCredentials)
			org := f.org
			put := func(content string) *orgtypes.ResourcePolicy {
				t.Helper()
				out, err := org.PutResourcePolicy(t.Context(), &organizations.PutResourcePolicyInput{Content: &content})
				if err != nil {
					t.Fatal(err)
				}
				return out.ResourcePolicy
			}
			doc := func(action, resource string, principal any, extra map[string]any) string {
				t.Helper()
				conditions := map[string]any{"ArnEquals": map[string]string{"aws:PrincipalArn": *role.Role.Arn}}
				for key, value := range extra {
					conditions[key] = value
				}
				data, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": principal, "Action": action, "Resource": resource, "Condition": conditions}}})
				if err != nil {
					t.Fatal(err)
				}
				return string(data)
			}
			principal := map[string]string{"AWS": member}
			base := doc("organizations:DescribePolicy", targetARN, principal, nil)
			put(base)
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "resource-grant-without-identity", err)
			putRolePolicy(t, memberIAM, "OWNED_NAME", allow(`"organizations:DescribePolicy"`, targetARN))
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "resource-and-identity-grant", err)
			put(doc("organizations:DescribePolicy", targetARN, principal, map[string]any{"ArnEquals": map[string]string{"aws:PrincipalArn": *role.Role.Arn + "-unmatched"}}))
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "resource-grant-revoked", err)
			put(base)
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "resource-grant-restored", err)
			listing := doc("organizations:ListAccounts", "*", "*", nil)
			put(listing)
			_, err = actor.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
			check(t, "wildcard-resource-without-identity", err)
			full := allow(`["organizations:DescribePolicy","organizations:ListAccounts"]`, "*")
			putRolePolicy(t, memberIAM, "OWNED_NAME", full)
			listed, err := actor.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
			check(t, "wildcard-resource-with-identity", err)
			if len(listed.Accounts) != 2 {
				t.Fatalf("delegated listing omitted members: %+v", listed.Accounts)
			}
			limited := delegationSessionClient(c, assume(aws.String(allow(`"organizations:DescribePolicy"`, targetARN))))
			_, err = limited.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
			check(t, "wildcard-resource-with-restrictive-session", err)
			put(doc("organizations:ListAccounts", "*", "*", map[string]any{"StringEquals": map[string]string{"aws:ResourceAccount": "000000000000"}}))
			_, err = actor.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
			check(t, "resource-account-condition", err)
			put(doc("organizations:ListAccounts", "*", "*", map[string]any{"Null": map[string]string{"aws:ResourceAccount": "true"}}))
			_, err = actor.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
			check(t, "missing-resource-account-condition", err)
			put(fmt.Sprintf(`{"Statement":{"Effect":"Deny","Principal":"*","Action":"organizations:DescribePolicy","Resource":%q,"Condition":{"StringEquals":{"aws:PrincipalAccount":"000000000000"}}}}`, targetARN))
			_, err = org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "management-resource-policy-deny", err)
			put(base)
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "restore-before-deletion", err)

			// Controls on the member continue to restrict delegation. Management
			// authorization does not inherit the delegation policy's restrictions.
			boundary, err := memberIAM.CreatePolicy(t.Context(), &iam.CreatePolicyInput{PolicyName: aws.String("ReadOnlyLists"), PolicyDocument: aws.String(allow(`"organizations:ListAccounts"`, "*"))})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := memberIAM.PutRolePermissionsBoundary(t.Context(), &iam.PutRolePermissionsBoundaryInput{RoleName: role.Role.RoleName, PermissionsBoundary: boundary.Policy.Arn}); err != nil {
				t.Fatal(err)
			}
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := memberIAM.DeleteRolePermissionsBoundary(t.Context(), &iam.DeleteRolePermissionsBoundaryInput{RoleName: role.Role.RoleName}); err != nil {
				t.Fatal(err)
			}
			denyID := f.policy(t, "BlockDelegation", `{"Statement":{"Effect":"Deny","Action":"organizations:DescribePolicy","Resource":"*"}}`, member)
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: &denyID, TargetId: &member}); err != nil {
				t.Fatal(err)
			}
			put(doc("organizations:DescribePolicy", targetARN, "*", nil))
			_, outsiderKey, outsiderSecret := c.user(t, "999999999999", "outsider")
			putUserPolicy(t, c.iam("999999999999", "test", ""), "outsider", allow(`"organizations:*"`, "*"))
			_, err = c.organizations(outsiderKey, outsiderSecret).DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			assertAPIError(t, err, "AWSOrganizationsNotInUseException")
			saved := put(base)
			rpID := saved.ResourcePolicySummary.Id
			if _, err := org.TagResource(t.Context(), &organizations.TagResourceInput{ResourceId: rpID, Tags: []orgtypes.Tag{{Key: aws.String("owner"), Value: aws.String("platform")}}}); err != nil {
				t.Fatal(err)
			}
			close()
			c, close = start()
			org, actor = c.organizations("test", "test"), delegationSessionClient(c, actorCredentials)
			restored, err := org.DescribeResourcePolicy(t.Context(), &organizations.DescribeResourcePolicyInput{})
			if err != nil || aws.ToString(restored.ResourcePolicy.Content) != aws.ToString(saved.Content) || aws.ToString(restored.ResourcePolicy.ResourcePolicySummary.Id) != *rpID {
				t.Fatalf("delegation lost on recovery: %+v, %v", restored, err)
			}
			tags, err := org.ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: rpID})
			if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Value) != "platform" {
				t.Fatalf("tags lost on recovery: %+v, %v", tags, err)
			}
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "resource-and-identity-grant", err)
			if _, err := org.DeleteResourcePolicy(t.Context(), &organizations.DeleteResourcePolicyInput{}); err != nil {
				t.Fatal(err)
			}
			_, err = actor.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "resource-policy-deleted", err)
			close()
			c, _ = start()
			_, err = c.organizations("test", "test").DescribeResourcePolicy(t.Context(), &organizations.DescribeResourcePolicyInput{})
			assertAPIError(t, err, "ResourcePolicyNotFoundException")
			_, err = delegationSessionClient(c, actorCredentials).DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: &targetID})
			check(t, "resource-policy-deleted", err)
		})
	}
}

func delegationSessionClient(c cloudClients, session *ststypes.Credentials) *organizations.Client {
	return organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(*session.AccessKeyId, *session.SecretAccessKey, *session.SessionToken), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

// Each open reconstructs the services; SQLite also reopens the native database.
func retainedDelegationCloud(t *testing.T, backend string, source *clock.Manual) func() (cloudClients, func()) {
	t.Helper()
	backends := storage.NewMemory()
	path := filepath.Join(t.TempDir(), "delegation.sqlite")
	return func() (cloudClients, func()) {
		if backend == "sqlite" {
			return openSQLiteCloud(t, path, backends, source)
		}
		cloud, err := stackd.New(stackd.Config{Storage: backends, Clock: source})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(cloud)
		close := func() {
			server.Close()
			if err := cloud.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Cleanup(close)
		return cloudClients{server}, close
	}
}

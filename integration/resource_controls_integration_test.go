package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func (c cloudClients) kms(key, secret, token string) *kms.Client {
	return c.kmsRegion("us-east-1", key, secret, token)
}

func (c cloudClients) kmsRegion(region, key, secret, token string) *kms.Client {
	return kms.New(kms.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func (f organizationReportFixture) enableRCP(t *testing.T) {
	t.Helper()
	if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeResourceControlPolicy}); err != nil {
		t.Fatal(err)
	}
}

func (f organizationReportFixture) rcp(t *testing.T, name, document, target string) string {
	t.Helper()
	out, err := f.org.CreatePolicy(t.Context(), &organizations.CreatePolicyInput{Name: &name, Description: aws.String("Resource control integration"), Type: orgtypes.PolicyTypeResourceControlPolicy, Content: &document})
	if err != nil {
		t.Fatal(err)
	}
	id := *out.Policy.PolicySummary.Id
	if target != "" {
		if _, err := f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: &id, TargetId: &target}); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func TestResourceControlPolicyAWSSyntax(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	fixture := templateFixture(t, "resource_controls.json")
	for label, row := range fixture {
		if !strings.HasPrefix(label, "syntax_") {
			continue
		}
		t.Run(label, func(t *testing.T) {
			var in organizations.CreatePolicyInput
			if err := json.Unmarshal(row["input"], &in); err != nil {
				t.Fatal(err)
			}
			out, err := f.org.CreatePolicy(t.Context(), &in)
			if row["error"] != nil {
				var expected struct{ Code string }
				if err := json.Unmarshal(row["error"], &expected); err != nil {
					t.Fatal(err)
				}
				assertAPIError(t, err, expected.Code)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Storage does not require enablement; attachment does.
			_, err = f.org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: out.Policy.PolicySummary.Id, TargetId: &f.rootID})
			assertAPIError(t, err, "PolicyTypeNotEnabledException")
			_, err = f.org.UpdatePolicy(t.Context(), &organizations.UpdatePolicyInput{PolicyId: out.Policy.PolicySummary.Id, Content: aws.String(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sqs:*","Resource":"*"}}`)})
			assertAPIError(t, err, "MalformedPolicyDocumentException")
			retained, err := f.org.DescribePolicy(t.Context(), &organizations.DescribePolicyInput{PolicyId: out.Policy.PolicySummary.Id})
			if err != nil || *retained.Policy.Content != *in.Content {
				t.Fatalf("failed update changed policy: %+v, %v", retained, err)
			}
		})
	}
}

func TestResourceControlsAWSServiceEnforcement(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	fixture := templateFixture(t, "resource_controls.json")
	check := func(label string, err error) {
		t.Helper()
		if raw := fixture[label]["error"]; raw != nil {
			var expected struct{ Code string }
			if err := json.Unmarshal(raw, &expected); err != nil {
				t.Fatal(err)
			}
			assertAPIError(t, err, expected.Code)
		} else if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	}
	member := f.account(t, f.rootID, "rcp-member")
	identity, err := f.cloud.sts("test", "test", "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatal(err)
	}
	management := *identity.Account
	memberIAM := f.cloud.iam(member, "test", "")
	role, err := memberIAM.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("rcp-owner"), AssumeRolePolicyDocument: aws.String(fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}}`, management))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := memberIAM.AttachRolePolicy(t.Context(), &iam.AttachRolePolicyInput{RoleName: role.Role.RoleName, PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")}); err != nil {
		t.Fatal(err)
	}
	assume := &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("rcp"), DurationSeconds: aws.Int32(900)}
	session, err := f.cloud.sts("test", "test", "").AssumeRole(t.Context(), assume)
	if err != nil {
		t.Fatal(err)
	}
	c := session.Credentials
	owner := f.cloud.sqs(*c.AccessKeyId, *c.SecretAccessKey, *c.SessionToken)
	ownerKMS := f.cloud.kms(*c.AccessKeyId, *c.SecretAccessKey, *c.SessionToken)
	manager := f.cloud.sqs("test", "test", "")
	createQueue := func(client *sqs.Client, account, peer string) *string {
		arn := "arn:aws:sqs:us-east-1:" + account + ":rcp-work"
		policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sqs:SendMessage","Resource":%q}}`, peer, arn)
		out, err := client.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("rcp-work"), Attributes: map[string]string{"Policy": policy}})
		if err != nil {
			t.Fatal(err)
		}
		return out.QueueUrl
	}
	memberQueue := createQueue(owner, member, management)
	managementQueue := createQueue(manager, management, member)
	key, err := ownerKMS.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ownerKMS.CreateGrant(t.Context(), &kms.CreateGrantInput{KeyId: key.KeyMetadata.KeyId, GranteePrincipal: role.Role.Arn, RetiringPrincipal: role.Role.Arn, Operations: []kmstypes.GrantOperation{kmstypes.GrantOperationEncrypt}})
	if err != nil {
		t.Fatal(err)
	}
	send := func(client *sqs.Client, url *string) error {
		_, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: url, MessageBody: aws.String("RCP message")})
		return err
	}
	check("baseline_member_send", send(owner, memberQueue))
	check("baseline_management_send", send(manager, memberQueue))
	check("baseline_member_to_management", send(owner, managementQueue))
	_, err = ownerKMS.Encrypt(t.Context(), &kms.EncryptInput{KeyId: key.KeyMetadata.KeyId, Plaintext: []byte("RCP")})
	check("baseline_encrypt", err)
	f.enableRCP(t)
	document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["sqs:SendMessage","kms:Encrypt","kms:RetireGrant","sts:AssumeRole"],"Resource":["arn:aws:sqs:us-east-1:*:rcp-work",%q,%q]},{"Effect":"Deny","Principal":"*","Action":"sqs:ListQueues","Resource":"*","Condition":{"ArnEquals":{"aws:PrincipalArn":%q}}}]}`, *key.KeyMetadata.Arn, *role.Role.Arn, *role.Role.Arn)
	id := f.rcp(t, "resource-deny", document, member)
	check("restricted_member_send", send(owner, memberQueue))
	check("restricted_management_send", send(manager, memberQueue))
	check("restricted_member_to_management", send(owner, managementQueue))
	t.Run("current-primary-2026-09-27-supersedes-native-2026-09-12-listqueues", func(t *testing.T) {
		// The historical restricted_list capture is retained verbatim. AWS's
		// current RCP contract selects SAR resource types; ListQueues has none.
		queues, err := owner.ListQueues(t.Context(), &sqs.ListQueuesInput{})
		if err != nil || !slices.Contains(queues.QueueUrls, *memberQueue) {
			t.Fatalf("unscoped discovery must retain the member queue despite the RCP: %+v, %v", queues, err)
		}
	})
	_, err = ownerKMS.Encrypt(t.Context(), &kms.EncryptInput{KeyId: key.KeyMetadata.KeyId, Plaintext: []byte("RCP")})
	check("restricted_encrypt", err)
	_, err = f.cloud.sts("test", "test", "").AssumeRole(t.Context(), assume)
	check("restricted_assume", err)
	_, err = ownerKMS.RetireGrant(t.Context(), &kms.RetireGrantInput{KeyId: key.KeyMetadata.KeyId, GrantId: grant.GrantId})
	check("retire_grant_key_id", err)
	var invalidARN *kmstypes.NotFoundException
	if !errors.As(err, &invalidARN) || aws.ToString(invalidARN.Message) != "Invalid arn "+*key.KeyMetadata.KeyId {
		t.Fatalf("RetireGrant key-ID diagnostic: %v", err)
	}
	_, err = ownerKMS.RetireGrant(t.Context(), &kms.RetireGrantInput{KeyId: key.KeyMetadata.Arn, GrantId: grant.GrantId})
	check("retire_grant_exemption", err)
	grants, err := ownerKMS.ListGrants(t.Context(), &kms.ListGrantsInput{KeyId: key.KeyMetadata.KeyId})
	if err != nil || len(grants.Grants) != 0 {
		t.Fatalf("grant was not retired: %+v, %v", grants, err)
	}
	if _, err := f.org.DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: &id, TargetId: &member}); err != nil {
		t.Fatal(err)
	}
	check("restored_member_send", send(owner, memberQueue))
}

func TestResourceControlsFollowOwnerHierarchyAndCurrentMembership(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	unit := f.unit(t, f.rootID, "restricted")
	member := f.account(t, unit, "rcp-member")
	owner := f.cloud.sqs(member, "test", "")
	arn := "arn:aws:sqs:us-east-1:" + member + ":shared"
	orgID, _, _ := strings.Cut(f.rootPath, "/")
	resourcePolicy := func(path string) string {
		return fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceOrgID":%q},"ForAnyValue:StringEquals":{"aws:ResourceOrgPaths":%q}}}}`, arn, orgID, path)
	}
	queue, err := owner.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("shared"), Attributes: map[string]string{"Policy": resourcePolicy(f.rootPath + "/" + unit + "/")}})
	if err != nil {
		t.Fatal(err)
	}
	send := func(client *sqs.Client) error {
		_, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("RCP")})
		return err
	}
	outsider := f.cloud.sqs("333333333333", "test", "")
	if err := send(outsider); err != nil {
		t.Fatal(err)
	}
	f.enableRCP(t)
	doc := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sqs:SendMessage","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalOrgID":%q},"Bool":{"aws:PrincipalIsAWSService":"false"}}}}`, orgID)
	f.rcp(t, "external-access", doc, unit)
	assertAPIError(t, send(outsider), "AccessDenied")
	if err := send(f.cloud.sqs("test", "test", "")); err != nil {
		t.Fatal("same organization denied", err)
	}
	if _, err := f.org.MoveAccount(t.Context(), &organizations.MoveAccountInput{AccountId: &member, SourceParentId: &unit, DestinationParentId: &f.rootID}); err != nil {
		t.Fatal(err)
	}
	assertAPIError(t, send(outsider), "AccessDenied")
	if _, err := owner.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": resourcePolicy(f.rootPath + "/")}}); err != nil {
		t.Fatal(err)
	}
	if err := send(outsider); err != nil {
		t.Fatal("old OU policy still applied", err)
	}
	// The root level remains applicable after the move, including to member root.
	f.rcp(t, "root-deny", `{"Statement":{"Effect":"Deny","Principal":"*","Action":"sqs:SendMessage","Resource":"*"}}`, f.rootID)
	assertAPIError(t, send(owner), "AccessDenied")
	if _, err := f.org.DisablePolicyType(t.Context(), &organizations.DisablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeResourceControlPolicy}); err != nil {
		t.Fatal(err)
	}
	if err := send(outsider); err != nil {
		t.Fatal("disabled RCP still applied", err)
	}
}

func TestResourceControlsPreserveAWSManagedKMSServiceKeys(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	member := f.account(t, f.rootID, "kms-rcp-member")
	owner := f.cloud.sqs(member, "test", "")
	key, err := f.cloud.kms(member, "test", "").CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	f.enableRCP(t)
	f.rcp(t, "deny-customer-kms", `{"Statement":{"Effect":"Deny","Principal":"*","Action":"kms:*","Resource":"*"}}`, member)
	for _, tc := range []struct{ name, key, code string }{{"managed", "alias/aws/sqs", ""}, {"customer", *key.KeyMetadata.Arn, "KMS.AccessDeniedException"}} {
		queue, err := owner.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: &tc.name, Attributes: map[string]string{"KmsMasterKeyId": tc.key}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = owner.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("encrypted")})
		if tc.code != "" {
			assertAPIError(t, err, tc.code)
		} else if err != nil {
			t.Fatal("AWS managed key restricted by RCP", err)
		}
	}
}

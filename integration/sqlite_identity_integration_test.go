package stackd_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd/clock"
	"stackd/storage"
)

func TestSQLiteIAMRestoresPolicyGraphAndSessionRestrictions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.sqlite")
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	backends := &storage.Backends{}
	c, close := openSQLiteCloud(t, path, backends, source)
	root := c.iam("test", "test", "")
	arn, key, secret := c.user(t, "test", "PersistedUser")
	group, err := root.CreateGroup(t.Context(), &iam.CreateGroupInput{GroupName: aws.String("Operators")})
	if err != nil {
		t.Fatal(err)
	}
	permissions, err := root.CreatePolicy(t.Context(), &iam.CreatePolicyInput{PolicyName: aws.String("UserPermissions"), PolicyDocument: aws.String(allow(`["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity","iam:ChangePassword"]`, "*"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.AttachGroupPolicy(t.Context(), &iam.AttachGroupPolicyInput{GroupName: group.Group.GroupName, PolicyArn: permissions.Policy.Arn}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.AddUserToGroup(t.Context(), &iam.AddUserToGroupInput{GroupName: group.Group.GroupName, UserName: aws.String("PersistedUser")}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.PutUserPermissionsBoundary(t.Context(), &iam.PutUserPermissionsBoundaryInput{UserName: aws.String("PersistedUser"), PermissionsBoundary: permissions.Policy.Arn}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.UpdateAccountPasswordPolicy(t.Context(), &iam.UpdateAccountPasswordPolicyInput{PasswordReusePrevention: aws.Int32(2)}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.CreateLoginProfile(t.Context(), &iam.CreateLoginProfileInput{UserName: aws.String("PersistedUser"), Password: aws.String("First!Passphrase1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.iam(key, secret, "").ChangePassword(t.Context(), &iam.ChangePasswordInput{OldPassword: aws.String("First!Passphrase1"), NewPassword: aws.String("Second!Passphrase2")}); err != nil {
		t.Fatal(err)
	}
	trust := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]}}`, arn)
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("PersistedRole"), AssumeRolePolicyDocument: aws.String(trust)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "PersistedRole", `{"Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"storage","aws:SourceIdentity":"restart"}}}}`)
	sessionPolicy, err := root.CreatePolicy(t.Context(), &iam.CreatePolicyInput{PolicyName: aws.String("SessionPermissions"), PolicyDocument: aws.String(allow(`"sqs:GetQueueUrl"`, "*"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("retained-authority")}); err != nil {
		t.Fatal(err)
	}
	assume := &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("retained"), DurationSeconds: aws.Int32(900), PolicyArns: []ststypes.PolicyDescriptorType{{Arn: sessionPolicy.Policy.Arn}}, Tags: []ststypes.Tag{{Key: aws.String("team"), Value: aws.String("storage")}}, TransitiveTagKeys: []string{"team"}, SourceIdentity: aws.String("restart")}
	issued, err := c.sts(key, secret, "").AssumeRole(t.Context(), assume)
	if err != nil {
		t.Fatal(err)
	}
	close()
	c, close = openSQLiteCloud(t, path, backends, source)
	root = c.iam("test", "test", "")
	user, err := root.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("persisteduser")})
	if err != nil || aws.ToString(user.User.Arn) != arn || user.User.PermissionsBoundary == nil || aws.ToString(user.User.PermissionsBoundary.PermissionsBoundaryArn) != aws.ToString(permissions.Policy.Arn) {
		t.Fatal("user or boundary lost", err)
	}
	if _, err := c.sts(key, secret, "").AssumeRole(t.Context(), assume); err != nil {
		t.Fatal("group permissions or trust bindings lost", err)
	}
	session := c.sessionSQS(issued.Credentials)
	url, err := session.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("retained-authority")})
	if err != nil {
		t.Fatal("session tags, source identity or policies lost", err)
	}
	_, err = session.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: url.QueueUrl, MessageBody: aws.String("forbidden")})
	assertAPIError(t, err, "AccessDenied")
	_, err = c.iam(key, secret, "").ChangePassword(t.Context(), &iam.ChangePasswordInput{OldPassword: aws.String("Second!Passphrase2"), NewPassword: aws.String("First!Passphrase1")})
	assertAPIError(t, err, "PasswordPolicyViolation")
	// Current versions continue to govern already issued sessions after recovery.
	version, err := root.CreatePolicyVersion(t.Context(), &iam.CreatePolicyVersionInput{PolicyArn: sessionPolicy.Policy.Arn, PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Action":"sqs:*","Resource":"*"}}`), SetAsDefault: true})
	if err != nil {
		t.Fatal(err)
	}
	close()
	c, _ = openSQLiteCloud(t, path, backends, source)
	_, err = c.sessionSQS(issued.Credentials).GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("retained-authority")})
	assertAPIError(t, err, "AccessDenied")
	previous, err := c.iam("test", "test", "").GetPolicyVersion(t.Context(), &iam.GetPolicyVersionInput{PolicyArn: sessionPolicy.Policy.Arn, VersionId: aws.String("v1")})
	if err != nil || previous.PolicyVersion.IsDefaultVersion || aws.ToString(version.PolicyVersion.VersionId) != "v2" {
		t.Fatal("policy history lost", err)
	}
	advanceClock(t, source, 15*time.Minute)
	_, err = c.sessionSTS(issued.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "ExpiredToken")
}

func TestSQLiteOrganizationsRecoversProvisioningContactsAndSCPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "organization.sqlite")
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	backends := &storage.Backends{}
	c, close := openSQLiteCloud(t, path, backends, source)
	org := c.organizations("test", "test")
	if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.account("test", "test", "").PutContactInformation(t.Context(), &account.PutContactInformationInput{ContactInformation: primaryContact()}); err != nil {
		t.Fatal(err)
	}
	created, err := org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("durable-member"), Email: aws.String("durable@example.test"), RoleName: aws.String("DurableAccess"), Tags: []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("storage")}}})
	if err != nil || created.CreateAccountStatus.State != orgtypes.CreateAccountStateInProgress {
		t.Fatal("creation was not admitted", err)
	}
	close()
	advanceClock(t, source, 3*time.Second)
	c, close = openSQLiteCloud(t, path, backends, source)
	org = c.organizations("test", "test")
	status := waitAccountCreation(t, org, created.CreateAccountStatus, nil)
	if status.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("recovered creation failed: %s", status.State)
	}
	member := aws.ToString(status.AccountId)
	contact, err := c.account(member, "test", "").GetContactInformation(t.Context(), &account.GetContactInformationInput{})
	expectedContact := primaryContact()
	expectedContact.FullName = aws.String("durable-member")
	if err != nil || !reflect.DeepEqual(contact.ContactInformation, expectedContact) {
		t.Fatal("copied contact lost", err)
	}
	role, err := c.iam(member, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("DurableAccess")})
	if err != nil || !role.Role.CreateDate.Equal(*status.CompletedTimestamp) {
		t.Fatal("access role and membership did not commit together", err)
	}
	roots, err := org.ListRoots(t.Context(), &organizations.ListRootsInput{})
	if err != nil {
		t.Fatal(err)
	}
	unit, err := org.CreateOrganizationalUnit(t.Context(), &organizations.CreateOrganizationalUnitInput{ParentId: roots.Roots[0].Id, Name: aws.String("restricted")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := org.MoveAccount(t.Context(), &organizations.MoveAccountInput{AccountId: status.AccountId, SourceParentId: roots.Roots[0].Id, DestinationParentId: unit.OrganizationalUnit.Id}); err != nil {
		t.Fatal(err)
	}
	policy, err := org.CreatePolicy(t.Context(), &organizations.CreatePolicyInput{Name: aws.String("BlockSend"), Description: aws.String("block queue publication"), Type: orgtypes.PolicyTypeServiceControlPolicy, Content: aws.String(`{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := org.AttachPolicy(t.Context(), &organizations.AttachPolicyInput{PolicyId: policy.Policy.PolicySummary.Id, TargetId: unit.OrganizationalUnit.Id}); err != nil {
		t.Fatal(err)
	}
	session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("member")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.account(member, "test", "").EnableRegion(t.Context(), &account.EnableRegionInput{RegionName: aws.String("ap-east-1")}); err != nil {
		t.Fatal(err)
	}
	close()
	advanceClock(t, source, 2*time.Minute)
	c, _ = openSQLiteCloud(t, path, backends, source)
	regional, err := c.account(member, "test", "").GetRegionOptStatus(t.Context(), &account.GetRegionOptStatusInput{RegionName: aws.String("ap-east-1")})
	if err != nil || regional.RegionOptStatus != accounttypes.RegionOptStatusEnabled {
		t.Fatal("region transition lost", err)
	}
	queues := c.sessionSQS(session.Credentials)
	queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("durable-member")})
	if err != nil {
		t.Fatal("recovered access role unusable", err)
	}
	_, err = queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("blocked")})
	assertAPIError(t, err, "AccessDenied")
	if _, err := c.organizations("test", "test").DetachPolicy(t.Context(), &organizations.DetachPolicyInput{PolicyId: policy.Policy.PolicySummary.Id, TargetId: unit.OrganizationalUnit.Id}); err != nil {
		t.Fatal(err)
	}
	if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("permitted")}); err != nil {
		t.Fatal(err)
	}
	tags, err := c.organizations("test", "test").ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: status.AccountId})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Value) != "storage" {
		t.Fatal("creation tags lost", err)
	}
}

package stackd_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd/storage"
	iamstore "stackd/storage/iam"
)

func TestCentralizedRootAccessThroughSignedSDKRequests(t *testing.T) {
	backends := storage.NewMemory()
	f := newOrganizationReportFixture(t, backends)
	ctx := t.Context()
	_, err := f.iam.ListOrganizationsFeatures(ctx, &iam.ListOrganizationsFeaturesInput{})
	assertAPIError(t, err, "ServiceAccessNotEnabledException")
	member := f.account(t, f.rootID, "root-task-member")
	// Root MFA can be present in an imported account backend. Audit/deletion
	// must operate on that association, not a same-named IAM user's device.
	serial := "arn:aws:iam::" + member + ":mfa/root-device"
	if err := backends.IAM.Update(ctx, func(tx iamstore.WriteTx) error {
		return tx.PutMFADevice(iamstore.Scope{Partition: "aws", AccountID: member}, iamstore.MFADevice{SerialNumber: serial, Binding: iamstore.Propagated[iamstore.MFABinding]{Value: iamstore.MFABinding{UserID: member}}, EnableDate: f.clock.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	memberIAM := f.cloud.iam(member, "test", "")
	rootKey, err := memberIAM.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = memberIAM.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("untouched")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.org.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := f.iam.EnableOrganizationsRootSessions(ctx, &iam.EnableOrganizationsRootSessionsInput{})
	if err != nil || !slices.Equal(enabled.EnabledFeatures, []iamtypes.FeatureType{iamtypes.FeatureTypeRootSessions}) {
		t.Fatalf("enable sessions: %+v %v", enabled, err)
	}
	_, err = f.iam.EnableOrganizationsRootCredentialsManagement(ctx, &iam.EnableOrganizationsRootCredentialsManagementInput{})
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := f.iam.DisableOrganizationsRootCredentialsManagement(ctx, &iam.DisableOrganizationsRootCredentialsManagementInput{})
	if err != nil || !slices.Equal(disabled.EnabledFeatures, []iamtypes.FeatureType{iamtypes.FeatureTypeRootSessions}) {
		t.Fatalf("independent feature disable: %+v %v", disabled, err)
	}
	// Enabling/disabling centralized credentials management never deletes an
	// existing member key. IAM user administration is separate from root tasks.
	keys, err := memberIAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	if err != nil || len(keys.AccessKeyMetadata) != 1 {
		t.Fatalf("existing root key: %+v %v", keys, err)
	}
	if _, err := f.iam.EnableOrganizationsRootCredentialsManagement(ctx, &iam.EnableOrganizationsRootCredentialsManagementInput{}); err != nil {
		t.Fatal(err)
	}
	_, key, secret := f.cloud.user(t, "test", "root-operator")
	targetARN := "arn:aws:iam::" + member + ":root"
	putUserPolicy(t, f.iam, "root-operator", fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRoot","Resource":%q,"Condition":{"ArnLike":{"sts:TaskPolicyArn":"arn:aws:iam::aws:policy/root-task/*"}}},{"Effect":"Allow","Action":"iam:ListOrganizationsFeatures","Resource":"*"},{"Effect":"Deny","Action":"organizations:*","Resource":"*"}]}`, targetARN))
	caller := f.cloud.sts(key, secret, "")
	features, err := f.cloud.iam(key, secret, "").ListOrganizationsFeatures(ctx, &iam.ListOrganizationsFeaturesInput{})
	if err != nil || len(features.EnabledFeatures) != 2 {
		t.Fatalf("IAM-only feature read: %+v %v", features, err)
	}
	input := &sts.AssumeRootInput{TargetPrincipal: &member, TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String("arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials")}}
	_, err = f.cloud.sts("test", "test", "").AssumeRoot(ctx, input)
	assertAPIError(t, err, "AccessDenied")
	assume := func(task string) (*iam.Client, *ststypes.Credentials) {
		t.Helper()
		in := *input
		in.TaskPolicyArn = &ststypes.PolicyDescriptorType{Arn: aws.String("arn:aws:iam::aws:policy/root-task/" + task)}
		out, err := caller.AssumeRoot(ctx, &in)
		if err != nil {
			t.Fatal(err)
		}
		if out.Credentials == nil || !out.Credentials.Expiration.Equal(f.clock.Now().Add(15*time.Minute)) {
			t.Fatalf("root expiration: %+v", out.Credentials)
		}
		c := out.Credentials
		return f.cloud.iam(aws.ToString(c.AccessKeyId), aws.ToString(c.SecretAccessKey), aws.ToString(c.SessionToken)), c
	}
	audit, auditCredentials := assume("IAMAuditRootUserCredentials")
	user, err := audit.GetUser(ctx, &iam.GetUserInput{})
	if err != nil || aws.ToString(user.User.Arn) != targetARN || aws.ToString(user.User.UserId) != member {
		t.Fatalf("root identity: %+v %v", user, err)
	}
	if user.User.UserName != nil || user.User.Path != nil {
		t.Fatalf("root received IAM-user-only fields: %+v", user.User)
	}
	keys, err = audit.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	if err != nil || len(keys.AccessKeyMetadata) != 1 || aws.ToString(keys.AccessKeyMetadata[0].AccessKeyId) != aws.ToString(rootKey.AccessKey.AccessKeyId) {
		t.Fatalf("audit root keys: %+v %v", keys, err)
	}
	certs, err := audit.ListSigningCertificates(ctx, &iam.ListSigningCertificatesInput{})
	if err != nil || len(certs.Certificates) != 0 {
		t.Fatalf("root signing certificates: %+v %v", certs, err)
	}
	devices, err := audit.ListMFADevices(ctx, &iam.ListMFADevicesInput{})
	if err != nil || len(devices.MFADevices) != 1 || aws.ToString(devices.MFADevices[0].SerialNumber) != serial {
		t.Fatalf("root MFA: %+v %v", devices, err)
	}
	_, err = audit.GetLoginProfile(ctx, &iam.GetLoginProfileInput{})
	assertAPIError(t, err, "NoSuchEntity")
	_, err = audit.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: rootKey.AccessKey.AccessKeyId})
	if err != nil {
		t.Fatal(err)
	}
	_, err = audit.GetUser(ctx, &iam.GetUserInput{UserName: aws.String("untouched")})
	assertAPIError(t, err, "AccessDenied")
	_, err = audit.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	assertAPIError(t, err, "AccessDenied")
	creator, _ := assume("IAMCreateRootUserPassword")
	_, err = creator.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{Password: aws.String("MayNotSpecifyPassword1!")})
	assertAPIError(t, err, "ValidationError")
	profile, err := creator.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{})
	if err != nil || !profile.LoginProfile.CreateDate.Equal(f.clock.Now()) {
		t.Fatalf("root recovery profile: %+v %v", profile, err)
	}
	if profile.LoginProfile.UserName != nil || profile.LoginProfile.PasswordResetRequired {
		t.Fatalf("root recovery profile contains user password fields: %+v", profile.LoginProfile)
	}
	_, err = creator.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{})
	assertAPIError(t, err, "EntityAlreadyExists")
	if _, err = audit.GetLoginProfile(ctx, &iam.GetLoginProfileInput{}); err != nil {
		t.Fatal(err)
	}
	summary, err := audit.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil || summary.SummaryMap["AccountPasswordPresent"] != 1 || summary.SummaryMap["AccountAccessKeysPresent"] != 1 || summary.SummaryMap["AccountMFAEnabled"] != 1 {
		t.Fatalf("root summary: %+v %v", summary, err)
	}
	deleter, _ := assume("IAMDeleteRootUserCredentials")
	_, err = memberIAM.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{SerialNumber: &serial})
	assertAPIError(t, err, "InvalidUserType")
	if _, err = deleter.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{SerialNumber: &serial}); err != nil {
		t.Fatal(err)
	}
	if _, err = deleter.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err = deleter.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{AccessKeyId: rootKey.AccessKey.AccessKeyId}); err != nil {
		t.Fatal(err)
	}
	_, err = audit.GetLoginProfile(ctx, &iam.GetLoginProfileInput{})
	assertAPIError(t, err, "NoSuchEntity")
	summary, err = audit.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil || summary.SummaryMap["AccountPasswordPresent"] != 0 || summary.SummaryMap["AccountAccessKeysPresent"] != 0 || summary.SummaryMap["Users"] != 1 || summary.SummaryMap["AccountMFAEnabled"] != 0 {
		t.Fatalf("root cleanup summary: %+v %v", summary, err)
	}
	// A member SCP can distinguish privileged sessions from ordinary root keys.
	policy := f.policy(t, "RootAuditDenied", `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"iam:GetUser","Resource":"*","Condition":{"Bool":{"aws:AssumedRoot":"true"}}}}`, member)
	_, err = audit.GetUser(ctx, &iam.GetUserInput{})
	assertAPIError(t, err, "AccessDenied")
	if _, err = memberIAM.GetUser(ctx, &iam.GetUserInput{}); err != nil {
		t.Fatalf("ordinary root inherited AssumedRoot condition: %v", err)
	}
	if _, err = f.org.DetachPolicy(ctx, &organizations.DetachPolicyInput{PolicyId: &policy, TargetId: &member}); err != nil {
		t.Fatal(err)
	}
	// The SQS task can recover a policy which denies every principal. Other
	// queue operations remain denied by its actual AWS task document.
	memberSQS := f.cloud.sqs(member, "test", "")
	queue, err := memberSQS.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("locked-root-task"), Attributes: map[string]string{"Policy": `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"sqs:*","Resource":"*"}}`}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = memberSQS.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNamePolicy}})
	assertAPIError(t, err, "AccessDenied")
	_, unlockCredentials := assume("SQSUnlockQueuePolicy")
	unlock := f.cloud.sessionSQS(unlockCredentials)
	attrs, err := unlock.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: queue.QueueUrl, AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNamePolicy}})
	if err != nil || attrs.Attributes["Policy"] == "" {
		t.Fatalf("read denied queue policy for recovery: %+v %v", attrs, err)
	}
	_, err = unlock.SetQueueAttributes(ctx, &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": ""}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = unlock.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("still task scoped")})
	assertAPIError(t, err, "AccessDenied")
	_, err = memberSQS.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("recovered")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.iam.DisableOrganizationsRootSessions(ctx, &iam.DisableOrganizationsRootSessionsInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.iam.DisableOrganizationsRootCredentialsManagement(ctx, &iam.DisableOrganizationsRootCredentialsManagementInput{}); err != nil {
		t.Fatal(err)
	}
	_, err = caller.AssumeRoot(ctx, input)
	assertAPIError(t, err, "AccessDenied")
	advanceClock(t, f.clock, 15*time.Minute)
	_, err = f.cloud.sessionSTS(auditCredentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "ExpiredToken")
}

func TestAssumedRoleCannotDefaultCredentialOwnerToRoot(t *testing.T) {
	c := newCloudClients(t)
	ctx := t.Context()
	root := c.iam("test", "test", "")
	role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("key-manager"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "key-manager", allow(`["iam:CreateAccessKey","iam:ListAccessKeys","iam:ListMFADevices"]`, "*"))
	session, err := c.sts("test", "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("key-manager")})
	if err != nil {
		t.Fatal(err)
	}
	v := session.Credentials
	manager := c.iam(aws.ToString(v.AccessKeyId), aws.ToString(v.SecretAccessKey), aws.ToString(v.SessionToken))
	_, err = manager.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	assertAPIError(t, err, "ValidationError")
	_, err = manager.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	assertAPIError(t, err, "ValidationError")
	_, err = manager.ListMFADevices(ctx, &iam.ListMFADevicesInput{})
	assertAPIError(t, err, "ValidationError")
	keys, err := root.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	if err != nil || len(keys.AccessKeyMetadata) != 0 {
		t.Fatalf("role created a root access key: %+v %v", keys, err)
	}
	user, err := root.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("managed-user")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: user.User.UserName}); err != nil {
		t.Fatalf("named user administration rejected: %v", err)
	}
}

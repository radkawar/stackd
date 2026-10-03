package stackd_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestRootCredentialsManagementTasksThroughSignedSDK(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	ctx := t.Context()
	member := f.account(t, f.rootID, "credentials-only-member")
	memberIAM := f.cloud.iam(member, "test", "")
	key, err := memberIAM.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.org.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	enabled, err := f.iam.EnableOrganizationsRootCredentialsManagement(ctx, &iam.EnableOrganizationsRootCredentialsManagementInput{})
	if err != nil || !slices.Equal(enabled.EnabledFeatures, []iamtypes.FeatureType{iamtypes.FeatureTypeRootCredentialsManagement}) {
		t.Fatalf("credentials-management-only features: %+v %v", enabled, err)
	}
	_, accessKey, secret := f.cloud.user(t, "test", "credentials-only-operator")
	putUserPolicy(t, f.iam, "credentials-only-operator", fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRoot","Resource":"arn:aws:iam::%s:root"}}`, member))
	caller := f.cloud.sts(accessKey, secret, "")
	assume := func(task string) (*sts.AssumeRootOutput, error) {
		return caller.AssumeRoot(ctx, &sts.AssumeRootInput{TargetPrincipal: aws.String(member), TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String("arn:aws:iam::aws:policy/root-task/" + task)}})
	}
	audit, err := assume("IAMAuditRootUserCredentials")
	if err != nil {
		t.Fatal("credentials management must permit audit:", err)
	}
	c := audit.Credentials
	auditor := f.cloud.iam(aws.ToString(c.AccessKeyId), aws.ToString(c.SecretAccessKey), aws.ToString(c.SessionToken))
	keys, err := auditor.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	if err != nil || len(keys.AccessKeyMetadata) != 1 || aws.ToString(keys.AccessKeyMetadata[0].AccessKeyId) != aws.ToString(key.AccessKey.AccessKeyId) {
		t.Fatalf("audit root credentials: %+v %v", keys, err)
	}
	deletion, err := assume("IAMDeleteRootUserCredentials")
	if err != nil {
		t.Fatal("credentials management must permit deletion:", err)
	}
	c = deletion.Credentials
	deleter := f.cloud.iam(aws.ToString(c.AccessKeyId), aws.ToString(c.SecretAccessKey), aws.ToString(c.SessionToken))
	if _, err = deleter.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{AccessKeyId: key.AccessKey.AccessKeyId}); err != nil {
		t.Fatal(err)
	}
	keys, err = auditor.ListAccessKeys(ctx, &iam.ListAccessKeysInput{})
	if err != nil || len(keys.AccessKeyMetadata) != 0 {
		t.Fatalf("root credential deletion had no effect: %+v %v", keys, err)
	}
	recovery, err := assume("IAMCreateRootUserPassword")
	if err != nil {
		t.Fatal("credentials management must permit password recovery:", err)
	}
	c = recovery.Credentials
	creator := f.cloud.iam(aws.ToString(c.AccessKeyId), aws.ToString(c.SecretAccessKey), aws.ToString(c.SessionToken))
	if _, err := creator.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := deleter.DeleteLoginProfile(ctx, &iam.DeleteLoginProfileInput{}); err != nil {
		t.Fatal(err)
	}
	for _, task := range []string{"S3UnlockBucketPolicy", "SQSUnlockQueuePolicy"} {
		out, err := assume(task)
		assertAPIError(t, err, "AccessDenied")
		if out != nil && out.Credentials != nil {
			t.Fatal("task requiring RootSessions returned credentials")
		}
	}
	disabled, err := f.iam.DisableOrganizationsRootCredentialsManagement(ctx, &iam.DisableOrganizationsRootCredentialsManagementInput{})
	if err != nil || len(disabled.EnabledFeatures) != 0 {
		t.Fatalf("disable both root features: %+v %v", disabled, err)
	}
	for _, task := range []string{"IAMAuditRootUserCredentials", "IAMDeleteRootUserCredentials", "IAMCreateRootUserPassword", "S3UnlockBucketPolicy", "SQSUnlockQueuePolicy"} {
		_, err := assume(task)
		assertAPIError(t, err, "AccessDenied")
	}
}

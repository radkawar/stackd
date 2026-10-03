package iam_test

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func accountSummary(t *testing.T, client *sdkiam.Client) map[string]int32 {
	t.Helper()
	out, err := client.GetAccountSummary(t.Context(), &sdkiam.GetAccountSummaryInput{})
	if err != nil {
		t.Fatal(err)
	}
	return out.SummaryMap
}

func requireSummaryValues(t *testing.T, summary, want map[string]int32) {
	t.Helper()
	for key, value := range want {
		if actual, present := summary[key]; !present || actual != value {
			t.Errorf("%s=%d (present=%t); want %d", key, actual, present, value)
		}
	}
}

func TestIAMAccountSummaryStateScopeAndDefaults(t *testing.T) {
	epoch := time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC)
	repository := iam.NewMemoryRepository(nil)
	source := clock.NewManual(epoch)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
	client := clientFor(t, service, "123456789012", "us-east-1")
	initial := accountSummary(t, client)
	requireSummaryValues(t, initial, map[string]int32{
		"Users": 0, "Groups": 0, "Roles": 0, "InstanceProfiles": 0, "ServerCertificates": 0, "Policies": 0, "PolicyVersionsInUse": 0, "Providers": 0, "MFADevices": 0, "MFADevicesInUse": 0,
		"AccountAccessKeysPresent": 0, "AccountSigningCertificatesPresent": 0, "AccountMFAEnabled": 0, "AccountPasswordPresent": 0, "GlobalEndpointTokenVersion": 1,
		"UsersQuota": 5000, "GroupsQuota": 300, "RolesQuota": 1000, "InstanceProfilesQuota": 1000, "ServerCertificatesQuota": 20, "PoliciesQuota": 1500,
		"PolicyVersionsInUseQuota": 10000, "VersionsPerPolicyQuota": 5, "PolicySizeQuota": 6144, "AssumeRolePolicySizeQuota": 2048,
		"UserPolicySizeQuota": 2048, "GroupPolicySizeQuota": 5120, "RolePolicySizeQuota": 10240,
		"AttachedPoliciesPerRoleQuota": 20, "AttachedPoliciesPerUserQuota": 10, "AttachedPoliciesPerGroupQuota": 10, "GroupsPerUserQuota": 10, "AccessKeysPerUserQuota": 2, "SigningCertificatesPerUserQuota": 2,
	})
	user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("summary-user")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("summary-group")}); err != nil {
		t.Fatal(err)
	}
	trust := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("summary-role"), AssumeRolePolicyDocument: aws.String(trust)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateInstanceProfile(t.Context(), &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("summary-profile")}); err != nil {
		t.Fatal(err)
	}
	policyARN := mustCreatePolicy(t, client, "summary-policy")
	if err := source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	version, err := client.CreatePolicyVersion(t.Context(), &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(policyARN), PolicyDocument: aws.String(allowRead)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachUserPolicy(t.Context(), &sdkiam.AttachUserPolicyInput{UserName: user.User.UserName, PolicyArn: aws.String(awsAdministrator)}); err != nil {
		t.Fatal(err)
	}
	policy, err := client.GetPolicy(t.Context(), &sdkiam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		t.Fatal(err)
	}
	if !aws.ToTime(policy.Policy.UpdateDate).Equal(source.Now()) || !aws.ToTime(policy.Policy.CreateDate).Equal(epoch) || aws.ToString(policy.Policy.DefaultVersionId) != "v1" {
		t.Fatal("nondefault version did not update policy metadata independently of its default")
	}
	if _, err := client.CreateLoginProfile(t.Context(), &sdkiam.CreateLoginProfileInput{UserName: user.User.UserName, Password: aws.String(loginPasswordA)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: user.User.UserName}); err != nil {
		t.Fatal(err)
	}
	userCertificate, _ := certificateTestMaterial(t, certificateTestECKey(t), nil, nil, false, epoch.Add(-time.Hour), epoch.Add(time.Hour))
	if _, err := client.UploadSigningCertificate(t.Context(), &sdkiam.UploadSigningCertificateInput{UserName: user.User.UserName, CertificateBody: aws.String(userCertificate)}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unassigned", "assigned"} {
		device, err := client.CreateVirtualMFADevice(t.Context(), &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String(name)})
		if err != nil {
			t.Fatal(err)
		}
		if name == "assigned" {
			seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(device.VirtualMFADevice.Base32StringSeed))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.EnableMFADevice(t.Context(), &sdkiam.EnableMFADeviceInput{UserName: user.User.UserName, SerialNumber: device.VirtualMFADevice.SerialNumber, AuthenticationCode1: aws.String(testMFAOTP(seed, source.Now().Unix()/30)), AuthenticationCode2: aws.String(testMFAOTP(seed, source.Now().Unix()/30+1))}); err != nil {
				t.Fatal(err)
			}
		}
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.PutSAMLProvider(scope, iam.SAMLProviderRecord{ARN: "arn:aws:iam::123456789012:saml-provider/summary", UUID: "SAML", MetadataDocument: "<metadata/>"}); err != nil {
			return err
		}
		if err := tx.PutOIDCProvider(scope, iam.OIDCProviderRecord{ARN: "arn:aws:iam::123456789012:oidc-provider/summary.test", ID: "OIDC", URL: "summary.test"}); err != nil {
			return err
		}
		return tx.PutServerCertificate(scope, iam.ServerCertificateRecord{Name: "summary", ID: "ASCA", ARN: "arn:aws:iam::123456789012:server-certificate/summary"})
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]int32{"Users": 1, "Groups": 1, "Roles": 1, "InstanceProfiles": 1, "ServerCertificates": 1, "Policies": 1, "PolicyVersionsInUse": 1, "Providers": 2, "MFADevices": 2, "MFADevicesInUse": 1, "AccountMFAEnabled": 0, "AccountPasswordPresent": 0, "AccountAccessKeysPresent": 0, "AccountSigningCertificatesPresent": 0}
	requireSummaryValues(t, accountSummary(t, client), want)
	requireSummaryValues(t, accountSummary(t, clientFor(t, service, scope.AccountID, "eu-west-1")), want)
	for _, isolated := range []*sdkiam.Client{clientFor(t, service, "999999999999", "us-east-1"), clientForPartition(t, service, scope.AccountID, "cn-north-1", "aws-cn")} {
		requireSummaryValues(t, accountSummary(t, isolated), map[string]int32{"Users": 0, "Groups": 0, "Roles": 0, "Policies": 0, "Providers": 0, "MFADevices": 0, "PolicyVersionsInUse": 0})
	}
	if _, err := client.DeletePolicyVersion(t.Context(), &sdkiam.DeletePolicyVersionInput{PolicyArn: aws.String(policyARN), VersionId: version.PolicyVersion.VersionId}); err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"PolicyVersionsInUse": 1})
	if _, err := client.DeletePolicy(t.Context(), &sdkiam.DeletePolicyInput{PolicyArn: aws.String(policyARN)}); err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"Policies": 0, "PolicyVersionsInUse": 1})
}

func TestIAMAccountSummaryRootCredentialPresence(t *testing.T) {
	now := time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC)
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(now)})
	client := clientFor(t, service, "123456789012", "us-east-1")
	key, err := client.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"AccountAccessKeysPresent": 1})
	if _, err := client.UpdateAccessKey(t.Context(), &sdkiam.UpdateAccessKeyInput{AccessKeyId: key.AccessKey.AccessKeyId, Status: types.StatusTypeInactive}); err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"AccountAccessKeysPresent": 1})
	if _, err := client.DeleteAccessKey(t.Context(), &sdkiam.DeleteAccessKeyInput{AccessKeyId: key.AccessKey.AccessKeyId}); err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"AccountAccessKeysPresent": 0})
	body, _ := certificateTestMaterial(t, certificateTestECKey(t), nil, nil, false, now.Add(-time.Hour), now.Add(time.Hour))
	certificate, err := client.UploadSigningCertificate(t.Context(), &sdkiam.UploadSigningCertificateInput{CertificateBody: aws.String(body)})
	if err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"AccountSigningCertificatesPresent": 1})
	if _, err := client.UpdateSigningCertificate(t.Context(), &sdkiam.UpdateSigningCertificateInput{CertificateId: certificate.Certificate.CertificateId, Status: types.StatusTypeInactive}); err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"AccountSigningCertificatesPresent": 1})
	if _, err := client.DeleteSigningCertificate(t.Context(), &sdkiam.DeleteSigningCertificateInput{CertificateId: certificate.Certificate.CertificateId}); err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"AccountSigningCertificatesPresent": 0})
	// Account-root MFA has no IAM user lifecycle. The summary nevertheless
	// reflects explicit stored root assignments, including a zero enable time.
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	device := iam.MFADevice{SerialNumber: "arn:aws:iam::123456789012:mfa/root", Binding: iam.Propagated[iam.MFABinding]{Value: iam.MFABinding{UserID: scope.AccountID, Seed: "12345678901234567890"}}}
	if err := repository.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutMFADevice(scope, device) }); err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"AccountMFAEnabled": 1, "MFADevicesInUse": 1})
	device.Binding.Value.UserID = ""
	if err := repository.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutMFADevice(scope, device) }); err != nil {
		t.Fatal(err)
	}
	requireSummaryValues(t, accountSummary(t, client), map[string]int32{"AccountMFAEnabled": 0, "MFADevicesInUse": 0})
}

type failedSummaryRepository struct{ iam.Repository }
type failedSummaryTx struct{ iam.WriteTx }

func (r failedSummaryRepository) Update(ctx context.Context, fn func(iam.WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx iam.WriteTx) error { return fn(failedSummaryTx{tx}) })
}
func (failedSummaryTx) PrincipalCredentials(string, string) ([]identity.Record, error) {
	return nil, errors.New("injected credential storage failure")
}

func TestIAMAccountSummaryPermissionAndStorageErrors(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	user, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("summary-reader")})
	if err != nil {
		t.Fatal(err)
	}
	client := clientForIAMPrincipal(t, service, user.User)
	for _, effect := range []string{"", "Allow", "Deny"} {
		if effect != "" {
			if _, err := root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("summary"), PolicyDocument: aws.String(fmt.Sprintf(`{"Statement":{"Effect":%q,"Action":"iam:GetAccountSummary","Resource":"*"}}`, effect))}); err != nil {
				t.Fatal(err)
			}
		}
		_, err := client.GetAccountSummary(t.Context(), &sdkiam.GetAccountSummaryInput{})
		if effect == "Allow" {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			requireCode(t, err, "AccessDenied")
		}
	}
	broken := iam.NewWithRepository(nil, failedSummaryRepository{iam.NewMemoryRepository(nil)})
	_, err = clientFor(t, broken, "123456789012", "us-east-1").GetAccountSummary(t.Context(), &sdkiam.GetAccountSummaryInput{})
	var failure *types.ServiceFailureException
	if !errors.As(err, &failure) {
		t.Fatalf("storage failure was not modeled: %v", err)
	}
}

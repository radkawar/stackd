package stackd_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func clockCloud(t *testing.T, config stackd.Config) cloudClients {
	t.Helper()
	cloud, err := stackd.New(config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(cloud)
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
	})
	return cloudClients{server}
}

func advanceClock(t *testing.T, source *clock.Manual, d time.Duration) {
	t.Helper()
	if err := source.Advance(d); err != nil {
		t.Fatal(err)
	}
}

func TestManualClockSDKDelegationAtUnixEpoch(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	source := clock.NewManual(epoch.Add(-time.Second))
	c := clockCloud(t, stackd.Config{Clock: source})
	orgs := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	if _, err := orgs.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	account, err := orgs.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("delegated"), Email: aws.String("delegated@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	account.CreateAccountStatus = waitAccountCreation(t, orgs, account.CreateAccountStatus, source)
	principal := aws.String("config.amazonaws.com")
	if _, err := orgs.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: principal}); err != nil {
		t.Fatal(err)
	}
	if _, err := orgs.RegisterDelegatedAdministrator(t.Context(), &organizations.RegisterDelegatedAdministratorInput{AccountId: account.CreateAccountStatus.AccountId, ServicePrincipal: principal}); err != nil {
		t.Fatal(err)
	}
	for _, filter := range []*string{nil, principal} {
		delegates, err := orgs.ListDelegatedAdministrators(t.Context(), &organizations.ListDelegatedAdministratorsInput{ServicePrincipal: filter})
		if err != nil || len(delegates.DelegatedAdministrators) != 1 || !aws.ToTime(delegates.DelegatedAdministrators[0].DelegationEnabledDate).Equal(epoch) {
			t.Fatalf("delegation at Unix epoch lost: %v, %v", delegates, err)
		}
	}
}

func TestManualClockSDKReconstructionKeepsCredentialDeadline(t *testing.T) {
	epoch := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	backends := storage.NewMemory()
	first, err := stackd.New(stackd.Config{Clock: source, Storage: backends})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(first)
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = first.Close() })
	c := cloudClients{server}
	session, err := c.sts("test", "test", "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	server.Close()
	advanceClock(t, source, 10*time.Minute)
	restored := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
	if _, err := restored.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatal("valid credentials lost on reconstruction:", err)
	}
	advanceClock(t, source, 5*time.Minute)
	_, err = restored.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "ExpiredToken")
}

func TestManualClockSDKCredentialsAndDateConditions(t *testing.T) {
	// Intentionally far from wall time: SDK signatures remain ordinary, while
	// all service timestamps, date conditions and expiry use this epoch.
	epoch := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	c := clockCloud(t, stackd.Config{Clock: source})
	root := c.iam("test", "test", "")
	user, err := root.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String("clock-user")})
	if err != nil || !aws.ToTime(user.User.CreateDate).Equal(epoch) {
		t.Fatalf("IAM user timestamp: %v, %v", user, err)
	}
	key, err := root.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: user.User.UserName})
	if err != nil || !aws.ToTime(key.AccessKey.CreateDate).Equal(epoch) {
		t.Fatalf("IAM credential timestamp: %v, %v", key, err)
	}
	putUserPolicy(t, root, "clock-user", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":%q}}}}`, epoch.Add(2*time.Minute).Format(time.RFC3339)))
	queue, err := c.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("clock-queue")})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.sts(aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil || !aws.ToTime(session.Credentials.Expiration).Equal(epoch.Add(15*time.Minute)) {
		t.Fatalf("STS expiration: %v, %v", session, err)
	}
	send := func() error {
		_, err := c.sessionSQS(session.Credentials).SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("time-limited")})
		return err
	}
	if err := send(); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 2*time.Minute)
	assertAPIError(t, send(), "AccessDenied")
	advanceClock(t, source, 13*time.Minute-time.Nanosecond)
	if _, err := c.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatal("credential expired before its deadline:", err)
	}
	advanceClock(t, source, time.Nanosecond)
	_, err = c.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "ExpiredToken")
	if _, err := root.ListUsers(t.Context(), &iam.ListUsersInput{}); err != nil {
		t.Fatal("service clock changed wall-clock signature verification:", err)
	}
}

func TestManualClockSDKMFAAge(t *testing.T) {
	epoch := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	c := clockCloud(t, stackd.Config{Clock: source})
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "clock-mfa")
	putUserPolicy(t, root, "clock-mfa", `{"Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"},"NumericLessThanEquals":{"aws:MultiFactorAuthAge":"60"}}}}`)
	device, err := root.CreateVirtualMFADevice(t.Context(), &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("clock-device")})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(device.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	step := epoch.Unix() / 30
	serial := device.VirtualMFADevice.SerialNumber
	_, err = root.EnableMFADevice(t.Context(), &iam.EnableMFADeviceInput{UserName: aws.String("clock-mfa"), SerialNumber: serial, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))})
	if err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 30*time.Second)
	session, err := c.sts(key, secret, "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900), SerialNumber: serial, TokenCode: aws.String(otpForTest(seed, step+1))})
	if err != nil {
		t.Fatal(err)
	}
	client := c.iam(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken))
	advanceClock(t, source, time.Minute)
	if _, err := client.ListUsers(t.Context(), &iam.ListUsersInput{}); err != nil {
		t.Fatal("MFA should allow at exactly 60 seconds:", err)
	}
	advanceClock(t, source, time.Second)
	_, err = client.ListUsers(t.Context(), &iam.ListUsersInput{})
	assertAPIError(t, err, "AccessDenied")
	advanceClock(t, source, time.Minute)
	_, err = c.sts(key, secret, "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(otpForTest(seed, step))})
	assertAPIError(t, err, "AccessDenied")
}

func TestManualClockSDKKMSOrganizationsAndIsolation(t *testing.T) {
	epoch := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	c := clockCloud(t, stackd.Config{Clock: source})
	otherSource := clock.NewManual(epoch)
	other := clockCloud(t, stackd.Config{Clock: otherSource})
	otherSession, err := other.sts("test", "test", "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	keys := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	key, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil || !aws.ToTime(key.KeyMetadata.CreationDate).Equal(epoch) {
		t.Fatalf("KMS creation: %v, %v", key, err)
	}
	deletion, err := keys.ScheduleKeyDeletion(t.Context(), &kms.ScheduleKeyDeletionInput{KeyId: key.KeyMetadata.KeyId, PendingWindowInDays: aws.Int32(7)})
	if err != nil || !aws.ToTime(deletion.DeletionDate).Equal(epoch.Add(7*24*time.Hour)) {
		t.Fatalf("KMS deletion deadline: %v, %v", deletion, err)
	}
	orgs := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	if _, err := orgs.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	accounts, err := orgs.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
	if err != nil || len(accounts.Accounts) != 1 || !aws.ToTime(accounts.Accounts[0].JoinedTimestamp).Equal(epoch) {
		t.Fatalf("Organizations timestamp: %v, %v", accounts, err)
	}
	advanceClock(t, source, 7*24*time.Hour-time.Nanosecond)
	if _, err := keys.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.KeyId}); err != nil {
		t.Fatal("key removed before deletion deadline:", err)
	}
	advanceClock(t, source, time.Nanosecond)
	_, err = keys.DescribeKey(t.Context(), &kms.DescribeKeyInput{KeyId: key.KeyMetadata.KeyId})
	assertAPIError(t, err, "NotFoundException")
	if _, err := other.sessionSTS(otherSession.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}); err != nil || !otherSource.Now().Equal(epoch) {
		t.Fatal("advancing one stack affected an independent clock:", err)
	}
}

func TestManualClockSDKOIDCVerificationAndSessionExpiry(t *testing.T) {
	epoch := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
	source := clock.NewManual(epoch)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	discovery := &federationIntegrationDiscovery{key: key, kid: "manual-clock"}
	c := clockCloud(t, stackd.Config{Clock: source, OIDCDiscovery: discovery})
	role, _ := federationIntegrationRole(t, c, "test", "clock-role", `"sts:AssumeRoleWithWebIdentity"`)
	input := &sts.AssumeRoleWithWebIdentityInput{RoleArn: role.Arn, RoleSessionName: aws.String("manual-session"), DurationSeconds: aws.Int32(900), WebIdentityToken: aws.String(discovery.token(t, map[string]any{"iat": epoch.Unix(), "exp": epoch.Add(time.Minute).Unix()}))}
	session, err := federationIntegrationUnsigned(c).AssumeRoleWithWebIdentity(t.Context(), input)
	if err != nil || !aws.ToTime(session.Credentials.Expiration).Equal(epoch.Add(15*time.Minute)) {
		t.Fatalf("OIDC did not use the shared transaction clock: %v, %v", session, err)
	}
	advanceClock(t, source, 10*time.Minute)
	_, err = federationIntegrationUnsigned(c).AssumeRoleWithWebIdentity(t.Context(), input)
	assertAPIError(t, err, "ExpiredTokenException")
	if _, err := c.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatal("JWT expiry incorrectly capped role session:", err)
	}
	advanceClock(t, source, 5*time.Minute)
	_, err = c.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "ExpiredToken")
}

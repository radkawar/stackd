package iam_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awswire"
	"stackd/internal/services/iam"
)

var iamClockEpoch = time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)

type iamAdvancingAuthorizer struct {
	clock    *clock.Manual
	mu       sync.Mutex
	requests []authorization.Request
}

func (a *iamAdvancingAuthorizer) Authorize(_ context.Context, request authorization.Request) *awswire.Error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, request)
	_ = a.clock.Advance(time.Hour)
	return nil
}

func TestIAMClockTransactionTimestampsAndDependentAuthorization(t *testing.T) {
	source := clock.NewManual(iamClockEpoch)
	s := iam.NewWithConfig(iam.Config{Clock: source})
	authorizer := &iamAdvancingAuthorizer{clock: source}
	s.SetAuthorizer(authorizer)
	c := clientFor(t, s, "123456789012", "us-east-1")
	user, err := c.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("clock-user"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("test")}}})
	if err != nil || !user.User.CreateDate.Equal(iamClockEpoch) {
		t.Fatal("user creation did not preserve the transaction instant", err)
	}
	authorizer.mu.Lock()
	if len(authorizer.requests) != 2 || !authorizer.requests[0].EvaluationTime.Equal(iamClockEpoch) || !authorizer.requests[1].EvaluationTime.Equal(iamClockEpoch) {
		t.Fatal("tag-on-create authorization did not share the transaction instant")
	}
	authorizer.mu.Unlock()
	keyTime := source.Now()
	key, err := c.CreateAccessKey(t.Context(), &sdkiam.CreateAccessKeyInput{UserName: user.User.UserName})
	if err != nil || !key.AccessKey.CreateDate.Equal(keyTime) {
		t.Fatal("borrowed credential store ignored the transaction clock", err)
	}
	if _, err := c.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("clock-role"), AssumeRolePolicyDocument: aws.String(trustEC2)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateInstanceProfile(t.Context(), &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("clock-profile")}); err != nil {
		t.Fatal(err)
	}
	before := source.Now()
	if _, err := c.AddRoleToInstanceProfile(t.Context(), &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String("clock-profile"), RoleName: aws.String("clock-role")}); err != nil {
		t.Fatal(err)
	}
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	requests := authorizer.requests[len(authorizer.requests)-2:]
	if requests[1].Action != "iam:PassRole" || !requests[0].EvaluationTime.Equal(before) || !requests[1].EvaluationTime.Equal(before) {
		t.Fatal("PassRole dependency did not share the IAM command instant")
	}
}

func TestIAMClockPasswordServiceCredentialAndCertificateExpiry(t *testing.T) {
	source := clock.NewManual(iamClockEpoch)
	s := iam.NewWithConfig(iam.Config{Clock: source})
	c := clientFor(t, s, "123456789012", "us-east-1")
	ctx := t.Context()
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	user, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("expires")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateAccountPasswordPolicy(ctx, &sdkiam.UpdateAccountPasswordPolicyInput{MinimumPasswordLength: aws.Int32(8), MaxPasswordAge: aws.Int32(1), HardExpiry: aws.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	profile, err := c.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: user.User.UserName, Password: aws.String(loginPasswordA)})
	if err != nil || !profile.LoginProfile.CreateDate.Equal(iamClockEpoch) {
		t.Fatal("profile timestamp", err)
	}
	service, err := c.CreateServiceSpecificCredential(ctx, &sdkiam.CreateServiceSpecificCredentialInput{UserName: user.User.UserName, ServiceName: aws.String("logs.amazonaws.com"), CredentialAgeDays: aws.Int32(1)})
	if err != nil {
		t.Fatal(err)
	}
	identifier, secret := serviceCredentialMaterial(service.ServiceSpecificCredential)
	key := certificateTestECKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, iamClockEpoch.Add(-time.Hour), iamClockEpoch.Add(24*time.Hour))
	cert, err := c.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: user.User.UserName, CertificateBody: aws.String(body)})
	if err != nil || !cert.Certificate.UploadDate.Equal(iamClockEpoch) {
		t.Fatal("certificate timestamp/validation", err)
	}
	server, err := c.UploadServerCertificate(ctx, &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String("clock-server"), CertificateBody: aws.String(body), PrivateKey: aws.String(certificateTestPrivate(t, key))})
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("clock-bound signed request")
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(24*time.Hour - time.Second); err != nil {
		t.Fatal(err)
	}
	authenticated, err := s.VerifyPassword(ctx, scope, "expires", loginPasswordA)
	if err != nil || authenticated.PasswordExpired {
		t.Fatal("password expired before boundary", err)
	}
	if _, err := s.VerifyServiceCredential(ctx, scope, "logs.amazonaws.com", identifier, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifySigningCertificate(ctx, scope, aws.ToString(cert.Certificate.CertificateId), x509.ECDSAWithSHA256, message, signature); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ServerCertificateForTLS(ctx, scope, aws.ToString(server.ServerCertificateMetadata.Arn)); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	authenticated, err = s.VerifyPassword(ctx, scope, "expires", loginPasswordA)
	if err != nil || !authenticated.PasswordExpired || !authenticated.AdministratorResetRequired {
		t.Fatal("password expiry boundary ignored", err)
	}
	if _, err := s.VerifyServiceCredential(ctx, scope, "logs.amazonaws.com", identifier, secret); !errors.Is(err, iam.ErrInvalidServiceCredential) {
		t.Fatal("expired service secret verified", err)
	}
	if _, err := s.VerifySigningCertificate(ctx, scope, aws.ToString(cert.Certificate.CertificateId), x509.ECDSAWithSHA256, message, signature); !errors.Is(err, iam.ErrInvalidSigningCertificate) {
		t.Fatal("expired signing certificate verified", err)
	}
	if _, err := s.ServerCertificateForTLS(ctx, scope, aws.ToString(server.ServerCertificateMetadata.Arn)); !errors.Is(err, iam.ErrInvalidServerCertificate) {
		t.Fatal("expired TLS certificate returned", err)
	}
	listed, err := c.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: user.User.UserName})
	if err != nil || len(listed.ServiceSpecificCredentials) != 1 || listed.ServiceSpecificCredentials[0].Status != types.StatusType("Expired") {
		t.Fatal("wire credential status ignores clock", err)
	}
	_, err = c.ResetServiceSpecificCredential(ctx, &sdkiam.ResetServiceSpecificCredentialInput{UserName: user.User.UserName, ServiceSpecificCredentialId: service.ServiceSpecificCredential.ServiceSpecificCredentialId})
	requireCode(t, err, "InvalidInput")
	_, err = c.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: user.User.UserName, CertificateBody: aws.String(body)})
	requireCode(t, err, "MalformedCertificate")
}

func TestIAMClockReauthorizesAfterDiscoveryAtFreshTime(t *testing.T) {
	source := clock.NewManual(iamClockEpoch)
	s := iam.NewWithConfig(iam.Config{Clock: source})
	c := clientFor(t, s, "123456789012", "us-east-1")
	user, err := c.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("discovery-manager")})
	if err != nil {
		t.Fatal(err)
	}
	policy := `{"Statement":{"Effect":"Allow","Action":"iam:CreateOpenIDConnectProvider","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"` + iamClockEpoch.Add(time.Minute).Format(time.RFC3339) + `"}}}}`
	if _, err := c.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("Timed"), PolicyDocument: aws.String(policy)}); err != nil {
		t.Fatal(err)
	}
	var called bool
	s.SetOIDCDiscovery(oidcDiscoveryFunc(func(_ context.Context, request iam.OIDCDiscoveryRequest) (iam.OIDCDiscoveryResult, error) {
		called = true
		if err := source.Advance(time.Minute); err != nil {
			return iam.OIDCDiscoveryResult{}, err
		}
		return iam.OIDCDiscoveryResult{IssuerURL: request.IssuerURL, Thumbprints: []string{strings.Repeat("a", 40)}}, nil
	}))
	caller := clientForIAMPrincipal(t, s, user.User)
	_, err = caller.CreateOpenIDConnectProvider(t.Context(), &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://clock.example.test"), ClientIDList: []string{"audience"}})
	requireCode(t, err, "AccessDenied")
	if !called {
		t.Fatal("initial authorization ignored service time")
	}
	providers, err := c.ListOpenIDConnectProviders(t.Context(), &sdkiam.ListOpenIDConnectProvidersInput{})
	if err != nil || len(providers.OpenIDConnectProviderList) != 0 {
		t.Fatal("expired authorization committed provider", err)
	}
}

func TestIAMClockRoleHistoryAndProviderRotation(t *testing.T) {
	source := clock.NewManual(iamClockEpoch)
	repository := iam.NewMemoryRepository(nil)
	s := iam.NewWithConfig(iam.Config{Clock: source, Repository: repository})
	c := clientFor(t, s, "123456789012", "us-east-1")
	ctx := t.Context()
	role, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("history"), AssumeRolePolicyDocument: aws.String(trustEC2)})
	if err != nil || !role.Role.CreateDate.Equal(iamClockEpoch) {
		t.Fatal("role creation ignored service epoch", err)
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	if err := repository.Update(ctx, func(tx iam.WriteTx) error {
		r, err := tx.Role(scope, "history")
		if err != nil {
			return err
		}
		r.LastUsed = iam.RoleLastUse{Date: iamClockEpoch, Region: "us-east-1"}
		return tx.PutRole(scope, r)
	}); err != nil {
		t.Fatal(err)
	}
	provider, err := c.CreateSAMLProvider(ctx, &sdkiam.CreateSAMLProviderInput{Name: aws.String("clock-provider"), SAMLMetadataDocument: aws.String(federationFixture(t, "metadata.xml")), AddPrivateKey: aws.String(federationFixture(t, "private-key-1.pem"))})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: provider.SAMLProviderArn})
	if err != nil || !initial.CreateDate.Equal(iamClockEpoch) || !initial.ValidUntil.Equal(iamClockEpoch.AddDate(100, 0, 0)) || len(initial.PrivateKeyList) != 1 || !initial.PrivateKeyList[0].Timestamp.Equal(iamClockEpoch) {
		t.Fatal("SAML initial timestamps ignored transaction time", err)
	}
	if err := source.Advance(400*24*time.Hour - time.Second); err != nil {
		t.Fatal(err)
	}
	before, err := c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: role.Role.RoleName})
	if err != nil || before.Role.RoleLastUsed.LastUsedDate == nil {
		t.Fatal("role history aged before boundary", err)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	after, err := c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: role.Role.RoleName})
	if err != nil || after.Role.RoleLastUsed.LastUsedDate != nil {
		t.Fatal("400-day role history did not age at boundary", err)
	}
	_, err = c.UpdateSAMLProvider(ctx, &sdkiam.UpdateSAMLProviderInput{SAMLProviderArn: provider.SAMLProviderArn, SAMLMetadataDocument: aws.String(federationFixture(t, "metadata.xml")), AddPrivateKey: aws.String(federationFixture(t, "private-key-1.pem"))})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := c.GetSAMLProvider(ctx, &sdkiam.GetSAMLProviderInput{SAMLProviderArn: provider.SAMLProviderArn})
	if err != nil || !rotated.CreateDate.Equal(iamClockEpoch) || !rotated.ValidUntil.Equal(source.Now().AddDate(100, 0, 0)) || len(rotated.PrivateKeyList) != 2 || !rotated.PrivateKeyList[1].Timestamp.Equal(source.Now()) {
		t.Fatal("SAML rotation did not preserve creation/use new epoch", err)
	}
}

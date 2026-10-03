package iam_test

import (
	"encoding/base32"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/clock"
	"stackd/internal/services/iam"
)

type summaryObservation struct {
	Case      string           `json:"case"`
	Operation string           `json:"operation"`
	Delta     map[string]int32 `json:"delta_from_baseline"`
}

func summaryObservations(t *testing.T) map[string]summaryObservation {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/iam/account_reporting.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []summaryObservation `json:"observations"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	observations := make(map[string]summaryObservation)
	for _, item := range capture.Observations {
		if item.Operation == "GetAccountSummary" {
			observations[item.Case] = item
		}
	}
	return observations
}

func requireSummaryObservation(t *testing.T, observations map[string]summaryObservation, name string, baseline, actual map[string]int32, keys ...string) {
	t.Helper()
	observation, ok := observations[name]
	if !ok {
		t.Fatalf("missing AWS GetAccountSummary observation %q", name)
	}
	for _, key := range keys {
		if delta := actual[key] - baseline[key]; delta != observation.Delta[key] {
			t.Errorf("%s: %s delta=%d, AWS observed %d", name, key, delta, observation.Delta[key])
		}
	}
}

func TestIAMAccountSummaryAWSPolicyReplay(t *testing.T) {
	observations := summaryObservations(t)
	client := clientFor(t, iam.New(), "123456789012", "us-east-1")
	baseline := accountSummary(t, client)
	check := func(name string) {
		t.Helper()
		// Compare the owned policy changes, independently of the live account's
		// unrelated identities, configured quota increases, and root settings.
		requireSummaryObservation(t, observations, name, baseline, accountSummary(t, client), "Policies", "PolicyVersionsInUse")
	}
	if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("replay-user")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("replay-role"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}}`)}); err != nil {
		t.Fatal(err)
	}
	main := mustCreatePolicy(t, client, "replay-main")
	boundary := mustCreatePolicy(t, client, "replay-boundary")
	check("unattached_policies")
	for _, setDefault := range []bool{false, true, false} {
		if _, err := client.CreatePolicyVersion(t.Context(), &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(main), PolicyDocument: aws.String(allowRead), SetAsDefault: setDefault}); err != nil {
			t.Fatal(err)
		}
	}
	check("unattached_versions")
	if _, err := client.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: aws.String("replay-user"), PermissionsBoundary: aws.String(boundary)}); err != nil {
		t.Fatal(err)
	}
	check("customer_boundary_only")
	const awsPolicy = "arn:aws:iam::aws:policy/AWSCloud9SSMInstanceProfile"
	if _, err := client.PutRolePermissionsBoundary(t.Context(), &sdkiam.PutRolePermissionsBoundaryInput{RoleName: aws.String("replay-role"), PermissionsBoundary: aws.String(awsPolicy)}); err != nil {
		t.Fatal(err)
	}
	check("aws_boundary_only")
	if _, err := client.DeleteRolePermissionsBoundary(t.Context(), &sdkiam.DeleteRolePermissionsBoundaryInput{RoleName: aws.String("replay-role")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachRolePolicy(t.Context(), &sdkiam.AttachRolePolicyInput{RoleName: aws.String("replay-role"), PolicyArn: aws.String(awsPolicy)}); err != nil {
		t.Fatal(err)
	}
	check("aws_attachment_only")
}

func TestIAMAccountSummaryAWSCredentialsAndProvidersReplay(t *testing.T) {
	observations := summaryObservations(t)
	now := time.Date(2027, 2, 3, 4, 5, 0, 0, time.UTC)
	service := iam.NewWithConfig(iam.Config{Clock: clock.NewManual(now)})
	client := clientFor(t, service, "123456789012", "us-east-1")
	baseline := accountSummary(t, client)
	check := func(name string) {
		t.Helper()
		requireSummaryObservation(t, observations, name, baseline, accountSummary(t, client),
			"Users", "MFADevices", "MFADevicesInUse", "Providers", "ServerCertificates",
			"AccountMFAEnabled", "AccountSigningCertificatesPresent")
	}
	user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("replay-user")})
	if err != nil {
		t.Fatal(err)
	}
	device, err := client.CreateVirtualMFADevice(t.Context(), &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("replay-device")})
	if err != nil {
		t.Fatal(err)
	}
	check("unassigned_mfa")
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(device.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.EnableMFADevice(t.Context(), &sdkiam.EnableMFADeviceInput{UserName: user.User.UserName, SerialNumber: device.VirtualMFADevice.SerialNumber, AuthenticationCode1: aws.String(testMFAOTP(seed, now.Unix()/30)), AuthenticationCode2: aws.String(testMFAOTP(seed, now.Unix()/30+1))}); err != nil {
		t.Fatal(err)
	}
	check("assigned_mfa")
	if _, err := client.CreateSAMLProvider(t.Context(), &sdkiam.CreateSAMLProviderInput{Name: aws.String("replay-saml"), SAMLMetadataDocument: aws.String(federationFixture(t, "metadata.xml"))}); err != nil {
		t.Fatal(err)
	}
	check("saml_provider")
	if _, err := client.CreateOpenIDConnectProvider(t.Context(), &sdkiam.CreateOpenIDConnectProviderInput{Url: aws.String("https://replay.example.com"), ThumbprintList: []string{strings.Repeat("a", 40)}}); err != nil {
		t.Fatal(err)
	}
	check("oidc_provider")
	key := certificateTestECKey(t)
	certificate, _ := certificateTestMaterial(t, key, nil, nil, false, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := client.UploadSigningCertificate(t.Context(), &sdkiam.UploadSigningCertificateInput{UserName: user.User.UserName, CertificateBody: aws.String(certificate)}); err != nil {
		t.Fatal(err)
	}
	check("user_signing_certificate")
	if _, err := client.UploadServerCertificate(t.Context(), &sdkiam.UploadServerCertificateInput{ServerCertificateName: aws.String("replay-server"), CertificateBody: aws.String(certificate), PrivateKey: aws.String(certificateTestPrivate(t, key))}); err != nil {
		t.Fatal(err)
	}
	check("server_certificate")
}

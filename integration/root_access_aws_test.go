package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type rootAWSObservation struct {
	Case   string
	Code   string
	Input  json.RawMessage
	Output json.RawMessage
}

func rootAWSCapture(t *testing.T) map[string]rootAWSObservation {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/iam/root_sessions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Observations []rootAWSObservation }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]rootAWSObservation)
	for _, row := range fixture.Observations {
		rows[row.Case] = row
	}
	return rows
}

func rootAWSResult(t *testing.T, rows map[string]rootAWSObservation, name string, err error) json.RawMessage {
	t.Helper()
	row, found := rows[name]
	if !found {
		t.Fatalf("missing native root observation %s", name)
	}
	if row.Code == "Success" {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	} else {
		assertAPIError(t, err, row.Code)
	}
	return row.Output
}

func TestRootTaskFeatureMatrixAWSReplay(t *testing.T) {
	rows := rootAWSCapture(t)
	for _, mode := range []string{"credentials_only_", "sessions_only_"} {
		t.Run(mode, func(t *testing.T) {
			f := newOrganizationReportFixture(t, nil)
			member := f.account(t, f.rootID, "root-matrix")
			if _, err := f.org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			operation := "EnableOrganizationsRootCredentialsManagement"
			if mode == "sessions_only_" {
				operation = "EnableOrganizationsRootSessions"
			}
			if err := callRootFeature(t.Context(), f.iam, operation); err != nil {
				t.Fatal(err)
			}
			_, key, secret := f.cloud.user(t, "test", "root-matrix-operator")
			putUserPolicy(t, f.iam, "root-matrix-operator", fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sts:AssumeRoot","Resource":"arn:aws:iam::%s:root"}}`, member))
			caller := f.cloud.sts(key, secret, "")
			for _, task := range []string{"IAMAuditRootUserCredentials", "IAMDeleteRootUserCredentials", "IAMCreateRootUserPassword", "S3UnlockBucketPolicy", "SQSUnlockQueuePolicy"} {
				t.Run(task, func(t *testing.T) {
					name := mode + task
					var in sts.AssumeRootInput
					if err := json.Unmarshal(rows[name].Input, &in); err != nil {
						t.Fatal(err)
					}
					in.TargetPrincipal = &member
					out, err := caller.AssumeRoot(t.Context(), &in)
					rootAWSResult(t, rows, name, err)
					if err != nil {
						if out != nil {
							t.Fatal("denied task returned a credential payload")
						}
						return
					}
					if out.Credentials == nil || !out.Credentials.Expiration.Equal(f.clock.Now().Add(900*time.Second)) {
						t.Fatalf("issued task duration: %+v", out)
					}
				})
			}
		})
	}
}

func TestRootTrustedAccessAndIssuedSessionAWSReplay(t *testing.T) {
	rows := rootAWSCapture(t)
	f := newOrganizationReportFixture(t, nil)
	delegate := f.account(t, f.rootID, "root-native-delegate")
	target := f.account(t, f.rootID, "root-native-target")
	service := aws.String("iam.amazonaws.com")
	if _, err := f.org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: service}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.org.RegisterDelegatedAdministrator(t.Context(), &organizations.RegisterDelegatedAdministratorInput{AccountId: &delegate, ServicePrincipal: service}); err != nil {
		t.Fatal(err)
	}
	_, key, secret := f.cloud.user(t, delegate, "native-delegate")
	putUserPolicy(t, f.cloud.iam(delegate, "test", ""), "native-delegate", `{"Statement":{"Effect":"Allow","Action":["sts:AssumeRoot","iam:*Organizations*"],"Resource":"*"}}`)
	client := f.cloud.iam(key, secret, "")
	for _, tc := range []struct{ label, operation string }{{"delegate_enable_credentials", "EnableOrganizationsRootCredentialsManagement"}, {"delegate_enable_sessions", "EnableOrganizationsRootSessions"}} {
		rootAWSResult(t, rows, tc.label, callRootFeature(t.Context(), client, tc.operation))
		if err := callRootFeature(t.Context(), f.iam, tc.operation); err != nil {
			t.Fatal(err)
		}
	}
	_, err := f.org.DisableAWSServiceAccess(t.Context(), &organizations.DisableAWSServiceAccessInput{ServicePrincipal: service})
	rootAWSResult(t, rows, "trust_disable_with_delegate", err)
	var constraint *orgtypes.ConstraintViolationException
	if !errors.As(err, &constraint) || constraint.Reason != orgtypes.ConstraintViolationExceptionReasonDelegatedAdministratorExistsForThisService {
		t.Fatalf("trusted access constraint reason: %v", err)
	}
	if aws.ToString(constraint.Message) != "You have delegated administrator/s for this service. De-register them in order to disable service access." {
		t.Fatalf("trusted access constraint message: %v", err)
	}
	// A rejected disable must preserve both trusted access and root features.
	features, err := client.ListOrganizationsFeatures(t.Context(), &iam.ListOrganizationsFeaturesInput{})
	if err != nil || len(features.EnabledFeatures) != 2 {
		t.Fatalf("failed trusted access mutation changed features: %+v %v", features, err)
	}
	caller := f.cloud.sts(key, secret, "")
	input := &sts.AssumeRootInput{TargetPrincipal: &target, TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String("arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials")}}
	issued, err := caller.AssumeRoot(t.Context(), input)
	rootAWSResult(t, rows, "delegate_assume_enabled", err)
	c := issued.Credentials
	audit := f.cloud.iam(*c.AccessKeyId, *c.SecretAccessKey, *c.SessionToken)
	for _, tc := range []struct{ label, operation string }{{"delegate_disable_credentials", "DisableOrganizationsRootCredentialsManagement"}, {"delegate_disable_sessions", "DisableOrganizationsRootSessions"}} {
		rootAWSResult(t, rows, tc.label, callRootFeature(t.Context(), client, tc.operation))
	}
	_, err = caller.AssumeRoot(t.Context(), input)
	rootAWSResult(t, rows, "new_session_after_disable", err)
	_, err = audit.GetUser(t.Context(), &iam.GetUserInput{})
	rootAWSResult(t, rows, "issued_session_after_disable", err)
	for _, operation := range []string{"EnableOrganizationsRootCredentialsManagement", "EnableOrganizationsRootSessions"} {
		if err := callRootFeature(t.Context(), f.iam, operation); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.org.DeregisterDelegatedAdministrator(t.Context(), &organizations.DeregisterDelegatedAdministratorInput{AccountId: &delegate, ServicePrincipal: service}); err != nil {
		t.Fatal(err)
	}
	_, err = audit.GetUser(t.Context(), &iam.GetUserInput{})
	rootAWSResult(t, rows, "issued_session_after_deregister", err)
	if _, err := f.org.DisableAWSServiceAccess(t.Context(), &organizations.DisableAWSServiceAccessInput{ServicePrincipal: service}); err != nil {
		t.Fatal(err)
	}
	_, err = f.iam.ListOrganizationsFeatures(t.Context(), &iam.ListOrganizationsFeaturesInput{})
	rootAWSResult(t, rows, "features_without_trust", err)
	_, err = audit.GetUser(t.Context(), &iam.GetUserInput{})
	rootAWSResult(t, rows, "issued_session_without_trust", err)
	if _, err := f.org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: service}); err != nil {
		t.Fatal(err)
	}
	features, err = f.iam.ListOrganizationsFeatures(t.Context(), &iam.ListOrganizationsFeaturesInput{})
	var expected struct{ EnabledFeatures []iamtypes.FeatureType }
	if err := json.Unmarshal(rootAWSResult(t, rows, "features_after_trust_restore", err), &expected); err != nil {
		t.Fatal(err)
	}
	got := slices.Clone(features.EnabledFeatures)
	slices.Sort(got)
	slices.Sort(expected.EnabledFeatures)
	if !slices.Equal(got, expected.EnabledFeatures) {
		t.Fatalf("features after trust restore: %v, want %v", got, expected.EnabledFeatures)
	}
}

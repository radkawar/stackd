package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd/storage"
)

func TestRootAccessFeaturesAWSAuthorizationReplay(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/root_access.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case       string
			Operation  string
			Credential string
			Code       string
			HTTPStatus int `json:"http_status"`
			Changes    []struct {
				Operation string
				Input     json.RawMessage
			} `json:"state_changes_before"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	f := newOrganizationReportFixture(t, nil)
	clients := map[string]*iam.Client{"original": f.iam}
	for _, observation := range fixture.Observations {
		if observation.Operation != "ListOrganizationsFeatures" &&
			!strings.HasPrefix(observation.Operation, "EnableOrganizationsRoot") &&
			!strings.HasPrefix(observation.Operation, "DisableOrganizationsRoot") {
			continue
		}
		t.Run(observation.Case, func(t *testing.T) {
			for _, change := range observation.Changes {
				input := []byte(strings.ReplaceAll(string(change.Input), "123456789012", "000000000000"))
				switch change.Operation {
				case "CreateUser":
					var in iam.CreateUserInput
					if err := json.Unmarshal(input, &in); err != nil {
						t.Fatal(err)
					}
					if _, err := f.iam.CreateUser(t.Context(), &in); err != nil {
						t.Fatal(err)
					}
				case "PutUserPolicy":
					var in iam.PutUserPolicyInput
					if err := json.Unmarshal(input, &in); err != nil {
						t.Fatal(err)
					}
					if _, err := f.iam.PutUserPolicy(t.Context(), &in); err != nil {
						t.Fatal(err)
					}
				case "CreateAccessKey":
					var in iam.CreateAccessKeyInput
					if err := json.Unmarshal(input, &in); err != nil {
						t.Fatal(err)
					}
					out, err := f.iam.CreateAccessKey(t.Context(), &in)
					if err != nil {
						t.Fatal(err)
					}
					clients[observation.Credential] = f.cloud.iam(aws.ToString(out.AccessKey.AccessKeyId), aws.ToString(out.AccessKey.SecretAccessKey), "")
				default:
					t.Fatalf("unsupported fixture setup: %s", change.Operation)
				}
			}
			client := clients[observation.Credential]
			if client == nil {
				t.Fatalf("missing caller %s", observation.Credential)
			}
			err := callRootFeature(t.Context(), client, observation.Operation)
			assertAPIError(t, err, observation.Code)
			var response *smithyhttp.ResponseError
			if !errors.As(err, &response) || response.HTTPStatusCode() != observation.HTTPStatus {
				t.Fatalf("expected HTTP %d: %v", observation.HTTPStatus, err)
			}
		})
	}
}

func callRootFeature(ctx context.Context, client *iam.Client, operation string) error {
	switch operation {
	case "ListOrganizationsFeatures":
		_, err := client.ListOrganizationsFeatures(ctx, &iam.ListOrganizationsFeaturesInput{})
		return err
	case "EnableOrganizationsRootCredentialsManagement":
		_, err := client.EnableOrganizationsRootCredentialsManagement(ctx, &iam.EnableOrganizationsRootCredentialsManagementInput{})
		return err
	case "DisableOrganizationsRootCredentialsManagement":
		_, err := client.DisableOrganizationsRootCredentialsManagement(ctx, &iam.DisableOrganizationsRootCredentialsManagementInput{})
		return err
	case "EnableOrganizationsRootSessions":
		_, err := client.EnableOrganizationsRootSessions(ctx, &iam.EnableOrganizationsRootSessionsInput{})
		return err
	case "DisableOrganizationsRootSessions":
		_, err := client.DisableOrganizationsRootSessions(ctx, &iam.DisableOrganizationsRootSessionsInput{})
		return err
	default:
		return fmt.Errorf("unknown root feature operation %q", operation)
	}
}

func TestRootAccessFeaturesOrganizationPrerequisitesSDK(t *testing.T) {
	for _, test := range []struct {
		name       string
		featureSet orgtypes.OrganizationFeatureSet
		code       string
	}{
		{"no organization", "", "OrganizationNotFoundException"},
		{"consolidated billing", orgtypes.OrganizationFeatureSetConsolidatedBilling, "OrganizationNotInAllFeaturesModeException"},
		{"trusted access disabled", orgtypes.OrganizationFeatureSetAll, "ServiceAccessNotEnabledException"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newCloudClients(t)
			if test.featureSet != "" {
				org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: test.featureSet}); err != nil {
					t.Fatal(err)
				}
			}
			for _, operation := range []string{"ListOrganizationsFeatures", "EnableOrganizationsRootCredentialsManagement", "DisableOrganizationsRootCredentialsManagement", "EnableOrganizationsRootSessions", "DisableOrganizationsRootSessions"} {
				t.Run(operation, func(t *testing.T) {
					assertAPIError(t, callRootFeature(t.Context(), c.iam("test", "test", ""), operation), test.code)
				})
			}
		})
	}
}

func TestRootAccessFeaturesDelegationAndRevocationSDK(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	ctx := t.Context()
	delegate := f.account(t, f.rootID, "root-delegate")
	target := f.account(t, f.rootID, "root-delegate-target")
	if _, err := f.org.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.org.RegisterDelegatedAdministrator(ctx, &organizations.RegisterDelegatedAdministratorInput{AccountId: &delegate, ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	_, key, secret := f.cloud.user(t, delegate, "delegated-root-operator")
	putUserPolicy(t, f.cloud.iam(delegate, "test", ""), "delegated-root-operator", fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"iam:*Organizations*","Resource":"*"},{"Effect":"Allow","Action":"sts:AssumeRoot","Resource":"arn:aws:iam::%s:root"},{"Effect":"Deny","Action":"organizations:*","Resource":"*"}]}`, target))
	client := f.cloud.iam(key, secret, "")
	checkFeatures := func(want ...iamtypes.FeatureType) {
		t.Helper()
		out, err := client.ListOrganizationsFeatures(ctx, &iam.ListOrganizationsFeaturesInput{})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(out.EnabledFeatures, want) || aws.ToString(out.OrganizationId) != strings.Split(f.rootPath, "/")[0] {
			t.Fatalf("delegate features: %+v; want %v", out, want)
		}
	}
	checkFeatures()
	for _, operation := range []string{"EnableOrganizationsRootCredentialsManagement", "EnableOrganizationsRootSessions"} {
		assertAPIError(t, callRootFeature(ctx, client, operation), "CallerIsNotManagementAccountException")
		if err := callRootFeature(ctx, f.iam, operation); err != nil {
			t.Fatal(err)
		}
	}
	checkFeatures(iamtypes.FeatureTypeRootCredentialsManagement, iamtypes.FeatureTypeRootSessions)
	if _, err := client.DisableOrganizationsRootCredentialsManagement(ctx, &iam.DisableOrganizationsRootCredentialsManagementInput{}); err != nil {
		t.Fatal(err)
	}
	checkFeatures(iamtypes.FeatureTypeRootSessions)
	input := &sts.AssumeRootInput{TargetPrincipal: &target, TaskPolicyArn: &ststypes.PolicyDescriptorType{Arn: aws.String("arn:aws:iam::aws:policy/root-task/SQSUnlockQueuePolicy")}}
	caller := f.cloud.sts(key, secret, "")
	assume := func(wantCode string) {
		t.Helper()
		out, err := caller.AssumeRoot(ctx, input)
		if wantCode != "" {
			assertAPIError(t, err, wantCode)
			if out != nil && out.Credentials != nil {
				t.Fatalf("denied issuance returned credentials: %+v", out)
			}
			return
		}
		if err != nil || out == nil || out.Credentials == nil {
			t.Fatalf("delegate AssumeRoot: %+v %v", out, err)
		}
	}
	assume("")
	if _, err := client.DisableOrganizationsRootSessions(ctx, &iam.DisableOrganizationsRootSessionsInput{}); err != nil {
		t.Fatal(err)
	}
	checkFeatures()
	assume("AccessDenied")
	if _, err := f.iam.EnableOrganizationsRootSessions(ctx, &iam.EnableOrganizationsRootSessionsInput{}); err != nil {
		t.Fatal(err)
	}
	assume("")
	if _, err := f.org.DeregisterDelegatedAdministrator(ctx, &organizations.DeregisterDelegatedAdministratorInput{AccountId: &delegate, ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	assume("AccessDenied")
	_, err := client.ListOrganizationsFeatures(ctx, &iam.ListOrganizationsFeaturesInput{})
	assertAPIError(t, err, "AccountNotManagementOrDelegatedAdministratorException")
	_, err = client.DisableOrganizationsRootSessions(ctx, &iam.DisableOrganizationsRootSessionsInput{})
	assertAPIError(t, err, "AccountNotManagementOrDelegatedAdministratorException")
	out, err := f.iam.ListOrganizationsFeatures(ctx, &iam.ListOrganizationsFeaturesInput{})
	if err != nil || !slices.Equal(out.EnabledFeatures, []iamtypes.FeatureType{iamtypes.FeatureTypeRootSessions}) {
		t.Fatalf("revoked delegate changed features: %+v %v", out, err)
	}
}

func TestRootAccessFeaturesRollbackWithIAMAuthoritySDK(t *testing.T) {
	for _, failure := range []string{"commit", "cancellation"} {
		t.Run(failure, func(t *testing.T) {
			backends := storage.NewMemory()
			repository := &signedAuthorityRepository{Repository: backends.IAM}
			backends.IAM = repository
			f := newOrganizationReportFixture(t, backends)
			if _, err := f.org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			_, key, secret := f.cloud.user(t, "test", "feature-operator")
			putUserPolicy(t, f.iam, "feature-operator", `{"Statement":[{"Effect":"Allow","Action":"iam:*Organizations*","Resource":"*"},{"Effect":"Deny","Action":"organizations:*","Resource":"*"}]}`)
			client := f.cloud.iam(key, secret, "")
			for _, operation := range []string{"EnableOrganizationsRootCredentialsManagement", "EnableOrganizationsRootSessions", "DisableOrganizationsRootCredentialsManagement", "DisableOrganizationsRootSessions"} {
				before, err := client.ListOrganizationsFeatures(t.Context(), &iam.ListOrganizationsFeaturesInput{})
				if err != nil {
					t.Fatal(err)
				}
				plan := &signedAuthorityPlan{key: key, failCommit: failure == "commit", cancelCommit: failure == "cancellation"}
				repository.arm(plan)
				ctx, cancel := context.WithTimeout(t.Context(), signedAuthorityTimeout)
				err = callRootFeature(ctx, client, operation)
				plan.wait(t, ctx)
				cancel()
				assertAPIError(t, err, "ServiceFailure")
				after, err := client.ListOrganizationsFeatures(t.Context(), &iam.ListOrganizationsFeaturesInput{})
				if err != nil || !slices.Equal(before.EnabledFeatures, after.EnabledFeatures) {
					t.Fatalf("%s escaped failed IAM authority: before=%v after=%v err=%v", operation, before, after, err)
				}
				if err := callRootFeature(t.Context(), client, operation); err != nil {
					t.Fatalf("retry %s: %v", operation, err)
				}
			}
		})
	}
}

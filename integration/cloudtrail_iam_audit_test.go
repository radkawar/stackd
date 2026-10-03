package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/journal"
	"stackd/storage"
)

func TestCloudTrailIAMNativeRoleOutcomes(t *testing.T) {
	native := map[string]map[string]any{}
	for _, event := range auditNativeRecords(t, "service_management_events") {
		if event["eventSource"] != "iam.amazonaws.com" {
			continue
		}
		// Normalize only the owned account. Keep policy strings and their
		// native percent-encoded output representation, names, and member presence.
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var normalized map[string]any
		if err := json.Unmarshal([]byte(strings.ReplaceAll(string(body), "000000000000", eventDeliveryAccount)), &normalized); err != nil {
			t.Fatal(err)
		}
		native[event["eventName"].(string)] = normalized
	}
	created := native["CreateRole"]
	if created == nil {
		t.Fatal("native CreateRole capture missing")
	}
	at, err := time.Parse(time.RFC3339, created["eventTime"].(string))
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "iam.sqlite"))
			}
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(at))
			client, trails := c.iam(eventDeliveryAccount, "test", ""), trailNativeClient(c)
			roleName := created["requestParameters"].(map[string]any)["roleName"].(string)
			for _, operation := range []string{"CreateRole", "PutRolePolicy", "ListRolePolicies", "DeleteRolePolicy", "DeleteRole", "GetRole"} {
				t.Run(operation, func(t *testing.T) {
					want := native[operation]
					if want == nil {
						t.Fatalf("missing native %s", operation)
					}
					parameters := want["requestParameters"].(map[string]any)
					// The native read probes used separate owned roles; replay the
					// same transition on the role this test has actually created.
					parameters["roleName"] = roleName
					input, err := json.Marshal(parameters)
					if err != nil {
						t.Fatal(err)
					}
					row := s3NativeObservation{Label: operation, Operation: operation, Input: input}
					row.Result.HTTPStatus = 200
					output, requestID, err := s3NativeInvoke(t, client, row, nil)
					if want["errorCode"] != nil {
						assertAPIError(t, err, "NoSuchEntity")
					} else if err != nil {
						t.Fatal(err)
					}
					got := auditLookupRecord(t, trails, requestID, operation)
					for _, field := range []string{"eventSource", "eventName", "eventCategory", "managementEvent", "readOnly", "requestParameters", "resources", "errorCode"} {
						actual, present := got[field]
						expected, expectedPresent := want[field]
						if present != expectedPresent || !reflect.DeepEqual(actual, expected) {
							t.Fatalf("%s: got %#v, native %#v", field, actual, expected)
						}
					}
					if operation != "CreateRole" {
						if value, present := got["responseElements"]; !present || value != nil {
							t.Fatalf("native null response changed: %#v", got)
						}
						return
					}
					actualRole := got["responseElements"].(map[string]any)["role"].(map[string]any)
					expectedRole := maps.Clone(want["responseElements"].(map[string]any)["role"].(map[string]any))
					sdkRole := output["Role"].(map[string]any)
					expectedRole["roleId"] = sdkRole["RoleId"]
					// Trust policy rendering may change JSON whitespace while
					// retaining the native percent-encoded string representation.
					for _, role := range []map[string]any{actualRole, expectedRole} {
						text, ok := role["assumeRolePolicyDocument"].(string)
						if !ok || !strings.HasPrefix(text, "%7B") {
							t.Fatalf("trust policy is not native encoded JSON: %#v", role)
						}
						decoded, err := url.QueryUnescape(text)
						if err != nil {
							t.Fatal(err)
						}
						var policy any
						if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
							t.Fatal(err)
						}
						role["assumeRolePolicyDocument"] = policy
					}
					if !reflect.DeepEqual(actualRole, expectedRole) {
						t.Fatalf("role audit output: got %#v, native %#v", actualRole, expectedRole)
					}
					// Native CreateRole has three Lookup aliases, and no event
					// document resources. Exercise each consumer lookup independently.
					for _, alias := range []string{roleName, sdkRole["RoleId"].(string), sdkRole["Arn"].(string)} {
						out, err := trails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyResourceName, AttributeValue: &alias}}})
						if err != nil {
							t.Fatal(err)
						}
						if len(out.Events) != 1 || len(out.Events[0].Resources) != 3 {
							t.Fatalf("native CreateRole aliases missing for %s: %+v", alias, out)
						}
					}
				})
			}
		})
	}
}

type iamAuditAppendFailure struct {
	journal.Storage
	operation string
	fail      atomic.Bool
}

func (f *iamAuditAppendFailure) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := f.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "iam.amazonaws.com" && call.EventName == f.operation && f.fail.Swap(false) {
		return errors.New("injected IAM audit commit failure")
	}
	return nil
}

func TestCloudTrailIAMRootAccessAtomicOutcomes(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "root.sqlite"))
			}
			failure := &iamAuditAppendFailure{Storage: backends.Journal, operation: "EnableOrganizationsRootSessions"}
			backends.Journal = failure
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)))
			org := organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetAll}); err != nil {
				t.Fatal(err)
			}
			if _, err := org.EnableAWSServiceAccess(t.Context(), &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("iam.amazonaws.com")}); err != nil {
				t.Fatal(err)
			}
			client, trails := c.iam(eventDeliveryAccount, "test", ""), trailNativeClient(c)
			failure.fail.Store(true)
			_, err := client.EnableOrganizationsRootSessions(t.Context(), &iam.EnableOrganizationsRootSessionsInput{})
			assertAPIError(t, err, "ServiceFailure")
			var failed interface{ ServiceRequestID() string }
			if !errors.As(err, &failed) {
				t.Fatal(err)
			}
			outcome := auditLookupRecord(t, trails, failed.ServiceRequestID(), failure.operation)
			if outcome["errorCode"] == nil || outcome["readOnly"] != false {
				t.Fatalf("rejected root transition outcome: %#v", outcome)
			}
			features, err := client.ListOrganizationsFeatures(t.Context(), &iam.ListOrganizationsFeaturesInput{})
			if err != nil {
				t.Fatal(err)
			}
			if len(features.EnabledFeatures) != 0 {
				t.Fatalf("audit failure committed Organizations root state: %+v", features)
			}
			for _, operation := range []string{"EnableOrganizationsRootSessions", "EnableOrganizationsRootCredentialsManagement", "DisableOrganizationsRootSessions", "DisableOrganizationsRootCredentialsManagement", "ListOrganizationsFeatures"} {
				row := s3NativeObservation{Label: operation, Operation: operation, Input: json.RawMessage(`{}`)}
				row.Result.HTTPStatus = 200
				_, id, err := s3NativeInvoke(t, client, row, nil)
				if err != nil {
					t.Fatal(err)
				}
				got := auditLookupRecord(t, trails, id, operation)
				if got["errorCode"] != nil || got["readOnly"] != (operation == "ListOrganizationsFeatures") {
					t.Fatalf("root command classification: %#v", got)
				}
				if (got["responseElements"] == nil) != (operation == "ListOrganizationsFeatures") {
					t.Fatalf("root command response presence: %#v", got)
				}
			}
		})
	}
}

func TestCloudTrailIAMSecretsAndRejectedMutations(t *testing.T) {
	backends := storage.NewMemory()
	failure := &iamAuditAppendFailure{Storage: backends.Journal, operation: "CreateRole"}
	backends.Journal = failure
	_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC)))
	client, trails := c.iam(eventDeliveryAccount, "test", ""), trailNativeClient(c)
	_, key, secret := c.user(t, eventDeliveryAccount, "audit-user")
	profile, err := client.CreateLoginProfile(t.Context(), &iam.CreateLoginProfileInput{UserName: aws.String("audit-user"), Password: aws.String("Secret-Password-7!"), PasswordResetRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := awsmiddleware.GetRequestIDMetadata(profile.ResultMetadata)
	got := auditLookupRecord(t, trails, id, "CreateLoginProfile")
	parameters := got["requestParameters"].(map[string]any)
	if _, present := parameters["password"]; present || parameters["userName"] != "audit-user" {
		t.Fatalf("password projection: %#v", parameters)
	}
	role := &iam.CreateRoleInput{RoleName: aws.String("must-not-exist"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)}
	for _, caller := range []*iam.Client{c.iam(key, secret, ""), client} {
		if caller == client {
			failure.fail.Store(true)
		}
		_, err := caller.CreateRole(t.Context(), role)
		if err == nil {
			t.Fatal("rejected role creation succeeded")
		}
		var response interface{ ServiceRequestID() string }
		if !errors.As(err, &response) {
			t.Fatal(err)
		}
		got := auditLookupRecord(t, trails, response.ServiceRequestID(), "CreateRole")
		if got["errorCode"] == nil || got["responseElements"] != nil {
			t.Fatalf("missing rejected outcome: %#v", got)
		}
		_, err = client.GetRole(t.Context(), &iam.GetRoleInput{RoleName: role.RoleName})
		assertAPIError(t, err, "NoSuchEntity")
	}
	// The generated validation boundary rejects the malformed name before a
	// handler runs. Audit only its known operation, never the failed raw body.
	role.RoleName = aws.String("invalid/role")
	_, err = client.CreateRole(t.Context(), role)
	var rejected interface{ ServiceRequestID() string }
	if !errors.As(err, &rejected) {
		t.Fatalf("expected generated request rejection: %v", err)
	}
	denied := auditLookupRecord(t, trails, rejected.ServiceRequestID(), "CreateRole")
	if denied["errorCode"] == nil || denied["requestParameters"] != nil || denied["responseElements"] != nil {
		t.Fatalf("generated rejection copied failed input: %#v", denied)
	}
	// Catalog membership must not turn an unsupported command into success,
	// nor make its authenticated rejection disappear from history.
	_, err = client.GetMFADevice(t.Context(), &iam.GetMFADeviceInput{SerialNumber: aws.String("arn:aws:iam::" + eventDeliveryAccount + ":mfa/missing")})
	assertAPIError(t, err, "NotImplemented")
	if !errors.As(err, &rejected) {
		t.Fatal(err)
	}
	unsupported := auditLookupRecord(t, trails, rejected.ServiceRequestID(), "GetMFADevice")
	if unsupported["errorCode"] != "NotImplemented" || unsupported["readOnly"] != true {
		t.Fatalf("unsupported modeled outcome: %#v", unsupported)
	}
}

func TestCloudTrailIAMInternalServiceLinkedRoleAtomicOutcome(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "linked.sqlite"))
			}
			failure := &iamAuditAppendFailure{Storage: backends.Journal, operation: "CreateServiceLinkedRole"}
			backends.Journal = failure
			source := clock.NewManual(time.Date(2026, 9, 13, 15, 0, 0, 0, time.UTC))
			_, c, _ := startEventDeliveryCloud(t, backends, source)
			keys := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			client, trails := c.iam(eventDeliveryAccount, "test", ""), trailNativeClient(c)
			failure.fail.Store(true)
			_, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
			if err == nil {
				t.Fatal("failed internal IAM audit committed KMS key")
			}
			var response interface{ ServiceRequestID() string }
			if !errors.As(err, &response) {
				t.Fatal(err)
			}
			rejected := auditLatestRecord(t, trails, "CreateServiceLinkedRole")
			if rejected["requestID"] == response.ServiceRequestID() || rejected["errorCode"] == nil || rejected["responseElements"] != nil {
				t.Fatalf("lost internal IAM rejection after KMS rollback: %#v", rejected)
			}
			_, err = client.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("AWSServiceRoleForKeyManagementServiceMultiRegionKeys")})
			assertAPIError(t, err, "NoSuchEntity")
			listed, err := keys.ListKeys(t.Context(), &kms.ListKeysInput{})
			if err != nil || len(listed.Keys) != 0 {
				t.Fatalf("joint IAM/KMS rollback left a key: %+v %v", listed, err)
			}
			source.Advance(time.Second)
			created, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			id, _ := awsmiddleware.GetRequestIDMetadata(created.ResultMetadata)
			success := auditLatestRecord(t, trails, "CreateServiceLinkedRole")
			if success["requestID"] == id || success["errorCode"] != nil || success["responseElements"] == nil {
				t.Fatalf("missing internal IAM success: %#v", success)
			}
			// A second KMS key borrows the existing role. That internal lookup
			// is not a second CreateServiceLinkedRole command.
			if _, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{MultiRegion: aws.Bool(true)}); err != nil {
				t.Fatal(err)
			}
			history, err := trails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("CreateServiceLinkedRole")}}})
			if err != nil {
				t.Fatal(err)
			}
			if len(history.Events) != 2 {
				t.Fatalf("existing-role lookup invented an IAM command: %+v", history)
			}
		})
	}
}

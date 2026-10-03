package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage"
)

func TestCloudTrailSTSNativeCredentialProjections(t *testing.T) {
	native := map[string]map[string]any{}
	for _, event := range auditNativeRecords(t, "service_management_events") {
		if event["eventSource"] != "sts.amazonaws.com" {
			continue
		}
		action := event["eventName"].(string)
		if action == "GetWebIdentityToken" {
			if event["errorCode"] != "OutboundWebIdentityFederationDisabledException" {
				continue
			}
		} else if event["errorCode"] != nil {
			continue
		}
		if action == "AssumeRole" {
			if event["requestParameters"].(map[string]any)["sourceIdentity"] == nil {
				continue
			}
		}
		if native[action] != nil {
			continue
		}
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var normalized map[string]any
		if err := json.Unmarshal([]byte(strings.ReplaceAll(string(body), "000000000000", eventDeliveryAccount)), &normalized); err != nil {
			t.Fatal(err)
		}
		native[action] = normalized
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
			}
			epoch := time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)
			_, c, _ := startEventDeliveryCloud(t, backends, clock.NewManual(epoch))
			client, trails := c.sts(eventDeliveryAccount, "test", ""), trailNativeClient(c)
			for _, action := range []string{"GetCallerIdentity", "AssumeRole", "GetFederationToken", "GetSessionToken", "GetWebIdentityToken"} {
				t.Run(action, func(t *testing.T) {
					want := native[action]
					if want == nil {
						t.Fatalf("missing native %s record", action)
					}
					// Copy each expectation: provider identities and service time differ,
					// but member presence, classification, policy strings and names do not.
					body, err := json.Marshal(want)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(body, &want); err != nil {
						t.Fatal(err)
					}
					caller := client
					if action == "AssumeRole" {
						roleARN := want["requestParameters"].(map[string]any)["roleArn"].(string)
						resource := strings.SplitN(roleARN, ":role/", 2)[1]
						name, path := resource, "/"
						if slash := strings.LastIndex(resource, "/"); slash >= 0 {
							name, path = resource[slash+1:], "/"+resource[:slash+1]
						}
						trust := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + eventDeliveryAccount + `:root"},"Action":["sts:AssumeRole","sts:SetSourceIdentity"]}}`
						if _, err := c.iam(eventDeliveryAccount, "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: &name, Path: &path, AssumeRolePolicyDocument: &trust}); err != nil {
							t.Fatal(err)
						}
					}
					if action == "GetWebIdentityToken" {
						_, key, secret := c.user(t, eventDeliveryAccount, "outbound-audit")
						putUserPolicy(t, c.iam(eventDeliveryAccount, "test", ""), "outbound-audit", allow(`"sts:GetWebIdentityToken"`, "*"))
						caller = c.sts(key, secret, "")
					}
					input := want["requestParameters"]
					if input == nil {
						input = map[string]any{}
					}
					encoded, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					result, callErr := awstest.CallSDK(t.Context(), caller, action, encoded)
					var id string
					if code, rejected := want["errorCode"].(string); rejected {
						assertAPIError(t, callErr, code)
						var response *smithyhttp.ResponseError
						if !errors.As(callErr, &response) {
							t.Fatal(callErr)
						}
						id = response.Response.Header.Get("x-amzn-RequestId")
					} else {
						if callErr != nil {
							t.Fatal(callErr)
						}
						metadata := reflect.ValueOf(result).Elem().FieldByName("ResultMetadata").Interface().(middleware.Metadata)
						id, _ = awsmiddleware.GetRequestIDMetadata(metadata)
					}
					if id == "" {
						t.Fatal("missing SDK request correlation")
					}
					got := auditLookupRecord(t, trails, id, action)
					for _, key := range []string{"eventSource", "eventName", "requestParameters", "readOnly", "eventCategory", "managementEvent", "resources", "errorCode"} {
						if !reflect.DeepEqual(got[key], want[key]) {
							t.Fatalf("%s: got %#v; native %#v", key, got[key], want[key])
						}
					}
					if want["responseElements"] == nil {
						if got["responseElements"] != nil {
							t.Fatalf("native null response became %#v", got["responseElements"])
						}
						return
					}
					public := map[string]any{}
					body, err = json.Marshal(result)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(body, &public); err != nil {
						t.Fatal(err)
					}
					response := want["responseElements"].(map[string]any)
					creds := response["credentials"].(map[string]any)
					sdkCreds := public["Credentials"].(map[string]any)
					creds["accessKeyId"], creds["expiration"] = sdkCreds["AccessKeyId"], epoch.Add(15*time.Minute).Format(time.RFC3339)
					// AWS logs this token; stackd deliberately never does. AWS's packed
					// session diagnostics describe a different credential representation.
					delete(creds, "sessionToken")
					delete(response, "sessionTokenSize")
					delete(response, "sessionTokenUtilization")
					if _, ok := response["packedPolicySize"]; ok {
						response["packedPolicySize"] = public["PackedPolicySize"]
					}
					if role, ok := response["assumedRoleUser"].(map[string]any); ok {
						issued := public["AssumedRoleUser"].(map[string]any)
						role["assumedRoleId"] = issued["AssumedRoleId"]
					}
					if !reflect.DeepEqual(got["responseElements"], response) {
						t.Fatalf("credential projection: got %#v; native public %#v", got["responseElements"], response)
					}
					journalRows, err := backends.Journal.Read(t.Context(), 0, 1000)
					if err != nil {
						t.Fatal(err)
					}
					journalBody := journalJSON(t, journalRows)
					for _, secret := range []string{sdkCreds["SecretAccessKey"].(string), sdkCreds["SessionToken"].(string)} {
						if strings.Contains(journalBody, secret) {
							t.Fatal("issued session secret entered journal")
						}
					}
				})
			}
		})
	}
}

type stsRejectingAuditJournal struct {
	journal.Storage
	fail atomic.Bool
}

func (j *stsRejectingAuditJournal) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := j.Storage.AppendAPICallCompleted(ctx, envelope, call); err != nil {
		return err
	}
	if call.EventSource == "sts.amazonaws.com" && call.ErrorCode == "" && j.fail.CompareAndSwap(true, false) {
		return errors.New("injected STS audit append failure")
	}
	return nil
}

func TestCloudTrailSTSFailedAuditRollsBackIssuedCredential(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "state.sqlite"))
			}
			failure := &stsRejectingAuditJournal{Storage: backends.Journal}
			backends.Journal = failure
			f := newSignedAuthorityFixture(t, backends)
			failure.fail.Store(true)
			out, err := f.issue(t.Context(), "GetSessionToken")
			assertAPIError(t, err, "InternalFailure")
			if out != nil || f.sessionCount(t) != 0 {
				t.Fatal("failed CloudTrail append published a credential")
			}
			rows, err := backends.Journal.Read(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if call := row.APICallCompleted; call != nil && call.EventSource == "sts.amazonaws.com" && call.ErrorCode == "" {
					t.Fatal("rolled-back issuance retained successful audit")
				}
			}
			if _, err := f.issue(t.Context(), "GetSessionToken"); err != nil {
				t.Fatal(err)
			}
			if f.sessionCount(t) != 1 {
				t.Fatal("successful retry did not publish exactly one credential")
			}
		})
	}
}

func TestCloudTrailSTSFederationRejectionsNeverLogAssertions(t *testing.T) {
	_, c, _ := startEventDeliveryCloud(t, storage.NewMemory(), clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)))
	client, trails := c.sts(eventDeliveryAccount, "test", ""), trailNativeClient(c)
	role := "arn:aws:iam::" + eventDeliveryAccount + ":role/missing"
	for _, tc := range []struct {
		action, input string
		readOnly      bool
	}{
		{"AssumeRoleWithWebIdentity", `{"RoleArn":"` + role + `","RoleSessionName":"audit","WebIdentityToken":"private-federation-assertion"}`, true},
		{"AssumeRoleWithSAML", `{"RoleArn":"` + role + `","PrincipalArn":"arn:aws:iam::` + eventDeliveryAccount + `:saml-provider/missing","SAMLAssertion":"private-federation-assertion"}`, true},
		{"AssumeRoot", `{"TargetPrincipal":"` + eventDeliveryAccount + `","TaskPolicyArn":{"Arn":"arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials"}}`, false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			_, err := awstest.CallSDK(t.Context(), client, tc.action, json.RawMessage(tc.input))
			var response *smithyhttp.ResponseError
			if !errors.As(err, &response) {
				t.Fatalf("expected modeled HTTP rejection: %v", err)
			}
			got := auditLookupRecord(t, trails, response.Response.Header.Get("x-amzn-RequestId"), tc.action)
			if got["readOnly"] != tc.readOnly || got["eventCategory"] != "Management" || got["responseElements"] != nil {
				t.Fatalf("STS rejection classification: %#v", got)
			}
			body, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "private-federation-assertion") {
				t.Fatal("failed federation assertion entered CloudTrail")
			}
		})
	}
	issued, err := client.GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.GetAccessKeyInfo(t.Context(), &sts.GetAccessKeyInfoInput{AccessKeyId: issued.Credentials.AccessKeyId})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := awsmiddleware.GetRequestIDMetadata(info.ResultMetadata)
	got := auditLookupRecord(t, trails, id, "GetAccessKeyInfo")
	if got["readOnly"] != true || got["responseElements"] != nil || got["eventCategory"] != "Management" {
		t.Fatalf("access-key read did not retain null native response: %#v", got)
	}
}

func TestCloudTrailSTSCrossAccountOutcomesShareIdentity(t *testing.T) {
	// IAM's native CloudTrail cross-account examples specify two successful
	// records and no target-account record for a denied assumption.
	_, c, _ := startEventDeliveryCloud(t, storage.NewMemory(), clock.NewManual(time.Date(2026, 9, 13, 19, 0, 0, 0, time.UTC)))
	const target = "222222222222"
	trust := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + eventDeliveryAccount + `:root"},"Action":["sts:AssumeRole","sts:SetSourceIdentity"]}}`
	role, err := c.iam(target, "test", "").CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("cross-account-audit"), AssumeRolePolicyDocument: &trust})
	if err != nil {
		t.Fatal(err)
	}
	client, trails := c.sts(eventDeliveryAccount, "test", ""), trailNativeClient(c)
	input := &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("audit"), SourceIdentity: aws.String("verified-source")}
	issued, err := client.AssumeRole(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := awsmiddleware.GetRequestIDMetadata(issued.ResultMetadata)
	caller := auditLookupRecord(t, trails, id, "AssumeRole")
	options := trails.Options()
	options.Credentials = credentials.NewStaticCredentialsProvider(target, "test", "")
	targetTrails := cloudtrail.New(options)
	owner := auditLookupRecord(t, targetTrails, id, "AssumeRole")
	if caller["sharedEventID"] == nil || caller["sharedEventID"] == "" || caller["sharedEventID"] != owner["sharedEventID"] || caller["eventID"] == owner["eventID"] {
		t.Fatal("cross-account records lost shared request correlation", caller, owner)
	}
	if caller["recipientAccountId"] != eventDeliveryAccount || owner["recipientAccountId"] != target {
		t.Fatal("cross-account records stored in wrong recipient scope")
	}
	identity := owner["userIdentity"].(map[string]any)
	if identity["type"] != "AWSAccount" || identity["accountId"] != eventDeliveryAccount || identity["arn"] != nil || identity["accessKeyId"] != nil {
		t.Fatalf("target view disclosed caller credentials: %#v", identity)
	}
	deny := `{"Statement":{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`
	if _, err := c.iam(target, "test", "").UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: role.Role.RoleName, PolicyDocument: &deny}); err != nil {
		t.Fatal(err)
	}
	_, err = client.AssumeRole(t.Context(), input)
	assertAPIError(t, err, "AccessDenied")
	var response *smithyhttp.ResponseError
	if !errors.As(err, &response) {
		t.Fatal(err)
	}
	rejected := auditLookupRecord(t, trails, response.Response.Header.Get("x-amzn-RequestId"), "AssumeRole")
	if rejected["errorCode"] != "AccessDenied" || rejected["sharedEventID"] != nil {
		t.Fatal("caller rejection lost native account boundary", rejected)
	}
	history, err := targetTrails.LookupEvents(t.Context(), &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String("AssumeRole")}}})
	if err != nil || len(history.Events) != 1 {
		t.Fatalf("denied assumption leaked into target history: %+v %v", history, err)
	}
}

package stackd_test

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/identity"
	"stackd/internal/integrations"
	ec2service "stackd/internal/services/ec2"
	iamservice "stackd/internal/services/iam"
	domain "stackd/storage/ec2"
)

type intrinsicNativeMetadata struct {
	Path        string          `json:"path"`
	Status      int             `json:"status"`
	Body        json.RawMessage `json:"body"`
	ContentType string          `json:"content_type"`
}

type intrinsicNativeCall struct {
	Actor, Service, Action, Body string
	Status                       int
}

type ec2DeliveredCredential struct {
	Code, Type, AccessKeyId, SecretAccessKey, Token, LastUpdated, Expiration string
}

func startEC2CredentialCloud(t *testing.T, config stackd.Config, key domain.ResourceKey) (*stackd.Stack, *httptest.Server, http.Handler) {
	t.Helper()
	store := identity.NewWithConfig(identity.Config{AccountID: config.AccountID, Clock: config.Clock, Repository: iamservice.NewCredentialRepository(config.Storage.IAM, nil)})
	iamOwner := iamservice.NewWithConfig(iamservice.Config{Repository: config.Storage.IAM, Credentials: store, Clock: config.Clock})
	roles := integrations.ServiceRoles{IAM: iamOwner, Credentials: store, Authorizer: authorization.NewWithClock(iamOwner, nil, config.Clock)}
	owner := ec2service.New(ec2service.Config{Repository: config.Storage.EC2, Clock: config.Clock, InstanceProfiles: &integrations.EC2InstanceProfiles{IAM: iamOwner, Roles: roles}, InstanceIdentities: &integrations.EC2InstanceIdentityCredentials{IAM: iamOwner, Credentials: store}})
	cloud, err := stackd.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return cloud, httptest.NewServer(cloud), owner.InstanceMetadataHandler(key)
}

func ec2CredentialAuditIdentity(t *testing.T, clients cloudClients, account, region string, c ec2DeliveredCredential) (*sts.GetCallerIdentityOutput, map[string]any) {
	t.Helper()
	out, err := clients.sts(c.AccessKeyId, c.SecretAccessKey, c.Token).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	if err != nil {
		t.Fatal(err)
	}
	requestID, ok := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
	if !ok {
		t.Fatal("signed identity response lacks request correlation")
	}
	trails := cloudtrail.New(cloudtrail.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
	audited := auditLookupRecord(t, trails, requestID, "GetCallerIdentity")["userIdentity"].(map[string]any)
	return out, audited
}

// Native metadata is an expectation, not a credential source. The local metadata
// owner issues fresh signing material through the production IAM repository; the
// SDK then uses those bytes against the assembled STS/SQS authentication paths.
func TestEC2NativeIntrinsicIdentityCredentials(t *testing.T) {
	var fixture struct {
		Account, Region string
		Owned           struct{ Instances []string }
		Calls           []struct {
			Label  string
			Output struct {
				Instances []struct{ LaunchTime time.Time }
			}
		}
		GuestObservations []struct {
			Guest struct {
				ProfileDirectoryStatus int    `json:"profile_directory_status"`
				ErrorType              string `json:"error_type"`
				Metadata               []intrinsicNativeMetadata
				Signed                 []intrinsicNativeCall
			}
		} `json:"guest_observations"`
	}
	awsReadFixture(t, "ec2/instance_identity_credentials.json", &fixture)
	var auditFixture struct {
		Events []struct {
			Actor string
			Event struct{ UserIdentity map[string]any }
		}
	}
	awsReadFixture(t, "ec2/instance_identity_credentials_audit.json", &auditFixture)
	var nativeAuditIdentity map[string]any
	var nativeProfileScope any
	for _, event := range auditFixture.Events {
		if event.Actor == "intrinsic" && nativeAuditIdentity == nil {
			nativeAuditIdentity = event.Event.UserIdentity
		}
		if event.Actor == "profile" && nativeProfileScope == nil {
			nativeProfileScope = event.Event.UserIdentity["inScopeOf"]
		}
	}
	if nativeAuditIdentity == nil || nativeProfileScope == nil {
		t.Fatal("native credential audit observations unavailable")
	}
	var observedMetadata []intrinsicNativeMetadata
	var observedCalls []intrinsicNativeCall
	for _, row := range fixture.GuestObservations {
		ready := false
		for _, call := range row.Guest.Signed {
			ready = ready || (call.Actor == "intrinsic" && call.Action == "GetCallerIdentity" && call.Status == http.StatusOK)
		}
		if row.Guest.ProfileDirectoryStatus == http.StatusNotFound && ready && row.Guest.ErrorType == "" {
			observedMetadata, observedCalls = row.Guest.Metadata, row.Guest.Signed
			break
		}
	}
	if len(observedMetadata) == 0 {
		t.Fatal("native profile-independent metadata is missing")
	}
	var nativeCredential struct{ Code, Type, LastUpdated, Expiration string }
	var nativeInfo struct{ Code, LastUpdated, AccountId string }
	for _, row := range observedMetadata {
		if strings.HasSuffix(row.Path, "/ec2-instance") {
			if err := json.Unmarshal(row.Body, &nativeCredential); err != nil {
				t.Fatal(err)
			}
		}
		if strings.HasSuffix(row.Path, "/info") {
			var body string
			if err := json.Unmarshal(row.Body, &body); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(body), &nativeInfo); err != nil {
				t.Fatal(err)
			}
		}
	}
	epoch, err := time.Parse(time.RFC3339, nativeCredential.LastUpdated)
	if err != nil {
		t.Fatal(err)
	}
	infoLastUpdated, err := time.Parse(time.RFC3339, nativeInfo.LastUpdated)
	if err != nil {
		t.Fatal(err)
	}
	var launchTime time.Time
	for _, call := range fixture.Calls {
		if call.Label == "launch-without-profile" && len(call.Output.Instances) == 1 {
			launchTime = call.Output.Instances[0].LaunchTime
		}
	}
	if launchTime.IsZero() {
		t.Fatal("native launch observation unavailable")
	}
	var nativeIdentity struct {
		Result struct{ Account, Arn, UserId string } `xml:"GetCallerIdentityResult"`
	}
	nativeCodes := map[string]string{}
	nativeStatuses := map[string]int{}
	for _, row := range observedCalls {
		if row.Actor != "intrinsic" {
			continue
		}
		nativeStatuses[row.Action] = row.Status
		if row.Action == "GetCallerIdentity" && row.Status == http.StatusOK {
			if err := xml.Unmarshal([]byte(row.Body), &nativeIdentity); err != nil {
				t.Fatal(err)
			}
		} else if row.Service == "sts" {
			var failure struct{ Error struct{ Code string } }
			if err := xml.Unmarshal([]byte(row.Body), &failure); err != nil {
				t.Fatal(err)
			}
			nativeCodes[row.Action] = failure.Error.Code
		} else {
			var failure struct {
				Type string `json:"__type"`
			}
			if err := json.Unmarshal([]byte(row.Body), &failure); err != nil {
				t.Fatal(err)
			}
			_, code, found := strings.Cut(failure.Type, "#")
			if !found {
				code = failure.Type
			}
			nativeCodes[row.Action] = code
		}
	}
	if nativeIdentity.Result.Arn == "" || nativeCodes["SendMessage"] == "" || nativeCodes["GetSessionToken"] == "" {
		t.Fatal("native signed admission evidence incomplete")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			manual := clock.NewManual(epoch)
			key := domain.ResourceKey{Scope: domain.Scope{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region}, ID: fixture.Owned.Instances[0]}
			var repository domain.Repository
			var metadata http.Handler
			var cloud *stackd.Stack
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: manual}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				repository = config.Storage.EC2
				var server *httptest.Server
				cloud, server, metadata = startEC2CredentialCloud(t, config, key)
				return cloud, server
			})
			if err := repository.Update(ctx, func(tx domain.Transaction) error {
				return tx.PutInstance(domain.InstanceRecord{Key: key, IdentityInfoLastUpdated: infoLastUpdated, Data: api.Instance{InstanceId: new(api.String(key.ID)), LaunchTime: &launchTime, State: &api.InstanceState{Name: new(api.InstanceStateName("running")), Code: new(api.Integer(16))}, MetadataOptions: &api.InstanceMetadataOptionsResponse{HttpEndpoint: new(api.InstanceMetadataEndpointState("enabled")), HttpTokens: new(api.HttpTokensState("optional"))}}})
			}); err != nil {
				t.Fatal(err)
			}
			get := func(path string) *httptest.ResponseRecorder {
				t.Helper()
				response := httptest.NewRecorder()
				metadata.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/"+path, nil))
				return response
			}
			for _, row := range observedMetadata {
				response := get(row.Path)
				if response.Code != row.Status {
					t.Fatalf("%s HTTP %d; native %d", row.Path, response.Code, row.Status)
				}
				if response.Header().Get("Content-Type") != row.ContentType {
					t.Fatalf("%s content type %q; native %q", row.Path, response.Header().Get("Content-Type"), row.ContentType)
				}
				if strings.HasSuffix(row.Path, "/ec2-instance") {
					continue
				}
				if strings.HasSuffix(row.Path, "/info") {
					var got struct{ Code, LastUpdated, AccountId string }
					if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
						t.Fatal(err)
					}
					if got != nativeInfo {
						t.Fatalf("intrinsic info = %+v, native %+v", got, nativeInfo)
					}
					continue
				}
				var body string
				if err := json.Unmarshal(row.Body, &body); err != nil {
					t.Fatal(err)
				}
				if response.Body.String() != body {
					t.Fatalf("%s directory %q; native %q", row.Path, response.Body.String(), body)
				}
			}
			readCredential := func() ec2DeliveredCredential {
				t.Helper()
				response := get("identity-credentials/ec2/security-credentials/ec2-instance")
				if response.Code != http.StatusOK {
					t.Fatalf("intrinsic credential HTTP %d", response.Code)
				}
				var result ec2DeliveredCredential
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			first := readCredential()
			if first.Code != nativeCredential.Code || first.Type != nativeCredential.Type || first.LastUpdated != nativeCredential.LastUpdated {
				t.Fatal("intrinsic credential public fields differ from native")
			}
			assertIdentity := func(c ec2DeliveredCredential) {
				t.Helper()
				out, audited := ec2CredentialAuditIdentity(t, clients, fixture.Account, fixture.Region, c)
				if aws.ToString(out.Account) != nativeIdentity.Result.Account || aws.ToString(out.Arn) != nativeIdentity.Result.Arn || aws.ToString(out.UserId) != nativeIdentity.Result.UserId {
					t.Fatalf("signed identity differs from native: %v", out)
				}
				for _, field := range []string{"type", "principalId", "arn", "accountId", "inScopeOf"} {
					if !reflect.DeepEqual(audited[field], nativeAuditIdentity[field]) {
						t.Fatalf("intrinsic audit %s = %#v; native %#v", field, audited[field], nativeAuditIdentity[field])
					}
				}
				issuer := audited["sessionContext"].(map[string]any)["sessionIssuer"]
				if !reflect.DeepEqual(issuer, nativeAuditIdentity["sessionContext"].(map[string]any)["sessionIssuer"]) {
					t.Fatal("intrinsic audit issuer differs from native")
				}
			}
			assertNativeError := func(action string, err error) {
				t.Helper()
				assertAPIError(t, err, nativeCodes[action])
				var response *smithyhttp.ResponseError
				if !errors.As(err, &response) || response.HTTPStatusCode() != nativeStatuses[action] {
					t.Fatalf("%s HTTP status differs from native: %v", action, err)
				}
			}
			assertIdentity(first)
			_, err := clients.sts(first.AccessKeyId, first.SecretAccessKey+"tampered", first.Token).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			assertAPIError(t, err, "SignatureDoesNotMatch")
			_, err = clients.sts(first.AccessKeyId, first.SecretAccessKey, first.Token+"tampered").GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			assertAPIError(t, err, "InvalidClientTokenId")
			_, err = clients.sts(first.AccessKeyId, first.SecretAccessKey, first.Token).GetSessionToken(ctx, &sts.GetSessionTokenInput{})
			assertNativeError("GetSessionToken", err)
			root := clients.sqs(fixture.Account, "test", "")
			queue, err := root.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("intrinsic-boundary")})
			if err != nil {
				t.Fatal(err)
			}
			queueARN := "arn:aws:sqs:" + fixture.Region + ":" + fixture.Account + ":intrinsic-boundary"
			grant := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"` + queueARN + `","Condition":{"StringEquals":{"aws:PrincipalAccount":"` + fixture.Account + `"}}}]}`
			if _, err := root.SetQueueAttributes(ctx, &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": grant}}); err != nil {
				t.Fatal(err)
			}
			identityClient := clients.iam(fixture.Account, "test", "")
			_, err = clients.sqs(first.AccessKeyId, first.SecretAccessKey, first.Token).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("intrinsic-rejected")})
			assertNativeError("SendMessage", err)
			profileName := "intrinsic-independent-profile"
			if _, err := identityClient.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String(profileName), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`)}); err != nil {
				t.Fatal(err)
			}
			if _, err := identityClient.CreateInstanceProfile(ctx, &iam.CreateInstanceProfileInput{InstanceProfileName: aws.String(profileName)}); err != nil {
				t.Fatal(err)
			}
			if _, err := identityClient.AddRoleToInstanceProfile(ctx, &iam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String(profileName), RoleName: aws.String(profileName)}); err != nil {
				t.Fatal(err)
			}
			ec2Client := sdkec2.New(sdkec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			if _, err := ec2Client.AssociateIamInstanceProfile(ctx, &sdkec2.AssociateIamInstanceProfileInput{InstanceId: aws.String(key.ID), IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: aws.String(profileName)}}); err != nil {
				t.Fatal(err)
			}
			if err := manual.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := cloud.RunDueJobs(ctx, 100); err != nil {
				t.Fatal(err)
			}
			withProfile := readCredential()
			assertIdentity(withProfile)
			profileResponse := get("iam/security-credentials/" + profileName)
			if profileResponse.Code != http.StatusOK {
				t.Fatalf("profile credentials HTTP %d", profileResponse.Code)
			}
			var profile ec2DeliveredCredential
			if err := json.Unmarshal(profileResponse.Body.Bytes(), &profile); err != nil {
				t.Fatal(err)
			}
			_, profileAudit := ec2CredentialAuditIdentity(t, clients, fixture.Account, fixture.Region, profile)
			if !reflect.DeepEqual(profileAudit["inScopeOf"], nativeProfileScope) {
				t.Fatalf("profile credential audit scope = %#v; native %#v", profileAudit["inScopeOf"], nativeProfileScope)
			}
			// The same resource grant authorizes the distinct attached profile,
			// not the intrinsic identity before or after profile publication.
			if _, err := clients.sqs(profile.AccessKeyId, profile.SecretAccessKey, profile.Token).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("profile-control")}); err != nil {
				t.Fatal(err)
			}
			_, err = clients.sqs(withProfile.AccessKeyId, withProfile.SecretAccessKey, withProfile.Token).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("intrinsic-still-rejected")})
			assertNativeError("SendMessage", err)
			clients = reopen()
			retained := readCredential()
			if retained.AccessKeyId != withProfile.AccessKeyId || retained.SecretAccessKey != withProfile.SecretAccessKey || retained.Token != withProfile.Token {
				t.Fatal("controller restart replaced live intrinsic delivery")
			}
			assertIdentity(retained)
			expiration, err := time.Parse(time.RFC3339, retained.Expiration)
			if err != nil {
				t.Fatal(err)
			}
			if err := manual.Advance(expiration.Sub(manual.Now())); err != nil {
				t.Fatal(err)
			}
			_, err = clients.sts(retained.AccessKeyId, retained.SecretAccessKey, retained.Token).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			assertAPIError(t, err, "ExpiredToken")
			fresh := readCredential()
			if fresh.AccessKeyId == retained.AccessKeyId {
				t.Fatal("expired intrinsic credential was redelivered")
			}
			assertIdentity(fresh)
		})
	}
}

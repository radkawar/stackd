//go:build linux

package stackd_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"syscall"
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
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
)

type ec2DeliveryKey struct {
	Actor           string
	MetadataVersion int `json:"metadata_version"`
}

type ec2DeliveryCall struct {
	ec2DeliveryKey
	Service, Action, Source, Body string
	Status                        int
	RequestID                     string `json:"request_id"`
}

type ec2DeliveryObservation struct {
	Phase    string
	Metadata []struct {
		ec2DeliveryKey
		Status int
		Public struct{ Code, Type string }
	}
	Comparisons []struct {
		Actor          string
		AccessKeyEqual bool `json:"AccessKeyId_equal"`
		SecretEqual    bool `json:"SecretAccessKey_equal"`
		TokenEqual     bool `json:"Token_equal"`
	}
	Signed []ec2DeliveryCall
}

// Token PUT uses the accepted TCP socket, not a recorder that pretends to set
// a hop limit. This loopback transport does not prove guest routing or packet TTL.
type ec2DeliverySocketWriter struct {
	http.ResponseWriter
	connection *net.TCPConn
}

func (w ec2DeliverySocketWriter) SetHopLimit(limit int) error {
	connection, err := w.connection.SyscallConn()
	if err != nil {
		return err
	}
	var optionError error
	if err := connection.Control(func(fd uintptr) {
		optionError = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, limit)
	}); err != nil {
		return err
	}
	if optionError == nil {
		w.Header().Set("Connection", "close")
	}
	return optionError
}

func ec2CredentialMetadataServer(t *testing.T, metadata *http.Handler) (*httptest.Server, string) {
	t.Helper()
	type connectionKey struct{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection := r.Context().Value(connectionKey{}).(*net.TCPConn)
		(*metadata).ServeHTTP(ec2DeliverySocketWriter{ResponseWriter: w, connection: connection}, r)
	}))
	server.Config.ConnContext = func(ctx context.Context, connection net.Conn) context.Context {
		return context.WithValue(ctx, connectionKey{}, connection)
	}
	server.Start()
	t.Cleanup(server.Close)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+"/latest/api/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "3600")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	token, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("real IMDS token PUT: HTTP %d, %v", response.StatusCode, err)
	}
	return server, string(token)
}

func ec2NativeJSON(options *sqs.Options) {
	options.APIOptions = append(options.APIOptions, func(stack *middleware.Stack) error {
		return stack.Build.Add(middleware.BuildMiddlewareFunc("NativeJSON", func(ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
			input.Request.(*smithyhttp.Request).Header.Del("X-Amzn-Query-Mode")
			return next.HandleBuild(ctx, input)
		}), middleware.After)
	})
}

func TestEC2NativeCredentialDeliveryVersions(t *testing.T) {
	var fixture struct {
		Account, Region string
		CapturedAt      time.Time `json:"captured_at"`
		Owned           struct{ Instances []string }
		Calls           []struct {
			Label string
			Input json.RawMessage
		}
		GuestObservations []struct{ Guest ec2DeliveryObservation } `json:"guest_observations"`
	}
	awsReadFixture(t, "ec2/credential_delivery_versions.json", &fixture)
	var auditFixture struct {
		Events []struct {
			ec2DeliveryKey
			Source string
			Event  struct {
				RequestID    string
				UserIdentity map[string]any
			}
		}
	}
	awsReadFixture(t, "ec2/credential_delivery_versions_audit.json", &auditFixture)
	nativeAudit := map[string]map[string]any{}
	for _, row := range auditFixture.Events {
		nativeAudit[row.Event.RequestID] = row.Event.UserIdentity
	}
	// Three optional samples repeat the same paths. Exercise one plus the
	// required transition and its retained-token calls, not copied observations.
	phases := map[string]ec2DeliveryObservation{}
	for _, row := range fixture.GuestObservations {
		if _, exists := phases[row.Guest.Phase]; !exists {
			phases[row.Guest.Phase] = row.Guest
		}
	}
	if len(fixture.Owned.Instances) != 1 || len(phases["optional"].Metadata) != 4 || len(phases["required"].Metadata) != 4 {
		t.Fatal("native credential delivery transitions are incomplete")
	}
	input := func(label string, out any) {
		t.Helper()
		for _, row := range fixture.Calls {
			if row.Label == label {
				if err := json.Unmarshal(row.Input, out); err != nil {
					t.Fatal(err)
				}
				return
			}
		}
		t.Fatalf("native input %q unavailable", label)
	}
	var createRole iam.CreateRoleInput
	var createProfile iam.CreateInstanceProfileInput
	var addRole iam.AddRoleToInstanceProfileInput
	var rolePolicy iam.PutRolePolicyInput
	var createQueue sqs.CreateQueueInput
	var queuePolicy sqs.SetQueueAttributesInput
	var requireV2 sdkec2.ModifyInstanceMetadataOptionsInput
	var launch struct {
		MetadataOptions api.InstanceMetadataOptionsResponse
	}
	input("owned-guest-role", &createRole)
	input("owned-profile", &createProfile)
	input("owned-profile-role", &addRole)
	input("owned-role-delivery-policy", &rolePolicy)
	input("owned-boundary-queue", &createQueue)
	input("owned-account-resource-grant", &queuePolicy)
	input("require-v2", &requireV2)
	input("launch-delivery-versions", &launch)

	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			manual := clock.NewManual(fixture.CapturedAt)
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
			tokenKey := make([]byte, 32)
			if _, err := rand.Read(tokenKey); err != nil {
				t.Fatal(err)
			}
			if err := repository.Update(ctx, func(tx domain.Transaction) error {
				options := api.CloneInstanceMetadataOptionsResponse(launch.MetadataOptions)
				return tx.PutInstance(domain.InstanceRecord{Key: key, MetadataTokenKey: tokenKey, Data: api.Instance{InstanceId: new(api.String(key.ID)), State: &api.InstanceState{Name: new(api.InstanceStateName("running")), Code: new(api.Integer(16))}, MetadataOptions: &options}})
			}); err != nil {
				t.Fatal(err)
			}
			identityClient := clients.iam(fixture.Account, "test", "")
			role, err := identityClient.CreateRole(ctx, &createRole)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identityClient.CreateInstanceProfile(ctx, &createProfile); err != nil {
				t.Fatal(err)
			}
			if _, err := identityClient.AddRoleToInstanceProfile(ctx, &addRole); err != nil {
				t.Fatal(err)
			}
			if _, err := identityClient.PutRolePolicy(ctx, &rolePolicy); err != nil {
				t.Fatal(err)
			}
			rootQueue := clients.sqs(fixture.Account, "test", "")
			queue, err := rootQueue.CreateQueue(ctx, &createQueue)
			if err != nil {
				t.Fatal(err)
			}
			grant := queuePolicy
			grant.QueueUrl = queue.QueueUrl
			if _, err := rootQueue.SetQueueAttributes(ctx, &grant); err != nil {
				t.Fatal(err)
			}
			ec2Client := sdkec2.New(sdkec2.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			if _, err := ec2Client.AssociateIamInstanceProfile(ctx, &sdkec2.AssociateIamInstanceProfileInput{InstanceId: aws.String(key.ID), IamInstanceProfile: &ec2types.IamInstanceProfileSpecification{Name: createProfile.InstanceProfileName}}); err != nil {
				t.Fatal(err)
			}
			if err := manual.Advance(time.Second); err != nil {
				t.Fatal(err)
			}
			if _, err := cloud.RunDueJobs(ctx, 100); err != nil {
				t.Fatal(err)
			}

			metadataServer, token := ec2CredentialMetadataServer(t, &metadata)
			paths := map[string]string{"intrinsic": "identity-credentials/ec2/security-credentials/ec2-instance", "profile": "iam/security-credentials/" + aws.ToString(createRole.RoleName)}
			fetch := func(t *testing.T, observation ec2DeliveryObservation) map[ec2DeliveryKey]ec2DeliveredCredential {
				t.Helper()
				result := map[ec2DeliveryKey]ec2DeliveredCredential{}
				for _, row := range observation.Metadata {
					request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataServer.URL+"/latest/meta-data/"+paths[row.Actor], nil)
					if err != nil {
						t.Fatal(err)
					}
					if row.MetadataVersion == 2 {
						request.Header.Set("X-aws-ec2-metadata-token", string(token))
					}
					response, err := metadataServer.Client().Do(request)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil || response.StatusCode != row.Status {
						t.Fatalf("%s %s/v%d metadata HTTP %d; native %d: %v", observation.Phase, row.Actor, row.MetadataVersion, response.StatusCode, row.Status, err)
					}
					if row.Status != http.StatusOK {
						continue
					}
					var delivered ec2DeliveredCredential
					if err := json.Unmarshal(body, &delivered); err != nil {
						t.Fatal(err)
					}
					if delivered.Code != row.Public.Code || delivered.Type != row.Public.Type {
						t.Fatalf("%s/v%d public credential status differs from native", row.Actor, row.MetadataVersion)
					}
					result[row.ec2DeliveryKey] = delivered
				}
				return result
			}
			retained := fetch(t, phases["optional"])
			for _, row := range phases["optional"].Comparisons {
				v1, v2 := retained[ec2DeliveryKey{row.Actor, 1}], retained[ec2DeliveryKey{row.Actor, 2}]
				if (v1.AccessKeyId == v2.AccessKeyId) != row.AccessKeyEqual || (v1.SecretAccessKey == v2.SecretAccessKey) != row.SecretEqual || (v1.Token == v2.Token) != row.TokenEqual {
					t.Errorf("%s v1/v2 credential material equality differs from native", row.Actor)
				}
			}
			assertAudit := func(t *testing.T, got, want map[string]any, c ec2DeliveredCredential, actor string) {
				t.Helper()
				wantedIssuer := want["sessionContext"].(map[string]any)["sessionIssuer"].(map[string]any)
				nativeRoleID := wantedIssuer["principalId"].(string)
				localValue := func(value any) any {
					if text, ok := value.(string); ok && actor == "profile" {
						return strings.ReplaceAll(text, nativeRoleID, aws.ToString(role.Role.RoleId))
					}
					return value
				}
				for _, field := range []string{"type", "principalId", "arn", "accountId", "inScopeOf"} {
					if !reflect.DeepEqual(got[field], localValue(want[field])) {
						t.Errorf("audit %s = %#v; native %#v", field, got[field], localValue(want[field]))
					}
				}
				gotContext, ok := got["sessionContext"].(map[string]any)
				if !ok {
					t.Fatal("EC2 credential audit lacks session context")
				}
				wantedDelivery := want["sessionContext"].(map[string]any)["ec2RoleDelivery"]
				if gotContext["ec2RoleDelivery"] != wantedDelivery {
					t.Errorf("audit ec2RoleDelivery = %#v; native %#v", gotContext["ec2RoleDelivery"], wantedDelivery)
				}
				gotIssuer, ok := gotContext["sessionIssuer"].(map[string]any)
				if !ok {
					t.Fatal("EC2 credential audit lacks issuer")
				}
				for field, value := range wantedIssuer {
					if gotIssuer[field] != localValue(value) {
						t.Errorf("audit issuer %s = %#v; native %#v", field, gotIssuer[field], localValue(value))
					}
				}
				if got["accessKeyId"] != c.AccessKeyId {
					t.Error("audit does not identify the credential used to sign the request")
				}
			}
			history := map[string]map[string]any{}
			principals := map[string]string{}
			replay := func(t *testing.T, observation ec2DeliveryObservation, current map[ec2DeliveryKey]ec2DeliveredCredential) {
				t.Helper()
				for _, row := range observation.Signed {
					t.Run(fmt.Sprintf("%s/v%d/%s/%s", row.Actor, row.MetadataVersion, row.Source, row.Action), func(t *testing.T) {
						c, ok := current[row.ec2DeliveryKey]
						if row.Source == "retained" {
							c, ok = retained[row.ec2DeliveryKey]
						}
						if !ok {
							t.Fatal("native signed call lacks delivered local credentials")
						}
						switch row.Action {
						case "GetCallerIdentity":
							out, audited := ec2CredentialAuditIdentity(t, clients, fixture.Account, fixture.Region, c)
							response, ok := awsmiddleware.GetRawResponse(out.ResultMetadata).(*smithyhttp.Response)
							if !ok || response.StatusCode != row.Status {
								t.Fatalf("STS HTTP response differs from native %d", row.Status)
							}
							var native struct {
								Result struct{ Account, Arn, UserId string } `xml:"GetCallerIdentityResult"`
							}
							if err := xml.Unmarshal([]byte(row.Body), &native); err != nil {
								t.Fatal(err)
							}
							userID := native.Result.UserId
							if row.Actor == "profile" {
								_, session, _ := strings.Cut(userID, ":")
								userID = aws.ToString(role.Role.RoleId) + ":" + session
							}
							if aws.ToString(out.Account) != native.Result.Account || aws.ToString(out.Arn) != native.Result.Arn || aws.ToString(out.UserId) != userID {
								t.Fatalf("STS principal differs from native: %v", out)
							}
							principal := aws.ToString(out.UserId)
							if previous, exists := principals[row.Actor]; exists && previous != principal {
								t.Error("delivery version or metadata enforcement changed the principal")
							}
							principals[row.Actor] = principal
							want, ok := nativeAudit[row.RequestID]
							if !ok {
								t.Fatal("native signed request has no exact CloudTrail join")
							}
							assertAudit(t, audited, want, c, row.Actor)
							requestID, _ := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
							history[requestID] = audited
						case "SendMessage":
							// The native guest signs JSON without query compatibility.
							// Keep that protocol when decoding its captured error codes.
							out, err := clients.sqs(c.AccessKeyId, c.SecretAccessKey, c.Token).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("delivery-version-boundary")}, ec2NativeJSON)
							if row.Status == http.StatusOK {
								if err != nil {
									t.Fatal(err)
								}
								response, ok := awsmiddleware.GetRawResponse(out.ResultMetadata).(*smithyhttp.Response)
								if !ok || response.StatusCode != row.Status {
									t.Fatalf("SQS HTTP response differs from native %d", row.Status)
								}
							} else {
								var native struct {
									Type string `json:"__type"`
								}
								if err := json.Unmarshal([]byte(row.Body), &native); err != nil {
									t.Fatal(err)
								}
								_, code, found := strings.Cut(native.Type, "#")
								if !found {
									code = native.Type
								}
								assertAPIError(t, err, code)
								var response *smithyhttp.ResponseError
								if !errors.As(err, &response) || response.HTTPStatusCode() != row.Status {
									t.Fatalf("SQS HTTP status differs from native %d: %v", row.Status, err)
								}
							}
						default:
							t.Fatalf("unhandled native signed action %q", row.Action)
						}
					})
				}
			}
			t.Run("optional", func(t *testing.T) { replay(t, phases["optional"], retained) })
			if _, err := ec2Client.ModifyInstanceMetadataOptions(ctx, &requireV2); err != nil {
				t.Fatal(err)
			}
			current := fetch(t, phases["required"])
			t.Run("required", func(t *testing.T) { replay(t, phases["required"], current) })

			// Ordinary temporary credentials must not inherit an EC2 delivery label.
			ordinary, err := clients.sts(fixture.Account, "test", "").GetSessionToken(ctx, &sts.GetSessionTokenInput{})
			if err != nil {
				t.Fatal(err)
			}
			out, audited := ec2CredentialAuditIdentity(t, clients, fixture.Account, fixture.Region, ec2DeliveredCredential{AccessKeyId: aws.ToString(ordinary.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(ordinary.Credentials.SecretAccessKey), Token: aws.ToString(ordinary.Credentials.SessionToken)})
			if session, ok := audited["sessionContext"].(map[string]any); ok {
				if _, present := session["ec2RoleDelivery"]; present {
					t.Error("ordinary temporary credential acquired an EC2 delivery label")
				}
			}
			requestID, _ := awsmiddleware.GetRequestIDMetadata(out.ResultMetadata)
			history[requestID] = audited

			clients = reopen()
			trails := cloudtrail.New(cloudtrail.Options{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			for requestID, before := range history {
				after := auditLookupRecord(t, trails, requestID, "GetCallerIdentity")["userIdentity"]
				if !reflect.DeepEqual(after, before) {
					t.Errorf("reopen changed retained credential audit origin for request %s", requestID)
				}
			}
			reopened := fetch(t, phases["required"])
			for source, before := range current {
				after := reopened[source]
				if before.AccessKeyId != after.AccessKeyId || before.SecretAccessKey != after.SecretAccessKey || before.Token != after.Token {
					t.Errorf("reopen replaced live %s/v%d metadata credentials", source.Actor, source.MetadataVersion)
				}
			}
			t.Run("reopened-required", func(t *testing.T) { replay(t, phases["required"], reopened) })
		})
	}
}

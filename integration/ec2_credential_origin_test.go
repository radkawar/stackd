//go:build linux

package stackd_test

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
)

func TestEC2NativeCredentialOriginContext(t *testing.T) {
	type observation struct {
		Complete bool
		Signed   []struct {
			ec2DeliveryCall
			ConditionCase string `json:"condition_case"`
		}
	}
	var fixture struct {
		Account, Region string
		CapturedAt      time.Time `json:"captured_at"`
		Owned           struct{ Instances []string }
		OriginFacts     struct {
			InstanceARN string `json:"instance_arn"`
			VPCID       string `json:"vpc_id"`
			PrivateIPv4 string `json:"private_ipv4"`
		} `json:"origin_facts"`
		Calls []struct {
			Label, Operation string
			Input            json.RawMessage
		}
		GuestObservations []struct{ Guest observation } `json:"guest_observations"`
	}
	awsReadFixture(t, "ec2/credential_origin_context.json", &fixture)
	var native observation
	for _, row := range fixture.GuestObservations {
		if row.Guest.Complete {
			native = row.Guest
			break
		}
	}
	if !native.Complete || len(fixture.Owned.Instances) != 1 {
		t.Fatal("native origin policy capture is incomplete")
	}
	inputs := map[string]json.RawMessage{}
	for _, row := range fixture.Calls {
		inputs[row.Label] = row.Input
	}
	input := func(label string, value any) {
		t.Helper()
		if err := json.Unmarshal(inputs[label], value); err != nil {
			t.Fatalf("native input %s: %v", label, err)
		}
	}
	var createRole iam.CreateRoleInput
	var createProfile iam.CreateInstanceProfileInput
	var addRole iam.AddRoleToInstanceProfileInput
	var rolePolicy iam.PutRolePolicyInput
	var queueGrant sqs.SetQueueAttributesInput
	var launch struct {
		MetadataOptions api.InstanceMetadataOptionsResponse
	}
	input("owned-guest-role", &createRole)
	input("owned-profile", &createProfile)
	input("owned-profile-role", &addRole)
	input("owned-origin-policy", &rolePolicy)
	input("owned-account-resource-grant", &queueGrant)
	input("launch-origin-context", &launch)
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
				return tx.PutInstance(domain.InstanceRecord{Key: key, MetadataTokenKey: tokenKey, Data: api.Instance{
					InstanceId: new(api.String(key.ID)), VpcId: new(api.String(fixture.OriginFacts.VPCID)), PrivateIpAddress: new(api.String(fixture.OriginFacts.PrivateIPv4)),
					State:           &api.InstanceState{Name: new(api.InstanceStateName("running")), Code: new(api.Integer(16))},
					MetadataOptions: &options,
				}})
			}); err != nil {
				t.Fatal(err)
			}
			identityClient := clients.iam(fixture.Account, "test", "")
			if _, err := identityClient.CreateRole(ctx, &createRole); err != nil {
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
			queues := map[string]*string{}
			rootQueue := clients.sqs(fixture.Account, "test", "")
			for _, row := range fixture.Calls {
				if row.Operation != "CreateQueue" {
					continue
				}
				label := strings.TrimPrefix(row.Label, "owned-queue-")
				if row.Label == "owned-boundary-queue" {
					label = "control"
				} else if label == row.Label {
					continue
				}
				var create sqs.CreateQueueInput
				input(row.Label, &create)
				out, err := rootQueue.CreateQueue(ctx, &create)
				if err != nil {
					t.Fatal(err)
				}
				queues[label] = out.QueueUrl
			}
			queueGrant.QueueUrl = queues["control"]
			if _, err := rootQueue.SetQueueAttributes(ctx, &queueGrant); err != nil {
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
			server, token := ec2CredentialMetadataServer(t, &metadata)
			delivered := map[int]ec2DeliveredCredential{}
			for _, version := range []int{1, 2} {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/latest/meta-data/iam/security-credentials/"+aws.ToString(createRole.RoleName), nil)
				if err != nil {
					t.Fatal(err)
				}
				if version == 2 {
					request.Header.Set("X-aws-ec2-metadata-token", token)
				}
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK {
					t.Fatalf("metadata v%d: HTTP %d, %v", version, response.StatusCode, err)
				}
				var credential ec2DeliveredCredential
				if err := json.Unmarshal(body, &credential); err != nil {
					t.Fatal(err)
				}
				delivered[version] = credential
			}
			replay := func(t *testing.T) {
				t.Helper()
				for _, row := range native.Signed {
					if row.Action != "SendMessage" {
						continue
					}
					t.Run(fmt.Sprintf("v%d/%s", row.MetadataVersion, row.ConditionCase), func(t *testing.T) {
						c := delivered[row.MetadataVersion]
						queue := queues[row.ConditionCase]
						if queue == nil {
							t.Fatalf("missing native queue case %s", row.ConditionCase)
						}
						out, err := clients.sqs(c.AccessKeyId, c.SecretAccessKey, c.Token).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue, MessageBody: aws.String("credential-origin")}, ec2NativeJSON)
						if row.Status == http.StatusOK {
							if err != nil {
								t.Fatal(err)
							}
							response, ok := awsmiddleware.GetRawResponse(out.ResultMetadata).(*smithyhttp.Response)
							if !ok || response.StatusCode != row.Status {
								t.Fatalf("SQS response differs from native HTTP %d", row.Status)
							}
						} else {
							var failure struct {
								Type string `json:"__type"`
							}
							if err := json.Unmarshal([]byte(row.Body), &failure); err != nil {
								t.Fatal(err)
							}
							code := failure.Type
							if _, suffix, ok := strings.Cut(code, "#"); ok {
								code = suffix
							}
							assertAPIError(t, err, code)
							var response *smithyhttp.ResponseError
							if !errors.As(err, &response) || response.HTTPStatusCode() != row.Status {
								t.Fatalf("SQS error differs from native HTTP %d: %v", row.Status, err)
							}
						}
					})
				}
			}
			t.Run("issued", replay)
			clients = reopen()
			for label, url := range queues {
				parsed := strings.LastIndexByte(*url, '/')
				out, err := clients.sqs(fixture.Account, "test", "").GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: aws.String((*url)[parsed+1:])})
				if err != nil {
					t.Fatal(err)
				}
				queues[label] = out.QueueUrl
			}
			t.Run("retained-after-reopen", replay)
		})
	}
}

package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	mqdomain "stackd/internal/services/mq"
)

// The API regression isolates control-plane replay on both repositories.
// create-identity in mq_standalone_smoke proves the actual native JMS effects.
type mqIdentityControlRuntime struct{}

func (mqIdentityControlRuntime) Ensure(_ context.Context, broker mqdomain.BrokerRecord) (mqdomain.Endpoint, error) {
	return mqdomain.Endpoint{NativeID: broker.ID, Address: "ssl://127.0.0.1:1", CAPEM: []byte("control-plane-fixture")}, nil
}
func (mqIdentityControlRuntime) Reboot(context.Context, mqdomain.BrokerRecord) (mqdomain.Endpoint, error) {
	return mqdomain.Endpoint{}, errors.New("unexpected reboot during control-plane replay")
}
func (mqIdentityControlRuntime) Delete(context.Context, mqdomain.BrokerRecord) error {
	return errors.New("unexpected deletion during control-plane replay")
}
func (mqIdentityControlRuntime) Close() error { return nil }

func TestMQNativeCreateBrokerIdentity(t *testing.T) {
	var fixture struct {
		Account, Region string
		Complete        bool
		Calls           []struct {
			Label, Operation, Code string
			Parameters             json.RawMessage
			HTTPStatus             int `json:"http_status"`
			Output                 struct {
				BrokerId, BrokerArn, EngineType string
				Error                           struct{ Code string }
				ErrorAttribute                  *string
			}
		}
	}
	awsReadFixture(t, "mq/create_identity.json", &fixture)
	if !fixture.Complete {
		t.Fatal("native CreateBroker identity capture is incomplete")
	}
	var nativeEngine string
	for _, row := range fixture.Calls {
		if row.Label == "after-mutation" {
			nativeEngine = row.Output.EngineType
		}
	}
	if nativeEngine == "" {
		t.Fatal("native broker description omitted EngineType")
	}
	const originalPassword = "Original-Identity-Password-123!"
	const changedPassword = "Changed-Identity-Password-456!"
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, MQRuntime: mqIdentityControlRuntime{}}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			clientFor := func(account, region string) *mq.Client {
				return mq.New(mq.Options{Region: region, BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			client := func(region string) *mq.Client { return clientFor(fixture.Account, region) }
			var id, arn, nativeID, nativeARN string
			var original mq.CreateBrokerInput
			var usernames []string
			waitRunning := func() {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for {
					current, err := client(fixture.Region).DescribeBroker(t.Context(), &mq.DescribeBrokerInput{BrokerId: &id})
					if err != nil {
						t.Fatal(err)
					}
					if current.BrokerState == types.BrokerStateRunning {
						return
					}
					if time.Now().After(deadline) {
						t.Fatalf("control-plane broker did not become RUNNING: %s", current.BrokerState)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			decode := func(raw json.RawMessage, out any) {
				t.Helper()
				if err := json.Unmarshal(raw, out); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() any {
				t.Helper()
				c := client(fixture.Region)
				broker, err := c.DescribeBroker(t.Context(), &mq.DescribeBrokerInput{BrokerId: &id})
				if err != nil {
					t.Fatal(err)
				}
				if string(broker.EngineType) != nativeEngine {
					t.Fatalf("DescribeBroker EngineType = %q, native = %q", broker.EngineType, nativeEngine)
				}
				list, err := c.ListBrokers(t.Context(), &mq.ListBrokersInput{})
				if err != nil {
					t.Fatal(err)
				}
				if len(list.BrokerSummaries) != 1 || aws.ToString(list.BrokerSummaries[0].BrokerId) != id || string(list.BrokerSummaries[0].EngineType) != nativeEngine {
					t.Fatalf("broker discovery = %+v, want %s with engine %q", list.BrokerSummaries, id, nativeEngine)
				}
				broker.ResultMetadata = middleware.Metadata{}
				tags, err := c.ListTags(t.Context(), &mq.ListTagsInput{ResourceArn: &arn})
				if err != nil {
					t.Fatal(err)
				}
				tags.ResultMetadata = middleware.Metadata{}
				users := make([]*mq.DescribeUserOutput, 0, len(usernames))
				for _, username := range usernames {
					user, err := c.DescribeUser(t.Context(), &mq.DescribeUserInput{BrokerId: &id, Username: &username})
					if err != nil {
						t.Fatal(err)
					}
					user.ResultMetadata = middleware.Metadata{}
					users = append(users, user)
				}
				return struct {
					Broker *mq.DescribeBrokerOutput
					Tags   *mq.ListTagsOutput
					Users  []*mq.DescribeUserOutput
				}{broker, tags, users}
			}
			replayed, afterMutation := 0, 0
			for _, row := range fixture.Calls {
				isReplay := row.Operation == "CreateBroker" && strings.HasPrefix(row.Label, "replay-")
				isMutation := strings.HasPrefix(row.Label, "mutate-")
				if row.Label != "create" && !isReplay && !isMutation {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					if row.Label == "replay-original-after-mutation" && backend == "sqlite" {
						before := snapshot()
						clients = reopen()
						waitRunning()
						after := snapshot()
						if !reflect.DeepEqual(before, after) {
							oldJSON, _ := json.Marshal(before)
							newJSON, _ := json.Marshal(after)
							t.Fatalf("SQLite reopen changed state:\nbefore=%s\nafter=%s", oldJSON, newJSON)
						}
					}
					var before any
					if isReplay {
						before = snapshot()
						replayed++
					}
					var err error
					c := client(fixture.Region)
					switch row.Operation {
					case "CreateBroker":
						var in mq.CreateBrokerInput
						decode(row.Parameters, &in)
						// Adapt only deployment prerequisites unsupported by this local engine.
						in.EngineVersion = new("5.18")
						in.PubliclyAccessible = new(true)
						in.SubnetIds, in.SecurityGroups = nil, nil
						in.AutoMinorVersionUpgrade = new(false)
						for i := range in.Users {
							password := originalPassword
							if row.Label == "replay-changed-password" || row.Label == "replay-current-values-after-mutation" {
								password = changedPassword
							}
							in.Users[i].Password = &password
						}
						var out *mq.CreateBrokerOutput
						out, err = c.CreateBroker(t.Context(), &in)
						if row.Label == "create" && err == nil {
							id, arn = aws.ToString(out.BrokerId), aws.ToString(out.BrokerArn)
							nativeID, nativeARN = row.Output.BrokerId, row.Output.BrokerArn
							waitRunning()
							original = in
							for _, user := range in.Users {
								usernames = append(usernames, aws.ToString(user.Username))
							}
						}
						if err == nil && row.Code == "Success" {
							if row.Output.BrokerId != nativeID || row.Output.BrokerArn != nativeARN {
								t.Fatal("native replay returned an unexpected identity")
							}
							if aws.ToString(out.BrokerId) != id || aws.ToString(out.BrokerArn) != arn {
								t.Fatalf("replay identity = %q/%q, want %q/%q", aws.ToString(out.BrokerId), aws.ToString(out.BrokerArn), id, arn)
							}
						}
					case "CreateTags":
						var in mq.CreateTagsInput
						decode(row.Parameters, &in)
						in.ResourceArn = &arn
						_, err = c.CreateTags(t.Context(), &in)
					case "UpdateBroker":
						var in mq.UpdateBrokerInput
						decode(row.Parameters, &in)
						in.BrokerId = &id
						_, err = c.UpdateBroker(t.Context(), &in)
					case "UpdateUser":
						var in mq.UpdateUserInput
						decode(row.Parameters, &in)
						in.BrokerId, in.Password = &id, new(changedPassword)
						_, err = c.UpdateUser(t.Context(), &in)
					default:
						t.Fatalf("unhandled captured mutation %s", row.Operation)
					}
					if row.Code == "Success" {
						if err != nil {
							t.Fatal(err)
						}
					} else {
						var api smithy.APIError
						if !errors.As(err, &api) || api.ErrorCode() != row.Output.Error.Code {
							t.Fatalf("error = %v, want %s", err, row.Output.Error.Code)
						}
						var response *smithyhttp.ResponseError
						if !errors.As(err, &response) || response.HTTPStatusCode() != row.HTTPStatus {
							t.Fatalf("error = %v, want HTTP %d", err, row.HTTPStatus)
						}
						var attribute *string
						var bad *types.BadRequestException
						var conflict *types.ConflictException
						if errors.As(err, &bad) {
							attribute = bad.ErrorAttribute
						} else if errors.As(err, &conflict) {
							attribute = conflict.ErrorAttribute
						} else {
							t.Fatalf("unexpected modeled replay error %T: %v", api, err)
						}
						if !reflect.DeepEqual(attribute, row.Output.ErrorAttribute) {
							t.Fatalf("ErrorAttribute = %v (%q), want %v (%q)", attribute, aws.ToString(attribute), row.Output.ErrorAttribute, aws.ToString(row.Output.ErrorAttribute))
						}
					}
					if isReplay && !reflect.DeepEqual(before, snapshot()) {
						t.Fatal("CreateBroker replay modified broker, tags, users, or pending state")
					}
					if isReplay && strings.HasSuffix(row.Label, "after-mutation") {
						afterMutation++
					}
				}) {
					t.FailNow()
				}
			}
			if id == "" || replayed != 12 || afterMutation != 2 {
				t.Fatalf("incomplete identity coverage: id=%q replays=%d after-mutation=%d", id, replayed, afterMutation)
			}
			otherRegion, otherAccount := "us-west-2", "222222222222"
			if fixture.Region == otherRegion {
				otherRegion = "us-east-1"
			}
			if fixture.Account == otherAccount {
				otherAccount = "333333333333"
			}
			for _, scope := range []struct{ name, account, region string }{
				{"region-independence", fixture.Account, otherRegion},
				{"account-independence", otherAccount, fixture.Region},
			} {
				t.Run(scope.name, func(t *testing.T) {
					before := snapshot()
					other := clientFor(scope.account, scope.region)
					created, err := other.CreateBroker(t.Context(), &original)
					if err != nil {
						t.Fatal(err)
					}
					if aws.ToString(created.BrokerArn) == arn || !strings.Contains(aws.ToString(created.BrokerArn), ":"+scope.region+":"+scope.account+":") {
						t.Fatalf("other-scope broker ARN = %q", aws.ToString(created.BrokerArn))
					}
					replayed, err := other.CreateBroker(t.Context(), &original)
					if err != nil {
						t.Fatal(err)
					}
					if aws.ToString(replayed.BrokerId) != aws.ToString(created.BrokerId) || aws.ToString(replayed.BrokerArn) != aws.ToString(created.BrokerArn) {
						t.Fatal("other-scope replay changed identity")
					}
					if !reflect.DeepEqual(before, snapshot()) {
						t.Fatal("other-scope creation changed original scope state")
					}
				})
			}
		})
	}
}

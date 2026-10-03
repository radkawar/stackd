package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
)

func mqMissingCall[I, O any](t *testing.T, input json.RawMessage, call func(context.Context, *I, ...func(*mq.Options)) (*O, error)) error {
	t.Helper()
	var in I
	if err := json.Unmarshal(input, &in); err != nil {
		t.Fatal(err)
	}
	_, err := call(t.Context(), &in)
	return err
}

func TestMQNativeMissingResourceErrors(t *testing.T) {
	var fixture struct {
		Account, Region string
		Observations    []struct {
			Operation string
			Input     json.RawMessage
			Result    struct {
				Error struct {
					Code           string
					ErrorAttribute *string
				}
			}
		}
	}
	awsReadFixture(t, "mq/missing_resources.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			client := mq.New(mq.Options{Region: fixture.Region, BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			for _, row := range fixture.Observations {
				t.Run(row.Operation, func(t *testing.T) {
					var err error
					switch row.Operation {
					case "describe-broker":
						err = mqMissingCall(t, row.Input, client.DescribeBroker)
					case "describe-user":
						err = mqMissingCall(t, row.Input, client.DescribeUser)
					case "list-users":
						err = mqMissingCall(t, row.Input, client.ListUsers)
					case "describe-configuration":
						err = mqMissingCall(t, row.Input, client.DescribeConfiguration)
					case "describe-configuration-revision":
						err = mqMissingCall(t, row.Input, client.DescribeConfigurationRevision)
					case "list-configuration-revisions":
						err = mqMissingCall(t, row.Input, client.ListConfigurationRevisions)
					case "list-tags":
						err = mqMissingCall(t, row.Input, client.ListTags)
					default:
						t.Fatalf("unhandled native operation %q", row.Operation)
					}
					var missing *types.NotFoundException
					var response *smithyhttp.ResponseError
					if !errors.As(err, &missing) || !errors.As(err, &response) || response.HTTPStatusCode() != 404 || missing.ErrorCode() != row.Result.Error.Code {
						t.Fatalf("missing-resource response: %v", err)
					}
					want := row.Result.Error.ErrorAttribute
					if (missing.ErrorAttribute == nil) != (want == nil) || aws.ToString(missing.ErrorAttribute) != aws.ToString(want) {
						t.Fatalf("ErrorAttribute = %v (%q), want %v (%q)", missing.ErrorAttribute, aws.ToString(missing.ErrorAttribute), want, aws.ToString(want))
					}
				})
			}
		})
	}
}

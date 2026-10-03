package stackd_test

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"

	"stackd"
)

func TestMQActiveMQPublicVersionAdmission(t *testing.T) {
	var fixture struct {
		Observations []struct {
			Input  mq.CreateConfigurationInput
			Result struct {
				Error struct{ Code, ErrorAttribute string }
			}
		}
	}
	awsReadFixture(t, "mq/engine_version_admission.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "123456789012"
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			client := mq.New(mq.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			row := fixture.Observations[0]
			if aws.ToString(row.Input.EngineVersion) != "5.18.7" {
				t.Fatal("fixture no longer covers former runtime patch admission")
			}
			_, err := client.CreateConfiguration(t.Context(), &row.Input)
			var bad *types.BadRequestException
			if !errors.As(err, &bad) || bad.ErrorCode() != row.Result.Error.Code || aws.ToString(bad.ErrorAttribute) != row.Result.Error.ErrorAttribute {
				t.Fatalf("patch-qualified API version was not rejected with native modeled error: %v", err)
			}
			rows, err := client.ListConfigurations(t.Context(), &mq.ListConfigurationsInput{})
			if err != nil {
				t.Fatal(err)
			}
			for _, configuration := range rows.Configurations {
				if aws.ToString(configuration.Name) == aws.ToString(row.Input.Name) {
					t.Fatal("rejected patch-qualified request created a configuration")
				}
			}
			row.Input.EngineVersion = new("5.18")
			created, err := client.CreateConfiguration(t.Context(), &row.Input)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := client.DescribeConfiguration(t.Context(), &mq.DescribeConfigurationInput{ConfigurationId: created.Id})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(actual.EngineVersion) != "5.18" {
				t.Fatalf("public engine release = %q", aws.ToString(actual.EngineVersion))
			}
		})
	}
}

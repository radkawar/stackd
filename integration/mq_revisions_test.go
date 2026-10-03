package stackd_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/smithy-go"

	"stackd"
)

func TestMQNativeConfigurationRevisionBoundaries(t *testing.T) {
	var fixture struct {
		Account, Region string
		Observations    []struct {
			Case, Operation string
			Input           json.RawMessage
			Result          struct {
				Code   string
				Output json.RawMessage
				Error  struct{ Code, ErrorAttribute string }
			}
		}
	}
	awsReadFixture(t, "mq/configuration_revision_boundaries.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			client := func() *mq.Client {
				return mq.New(mq.Options{Region: fixture.Region, BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			var id, firstToken, lastToken string
			var initialData *string
			for _, row := range fixture.Observations {
				if row.Result.Code == "ParamValidation" {
					continue
				} // CLI validation is not a native service response.
				t.Run(row.Case, func(t *testing.T) {
					var err error
					switch row.Operation {
					case "create-configuration":
						var in mq.CreateConfigurationInput
						if err = json.Unmarshal(row.Input, &in); err != nil {
							t.Fatal(err)
						}
						var out *mq.CreateConfigurationOutput
						out, err = client().CreateConfiguration(t.Context(), &in)
						if err == nil {
							id = aws.ToString(out.Id)
						}
						if err == nil {
							initial, readErr := client().DescribeConfigurationRevision(t.Context(), &mq.DescribeConfigurationRevisionInput{ConfigurationId: &id, ConfigurationRevision: new("1")})
							if readErr != nil {
								t.Fatal(readErr)
							}
							initialData = initial.Data
						}
					case "update-configuration":
						var in mq.UpdateConfigurationInput
						var expected mq.UpdateConfigurationOutput
						if err = json.Unmarshal(row.Input, &in); err != nil {
							t.Fatal(err)
						}
						if err = json.Unmarshal(row.Result.Output, &expected); err != nil {
							t.Fatal(err)
						}
						in.ConfigurationId = &id
						var out *mq.UpdateConfigurationOutput
						out, err = client().UpdateConfiguration(t.Context(), &in)
						if err == nil && (out.LatestRevision == nil || aws.ToInt32(out.LatestRevision.Revision) != aws.ToInt32(expected.LatestRevision.Revision)) {
							t.Fatalf("revision did not advance: %+v", out)
						}
					case "list-configuration-revisions":
						var in mq.ListConfigurationRevisionsInput
						if err = json.Unmarshal(row.Input, &in); err != nil {
							t.Fatal(err)
						}
						in.ConfigurationId = &id
						switch row.Case {
						case "continuation-after-append":
							if backend == "sqlite" {
								clients = reopen()
							}
							in.NextToken = &firstToken
						case "terminal-page":
							in.NextToken = &lastToken
						}
						var out *mq.ListConfigurationRevisionsOutput
						out, err = client().ListConfigurationRevisions(t.Context(), &in)
						if err == nil && row.Result.Code == "Success" {
							var expected mq.ListConfigurationRevisionsOutput
							if decodeErr := json.Unmarshal(row.Result.Output, &expected); decodeErr != nil {
								t.Fatal(decodeErr)
							}
							revisions := func(rows []types.ConfigurationRevision) []int32 {
								ids := make([]int32, len(rows))
								for i, v := range rows {
									ids[i] = aws.ToInt32(v.Revision)
								}
								return ids
							}
							if !slices.Equal(revisions(out.Revisions), revisions(expected.Revisions)) {
								t.Fatalf("revisions = %v, want %v", revisions(out.Revisions), revisions(expected.Revisions))
							}
							if (aws.ToString(out.NextToken) == "") != (aws.ToString(expected.NextToken) == "") {
								t.Errorf("continuation presence differs from native page")
							}
							if row.Case == "first-page" {
								firstToken = aws.ToString(out.NextToken)
							}
							if row.Case == "continuation-after-append" {
								lastToken = aws.ToString(out.NextToken)
							}
						}
					case "describe-configuration-revision":
						var in mq.DescribeConfigurationRevisionInput
						if err = json.Unmarshal(row.Input, &in); err != nil {
							t.Fatal(err)
						}
						in.ConfigurationId = &id
						var out *mq.DescribeConfigurationRevisionOutput
						out, err = client().DescribeConfigurationRevision(t.Context(), &in)
						if err == nil && row.Result.Code == "Success" && aws.ToString(out.Data) != aws.ToString(initialData) {
							t.Fatal("alternate revision spelling did not retrieve original revision bytes")
						}
					case "delete-configuration":
						_, err = client().DeleteConfiguration(t.Context(), &mq.DeleteConfigurationInput{ConfigurationId: &id})
					case "describe-configuration":
						_, err = client().DescribeConfiguration(t.Context(), &mq.DescribeConfigurationInput{ConfigurationId: &id})
					default:
						t.Fatalf("unhandled captured operation %s", row.Operation)
					}
					if row.Result.Code == "Success" {
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					var api smithy.APIError
					if !errors.As(err, &api) || api.ErrorCode() != row.Result.Error.Code {
						t.Fatalf("error = %v, want %s", err, row.Result.Error.Code)
					}
					var bad *types.BadRequestException
					var missing *types.NotFoundException
					var attribute *string
					if errors.As(err, &bad) {
						attribute = bad.ErrorAttribute
					} else if errors.As(err, &missing) {
						attribute = missing.ErrorAttribute
					}
					if aws.ToString(attribute) != row.Result.Error.ErrorAttribute {
						t.Errorf("error attribute = %q, want %q", aws.ToString(attribute), row.Result.Error.ErrorAttribute)
					}
				})
				if id == "" {
					t.Fatal("configuration setup failed")
				}
			}
			for _, revision := range []string{"abc", "2147483648"} {
				_, err := client().DescribeConfigurationRevision(t.Context(), &mq.DescribeConfigurationRevisionInput{ConfigurationId: &id, ConfigurationRevision: &revision})
				var bad *types.BadRequestException
				if !errors.As(err, &bad) || aws.ToString(bad.ErrorAttribute) != "configuration-revision" {
					t.Errorf("invalid revision on missing parent = %v", err)
				}
			}
		})
	}
}

func TestMQConfigurationPaginationOmittedLimit(t *testing.T) {
	// Native defaults are retained in mq/pagination_defaults.json. Cross the
	// 20-item boundary to verify actual traversal rather than a metadata default.
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			client := func() *mq.Client {
				return mq.New(mq.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("123456789012", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			var expected []string
			for i := range 21 {
				created, err := client().CreateConfiguration(t.Context(), &mq.CreateConfigurationInput{Name: new("page-" + strconv.Itoa(i)), EngineType: types.EngineTypeActivemq, EngineVersion: new("5.18")})
				if err != nil {
					t.Fatal(err)
				}
				expected = append(expected, aws.ToString(created.Arn))
			}
			slices.Sort(expected)
			var token *string
			start := 0
			for page, count := range []int{20, 1} {
				if page == 1 && backend == "sqlite" {
					clients = reopen()
				}
				out, err := client().ListConfigurations(t.Context(), &mq.ListConfigurationsInput{NextToken: token})
				if err != nil {
					t.Fatal(err)
				}
				var actual []string
				for _, configuration := range out.Configurations {
					actual = append(actual, aws.ToString(configuration.Arn))
				}
				if !slices.Equal(actual, expected[start:start+count]) {
					t.Fatalf("page %d: configurations = %v, want %v", page, actual, expected[start:start+count])
				}
				start += count
				token = out.NextToken
				if (aws.ToString(token) != "") != (page == 0) {
					t.Fatalf("page %d has wrong continuation presence", page)
				}
			}
		})
	}
}

package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"

	"stackd"
)

func TestMQNativeConfigurationSanitization(t *testing.T) {
	for _, capture := range []string{"configuration_sanitization", "configuration_sanitization_boundaries", "configuration_scheduling", "configuration_repeat_limit", "configuration_durable_consumers", "configuration_exclusive_consumers", "configuration_producer_backpressure", "configuration_composite_destinations", "configuration_filtered_destinations", "configuration_virtual_topics"} {
		var fixture struct {
			Region       string
			Observations []struct {
				Case   string
				Input  mq.UpdateConfigurationInput
				Result struct {
					Code   string
					Output mq.UpdateConfigurationOutput
				}
				RetainedRevision mq.DescribeConfigurationRevisionOutput `json:"retained_revision"`
			}
		}
		awsReadFixture(t, "mq/"+capture+".json", &fixture)
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(capture+"/"+backend, func(t *testing.T) {
				const account = "123456789012"
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
				client := func() *mq.Client {
					return mq.New(mq.Options{Region: fixture.Region, BaseEndpoint: new(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
				}
				created, err := client().CreateConfiguration(t.Context(), &mq.CreateConfigurationInput{Name: new("sanitization"), EngineType: types.EngineTypeActivemq, EngineVersion: new("5.18")})
				if err != nil {
					t.Fatal(err)
				}
				id := created.Id
				latest := int32(1)
				retained := map[int32]string{}
				for _, row := range fixture.Observations {
					t.Run(row.Case, func(t *testing.T) {
						input := row.Input
						input.ConfigurationId = id
						out, err := client().UpdateConfiguration(t.Context(), &input)
						// AWS retains this value; local primitive coercion remains
						// unsupported rather than silently changing the setting.
						unsupported := row.Case == "invalid-known-value"
						if row.Result.Code != "Success" || unsupported {
							var bad *types.BadRequestException
							if !errors.As(err, &bad) || aws.ToString(bad.ErrorAttribute) != "data" {
								t.Fatalf("expected data rejection, got %v", err)
							}
							state, err := client().DescribeConfiguration(t.Context(), &mq.DescribeConfigurationInput{ConfigurationId: id})
							if err != nil {
								t.Fatal(err)
							}
							if state.LatestRevision == nil || aws.ToInt32(state.LatestRevision.Revision) != latest {
								t.Fatal("rejected configuration advanced committed revision")
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						latest++
						if out.LatestRevision == nil || aws.ToInt32(out.LatestRevision.Revision) != latest {
							t.Fatalf("revision = %+v, want %d", out.LatestRevision, latest)
						}
						if !reflect.DeepEqual(mqSanitizationWarnings(out.Warnings), mqSanitizationWarnings(row.Result.Output.Warnings)) {
							t.Fatalf("warnings = %+v, want %+v", out.Warnings, row.Result.Output.Warnings)
						}
						retained[latest] = aws.ToString(row.RetainedRevision.Data)
						revision, err := client().DescribeConfigurationRevision(t.Context(), &mq.DescribeConfigurationRevisionInput{ConfigurationId: id, ConfigurationRevision: new(fmt.Sprint(latest))})
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(mqSanitizationXML(t, aws.ToString(revision.Data)), mqSanitizationXML(t, retained[latest])) {
							t.Fatal("retained semantic XML differs from native sanitization")
						}
					})
				}
				if backend == "sqlite" {
					clients = reopen()
				}
				for revision, expected := range retained {
					out, err := client().DescribeConfigurationRevision(t.Context(), &mq.DescribeConfigurationRevisionInput{ConfigurationId: id, ConfigurationRevision: new(fmt.Sprint(revision))})
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(mqSanitizationXML(t, aws.ToString(out.Data)), mqSanitizationXML(t, expected)) {
						t.Fatalf("revision %d lost kept attributes or restored removed subtree after reopen", revision)
					}
				}
				_, err = client().DeleteConfiguration(t.Context(), &mq.DeleteConfigurationInput{ConfigurationId: id})
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func mqSanitizationWarnings(warnings []types.SanitizationWarning) [][3]string {
	out := make([][3]string, len(warnings))
	for i, warning := range warnings {
		out[i] = [3]string{aws.ToString(warning.ElementName), aws.ToString(warning.AttributeName), string(warning.Reason)}
	}
	return out
}

// Compare expanded XML names, attribute values and child order, not AWS's
// declaration, whitespace, self-closing spelling, or attribute serialization.
func mqSanitizationXML(t *testing.T, encoded string) []string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	var events []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return events
		}
		if err != nil {
			t.Fatal(err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			var attrs []string
			for _, attr := range token.Attr {
				if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
					continue
				}
				value, err := json.Marshal([]string{attr.Name.Space, attr.Name.Local, attr.Value})
				if err != nil {
					t.Fatal(err)
				}
				attrs = append(attrs, string(value))
			}
			slices.Sort(attrs)
			events = append(events, fmt.Sprintf("start:%s:%s:%v", token.Name.Space, token.Name.Local, attrs))
		case xml.EndElement:
			events = append(events, fmt.Sprintf("end:%s:%s", token.Name.Space, token.Name.Local))
		case xml.CharData:
			if text := strings.TrimSpace(string(token)); text != "" {
				events = append(events, "text:"+text)
			}
		}
	}
}

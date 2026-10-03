package iam_test

import (
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/awstest"
	"stackd/internal/services/iam"
)

func TestIAMPaginationInputsReplayAWS(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/iam/pagination_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Case         string
			Operation    string
			Query        map[string]string
			MarkerSource string `json:"marker_source"`
			Code         string
			HTTPStatus   int `json:"http_status"`
			Count        int
			IsTruncated  bool `json:"is_truncated"`
			Overlap      bool
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			var client *sdkiam.Client
			if endpoint == "gateway" {
				client = newActivityFixture(t, nil, time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)).root
			} else {
				service := iam.New()
				t.Cleanup(func() { _ = service.Close() })
				client = clientFor(t, service, "123456789012", "us-east-1")
			}
			for _, suffix := range []string{"a", "b", "c"} {
				_, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("pages-" + suffix), Path: aws.String("/pages/"), Tags: []types.Tag{
					{Key: aws.String("a"), Value: aws.String("a")}, {Key: aws.String("b"), Value: aws.String("b")}, {Key: aws.String("c"), Value: aws.String("c")},
				}})
				if err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if _, err := client.CreateServiceSpecificCredential(t.Context(), &sdkiam.CreateServiceSpecificCredentialInput{UserName: aws.String("pages-a"), ServiceName: aws.String("bedrock.amazonaws.com"), CredentialAgeDays: aws.Int32(1)}); err != nil {
					t.Fatal(err)
				}
			}
			markers := make(map[string]string)
			previous := make(map[string][]string)
			for _, row := range fixture.Observations {
				t.Run(row.Case, func(t *testing.T) {
					query := maps.Clone(row.Query)
					for name, value := range query {
						switch value {
						case "<path>":
							query[name] = "/pages/"
						case "<user-a>":
							query[name] = "pages-a"
						case "<marker>":
							value = markers[row.MarkerSource]
							if value == "" {
								t.Fatal("source request did not produce a marker")
							}
							query[name] = value
						}
					}
					options := func(options *sdkiam.Options) {
						fields := make(url.Values, len(query))
						for name, value := range query {
							fields.Set(name, value)
						}
						options.APIOptions = append(options.APIOptions, awstest.QueryValues(fields))
					}
					var keys []string
					var token *string
					var truncated bool
					var err error
					switch row.Operation {
					case "ListUsers":
						var out *sdkiam.ListUsersOutput
						out, err = client.ListUsers(t.Context(), &sdkiam.ListUsersInput{}, options)
						if err == nil {
							for _, user := range out.Users {
								keys = append(keys, aws.ToString(user.UserName))
							}
							token, truncated = out.Marker, out.IsTruncated
						}
					case "ListUserTags":
						var out *sdkiam.ListUserTagsOutput
						out, err = client.ListUserTags(t.Context(), &sdkiam.ListUserTagsInput{UserName: aws.String("pages-a")}, options)
						if err == nil {
							for _, tag := range out.Tags {
								keys = append(keys, aws.ToString(tag.Key))
							}
							token, truncated = out.Marker, out.IsTruncated
						}
					case "ListServiceSpecificCredentials":
						var out *sdkiam.ListServiceSpecificCredentialsOutput
						out, err = client.ListServiceSpecificCredentials(t.Context(), &sdkiam.ListServiceSpecificCredentialsInput{}, options)
						if err == nil {
							for _, credential := range out.ServiceSpecificCredentials {
								keys = append(keys, aws.ToString(credential.ServiceSpecificCredentialId))
							}
							token, truncated = out.Marker, out.IsTruncated
						}
					default:
						t.Fatal("unsupported capture operation", row.Operation)
					}
					requireCode(t, err, row.Code)
					if err != nil {
						var response interface{ HTTPStatusCode() int }
						if !errors.As(err, &response) || response.HTTPStatusCode() != row.HTTPStatus {
							t.Fatalf("HTTP status differs from AWS %d: %v", row.HTTPStatus, err)
						}
						return
					}
					if len(keys) != row.Count || truncated != row.IsTruncated || (aws.ToString(token) != "") != truncated {
						t.Fatalf("page differs from AWS: count=%d truncated=%v marker=%v", len(keys), truncated, token)
					}
					if row.MarkerSource != "" {
						overlap := slices.ContainsFunc(keys, func(key string) bool { return slices.Contains(previous[row.MarkerSource], key) })
						if overlap != row.Overlap {
							t.Fatal("page overlap differs from AWS")
						}
					}
					markers[row.Case], previous[row.Case] = aws.ToString(token), keys
					if strings.HasPrefix(row.Case, "credentials_next_") && !slices.Equal(keys, previous["credentials_next_false"]) {
						t.Fatal("equivalent boolean representations changed the continued page")
					}
				})
			}
		})
	}
}

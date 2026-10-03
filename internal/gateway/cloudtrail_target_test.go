package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awscatalog"
	"stackd/internal/awstest"
	"stackd/internal/gateway"
	"stackd/internal/services/cloudtrail"
)

func TestCloudTrailSDKTargetPrefixes(t *testing.T) {
	type targetCase struct {
		Name, Target, AfterSigningTarget, Code string
		Status                                 int
		Input                                  json.RawMessage
	}
	var fixture struct {
		Observations  []targetCase
		BoundaryCases []targetCase `json:"boundary_cases"`
	}
	data, err := os.ReadFile("../../testdata/aws/cloudtrail/targets.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	model, _ := awscatalog.LookupService("cloudtrail")
	registry := &gateway.Registry{}
	if err := registry.Register(gateway.Service{Name: "cloudtrail", SigningName: "cloudtrail", Protocol: gateway.JSON11, TargetPrefix: model.TargetPrefix, Provider: cloudtrail.New(cloudtrail.Config{}), Model: &model, Decode: api.DecodeRequest}); err != nil {
		t.Fatal(err)
	}
	handler, err := gateway.New(registry, gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range append(fixture.Observations, fixture.BoundaryCases...) {
		if row.Name == "" {
			row.Name = row.Target
		}
		if len(row.Input) == 0 {
			row.Input = json.RawMessage(`{}`)
		}
		t.Run(row.Name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if row.AfterSigningTarget != "" {
					r.Header.Set("X-Amz-Target", row.AfterSigningTarget)
				}
				handler.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			client := sdk.New(sdk.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1, APIOptions: []func(*middleware.Stack) error{
				func(stack *middleware.Stack) error {
					return stack.Build.Add(middleware.BuildMiddlewareFunc("FixtureJSONTarget", func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
						in.Request.(*smithyhttp.Request).Header.Set("X-Amz-Target", row.Target)
						return next.HandleBuild(ctx, in)
					}), middleware.After)
				},
			}})
			out, err := awstest.CallSDK(t.Context(), client, "LookupEvents", row.Input)
			if row.Code != "Success" {
				var wire smithy.APIError
				var response *smithyhttp.ResponseError
				if !errors.As(err, &wire) || wire.ErrorCode() != row.Code || wire.ErrorMessage() == "" || !errors.As(err, &response) || response.HTTPStatusCode() != row.Status {
					t.Fatalf("expected HTTP %d %s with message; got %v", row.Status, row.Code, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(out.(*sdk.LookupEventsOutput).Events) != 0 {
				t.Fatal("empty history returned unexpected events")
			}
		})
	}
}

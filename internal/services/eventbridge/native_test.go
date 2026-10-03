package eventbridge_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/smithy-go"

	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awsctx"
	"stackd/internal/awstest"
	"stackd/internal/awswire"
	"stackd/internal/integrations"
	service "stackd/internal/services/eventbridge"
	"stackd/internal/services/iam"
	"stackd/internal/services/kms"
)

func sdkClient(t *testing.T, s *service.Service) *sdk.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			http.Error(w, "read failed", 500)
			return
		}
		action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AWSEvents.")
		decoded, err := api.DecodeRequest(action, awsapi.Request{JSON: body})
		if err != nil {
			awswire.JSONError(w, r, s.RequestError(action, err))
			return
		}
		ctx := awsctx.WithMetadata(r.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012", AccessKeyID: "123456789012", RequestID: "fixture-command"})
		ctx = awsapi.WithDecodedRequest(ctx, decoded)
		s.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(server.Close)
	return sdk.New(sdk.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), RetryMaxAttempts: 1, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
	})})
}

var archiveIncarnation = regexp.MustCompile(`(arn:aws[a-z-]*:events:[a-z0-9-]+:[0-9]{12}:archive/[.\-_A-Za-z0-9]+):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(")`)

func normalized(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range v {
			if item == nil || k == "ResultMetadata" {
				continue
			}
			switch k {
			case "CreationTime", "LastModifiedTime":
				out[k] = "<time>"
			case "EventId":
				out[k] = "<event-id>"
			case "EventPattern":
				// Only generated managed-rule patterns have incidental formatting.
				// DescribeArchive must preserve the customer's original pattern text.
				if v["ManagedBy"] == "prod.vhs.events.aws.internal" {
					if pattern, ok := item.(string); ok {
						var parsed any
						if json.Unmarshal([]byte(pattern), &parsed) == nil {
							out[k] = parsed
							continue
						}
					}
				}
				out[k] = item
			case "InputTemplate":
				if template, ok := item.(string); ok {
					out[k] = archiveIncarnation.ReplaceAllString(template, "${1}:<archive-incarnation>${2}")
				} else {
					out[k] = item
				}
			case "Archives", "Rules":
				out[k] = normalized(item)
				if items, ok := out[k].([]any); ok {
					key := "ArchiveName"
					if k == "Rules" {
						key = "Name"
					}
					// Compare page membership, not undefined order within a page.
					sort.Slice(items, func(i, j int) bool {
						return items[i].(map[string]any)[key].(string) < items[j].(map[string]any)[key].(string)
					})
				}
			default:
				out[k] = normalized(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = normalized(item)
		}
		return out
	default:
		return v
	}
}
func TestNativeControlPlane(t *testing.T) {
	for _, name := range []string{"control_plane.json", "scheduled_rules.json", "archives.json"} {
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) { nativeControlPlane(t, name) })
	}
}

func nativeControlPlane(t *testing.T, name string) {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/aws/eventbridge/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case, Action, Code string
			Input              json.RawMessage
			Output             map[string]any
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	backends(t, func(t *testing.T, b *backend) {
		source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
		identity := iam.NewWithConfig(iam.Config{Clock: source})
		keyService := kms.NewWithConfig(kms.Config{Clock: source})
		s := service.NewWithConfig(service.Config{Repository: b.repository, Events: b.events, Clock: source, Delivery: &sender{},
			Keys: integrations.EventBridgeArchiveKeys{KMS: keyService, Activity: identity}})
		t.Cleanup(func() { _ = s.Close(); _ = keyService.Close(); _ = identity.Close() })
		client := sdkClient(t, s)
		tokens := map[string]string{}
		for _, row := range capture.Observations {
			if !t.Run(row.Case, func(t *testing.T) {
				var input map[string]any
				if err := json.Unmarshal(row.Input, &input); err != nil {
					t.Fatal(err)
				}
				if nativeToken, ok := input["NextToken"].(string); ok {
					if localToken, bound := tokens[nativeToken]; bound {
						input["NextToken"] = localToken
					}
				}
				request, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				output, err := awstest.CallSDK(t.Context(), client, row.Action, request)
				code := "Success"
				if err != nil {
					var apiErr smithy.APIError
					if !errors.As(err, &apiErr) {
						t.Fatal(err)
					}
					code = apiErr.ErrorCode()
				}
				if code != row.Code {
					t.Fatalf("native=%s local=%s error=%v", row.Code, code, err)
				}
				if code != "Success" {
					return
				}
				encoded, err := json.Marshal(output)
				if err != nil {
					t.Fatal(err)
				}
				var actual map[string]any
				if err := json.Unmarshal(encoded, &actual); err != nil {
					t.Fatal(err)
				}
				if nativeToken, ok := row.Output["NextToken"].(string); ok && nativeToken != "" {
					localToken, ok := actual["NextToken"].(string)
					if !ok || localToken == "" {
						t.Fatal("native page has a continuation token but local page does not")
					}
					// Replay native token references using this backend's actual token,
					// including repeated use and changed-limit/filter probes.
					tokens[nativeToken] = localToken
					actual["NextToken"] = nativeToken
				}
				if !reflect.DeepEqual(normalized(actual), normalized(row.Output)) {
					t.Fatalf("native=%s\nlocal=%s", mustJSON(t, normalized(row.Output)), mustJSON(t, normalized(actual)))
				}
			}) {
				// Later observations depend on all preceding state transitions.
				return
			}
		}
	})
}
func TestNativePatternEnvelope(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/eventbridge/patterns.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case, Pattern, Event, Code string
			Output                     struct{ Result bool }
		} `json:"observations"`
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	s := service.NewWithConfig(service.Config{})
	defer s.Close()
	client := sdkClient(t, s)
	for _, row := range capture.Observations {
		if !strings.HasPrefix(row.Case, "edge_envelope_") && row.Code != "InternalFailure" {
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			input, _ := json.Marshal(map[string]string{"EventPattern": row.Pattern, "Event": row.Event})
			output, err := awstest.CallSDK(t.Context(), client, "TestEventPattern", input)
			code := "Success"
			if err != nil {
				var wire smithy.APIError
				if !errors.As(err, &wire) {
					t.Fatal(err)
				}
				code = wire.ErrorCode()
			}
			if code != row.Code {
				t.Fatalf("native=%s local=%s err=%v", row.Code, code, err)
			}
			if code == "Success" && output.(*sdk.TestEventPatternOutput).Result != row.Output.Result {
				t.Fatalf("native result=%v local=%v", row.Output.Result, output)
			}
		})
	}
}

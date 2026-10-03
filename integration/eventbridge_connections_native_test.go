package stackd_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

func TestEventBridgeNativeConnections(t *testing.T) {
	var fixture struct {
		Account, Region, Name string
		Observations          []awsNativeObservation
	}
	awsReadFixture(t, "eventbridge/connections.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source})
			bindings := map[string]string{}
			var currentConnection, firstSecret string
			var created, modified, authorized time.Time
			call := func(service, operation string, input json.RawMessage) (any, error) {
				text := string(input)
				for from, to := range bindings {
					text = strings.ReplaceAll(text, from, to)
				}
				config := aws.Config{Region: fixture.Region, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1, Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")}
				endpoint := aws.String(clients.server.URL)
				var client any
				switch service {
				case "events":
					client = eventbridge.NewFromConfig(config, func(o *eventbridge.Options) { o.BaseEndpoint = endpoint })
				case "secretsmanager":
					client = secretsmanager.NewFromConfig(config, func(o *secretsmanager.Options) { o.BaseEndpoint = endpoint })
				case "iam":
					client = iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = endpoint })
				default:
					t.Fatal("unsupported connection fixture service", service)
				}
				return awstest.CallSDK(t.Context(), client, operation, []byte(text))
			}
			for _, row := range fixture.Observations {
				if row.Label == "linked-role-before" {
					continue
				} // Native account already contained the shared linked role.
				advanceClock(t, source, time.Second)
				if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000); err != nil {
					t.Fatal(err)
				}
				if !t.Run(row.Label, func(t *testing.T) {
					actual, err := call(row.Service, row.Operation, row.Input)
					if row.Label == "get-deauthorized-secret" && connectionAPIError(err) == "ResourceNotFoundException" {
						return
					} // Native scheduled deletion has reached its terminal outcome.
					if strings.HasPrefix(row.Label, "cleanup-connection-absence-") && connectionAPIError(err) == "ResourceNotFoundException" {
						return
					}
					awsNativeResult(t, row, err)
					if err != nil {
						return
					}
					var native map[string]any
					awsDecodeJSON(t, row.Result.Output, &native)
					local := connectionSDKObject(t, actual)
					if row.Service == "events" {
						for _, key := range []string{"ConnectionArn", "SecretArn"} {
							if key == "SecretArn" && local["ConnectionState"] == "DEAUTHORIZED" {
								if secret, _ := local[key].(string); secret != "" {
									t.Fatal("settled deauthorization retained public SecretArn")
								}
								// Native may still be DEAUTHORIZING. Its secret identity
								// was bound before this asynchronous removal.
								continue
							}
							if from, ok := native[key].(string); ok {
								to, ok := local[key].(string)
								if !ok {
									t.Fatalf("missing %s", key)
								}
								if known := bindings[from]; known != "" && known != to {
									t.Fatalf("changed resource incarnation: %s", key)
								}
								bindings[from] = to
							}
						}
						switch result := actual.(type) {
						case *eventbridge.CreateConnectionOutput:
							currentConnection = aws.ToString(result.ConnectionArn)
							created = *result.CreationTime
							modified = *result.LastModifiedTime
						case *eventbridge.DescribeConnectionOutput:
							if aws.ToString(result.ConnectionArn) != currentConnection || !result.CreationTime.Equal(created) {
								t.Fatal("connection incarnation or creation time changed")
							}
							if row.Label == "describe-basic" {
								firstSecret = aws.ToString(result.SecretArn)
								authorized = *result.LastAuthorizedTime
								prefix := "arn:aws:secretsmanager:" + fixture.Region + ":" + fixture.Account + ":secret:events!connection/" + fixture.Name + "/"
								if !strings.HasPrefix(firstSecret, prefix) {
									t.Fatal("managed secret has wrong ownership scope or native name", firstSecret)
								}
								if strings.HasPrefix(strings.TrimPrefix(firstSecret, prefix), currentConnection[strings.LastIndex(currentConnection, "/")+1:]) {
									t.Fatal("connection and secret reused one incarnation UUID")
								}
							}
							if row.Label == "describe-api-key" && aws.ToString(result.SecretArn) == firstSecret {
								t.Fatal("reauthorization reused a removed secret incarnation")
							}
						case *eventbridge.UpdateConnectionOutput:
							if row.Label == "update-password-with-type" {
								if !result.LastModifiedTime.Equal(modified) || !result.LastAuthorizedTime.After(authorized) {
									t.Fatal("credential-only update changed metadata time or failed to advance authorization")
								}
								authorized = *result.LastAuthorizedTime
							}
							if row.Label == "update-description-only" {
								if !result.LastModifiedTime.After(modified) || !result.LastAuthorizedTime.Equal(authorized) {
									t.Fatal("description update changed authorization or failed to advance modification time")
								}
							}
						}
						nativeJSON, _ := json.Marshal(native)
						text := string(nativeJSON)
						for from, to := range bindings {
							text = strings.ReplaceAll(text, from, to)
						}
						awsDecodeJSON(t, []byte(text), &native)
						if want, got := connectionPublicProjection(native), connectionPublicProjection(local); !reflect.DeepEqual(want, got) {
							t.Fatalf("native projection mismatch\nwant %#v\ngot  %#v", want, got)
						}
						if row.Label == "describe-password-updated" || row.Label == "describe-api-key" {
							before := connectionPublicProjection(local)
							clients = reopen()
							again, err := call(row.Service, row.Operation, row.Input)
							if err != nil {
								t.Fatal(err)
							}
							if !reflect.DeepEqual(before, connectionPublicProjection(connectionSDKObject(t, again))) {
								t.Fatal("connection public metadata did not survive restart")
							}
						}
						return
					}
					switch result := actual.(type) {
					case *secretsmanager.DescribeSecretOutput:
						if aws.ToString(result.OwningService) != "events" {
							t.Fatal("managed secret lost its actual owning service")
						}
						ownerTag := false
						for _, tag := range result.Tags {
							if aws.ToString(tag.Key) == "aws:secretsmanager:owningService" && aws.ToString(tag.Value) == "events" {
								ownerTag = true
							}
						}
						if !ownerTag {
							t.Fatal("missing managed secret ownership tag")
						}
					case *secretsmanager.GetSecretValueOutput:
						var want, got any
						if err := json.Unmarshal([]byte(native["SecretString"].(string)), &want); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal([]byte(aws.ToString(result.SecretString)), &got); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(want, got) {
							t.Fatalf("actual managed credentials differ from native: want %#v got %#v", want, got)
						}
						if !slices.Equal(result.VersionStages, []string{"AWSCURRENT"}) {
							t.Fatal("managed secret current version is not readable as AWSCURRENT")
						}
					case *secretsmanager.ListSecretVersionIdsOutput:
						want := []string{}
						for _, item := range native["Versions"].([]any) {
							stages := item.(map[string]any)["VersionStages"].([]any)
							parts := []string{}
							for _, stage := range stages {
								parts = append(parts, stage.(string))
							}
							slices.Sort(parts)
							want = append(want, strings.Join(parts, ","))
						}
						got := []string{}
						for _, version := range result.Versions {
							parts := slices.Clone(version.VersionStages)
							slices.Sort(parts)
							got = append(got, strings.Join(parts, ","))
						}
						slices.Sort(want)
						slices.Sort(got)
						if !slices.Equal(want, got) {
							t.Fatalf("managed secret version-stage transition: want %v got %v", want, got)
						}
					case *iam.GetRoleOutput:
						if aws.ToString(result.Role.RoleName) != "AWSServiceRoleForAmazonEventBridgeApiDestinations" || aws.ToString(result.Role.Path) != "/aws-service-role/apidestinations.events.amazonaws.com/" {
							t.Fatal("connection did not provision the native service-linked role")
						}
						policy, err := url.QueryUnescape(aws.ToString(result.Role.AssumeRolePolicyDocument))
						if err != nil {
							t.Fatal(err)
						}
						var document any
						awsDecodeJSON(t, []byte(policy), &document)
						if !strings.Contains(policy, "apidestinations.events.amazonaws.com") {
							t.Fatal("connection linked role does not trust its owning service")
						}
					}
				}) {
					return
				}
			}
			clients = reopen()
			input, _ := json.Marshal(map[string]string{"Name": fixture.Name})
			_, err := call("events", "describe-connection", input)
			assertAPIError(t, err, "ResourceNotFoundException")
			t.Log("Replayed native connection lifecycle and real managed secrets across memory/SQLite restarts; UUIDs/version IDs and wall-clock timestamps are opaque, asynchronous deauthorization/deletion are compared by legal transitions.")
		})
	}
}

func connectionAPIError(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}
func connectionSDKObject(t *testing.T, value any) map[string]any {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	awsDecodeJSON(t, body, &out)
	return out
}
func connectionPublicProjection(input any) any {
	switch value := input.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, item := range value {
			if item == nil || key == "ResultMetadata" || key == "StateReason" {
				continue
			}
			if text, ok := item.(string); ok && text == "" {
				continue
			}
			if key == "SecretArn" && (value["ConnectionState"] == "DEAUTHORIZING" || value["ConnectionState"] == "DEAUTHORIZED") {
				continue
			}
			switch key {
			case "CreationTime", "LastModifiedTime", "LastAuthorizedTime":
				out[key] = "<timestamp>"
			case "ConnectionState":
				if item == "DEAUTHORIZING" || item == "DEAUTHORIZED" {
					out[key] = "<deauthorized>"
				} else {
					out[key] = item
				}
			default:
				out[key] = connectionPublicProjection(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = connectionPublicProjection(item)
		}
		return out
	default:
		return value
	}
}

package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/clock"
	"stackd/storage"
)

type lambdaTagsObservation struct {
	lambdaConcurrencyObservation
	Actor       string
	WireRequest struct {
		Method, Path, Query string
	} `json:"wire_request"`
}

type lambdaTagsFixture struct {
	Observations []lambdaTagsObservation
	CloudTrail   struct {
		Events []struct {
			Label     string `json:"correlated_observation"`
			Event     map[string]any
			Resources []trailtypes.Resource `json:"lookup_resources"`
		}
	}
}

// Reuse the same SDK/STS replay for the native scalar tag and multivalued TagKeys
// matrix. The supplemental mixed-case captures document unresolved native winner
// selection; they are evidence, not an inferred precedence contract.
func lambdaTagCaseObservations(t *testing.T) []lambdaTagsObservation {
	t.Helper()
	f := lambdaFixture[lambdaTagsFixture](t, "tag_condition_case")
	rows := make([]lambdaTagsObservation, 0, len(f.Observations))
	for _, row := range f.Observations {
		// Repeat observations establish native propagation stability, not a
		// second local behavior. The first capture includes full state readbacks.
		if strings.HasPrefix(row.Label, "settling_") || strings.Contains(row.Label, "_settled") || strings.HasPrefix(row.Label, "cleanup_") || row.Operation == "create-function" && row.Result.Code != "Success" {
			continue
		}
		if strings.Contains(row.Actor, ":assumed-role/") {
			row.Actor = row.Actor[strings.LastIndexByte(row.Actor, '/')+1:]
		}
		switch row.Operation {
		case "ListTags", "TagResource":
			wire := lambdaAdmissionInput[struct {
				Path string
				Body map[string]any
			}](t, row.Input)
			resource, err := url.PathUnescape(strings.TrimPrefix(wire.Path, "/2017-03-31/tags/"))
			if err != nil {
				t.Fatal(err)
			}
			input := map[string]any{"Resource": resource}
			if row.Operation == "TagResource" {
				input["Tags"] = wire.Body["Tags"]
				row.Operation = "tag-resource"
			} else {
				row.Operation = "list-tags"
			}
			row.Input, err = json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
		}
		row.Label = "case_" + row.Label
		rows = append(rows, row)
	}
	return rows
}

// Replay native state transitions, not complete response structs: tag values and
// the revision/time bijections defend atomic failures and successful no-ops.
// Real STS sessions retain their credentials across current role-policy changes.
func TestLambdaFunctionTagsNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaFixture[lambdaTagsFixture](t, "function_tags")
			f.Observations = append(f.Observations, lambdaTagCaseObservations(t)...)
			source := clock.NewManual(time.Date(2026, 9, 14, 20, 0, 0, 0, time.UTC))
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "tags.sqlite"))
			}
			c := lambdaEventsConnect(t, backends, source)
			clients := cloudClients{c.server}
			root := clients.iam("test", "test", "")
			status := &lambdaPolicyHTTP{client: c.server.Client()}
			transport := &lambdaConcurrencyHTTP{client: status}
			options := c.lambda.Options()
			options.HTTPClient = transport
			admin := awslambda.New(options)
			actors := map[string]*awslambda.Client{"authorized-probe-caller": admin}
			revisions, modified := lambdaPolicyRevisions{}, lambdaPolicyRevisions{}
			auditIDs := map[string]string{}
			for _, row := range f.Observations {
				// AWS's temporary role-policy propagation observations are not a
				// stable permission contract. Replay settled reads with the same
				// sessions, and do not replay fixture cleanup or CLI-only validation.
				if strings.HasPrefix(row.Label, "wait_active_") || strings.HasPrefix(row.Label, "current_absence_propagation_") || strings.HasPrefix(row.Label, "cleanup_") || row.Result.Code == "ParamValidation" {
					continue
				}
				advanceClock(t, source, time.Second)
				switch row.Operation {
				case "create-role":
					input := lambdaAdmissionInput[iam.CreateRoleInput](t, row.Input)
					// The captured administrator is an IAM user; the local test
					// root occupies that role without fabricated session metadata.
					input.AssumeRolePolicyDocument = aws.String(strings.ReplaceAll(aws.ToString(input.AssumeRolePolicyDocument), "arn:aws:iam::000000000000:user/Delegated", "arn:aws:iam::000000000000:root"))
					if _, err := root.CreateRole(t.Context(), input); err != nil {
						t.Fatal(err)
					}
					continue
				case "put-role-policy":
					if _, err := root.PutRolePolicy(t.Context(), lambdaAdmissionInput[iam.PutRolePolicyInput](t, row.Input)); err != nil {
						t.Fatal(err)
					}
					continue
				case "assume-role":
					input := lambdaAdmissionInput[sts.AssumeRoleInput](t, row.Input)
					issued, err := clients.sts("test", "test", "").AssumeRole(t.Context(), input)
					if err != nil {
						t.Fatal(err)
					}
					options.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(issued.Credentials.AccessKeyId), aws.ToString(issued.Credentials.SecretAccessKey), aws.ToString(issued.Credentials.SessionToken))
					actors[aws.ToString(input.RoleSessionName)] = awslambda.New(options)
					continue
				case "create-function":
					input := lambdaAdmissionInput[awslambda.CreateFunctionInput](t, row.Input)
					if _, err := admin.CreateFunction(t.Context(), input); err != nil {
						t.Fatal(err)
					}
					if err := awslambda.NewFunctionActiveWaiter(admin, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: input.FunctionName}, time.Minute); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if row.Service != "lambda" {
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) {
					client := actors[row.Actor]
					if client == nil {
						t.Fatalf("unmapped native actor %s", row.Actor)
					}
					input := *lambdaAdmissionInput[map[string]any](t, row.Input)
					if row.Label == "omitted_tags" {
						// The SDK rejects missing required Tags before transmission.
						// Preserve the native service-side observation through SigV4.
						request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.server.URL+row.WireRequest.Path, strings.NewReader(`{}`))
						if err != nil {
							t.Fatal(err)
						}
						request.Header.Set("Content-Type", "application/json")
						response, body := lambdaRawRequest(t, c.server, request, []byte(`{}`), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
						if response.StatusCode != row.Result.HTTPStatus || response.Header.Get("X-Amzn-ErrorType") != row.Result.Code {
							t.Fatalf("HTTP %d %s; native=%s", response.StatusCode, body, row.Result.Code)
						}
						return
					}
					if row.Operation == "untag-resource" && row.WireRequest.Query != "" {
						query, err := url.ParseQuery(row.WireRequest.Query)
						if err != nil {
							t.Fatal(err)
						}
						input["TagKeys"] = query["tagKeys"]
					}
					operations := map[string]lambdaPolicyOperation{
						"get-function":   lambdaPolicyBind(client.GetFunction),
						"list-tags":      lambdaPolicyBind(client.ListTags),
						"tag-resource":   lambdaPolicyBind(client.TagResource),
						"untag-resource": lambdaPolicyBind(client.UntagResource),
					}
					call := operations[row.Operation]
					if call == nil {
						t.Fatalf("unhandled native operation %s", row.Operation)
					}
					actual, err := call(t.Context(), input)
					auditIDs[row.Label] = transport.requestID
					if row.Result.HTTPStatus != 0 && status.status != row.Result.HTTPStatus {
						t.Fatalf("HTTP %d; native=%d: %v", status.status, row.Result.HTTPStatus, err)
					}
					if row.Result.Code != "Success" {
						assertAPIError(t, err, row.Result.Code)
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					want := *lambdaAdmissionInput[map[string]any](t, row.Result.Output)
					if row.Operation == "get-function" || row.Operation == "list-tags" {
						// SDK nil/empty distinctions are not the tag-state contract.
						gotTags, _ := actual["Tags"].(map[string]any)
						wantTags, _ := want["Tags"].(map[string]any)
						if len(gotTags) != len(wantTags) || len(wantTags) > 0 && !reflect.DeepEqual(gotTags, wantTags) {
							t.Fatalf("tags=%#v; native=%#v", gotTags, wantTags)
						}
					}
					if row.Operation == "get-function" {
						gotConfig := actual["Configuration"].(map[string]any)
						wantConfig := want["Configuration"].(map[string]any)
						revisions.observe(t, wantConfig["RevisionId"].(string), gotConfig["RevisionId"].(string))
						modified.observe(t, wantConfig["LastModified"].(string), gotConfig["LastModified"].(string))
					}
				}) {
					t.FailNow()
				}
			}
			// Native mutation, no-op, semantic failure and denied-session outcomes
			// defend both transactional publication and redacted IAM audit requests.
			trails := organizationsAuditClient(clients, "test", "us-east-1")
			trailNativeDrain(t, c.cloud)
			for _, label := range []string{"merge_replace_case", "identical_tag_noop", "empty_map", "remove_present_absent", "remove_absent_noop", "boundary_51_atomic_reject", "explicit-allow_tagged_list", "implicit-list-absence_tagged_list", "request_tag_missing", "tag_keys_untag_mixed_reject", "explicit-list-deny_tagged_get"} {
				found := false
				for _, native := range f.CloudTrail.Events {
					if native.Label != label {
						continue
					}
					found = true
					id := auditIDs[label]
					if id == "" {
						t.Fatalf("missing SDK request ID for %s", label)
					}
					got := auditLookupRecord(t, trails, id, native.Event["eventName"].(string))
					for _, key := range []string{"eventSource", "eventName", "readOnly", "eventType", "eventCategory", "requestParameters", "responseElements", "resources", "errorCode"} {
						if !reflect.DeepEqual(got[key], native.Event[key]) {
							t.Fatalf("%s audit %s=%#v; native=%#v", label, key, got[key], native.Event[key])
						}
					}
					pages := cloudtrail.NewLookupEventsPaginator(trails, &cloudtrail.LookupEventsInput{LookupAttributes: []trailtypes.LookupAttribute{{AttributeKey: trailtypes.LookupAttributeKeyEventName, AttributeValue: aws.String(native.Event["eventName"].(string))}}})
					matched := false
					for pages.HasMorePages() {
						page, err := pages.NextPage(t.Context())
						if err != nil {
							t.Fatal(err)
						}
						for _, event := range page.Events {
							if lambdaQueueObject(t, aws.ToString(event.CloudTrailEvent))["requestID"] != id {
								continue
							}
							matched = true
							if len(event.Resources) != len(native.Resources) || len(native.Resources) > 0 && !reflect.DeepEqual(event.Resources, native.Resources) {
								t.Fatalf("%s lookup resources=%+v; native=%+v", label, event.Resources, native.Resources)
							}
						}
					}
					if !matched {
						t.Fatalf("lookup lost request %s", id)
					}
				}
				if !found {
					t.Fatalf("missing native audit observation %s", label)
				}
			}
		})
	}
}

// A real module-global counter and process identity distinguish metadata writes
// from deployment updates. No-op tagging must not silently reset customer state.
func TestLambdaFunctionTagsPreserveWarmRuntime(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "warm-tags.sqlite"))
			}
			source := clock.NewManual(time.Date(2026, 9, 14, 20, 0, 0, 0, time.UTC))
			c := lambdaEventsConnect(t, backends, source)
			f := lambdaFixture[lambdaTagsFixture](t, "function_tags")
			root := (cloudClients{c.server}).iam("test", "test", "")
			var create *awslambda.CreateFunctionInput
			for _, row := range f.Observations {
				if row.Label == "create_execution_role" {
					if _, err := root.CreateRole(t.Context(), lambdaAdmissionInput[iam.CreateRoleInput](t, row.Input)); err != nil {
						t.Fatal(err)
					}
				}
				if row.Operation == "create-function" && row.Result.Code == "Success" {
					create = lambdaAdmissionInput[awslambda.CreateFunctionInput](t, row.Input)
					break
				}
			}
			if create == nil {
				t.Fatal("native fixture lacks function creation")
			}
			code := func(version string) []byte {
				t.Helper()
				var buffer bytes.Buffer
				archive := zip.NewWriter(&buffer)
				file, err := archive.Create("handler.py")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write([]byte("import uuid\nowner = str(uuid.uuid4())\ncount = 0\ndef handler(event, context):\n    global count\n    count += 1\n    return {'owner': owner, 'count': count, 'version': '" + version + "'}\n")); err != nil {
					t.Fatal(err)
				}
				if err := archive.Close(); err != nil {
					t.Fatal(err)
				}
				return buffer.Bytes()
			}
			create.Code.ZipFile = code("before")
			created, err := c.lambda.CreateFunction(t.Context(), create)
			if err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionActiveWaiter(c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: create.FunctionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			invoke := func() map[string]any {
				t.Helper()
				out, err := c.lambda.Invoke(t.Context(), &awslambda.InvokeInput{FunctionName: create.FunctionName, Payload: []byte(`{}`)})
				if err != nil {
					t.Fatal(err)
				}
				if out.FunctionError != nil {
					t.Fatalf("handler failed: %s", out.Payload)
				}
				return lambdaQueueObject(t, string(out.Payload))
			}
			first := invoke()
			count := 1
			for _, label := range []string{"merge_replace_case", "identical_tag_noop", "remove_present_absent", "remove_absent_noop"} {
				for _, row := range f.Observations {
					if row.Label != label {
						continue
					}
					before, err := c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: create.FunctionName})
					if err != nil {
						t.Fatal(err)
					}
					advanceClock(t, source, time.Second)
					if row.Operation == "tag-resource" {
						input := lambdaAdmissionInput[awslambda.TagResourceInput](t, row.Input)
						input.Resource = created.FunctionArn
						_, err = c.lambda.TagResource(t.Context(), input)
					} else {
						input := lambdaAdmissionInput[awslambda.UntagResourceInput](t, row.Input)
						input.Resource = created.FunctionArn
						_, err = c.lambda.UntagResource(t.Context(), input)
					}
					if err != nil {
						t.Fatal(err)
					}
					after, err := c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: create.FunctionName})
					if err != nil {
						t.Fatal(err)
					}
					if aws.ToString(after.RevisionId) == aws.ToString(before.RevisionId) || aws.ToString(after.LastModified) == aws.ToString(before.LastModified) {
						t.Fatalf("%s did not rotate public metadata", label)
					}
					count++
					got := invoke()
					if got["owner"] != first["owner"] || got["count"] != float64(count) || got["version"] != "before" {
						t.Fatalf("%s reset warm customer state: first=%v got=%v", label, first, got)
					}
				}
			}
			// Smithy limits count characters, not UTF-8 bytes. A rejected
			// multibyte boundary write must not replace an existing ASCII tag.
			unicodeKey, unicodeValue := strings.Repeat("é", 128), strings.Repeat("界", 256)
			if _, err := c.lambda.TagResource(t.Context(), &awslambda.TagResourceInput{Resource: created.FunctionArn, Tags: map[string]string{unicodeKey: unicodeValue}}); err != nil {
				t.Fatal(err)
			}
			beforeTags, err := c.lambda.ListTags(t.Context(), &awslambda.ListTagsInput{Resource: created.FunctionArn})
			if err != nil {
				t.Fatal(err)
			}
			if beforeTags.Tags[unicodeKey] != unicodeValue {
				t.Fatal("Unicode tag boundary was not retained")
			}
			for _, invalid := range []map[string]string{
				{unicodeKey + "é": "rejected", "Owner": "must-not-replace"},
				{unicodeKey: unicodeValue + "界", "Owner": "must-not-replace"},
			} {
				_, err := c.lambda.TagResource(t.Context(), &awslambda.TagResourceInput{Resource: created.FunctionArn, Tags: invalid})
				assertAPIError(t, err, "ValidationException")
				afterTags, err := c.lambda.ListTags(t.Context(), &awslambda.ListTagsInput{Resource: created.FunctionArn})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(afterTags.Tags, beforeTags.Tags) {
					t.Fatalf("rejected Unicode boundary changed tags: before=%v after=%v", beforeTags.Tags, afterTags.Tags)
				}
			}
			if _, err := c.lambda.UpdateFunctionCode(t.Context(), &awslambda.UpdateFunctionCodeInput{FunctionName: create.FunctionName, ZipFile: code("after")}); err != nil {
				t.Fatal(err)
			}
			if err := awslambda.NewFunctionUpdatedWaiter(c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: create.FunctionName}, time.Minute); err != nil {
				t.Fatal(err)
			}
			got := invoke()
			if got["owner"] == first["owner"] || got["count"] != float64(1) || got["version"] != "after" {
				t.Fatalf("code update did not replace the tagged runtime: first=%v got=%v", first, got)
			}
		})
	}
}

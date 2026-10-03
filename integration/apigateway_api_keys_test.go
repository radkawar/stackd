package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type gatewayAPIKeysFixture struct {
	gatewayTimelineFixture
	TargetOperations  []string `json:"target_operations"`
	Pagination        map[string][]string
	DistinctIDCapture *gatewayAPIKeysFixture `json:"distinct_id_capture"`
}

func TestAPIGatewayAPIKeysNative(t *testing.T) {
	var native gatewayAPIKeysFixture
	// prior_captures retains interrupted runs and the earlier MOCK prerequisite,
	// not selected evidence. The final controls and distinct-ID supplement each
	// start with their own real operator, resources and storage.
	awsReadFixture(t, "apigateway/api_keys.json", &native)
	if native.Mode != "api-keys-control" {
		t.Fatal("missing native API key control capture")
	}
	for _, capture := range []struct {
		name    string
		fixture *gatewayAPIKeysFixture
	}{{"controls", &native}, {"distinct-id", native.DistinctIDCapture}} {
		fixture := capture.fixture
		if fixture == nil || len(fixture.Observations) == 0 {
			t.Fatalf("missing native %s capture", capture.name)
		}
		for _, backend := range []string{"memory", "sqlite"} {
			t.Run(capture.name+"/"+backend, func(t *testing.T) {
				source := clock.NewManual(fixture.Observations[0].StartedAt)
				clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source})
				owner := gatewayNativeUser(t, clients, fixture.Account, fixture.Region, fixture.Identity.Arn)
				actors := map[string]credentials.StaticCredentialsProvider{fixture.Identity.Arn: owner}
				bindings := map[string]string{}
				seen := map[string]bool{}
				orders := map[string][]string{}
				controls, pages := 0, 0
				reopened := false
				var excluded []string

				call := func(row gatewaySDKObservation, input map[string]any) map[string]any {
					t.Helper()
					if row.StartedAt.After(source.Now()) {
						source.Advance(row.StartedAt.Sub(source.Now()))
					}
					actor, ok := actors[row.Actor.Arn]
					if !ok {
						t.Fatalf("%s has no established actor %s", row.Label, row.Actor.Arn)
					}
					input = gatewayClone(t, input)
					gatewaySubstitute(input, bindings)
					if row.Operation == "ImportApiKeys" {
						blob, ok := input["body"].(map[string]any)
						if !ok {
							t.Fatalf("%s lacks the captured SDK blob envelope", row.Label)
						}
						encoded, ok := blob["base64"].(string)
						if !ok {
							t.Fatalf("%s lacks the captured body bytes", row.Label)
						}
						// The capture wraps bytes; Go's SDK JSON expects a base64
						// string. Decode first so plan IDs inside the CSV are bound.
						body := gatewayWSDecode64(t, encoded)
						input["body"] = []byte(gatewayReplace(string(body), bindings))
					}
					wire := &awstest.WireClient{Client: clients.server.Client()}
					client := gatewaySDKClient(t, row.Service, aws.Config{Region: fixture.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: actor, HTTPClient: wire, RetryMaxAttempts: 1})
					encoded, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					out, err := awstest.CallSDK(t.Context(), client, row.Operation, encoded)
					if row.Result.Code == "ParamValidationError" {
						var validation smithy.InvalidParamsError
						if wire.Status != 0 || !errors.As(err, &validation) {
							t.Fatalf("%s must fail SDK validation without a service request: HTTP=%d error=%v", row.Label, wire.Status, err)
						}
						return nil
					}
					if wire.Status != row.Result.HTTPStatus {
						t.Fatalf("%s HTTP=%d native=%d: %v", row.Label, wire.Status, row.Result.HTTPStatus, err)
					}
					controls++
					seen[row.Operation] = true
					if row.Result.Code != "Success" {
						assertAPIError(t, err, row.Result.Code)
						return nil
					}
					if err != nil {
						t.Fatalf("%s: %v", row.Label, err)
					}
					if session, ok := out.(*sts.AssumeRoleOutput); ok {
						nativeActor := row.Result.Output["AssumedRoleUser"].(map[string]any)["Arn"].(string)
						if aws.ToString(session.AssumedRoleUser.Arn) != nativeActor {
							t.Fatalf("%s assumed principal=%s native=%s", row.Label, aws.ToString(session.AssumedRoleUser.Arn), nativeActor)
						}
						actors[nativeActor] = credentials.NewStaticCredentialsProvider(*session.Credentials.AccessKeyId, *session.Credentials.SecretAccessKey, *session.Credentials.SessionToken)
					}
					if row.Service != "apigateway" {
						encoded, err = json.Marshal(out)
						if err != nil {
							t.Fatal(err)
						}
						var actual map[string]any
						awsDecodeJSON(t, encoded, &actual)
						gatewayWSAuthorizerControl(t, row.Label, actual, row.Result.Output, bindings)
						if row.Operation == "GetCallerIdentity" {
							for _, field := range []string{"Account", "Arn"} {
								if actual[field] != row.Result.Output[field] {
									t.Fatalf("%s %s=%v native=%v", row.Label, field, actual[field], row.Result.Output[field])
								}
							}
						}
						return nil
					}
					actual := map[string]any{}
					if len(wire.Body) != 0 {
						awsDecodeJSON(t, wire.Body, &actual)
					}
					// REST's wire member is "item"; both SDKs expose it as
					// "items". Preserve absent/null/empty while projecting that name.
					switch row.Operation {
					case "GetApiKeys", "GetUsagePlans", "GetUsagePlanKeys", "GetResources":
						if items, present := actual["item"]; present {
							actual["items"] = items
							delete(actual, "item")
						}
					}
					switch row.Operation {
					case "CreateApiKey", "CreateUsagePlan", "CreateRestApi", "CreateResource", "CreateDeployment":
						gatewayWSAuthorizerBind(t, row.Label+" id", row.Result.Output["id"].(string), actual["id"], bindings)
						if row.Operation == "CreateApiKey" && (row.Result.Output["id"] == row.Result.Output["value"]) != (actual["id"] == actual["value"]) {
							t.Fatalf("%s changed the native ID/value distinction: id=%v value=%v", row.Label, actual["id"], actual["value"])
						}
						if row.Operation == "CreateApiKey" && row.Input["value"] == nil {
							gatewayWSAuthorizerBind(t, row.Label+" generated value", row.Result.Output["value"].(string), actual["value"], bindings)
						}
						if native, ok := row.Result.Output["rootResourceId"].(string); ok {
							gatewayWSAuthorizerBind(t, row.Label+" root", native, actual["rootResourceId"], bindings)
						}
					case "GetResources":
						for _, item := range row.Result.Output["items"].([]any) {
							native := item.(map[string]any)
							for _, candidate := range actual["items"].([]any) {
								local := candidate.(map[string]any)
								if native["path"] == local["path"] {
									gatewayWSAuthorizerBind(t, row.Label+" resource", native["id"].(string), local["id"], bindings)
								}
							}
						}
					case "ImportApiKeys":
						native, _ := row.Result.Output["ids"].([]any)
						local, _ := actual["ids"].([]any)
						if len(native) != len(local) {
							t.Fatalf("%s imported IDs=%v native=%v", row.Label, local, native)
						}
						for i, id := range native {
							gatewayWSAuthorizerBind(t, row.Label+" imported id", id.(string), local[i], bindings)
						}
					}
					return actual
				}

				for index := 0; index < len(fixture.Observations); index++ {
					row := fixture.Observations[index]
					switch {
					case row.Phase == "cleanup":
						excluded = append(excluded, row.Label+" (native cleanup/absence evidence)")
						continue
					case row.Result.Code == "ParamValidationError":
						if row.Result.HTTPStatus != 0 {
							t.Fatalf("%s SDK validation unexpectedly has a service response", row.Label)
						}
						excluded = append(excluded, row.Label+" (botocore validation; no service request)")
						call(row, row.Input)
						continue
					case row.Phase == "readiness" && row.Result.Code != "Success":
						excluded = append(excluded, row.Label+" (bounded IAM propagation sample)")
						continue
					}
					if row.Result.Code == "Success" && (row.Operation == "GetApiKeys" || row.Operation == "GetUsagePlans" || row.Operation == "GetUsagePlanKeys") {
						// Native lists are projected to owned resources. Their opaque
						// tokens and random-ID tie order are not portable: compare the
						// complete enumeration, retaining all item fields and requiring
						// the repeated native scans to have stable local order too.
						group := row.Label
						if cut := strings.LastIndex(group, "-page-"); cut >= 0 {
							group = group[:cut]
						}
						native := gatewayClone(t, row.Result.Output)
						for index+1 < len(fixture.Observations) && strings.HasPrefix(fixture.Observations[index+1].Label, group+"-page-") {
							index++
							next := fixture.Observations[index]
							if next.Operation != row.Operation || next.Result.Code != "Success" || next.Result.HTTPStatus != row.Result.HTTPStatus {
								t.Fatalf("%s has a non-successful or mismatched native page", next.Label)
							}
							native["items"] = append(native["items"].([]any), next.Result.Output["items"].([]any)...)
						}
						delete(native, "position")
						input := gatewayClone(t, row.Input)
						delete(input, "position")
						actual := map[string]any{"items": []any{}}
						tokens := map[string]bool{}
						for page := 0; ; page++ {
							if page == 100 {
								t.Fatalf("%s pagination did not terminate", group)
							}
							result := call(row, input)
							items, ok := result["items"].([]any)
							if !ok {
								t.Fatalf("%s page %d omitted the items array: %v", group, page, result)
							}
							if limit, ok := input["limit"].(float64); ok && len(items) > int(limit) {
								t.Fatalf("%s page exceeded its limit: %v", group, result)
							}
							actual["items"] = append(actual["items"].([]any), items...)
							pages++
							token, more := result["position"]
							position, valid := token.(string)
							if more && (!valid || position == "") {
								t.Fatalf("%s returned an invalid position: %v", group, token)
							}
							delete(result, "items")
							delete(result, "position")
							for field, value := range result {
								actual[field] = value
							}
							if !more {
								break
							}
							if tokens[position] {
								t.Fatalf("%s returned a repeated position", group)
							}
							tokens[position] = true
							input["position"] = position
						}
						order := gatewayAPIKeysList(t, group, actual, native, bindings)
						for _, family := range []string{"keys", "plans", "associations"} {
							if group == family+"-pagination-0" {
								orders[family] = order
							}
							if group == family+"-pagination-1" && reflect.DeepEqual(fixture.Pagination[family+"-0"], fixture.Pagination[family+"-1"]) && !reflect.DeepEqual(orders[family], order) {
								t.Fatalf("%s changed order across unchanged repeated scans: %v then %v", family, orders[family], order)
							}
						}
						continue
					}
					actual := call(row, row.Input)
					if row.Service == "apigateway" && row.Result.Code == "Success" && row.Phase != "setup" {
						gatewayAPIKeysCompare(t, row.Label, actual, row.Result.Output, bindings)
					}
					if row.Operation == "ImportApiKeys" && row.Input["failOnWarnings"] == true && row.Result.Code != "Success" {
						// Reopen before the very next captured state read. A failed
						// import retained a fresh valid row; keys, plans, tags and
						// associations must survive, as must the operator credential.
						clients = reopen()
						reopened = true
					} else if capture.name == "distinct-id" && row.Operation == "CreateApiKey" && row.Result.Code == "Success" {
						clients = reopen()
						reopened = true
					}
				}
				if !reopened {
					t.Fatal("native capture did not reach its retained key state boundary")
				}
				for _, operation := range fixture.TargetOperations {
					if !seen[operation] {
						t.Fatalf("native target %s was not replayed", operation)
					}
				}
				t.Logf("replayed %d native SDK controls and %d list pages on reopened %s; exact statuses, error codes, field presence and retained state; excluded %v; prior_captures are not selected; no account-wide ordering, token encoding, propagation timing or invocation claim", controls, pages, backend, excluded)
			})
		}
	}
}

func gatewayAPIKeysList(t *testing.T, label string, actual, native map[string]any, bindings map[string]string) []string {
	t.Helper()
	got, want := actual["items"].([]any), native["items"].([]any)
	if len(got) != len(want) {
		t.Fatalf("%s items=%v native=%v", label, got, want)
	}
	byID := map[string]map[string]any{}
	order := make([]string, 0, len(got))
	for _, item := range got {
		object := item.(map[string]any)
		id, ok := object["id"].(string)
		if !ok || id == "" || byID[id] != nil {
			t.Fatalf("%s missing or repeated resource identity: %v", label, object)
		}
		byID[id] = object
		order = append(order, id)
	}
	for _, item := range want {
		object := item.(map[string]any)
		id := object["id"].(string)
		bound, known := bindings[id]
		if !known {
			// Failed imports can commit keys without returning their IDs.
			// Discover these by the supplied name/value, never list position.
			for localID, candidate := range byID {
				if object["name"] == nil || object["name"] != candidate["name"] || object["value"] != nil && gatewayReplace(object["value"].(string), bindings) != candidate["value"] {
					continue
				}
				if bound != "" {
					t.Fatalf("%s ambiguous newly discovered native key %s", label, id)
				}
				bound = localID
			}
			gatewayWSAuthorizerBind(t, label+" discovered id", id, bound, bindings)
		}
		candidate, ok := byID[bound]
		if !ok {
			t.Fatalf("%s missing native item %v", label, object)
		}
		gatewayAPIKeysCompare(t, label+" item "+id, candidate, object, bindings)
		delete(byID, bound)
	}
	delete(actual, "items")
	metadata := gatewayClone(t, native)
	delete(metadata, "items")
	gatewayAPIKeysCompare(t, label+" page fields", actual, metadata, bindings)
	return order
}

func gatewayAPIKeysCompare(t *testing.T, label string, actual, native map[string]any, bindings map[string]string) {
	t.Helper()
	got, want := gatewayClone(t, actual), gatewayClone(t, native)
	gatewaySubstitute(want, bindings)
	// Boto serializes dates as RFC3339; the REST wire uses epoch seconds.
	// Compare presence and valid encoding, not native wall-clock instants.
	// CSV warnings identify rejected records; diagnostic prose is not a contract.
	for index, object := range []map[string]any{got, want} {
		if value, present := object["warnings"]; present {
			warnings, ok := value.([]any)
			if !ok {
				t.Fatalf("%s warnings are not an array: %v", label, value)
			}
			records := make([]int, len(warnings))
			for i, value := range warnings {
				warning, ok := value.(string)
				if !ok {
					t.Fatalf("%s warning is not a string: %v", label, value)
				}
				_, record, found := strings.Cut(warning, "record: ")
				number, _, delimited := strings.Cut(record, ".")
				row, err := strconv.Atoi(number)
				if !found || !delimited || err != nil || row < 1 {
					t.Fatalf("%s warning does not identify its CSV record: %q", label, warning)
				}
				records[i] = row
			}
			object["warnings"] = records
		}
		for _, field := range []string{"createdDate", "lastUpdatedDate"} {
			value, present := object[field]
			if !present {
				continue
			}
			if index == 0 {
				if epoch, ok := value.(float64); !ok || epoch <= 0 {
					t.Fatalf("%s invalid wire %s=%v", label, field, value)
				}
			} else if _, err := time.Parse(time.RFC3339, fmt.Sprint(value)); err != nil {
				t.Fatalf("%s invalid native %s=%v: %v", label, field, value, err)
			}
			object[field] = "<timestamp>"
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s response=%v native=%v", label, got, want)
	}
}

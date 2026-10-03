package stackd_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/clock"
	"stackd/storage"
)

type lambdaQualifiedRow struct {
	lambdaPolicyObservation
	Result struct {
		Code       string
		HTTPStatus int `json:"http_status"`
		Output     map[string]any
		Error      json.RawMessage
	}
}

type lambdaQualifiedFixture struct {
	Observations           []lambdaQualifiedRow
	PublicationEligibility struct{ Observations []lambdaQualifiedRow } `json:"publication_eligibility"`
	RuntimeMarkers         []struct{ Body map[string]any }             `json:"runtime_markers"`
	DestinationRecords     []struct {
		Queue string
		Body  map[string]any
	} `json:"destination_records"`
	CaseMatrix []struct {
		Case              string
		InvokeLabel       string   `json:"invoke_label"`
		DestinationQueues []string `json:"destination_queues"`
	} `json:"case_matrix"`
	CaseSummaries []struct {
		Case            string
		Versions        []string
		RequestContext  map[string]any `json:"requestContext"`
		ResponseContext map[string]any `json:"responseContext"`
	} `json:"case_summaries"`
}

// The same SDK bindings replay native transitions, including failed mutations
// and their following reads. Only transport/runtime identities are normalized.
// Native readiness polling is replaced by the official SDK waiter, not sleeps.
type lambdaQualifiedReplay struct {
	c             *lambdaEventsCloud
	clock         *clock.Manual
	status        *lambdaPolicyHTTP
	actors        map[string]*awslambda.Client
	revisions     lambdaPolicyRevisions
	markers       map[string]string
	queues        map[string]string
	backend, path string
	closeDatabase func()
	reopened      bool
}

func newLambdaQualifiedReplay(t *testing.T, backend string) *lambdaQualifiedReplay {
	t.Helper()
	r := &lambdaQualifiedReplay{backend: backend, path: filepath.Join(t.TempDir(), "qualified.sqlite"), revisions: lambdaPolicyRevisions{}, markers: map[string]string{}, queues: map[string]string{}}
	r.clock = clock.NewManual(time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	backends := storage.NewMemory()
	if backend == "sqlite" {
		backends, r.closeDatabase = openSQLiteBackends(t, r.path)
	}
	r.connect(t, backends)
	return r
}

func (r *lambdaQualifiedReplay) connect(t *testing.T, backends *storage.Backends) {
	r.c = lambdaEventsConnect(t, backends, r.clock)
	r.status = &lambdaPolicyHTTP{client: r.c.server.Client()}
	options := r.c.lambda.Options()
	options.HTTPClient = r.status
	r.c.lambda = awslambda.New(options)
	r.actors = map[string]*awslambda.Client{}
	for _, name := range []string{"", "caller", "native-caller", "authorized-probe-caller", "arn:aws:iam::000000000000:user/Delegated"} {
		r.actors[name] = r.c.lambda
	}
}

func lambdaQualifiedOperations(c *awslambda.Client) map[string]lambdaPolicyOperation {
	return map[string]lambdaPolicyOperation{
		"create-function": lambdaPolicyBind(c.CreateFunction), "update-function-code": lambdaPolicyBind(c.UpdateFunctionCode),
		"update-function-configuration": lambdaPolicyBind(c.UpdateFunctionConfiguration), "get-function-configuration": lambdaPolicyBind(c.GetFunctionConfiguration),
		"get-function": lambdaPolicyBind(c.GetFunction), "delete-function": lambdaPolicyBind(c.DeleteFunction),
		"publish-version": lambdaPolicyBind(c.PublishVersion), "list-versions-by-function": lambdaPolicyBind(c.ListVersionsByFunction), "list-functions": lambdaPolicyBind(c.ListFunctions),
		"create-alias": lambdaPolicyBind(c.CreateAlias), "update-alias": lambdaPolicyBind(c.UpdateAlias), "get-alias": lambdaPolicyBind(c.GetAlias), "delete-alias": lambdaPolicyBind(c.DeleteAlias), "list-aliases": lambdaPolicyBind(c.ListAliases),
		"invoke": lambdaPolicyBind(c.Invoke), "list-tags": lambdaPolicyBind(c.ListTags), "tag-resource": lambdaPolicyBind(c.TagResource),
		"get-function-concurrency": lambdaPolicyBind(c.GetFunctionConcurrency), "put-function-concurrency": lambdaPolicyBind(c.PutFunctionConcurrency), "delete-function-concurrency": lambdaPolicyBind(c.DeleteFunctionConcurrency),
		"add-permission": lambdaPolicyBind(c.AddPermission), "get-policy": lambdaPolicyBind(c.GetPolicy), "remove-permission": lambdaPolicyBind(c.RemovePermission),
		"put-function-event-invoke-config": lambdaPolicyBind(c.PutFunctionEventInvokeConfig), "update-function-event-invoke-config": lambdaPolicyBind(c.UpdateFunctionEventInvokeConfig),
		"get-function-event-invoke-config": lambdaPolicyBind(c.GetFunctionEventInvokeConfig), "delete-function-event-invoke-config": lambdaPolicyBind(c.DeleteFunctionEventInvokeConfig), "list-function-event-invoke-configs": lambdaPolicyBind(c.ListFunctionEventInvokeConfigs),
	}
}

func lambdaQualifiedJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (r *lambdaQualifiedReplay) input(t *testing.T, row lambdaQualifiedRow) map[string]any {
	t.Helper()
	input := *lambdaAdmissionInput[map[string]any](t, lambdaQualifiedJSON(t, row.Input))
	for _, key := range []string{"RevisionId", "Marker"} {
		if native, ok := input[key].(string); ok {
			if local, found := r.revisions[native]; found && key == "RevisionId" {
				input[key] = local
			}
			if local, found := r.markers[native]; found && key == "Marker" {
				input[key] = local
			}
		}
	}
	if payload, ok := input["Payload"].(string); ok && json.Valid([]byte(payload)) {
		input["Payload"] = base64.StdEncoding.EncodeToString([]byte(payload))
	}
	if environment, ok := input["Environment"].(map[string]any); ok {
		if variables, ok := environment["Variables"].(map[string]any); ok {
			for key, value := range variables {
				if native, ok := value.(string); ok {
					if local, found := r.queues[native]; found {
						variables[key] = strings.Replace(local, "127.0.0.1", "host.docker.internal", 1)
					}
				}
			}
		}
	}
	return input
}

func (r *lambdaQualifiedReplay) ready(t *testing.T, name string) {
	t.Helper()
	if err := awslambda.NewFunctionActiveWaiter(r.c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := awslambda.NewFunctionUpdatedV2Waiter(r.c.lambda, func(o *awslambda.FunctionUpdatedV2WaiterOptions) {
		o.MinDelay = 10 * time.Millisecond
		o.MaxDelay = 100 * time.Millisecond
	}).Wait(t.Context(), &awslambda.GetFunctionInput{FunctionName: aws.String(name)}, time.Minute); err != nil {
		t.Fatal(err)
	}
}

func (r *lambdaQualifiedReplay) setup(t *testing.T, row lambdaQualifiedRow) bool {
	t.Helper()
	root := (cloudClients{r.c.server}).iam("test", "test", "")
	input := lambdaQualifiedJSON(t, row.Input)
	var err error
	switch row.Service + "/" + row.Operation {
	case "iam/create-role":
		in := lambdaAdmissionInput[iam.CreateRoleInput](t, input)
		in.AssumeRolePolicyDocument = aws.String(strings.ReplaceAll(aws.ToString(in.AssumeRolePolicyDocument), "arn:aws:iam::000000000000:user/Delegated", "arn:aws:iam::000000000000:root"))
		_, err = root.CreateRole(t.Context(), in)
	case "iam/put-role-policy":
		_, err = root.PutRolePolicy(t.Context(), lambdaAdmissionInput[iam.PutRolePolicyInput](t, input))
	case "iam/delete-role-policy":
		_, err = root.DeleteRolePolicy(t.Context(), lambdaAdmissionInput[iam.DeleteRolePolicyInput](t, input))
	case "iam/delete-role":
		_, err = root.DeleteRole(t.Context(), lambdaAdmissionInput[iam.DeleteRoleInput](t, input))
	case "sts/assume-role":
		in := lambdaAdmissionInput[sts.AssumeRoleInput](t, input)
		out, issueErr := (cloudClients{r.c.server}).sts("test", "test", "").AssumeRole(t.Context(), in)
		err = issueErr
		if err == nil {
			options := r.c.lambda.Options()
			options.Credentials = credentials.NewStaticCredentialsProvider(aws.ToString(out.Credentials.AccessKeyId), aws.ToString(out.Credentials.SecretAccessKey), aws.ToString(out.Credentials.SessionToken))
			actor := awslambda.New(options)
			name := aws.ToString(in.RoleSessionName)
			r.actors[name], r.actors["sts-session-"+name], r.actors["session-"+name] = actor, actor, actor
		}
	case "sqs/create-queue":
		out, createErr := r.c.queues.CreateQueue(t.Context(), lambdaAdmissionInput[sqs.CreateQueueInput](t, input))
		err = createErr
		if err == nil {
			native, _ := row.Result.Output["QueueUrl"].(string)
			r.queues[native] = aws.ToString(out.QueueUrl)
		}
	default:
		return false
	}
	if row.Result.Code == "Success" {
		if err != nil {
			t.Fatal(err)
		}
	} else {
		assertAPIError(t, err, row.Result.Code)
	}
	return true
}

func lambdaQualifiedTransient(row lambdaQualifiedRow) bool {
	// IAM trust/target-permission propagation and a broken captured SigV4
	// request are capture conditions, not Lambda alias/version semantics.
	if row.Operation == "create-function" && row.Result.Code == "InvalidParameterValueException" {
		return strings.Contains(fmt.Sprint(row.Result.Output)+string(row.Result.Error), "cannot be assumed by Lambda")
	}
	if row.Operation == "update-function-configuration" && row.Result.Code == "InvalidParameterValueException" && strings.Contains(row.Label, "_attempt_") {
		return strings.Contains(fmt.Sprint(row.Result.Output)+string(row.Result.Error), "execution role does not have permissions to call SendMessage on SQS")
	}
	return row.Result.Code == "InvalidSignatureException"
}

func (r *lambdaQualifiedReplay) replay(t *testing.T, row lambdaQualifiedRow) map[string]any {
	t.Helper()
	if lambdaQualifiedTransient(row) {
		t.Logf("native transport/propagation observation replaced: %s", row.Label)
		return nil
	}
	if r.setup(t, row) || row.Service != "lambda" {
		return nil
	}
	input := r.input(t, row)
	client := r.actors[row.Actor]
	if client == nil {
		t.Fatalf("unmapped fixture actor %q", row.Actor)
	}
	operation := lambdaQualifiedOperations(client)[row.Operation]
	if operation == nil {
		t.Fatalf("unbound fixture operation %s", row.Operation)
	}
	// Readiness sequences contain arbitrary numbers of transient snapshots.
	// Preserve their settled revision/configuration observations only.
	if row.Operation == "get-function-configuration" && row.Result.Code == "Success" {
		state, update := row.Result.Output["State"], row.Result.Output["LastUpdateStatus"]
		if state == "Pending" || update == "InProgress" {
			return nil
		}
		if state == "Active" {
			r.ready(t, input["FunctionName"].(string))
		}
	}
	r.status.status = 0
	var actual map[string]any
	var err error
	// The SDK rejects missing required bodies and empty URI labels before HTTP.
	// Replay the captured path directly; an empty alias resolves to its collection.
	emptyAlias := row.Operation == "get-alias" && input["Name"] == ""
	if emptyAlias || row.Operation == "create-alias" && (input["Name"] == nil || input["FunctionVersion"] == nil) {
		method := http.MethodPost
		path := r.c.server.URL + "/2015-03-31/functions/" + url.PathEscape(input["FunctionName"].(string)) + "/aliases"
		body := lambdaQualifiedJSON(t, input)
		if emptyAlias {
			method, path, body = http.MethodGet, path+"/", nil
		}
		request, requestErr := http.NewRequestWithContext(t.Context(), method, path, strings.NewReader(string(body)))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Content-Type", "application/json")
		response, data := lambdaRawRequest(t, r.c.server, request, body, aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"})
		if response.StatusCode != row.Result.HTTPStatus || row.Result.Code != "Success" && response.Header.Get("X-Amzn-ErrorType") != row.Result.Code {
			t.Fatalf("HTTP %d %s; native %s", response.StatusCode, data, row.Result.Code)
		}
		if row.Result.Code == "Success" {
			if err := json.Unmarshal(data, &actual); err != nil {
				t.Fatal(err)
			}
			r.compare(t, actual, row.Result.Output, "")
			return actual
		}
		return nil
	}
	actual, err = operation(t.Context(), input)
	if row.Result.HTTPStatus != 0 && r.status.status != row.Result.HTTPStatus {
		t.Fatalf("%s HTTP %d; native %d: %v", row.Label, r.status.status, row.Result.HTTPStatus, err)
	}
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	want := *lambdaAdmissionInput[map[string]any](t, lambdaQualifiedJSON(t, row.Result.Output))
	if row.Operation == "invoke" {
		if payload, ok := actual["Payload"].(string); ok && payload != "" {
			decoded, decodeErr := base64.StdEncoding.DecodeString(payload)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			var value any
			if err := json.Unmarshal(decoded, &value); err != nil {
				t.Fatalf("customer payload %s: %v", decoded, err)
			}
			actual["Payload"] = value
		}
		if _, wrapped := want["StatusCode"]; !wrapped {
			actual = actual["Payload"].(map[string]any)
		}
		if strings.Contains(row.Label, "invoke_mixed_") {
			// A finite sample says nothing about exact routing frequencies. Every
			// selected artifact must nevertheless agree with runtime identity.
			version := actual["function_version"]
			if version != "1" && version != "2" {
				t.Fatalf("unexpected selected version %#v", actual)
			}
			want["function_version"] = version
			if version == "1" {
				want["marker"] = "version-a"
			} else {
				want["marker"] = "version-b"
			}
		}
	}
	if strings.Contains(row.Operation, "event-invoke-config") {
		for _, key := range []string{"MaximumRetryAttempts", "MaximumEventAgeInSeconds"} {
			if _, present := want[key]; !present && actual[key] != nil {
				t.Fatalf("replacement retained %s=%v absent from native response", key, actual[key])
			}
		}
	}
	r.compare(t, actual, want, "")
	return actual
}

// Project meaningful configuration/state and complete policy/routing/tag maps;
// SDK incidental default fields, transport metadata and runtime image ARN are
// intentionally not an API contract of this replay.
func (r *lambdaQualifiedReplay) compare(t *testing.T, actual, want map[string]any, parent string) {
	t.Helper()
	fields := map[string]bool{}
	for _, key := range strings.Fields("FunctionName FunctionArn Runtime Role Handler CodeSize CodeSha256 Description Timeout MemorySize Version State LastUpdateStatus Environment Variables DeadLetterConfig TargetArn Configuration Versions Functions AliasArn Name FunctionVersion RoutingConfig AdditionalVersionWeights Aliases Tags ReservedConcurrentExecutions Statement Policy MaximumRetryAttempts MaximumEventAgeInSeconds DestinationConfig OnSuccess OnFailure Destination FunctionEventInvokeConfigs ExecutedVersion StatusCode FunctionError Payload code config version invoked_arn event marker function_version invoked_function_arn deployment kind requestContext responseContext requestPayload responsePayload functionArn condition statusCode executedVersion functionError errorType errorMessage") {
		fields[key] = true
	}
	for key, expected := range want {
		if key == "RevisionId" {
			if want["State"] == "Pending" || want["LastUpdateStatus"] == "InProgress" {
				continue
			}
			if native, ok := expected.(string); ok {
				local, _ := actual[key].(string)
				r.revisions.observe(t, native, local)
			}
			continue
		}
		if key == "NextMarker" {
			if expected == nil || expected == "" {
				if actual[key] != nil && actual[key] != "" {
					t.Fatalf("unexpected next page %v", actual[key])
				}
				continue
			}
			local, _ := actual[key].(string)
			if local == "" {
				t.Fatal("native continuation page lost")
			}
			r.markers[expected.(string)] = local
			continue
		}
		if key == "request_id" || key == "requestId" || key == "started_at" || key == "boot_id" || key == "boot_count" || key == "timestamp" || key == "LastModified" {
			continue
		}
		if !fields[key] && parent != "Variables" && parent != "Tags" && parent != "AdditionalVersionWeights" && parent != "event" && parent != "requestPayload" {
			continue
		}
		got := actual[key]
		if expected == nil && got == nil {
			continue
		}
		if expected == nil {
			// The SDK represents absent readiness enums as empty strings.
			if (key == "State" || key == "LastUpdateStatus") && got == "" {
				continue
			}
			if object, ok := got.(map[string]any); ok && lambdaQualifiedMapSize(object) == 0 {
				continue
			}
		}
		if key == "Payload" && expected == "" && got == nil {
			continue
		}
		if nested, ok := expected.(map[string]any); ok {
			local, _ := got.(map[string]any)
			if local == nil && len(nested) != 0 {
				t.Fatalf("%s missing map: local response %#v; native %#v", key, actual, nested)
			}
			if key == "Variables" || key == "Tags" || key == "AdditionalVersionWeights" || key == "RoutingConfig" || key == "DestinationConfig" {
				if lambdaQualifiedMapSize(local) != lambdaQualifiedMapSize(nested) {
					t.Fatalf("%s=%#v; native=%#v", key, local, nested)
				}
			}
			r.compare(t, local, nested, key)
			continue
		}
		if list, ok := expected.([]any); ok {
			local, _ := got.([]any)
			if len(local) != len(list) {
				t.Fatalf("%s=%#v; native=%#v", key, local, list)
			}
			for i, value := range list {
				if object, ok := value.(map[string]any); ok {
					r.compare(t, local[i].(map[string]any), object, key)
				} else if !reflect.DeepEqual(local[i], value) {
					t.Fatalf("%s[%d]=%#v; native %#v", key, i, local[i], value)
				}
			}
			continue
		}
		if key == "Policy" || key == "Statement" {
			var a, b any
			if json.Unmarshal([]byte(fmt.Sprint(got)), &a) != nil || json.Unmarshal([]byte(fmt.Sprint(expected)), &b) != nil || !reflect.DeepEqual(a, b) {
				t.Fatalf("%s=%s; native=%s", key, got, expected)
			}
			continue
		}
		if parent == "Variables" {
			if native, ok := expected.(string); ok {
				if local, found := r.queues[native]; found {
					expected = strings.Replace(local, "127.0.0.1", "host.docker.internal", 1)
				}
			}
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("%s.%s=%#v; native=%#v", parent, key, got, expected)
		}
	}
}
func lambdaQualifiedMapSize(object map[string]any) int {
	count := 0
	for _, value := range object {
		if value != nil {
			count++
		}
	}
	return count
}

func TestLambdaVersionsNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := lambdaFixture[lambdaQualifiedFixture](t, "version_publication")
			r := newLambdaQualifiedReplay(t, backend)
			listed := false
			rows := append(f.Observations, f.PublicationEligibility.Observations...)
			rows = append(rows, lambdaFixture[lambdaQualifiedFixture](t, "version_deletion").Observations...)
			for _, row := range rows {
				if row.Service != "lambda" && row.Service != "iam" {
					continue
				}
				// Native ListFunctions pages traverse unrelated account resources
				// that were deliberately redacted from this fixture. Compare their
				// complete owned inventory, not those account-global page boundaries.
				if row.Operation == "list-functions" {
					if listed {
						continue
					}
					listed = true
					var expected []any
					for _, page := range f.Observations {
						if page.Operation == "list-functions" {
							values, _ := page.Result.Output["Functions"].([]any)
							expected = append(expected, values...)
						}
					}
					input := r.input(t, row)
					delete(input, "Marker")
					delete(input, "MaxItems")
					actual, err := lambdaPolicyBind(r.c.lambda.ListFunctions)(t.Context(), input)
					if err != nil {
						t.Fatal(err)
					}
					r.compare(t, actual, map[string]any{"Functions": expected}, "")
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) { r.replay(t, row) }) {
					t.FailNow()
				}
			}
		})
	}
}

// Reopen with retained versions, aliases and archives before their native reads.
// Fetch a fresh signed URL after reopening; public endpoint identity is separate
// from persistence of the immutable ZIP itself.
func (r *lambdaQualifiedReplay) reopen(t *testing.T, name string) {
	t.Helper()
	if r.backend != "sqlite" || r.reopened {
		return
	}
	r.ready(t, name)
	if err := r.c.cloud.Close(); err != nil {
		t.Fatal(err)
	}
	r.c.server.Close()
	r.closeDatabase()
	backends, closeDatabase := openSQLiteBackends(t, r.path)
	r.closeDatabase = closeDatabase
	r.connect(t, backends)
	r.reopened = true
	versions, err := r.c.lambda.ListVersionsByFunction(t.Context(), &awslambda.ListVersionsByFunctionInput{FunctionName: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range versions.Versions {
		if aws.ToString(version.Version) == "$LATEST" {
			continue
		}
		out, err := r.c.lambda.GetFunction(t.Context(), &awslambda.GetFunctionInput{FunctionName: aws.String(name), Qualifier: version.Version})
		if err != nil {
			t.Fatal(err)
		}
		location, err := url.Parse(aws.ToString(out.Code.Location))
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, location.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = request.URL.Host
		local, _ := url.Parse(r.c.server.URL)
		request.URL.Host = local.Host
		response, err := r.c.server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		if response.StatusCode != http.StatusOK || base64.StdEncoding.EncodeToString(digest[:]) != aws.ToString(version.CodeSha256) {
			t.Fatalf("version %s archive changed across reopen: HTTP %d", aws.ToString(version.Version), response.StatusCode)
		}
	}
}

// Compare complete native inventories through the existing typed SDK bindings.
// Neither alias nor async-configuration listing promises an ordering.
func (r *lambdaQualifiedReplay) inventoryPages(t *testing.T, rows []lambdaQualifiedRow, field, identity string) int {
	t.Helper()
	want := map[string]map[string]any{}
	consumed := 0
	for {
		row := rows[consumed]
		items, _ := row.Result.Output[field].([]any)
		for _, item := range items {
			value := item.(map[string]any)
			want[value[identity].(string)] = value
		}
		consumed++
		marker, _ := row.Result.Output["NextMarker"].(string)
		if marker == "" {
			break
		}
		if consumed == len(rows) || rows[consumed].Operation != row.Operation || rows[consumed].Input["Marker"] != marker {
			t.Fatal("native inventory pagination chain is incomplete")
		}
	}
	input := r.input(t, rows[0])
	operation := lambdaQualifiedOperations(r.c.lambda)[rows[0].Operation]
	for {
		page, err := operation(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		items, _ := page[field].([]any)
		if limit, ok := input["MaxItems"].(float64); ok && len(items) > int(limit) {
			t.Fatalf("%s page exceeds MaxItems: %d", field, len(items))
		}
		for _, item := range items {
			value := item.(map[string]any)
			id := value[identity].(string)
			native, found := want[id]
			if !found {
				t.Fatalf("unexpected or repeated %s resource %s", field, id)
			}
			r.compare(t, value, native, "")
			delete(want, id)
		}
		marker, _ := page["NextMarker"].(string)
		if marker == "" {
			break
		}
		input["Marker"] = marker
	}
	if len(want) != 0 {
		t.Fatalf("%s pagination omitted native resources: %#v", field, want)
	}
	return consumed
}

package stackd_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

// Read the retained capture directly; only fields consumed by this replay are decoded.
type lambdaURLFixture struct {
	Prefix    string
	StartedAt time.Time `json:"started_at"`
	Artifact  struct {
		ZIP string `json:"zip_base64"`
	}
	Observations []lambdaURLRow
	HTTPCases    []json.RawMessage `json:"http_cases"`
}
type lambdaURLRow struct {
	Label, Service, Operation string
	StartedAt                 time.Time `json:"started_at"`
	Input                     json.RawMessage
	Result                    struct {
		Code   string
		Output map[string]any
	}
}

func (f lambdaURLFixture) row(t *testing.T, label string) lambdaURLRow {
	t.Helper()
	for _, row := range f.Observations {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("missing native URL observation %s", label)
	return lambdaURLRow{}
}
func lambdaURLDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to replay native function URLs against real Docker Lambda")
	}
}

type lambdaURLReplay struct {
	c                        *lambdaEventsCloud
	clock                    *clock.Manual
	fixture                  lambdaURLFixture
	wire                     *awstest.WireClient
	normalize                *strings.Replacer
	urls, markers            map[string]string
	keys                     map[string]aws.Credentials
	users                    map[string]string
	listActual, listExpected []any
}

func newLambdaURLReplay(t *testing.T, fixture string, backends *storage.Backends, source *clock.Manual) *lambdaURLReplay {
	t.Helper()
	f := lambdaFixture[lambdaURLFixture](t, fixture)
	if source == nil {
		source = clock.NewManual(f.StartedAt)
	}
	r := &lambdaURLReplay{fixture: f, clock: source, normalize: strings.NewReplacer("000000000000", "000000000000"), urls: map[string]string{}, markers: map[string]string{}, keys: map[string]aws.Credentials{}, users: map[string]string{}}
	r.connect(t, backends)
	return r
}
func (r *lambdaURLReplay) connect(t *testing.T, backends *storage.Backends) {
	r.c = lambdaEventsConnect(t, backends, r.clock)
	r.wire = &awstest.WireClient{Client: r.c.server.Client()}
	options := r.c.lambda.Options()
	options.HTTPClient = r.wire
	r.c.lambda = awslambda.New(options)
}
func lambdaURLOperations(c *awslambda.Client) map[string]lambdaPolicyOperation {
	ops := lambdaQualifiedOperations(c)
	ops["create-function-url-config"] = lambdaPolicyBind(c.CreateFunctionUrlConfig)
	ops["get-function-url-config"] = lambdaPolicyBind(c.GetFunctionUrlConfig)
	ops["update-function-url-config"] = lambdaPolicyBind(c.UpdateFunctionUrlConfig)
	ops["delete-function-url-config"] = lambdaPolicyBind(c.DeleteFunctionUrlConfig)
	ops["list-function-url-configs"] = lambdaPolicyBind(c.ListFunctionUrlConfigs)
	return ops
}
func (r *lambdaURLReplay) ready(t *testing.T) {
	t.Helper()
	if err := awslambda.NewFunctionActiveWaiter(r.c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &r.fixture.Prefix}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := awslambda.NewFunctionUpdatedWaiter(r.c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &r.fixture.Prefix}, time.Minute); err != nil {
		t.Fatal(err)
	}
}
func (r *lambdaURLReplay) command(t *testing.T, row lambdaURLRow) {
	t.Helper()
	root := (cloudClients{r.c.server}).iam("test", "test", "")
	var err error
	switch row.Operation {
	case "get_caller_identity", "sleep", "get_function_configuration", "get_user_policy", "list_user_policies", "list_attached_user_policies", "list_groups_for_user":
		t.Logf("native setup/polling record: %s (%s)", row.Label, row.Operation)
		return
	case "create_role":
		input := lambdaStreamingInput[iam.CreateRoleInput](t, row.Input, r.normalize)
		_, err = root.CreateRole(t.Context(), &input)
	case "put_role_policy":
		input := lambdaStreamingInput[iam.PutRolePolicyInput](t, row.Input, r.normalize)
		_, err = root.PutRolePolicy(t.Context(), &input)
	case "create_user":
		input := lambdaStreamingInput[iam.CreateUserInput](t, row.Input, r.normalize)
		var out *iam.CreateUserOutput
		out, err = root.CreateUser(t.Context(), &input)
		if err == nil {
			r.users[aws.ToString(input.UserName)] = aws.ToString(out.User.UserId)
		}
	case "create_access_key":
		input := lambdaStreamingInput[iam.CreateAccessKeyInput](t, row.Input, r.normalize)
		var out *iam.CreateAccessKeyOutput
		out, err = root.CreateAccessKey(t.Context(), &input)
		if err == nil {
			r.keys[aws.ToString(input.UserName)] = aws.Credentials{AccessKeyID: aws.ToString(out.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey)}
		}
	case "put_user_policy":
		input := lambdaStreamingInput[iam.PutUserPolicyInput](t, row.Input, r.normalize)
		_, err = root.PutUserPolicy(t.Context(), &input)
	case "delete_user_policy":
		input := lambdaStreamingInput[iam.DeleteUserPolicyInput](t, row.Input, r.normalize)
		_, err = root.DeleteUserPolicy(t.Context(), &input)
	case "create_log_group":
		input := lambdaStreamingInput[cloudwatchlogs.CreateLogGroupInput](t, row.Input, r.normalize)
		_, err = logsClient(cloudClients{r.c.server}, "test").CreateLogGroup(t.Context(), &input)
	default:
		input := lambdaStreamingInput[map[string]any](t, row.Input, r.normalize)
		if row.Operation == "create_function" {
			input["Code"] = map[string]any{"ZipFile": r.fixture.Artifact.ZIP}
		}
		if marker, ok := input["Marker"].(string); ok && r.markers[marker] != "" {
			input["Marker"] = r.markers[marker]
		}
		client := r.c.lambda
		if row.Operation == "invoke" {
			user := r.fixture.Prefix + "-caller"
			if strings.HasPrefix(row.Label, "direct_invoke_") {
				user = r.fixture.Prefix + "-" + strings.TrimPrefix(row.Label, "direct_invoke_")
			}
			key, ok := r.keys[user]
			if !ok {
				t.Fatalf("no credentials for %s", user)
			}
			options := client.Options()
			options.Credentials = credentials.NewStaticCredentialsProvider(key.AccessKeyID, key.SecretAccessKey, "")
			client = awslambda.New(options)
		}
		if strings.Contains(row.Operation, "function_url_config") && (input["AuthType"] == "" || input["InvokeMode"] == "") {
			// Go's enum zero value is omitted by its SDK serializer. Preserve the
			// native fixture's explicit empty field before the SDK signs and
			// deserializes the request, so this still tests the service boundary.
			body := make(map[string]any)
			for key, value := range input {
				if key != "FunctionName" && key != "Qualifier" {
					body[key] = value
				}
			}
			payload := lambdaQualifiedJSON(t, body)
			options := client.Options()
			options.APIOptions = append(options.APIOptions, awstest.JSONBody(payload))
			client = awslambda.New(options)
		}
		operation := lambdaURLOperations(client)[strings.ReplaceAll(row.Operation, "_", "-")]
		if operation == nil {
			t.Fatalf("unclassified native URL operation %s (%s)", row.Operation, row.Label)
		}
		var output map[string]any
		output, err = operation(t.Context(), input)
		if err == nil && (row.Operation == "add_permission" || row.Operation == "get_policy") {
			for _, field := range []string{"Statement", "Policy"} {
				native, ok := row.Result.Output[field].(string)
				if !ok {
					continue
				}
				local, ok := output[field].(string)
				if !ok {
					t.Fatalf("%s omitted %s", row.Label, field)
				}
				var actual, expected map[string]any
				if e := json.Unmarshal([]byte(local), &actual); e != nil {
					t.Fatal(e)
				}
				if e := json.Unmarshal([]byte(r.normalize.Replace(native)), &expected); e != nil {
					t.Fatal(e)
				}
				// Policy statement order is not significant; full conditions and resources are.
				order := func(policy map[string]any) {
					if rows, ok := policy["Statement"].([]any); ok {
						sort.Slice(rows, func(i, j int) bool {
							return rows[i].(map[string]any)["Sid"].(string) < rows[j].(map[string]any)["Sid"].(string)
						})
					}
				}
				order(actual)
				order(expected)
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("%s %s got %s want %s", row.Label, field, local, native)
				}
			}
		}
		if err == nil && strings.Contains(row.Operation, "function_url_config") {
			actual := map[string]any{}
			if len(r.wire.Body) > 0 {
				if e := json.Unmarshal(r.wire.Body, &actual); e != nil {
					t.Fatal(e)
				}
			}
			expected := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, row.Result.Output), r.normalize)
			if metadata, ok := expected["ResponseMetadata"].(map[string]any); ok && int(metadata["HTTPStatusCode"].(float64)) != r.wire.Status {
				t.Fatalf("%s HTTP status=%d want %v", row.Label, r.wire.Status, metadata["HTTPStatusCode"])
			}
			r.compareConfig(t, actual, expected)
		}
	}
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
		return
	}
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	if row.Operation == "create_function" || row.Operation == "update_function_configuration" {
		r.ready(t)
	}
}
func (r *lambdaURLReplay) compareConfig(t *testing.T, actual, expected map[string]any) {
	t.Helper()
	delete(expected, "ResponseMetadata")
	for _, field := range []string{"FunctionUrl", "CreationTime", "LastModifiedTime", "NextMarker"} {
		native, nativeOK := expected[field].(string)
		local, localOK := actual[field].(string)
		if nativeOK != localOK {
			t.Fatalf("%s presence: got %v want %v", field, actual, expected)
		}
		if !nativeOK {
			continue
		}
		if local == "" {
			t.Fatalf("empty %s", field)
		}
		switch field {
		case "FunctionUrl":
			u, e := url.Parse(local)
			if e != nil || !strings.HasPrefix(u.Path, "/_stackd/lambda/urls/") || !strings.HasSuffix(u.Path, "/") {
				t.Fatalf("invalid advertised URL %q: %v", local, e)
			}
			// Endpoint ports change on restart; URL identity does not.
			if old := r.urls[native]; old != "" {
				previous, _ := url.Parse(old)
				if previous.Path != u.Path {
					t.Fatalf("retained URL identity changed: %s -> %s", old, local)
				}
			} else {
				for other, old := range r.urls {
					previous, _ := url.Parse(old)
					if other != native && previous.Path == u.Path {
						t.Fatal("URL recreation reused a deleted identity")
					}
				}
			}
			r.urls[native] = local
		case "NextMarker":
			r.markers[native] = local
		default:
			if _, e := time.Parse(time.RFC3339Nano, local); e != nil {
				t.Fatalf("invalid %s %q", field, local)
			}
		}
		expected[field] = local
	}
	if values, ok := expected["FunctionUrlConfigs"].([]any); ok {
		got, ok := actual["FunctionUrlConfigs"].([]any)
		if !ok || len(got) != len(values) {
			t.Fatalf("URL inventory got %v want %v", actual, expected)
		}
		// AWS does not promise URL list ordering. Compare the complete traversal,
		// retaining page cardinality and cursor presence instead of equating an
		// arbitrary native page's member with the same local page position.
		more := expected["NextMarker"] != nil
		if more || r.listActual != nil {
			r.listActual = append(r.listActual, got...)
			r.listExpected = append(r.listExpected, values...)
			if more {
				return
			}
			got, values = r.listActual, r.listExpected
			r.listActual, r.listExpected = nil, nil
			actual["FunctionUrlConfigs"] = got
		}
		byARN := func(rows []any) {
			sort.Slice(rows, func(i, j int) bool {
				return rows[i].(map[string]any)["FunctionArn"].(string) < rows[j].(map[string]any)["FunctionArn"].(string)
			})
		}
		byARN(got)
		byARN(values)
		for i := range values {
			r.compareConfig(t, got[i].(map[string]any), values[i].(map[string]any))
		}
		expected["FunctionUrlConfigs"] = got
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("URL wire configuration differs:\ngot %s\nwant %s", lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
	}
}

func TestLambdaURLsDockerControlLifecycle(t *testing.T) {
	lambdaURLDocker(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			path := filepath.Join(t.TempDir(), "urls.sqlite")
			var closeDB func()
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			r := newLambdaURLReplay(t, "urls_control", backends, nil)
			// Public lifecycle HTTP runs immediately after each final native config/policy
			// snapshot. Earlier attempts are native propagation polling, not another matrix.
			public := map[string]lambdaURLAuthCase{}
			for _, raw := range r.fixture.HTTPCases {
				var h lambdaURLAuthCase
				if err := json.Unmarshal(raw, &h); err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(h.Label, "iam_") {
					if previous, ok := public[h.Label]; ok {
						t.Logf("native public URL propagation polling record: %s attempt %d", previous.Label, previous.Attempt)
					}
					public[h.Label] = h
				} else {
					t.Logf("native mutable-principal polling record %s; fixed-principal authorization replay owns this evidence", h.Label)
				}
			}
			for _, row := range r.fixture.Observations {
				if !t.Run(row.Label, func(t *testing.T) { r.command(t, row) }) {
					t.FailNow()
				}
				if row.Label == "get_after_omitted_update" && backend == "sqlite" {
					if err := r.c.cloud.Close(); err != nil {
						t.Fatal(err)
					}
					r.c.server.Close()
					closeDB()
					backends, closeDB = openSQLiteBackends(t, path)
					r.connect(t, backends)
					r.command(t, row)
				}
				for label, h := range public {
					if row.Label == label+"_policy_"+h.attempt() {
						advanceClock(t, r.clock, time.Minute)
						if !t.Run("http_"+label, func(t *testing.T) { r.authHTTP(t, h, aws.Credentials{}) }) {
							t.FailNow()
						}
						delete(public, label)
					}
				}
			}
			if r.listActual != nil {
				t.Fatal("URL pagination fixture did not finish its traversal")
			}
			if len(public) != 0 {
				t.Fatalf("unreplayed public lifecycle cases: %v", public)
			}
			t.Run("scoped_lookup", func(t *testing.T) {
				options := r.c.lambda.Options()
				options.Region = "us-west-2"
				otherRegion := awslambda.New(options)
				_, err := otherRegion.GetFunctionUrlConfig(t.Context(), &awslambda.GetFunctionUrlConfigInput{FunctionName: &r.fixture.Prefix})
				assertAPIError(t, err, "ResourceNotFoundException")
				_, err = r.c.lambda.ListFunctionUrlConfigs(t.Context(), &awslambda.ListFunctionUrlConfigsInput{FunctionName: aws.String(r.fixture.Prefix + "-missing")})
				assertAPIError(t, err, "ResourceNotFoundException")
			})
		})
	}
}

type lambdaURLAuthCase struct {
	Label, Method, URL, Path, Query string
	Attempt                         int
	SigningPrincipal                string      `json:"signing_principal"`
	RequestHeaders                  [][2]string `json:"request_headers"`
	RequestBody                     string      `json:"request_body_base64"`
	Status                          int
	Body                            string         `json:"body_base64"`
	Event                           map[string]any `json:"decoded_lambda_event"`
	Output                          map[string]any `json:"decoded_output"`
}

func (h lambdaURLAuthCase) attempt() string { return strconv.Itoa(h.Attempt) }

func TestLambdaURLsDockerFixedPrincipalAuthorization(t *testing.T) {
	lambdaURLDocker(t)
	r := newLambdaURLReplay(t, "urls_authorization", storage.NewMemory(), nil)
	for _, row := range r.fixture.Observations {
		if !t.Run(row.Label, func(t *testing.T) { r.command(t, row) }) {
			t.FailNow()
		}
	}
	advanceClock(t, r.clock, time.Minute)
	for _, raw := range r.fixture.HTTPCases {
		var h lambdaURLAuthCase
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(h.Label, "_round_2") {
			t.Logf("native fixed-principal settling/polling record: %s", h.Label)
			continue
		}
		user := h.SigningPrincipal[strings.LastIndex(h.SigningPrincipal, "/")+1:]
		key, ok := r.keys[user]
		if !ok {
			t.Fatalf("missing captured caller %s", user)
		}
		if !t.Run(h.Label, func(t *testing.T) { r.authHTTP(t, h, key) }) {
			t.FailNow()
		}
	}
}
func (r *lambdaURLReplay) authHTTP(t *testing.T, h lambdaURLAuthCase, key aws.Credentials) {
	t.Helper()
	native, _ := url.Parse(h.URL)
	native.Path = "/"
	native.RawPath = ""
	native.RawQuery = ""
	target := r.urls[native.String()]
	if target == "" {
		t.Fatalf("unmapped native URL %s", h.URL)
	}
	body, err := base64.StdEncoding.DecodeString(h.RequestBody)
	if err != nil {
		t.Fatal(err)
	}
	suffix := h.Path
	if h.Query != "" {
		suffix += "?" + h.Query
	}
	headers := make([][2]string, 0, len(h.RequestHeaders))
	for _, pair := range h.RequestHeaders {
		if !strings.EqualFold(pair[0], "Authorization") && !strings.EqualFold(pair[0], "X-Amz-Date") {
			headers = append(headers, pair)
		}
	}
	request := r.request(t, target, suffix, h.Method, headers, body)
	// Python's HTTP client in the control/auth capture adds this transport header.
	request.Header.Set("Accept-Encoding", "identity")
	if key.AccessKeyID != "" {
		lambdaURLSign(t, request, body, key)
	}
	client := r.httpClient()
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != h.Status {
		t.Fatalf("HTTP %d want %d: %s", response.StatusCode, h.Status, data)
	}
	if h.Status != 200 {
		want, _ := base64.StdEncoding.DecodeString(h.Body)
		if h.Status == http.StatusForbidden {
			lambdaURLForbidden(t, data, want)
		} else {
			lambdaURLBody(t, data, want)
		}
		return
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("not customer output: %s: %v", data, err)
	}
	event, ok := output["event"].(map[string]any)
	if !ok {
		t.Fatalf("no executed customer event: %s", data)
	}
	want := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, h.Event), r.normalize)
	if key.AccessKeyID != "" {
		user := h.SigningPrincipal[strings.LastIndex(h.SigningPrincipal, "/")+1:]
		identity := event["requestContext"].(map[string]any)["authorizer"].(map[string]any)["iam"].(map[string]any)
		if identity["userArn"] != r.normalize.Replace(h.SigningPrincipal) || identity["userId"] != r.users[user] || identity["accessKey"] != key.AccessKeyID {
			t.Fatalf("executed identity is not signed caller: %v", identity)
		}
		nativeIdentity := want["requestContext"].(map[string]any)["authorizer"].(map[string]any)["iam"].(map[string]any)
		nativeIdentity["userId"] = r.users[user]
		nativeIdentity["callerId"] = r.users[user]
		nativeIdentity["accessKey"] = key.AccessKeyID
	}
	lambdaURLEvent(t, event, want)
	for _, field := range []string{"revision", "version", "invokedFunctionArn", "ownedProbe"} {
		if expected, ok := h.Output[field]; ok {
			actual := output[field]
			if s, ok := expected.(string); ok {
				expected = r.normalize.Replace(s)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("customer %s got %v want %v", field, actual, expected)
			}
		}
	}
}

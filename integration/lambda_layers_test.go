package stackd_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"

	"stackd/storage"
)

type lambdaLayerFixture struct {
	Provenance struct {
		Context struct{ Prefix string }
	}
	ReplayCases  map[string][]string `json:"replay_cases"`
	Observations []lambdaQualifiedRow
	Artifacts    map[string]struct {
		ZIP        struct{ Base64 []byte }
		CodeSHA256 string `json:"code_sha256"`
	}
}

// Native captures retain binary provenance beside base64. The SDK's JSON input
// decoder takes the base64 string itself for []byte fields; never rewrite ZIPs.
func lambdaNativeBlobInput(value any) any {
	switch value := value.(type) {
	case map[string]any:
		if encoded, ok := value["base64"].(string); ok {
			if _, binary := value["sha256_hex"]; binary {
				return encoded
			}
		}
		out := make(map[string]any, len(value))
		for key, child := range value {
			out[key] = lambdaNativeBlobInput(child)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = lambdaNativeBlobInput(child)
		}
		return out
	default:
		return value
	}
}

func lambdaLayerOperations(client *awslambda.Client) map[string]lambdaPolicyOperation {
	operations := lambdaQualifiedOperations(client)
	operations["publish-layer-version"] = lambdaPolicyBind(client.PublishLayerVersion)
	operations["get-layer-version"] = lambdaPolicyBind(client.GetLayerVersion)
	operations["get-layer-version-by-arn"] = lambdaPolicyBind(client.GetLayerVersionByArn)
	operations["delete-layer-version"] = lambdaPolicyBind(client.DeleteLayerVersion)
	operations["list-layer-versions"] = lambdaPolicyBind(client.ListLayerVersions)
	operations["list-layers"] = lambdaPolicyBind(client.ListLayers)
	operations["add-layer-version-permission"] = lambdaPolicyBind(client.AddLayerVersionPermission)
	operations["remove-layer-version-permission"] = lambdaPolicyBind(client.RemoveLayerVersionPermission)
	operations["get-layer-version-policy"] = lambdaPolicyBind(client.GetLayerVersionPolicy)
	return operations
}

func TestLambdaLayerCatalogNativeSDK(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range []string{"catalog", "latest_filter"} {
			t.Run(backend+"/"+scenario, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "layers.sqlite"))
				}
				_, clients, _ := startEventDeliveryCloud(t, backends, nil)
				status := &lambdaPolicyHTTP{client: clients.server.Client()}
				client := awslambda.New(awslambda.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: status, RetryMaxAttempts: 1})
				r := &lambdaQualifiedReplay{c: &lambdaEventsCloud{server: clients.server, lambda: client}, status: status, revisions: lambdaPolicyRevisions{}, markers: map[string]string{}}
				lambdaLayersReplay(t, r, lambdaFixture[lambdaLayerFixture](t, "layers"), scenario)
			})
		}
	}
}

func TestLambdaLayerRuntimeNativeSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, scenario := range []string{"runtime", "cold_retention"} {
			t.Run(backend+"/"+scenario, func(t *testing.T) {
				lambdaLayersReplay(t, newLambdaQualifiedReplay(t, backend), lambdaFixture[lambdaLayerFixture](t, "layers"), scenario)
			})
		}
	}
}

func lambdaLayersReplay(t *testing.T, r *lambdaQualifiedReplay, fixture lambdaLayerFixture, scenario string) {
	t.Helper()
	replayOwner := t
	rows := make(map[string]lambdaQualifiedRow, len(fixture.Observations))
	for _, row := range fixture.Observations {
		rows[row.Label] = row
	}
	labels := fixture.ReplayCases[scenario]
	if len(labels) == 0 {
		t.Fatalf("missing native replay scenario %s", scenario)
	}
	boots := map[string]string{}
	for i := 0; i < len(labels); i++ {
		row, ok := rows[labels[i]]
		if !ok {
			t.Fatalf("missing native observation %s", labels[i])
		}
		if row.Operation == "list-layers" && row.Result.Code == "Success" {
			pages := []lambdaQualifiedRow{row}
			for i+1 < len(labels) {
				next := rows[labels[i+1]]
				if next.Operation != "list-layers" || next.Result.Code != "Success" || next.Input["Marker"] == nil {
					break
				}
				pages = append(pages, next)
				i++
			}
			if !t.Run(row.Label, func(t *testing.T) { lambdaLayerPages(t, r, fixture, scenario, pages) }) {
				t.FailNow()
			}
			continue
		}
		if !t.Run(row.Label, func(t *testing.T) {
			if r.setup(t, row) {
				return
			}
			input := lambdaNativeBlobInput(r.input(t, row)).(map[string]any)
			name, _ := input["FunctionName"].(string)
			if row.Label == "cold-first-invoke-published-after-delete-and-latest-clear" {
				// No invocation has occurred. Reopening also discards every runtime
				// environment, so SQLite must retain the published layer snapshot.
				r.reopen(replayOwner, name)
			}
			var before *awslambda.GetFunctionConfigurationOutput
			if row.Operation == "update-function-configuration" && row.Result.Code != "Success" {
				var err error
				before, err = r.c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
			}
			operation := lambdaLayerOperations(r.c.lambda)[row.Operation]
			if operation == nil {
				t.Fatalf("unbound layer replay operation %s", row.Operation)
			}
			r.status.status = 0
			actual, err := operation(t.Context(), input)
			if r.status.status != row.Result.HTTPStatus {
				t.Fatalf("HTTP %d, native %d: %v", r.status.status, row.Result.HTTPStatus, err)
			}
			if row.Result.Code != "Success" {
				assertAPIError(t, err, row.Result.Code)
				if before != nil {
					after, err := r.c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(before.Layers, after.Layers) || !reflect.DeepEqual(before.Environment, after.Environment) || aws.ToString(before.RevisionId) != aws.ToString(after.RevisionId) || before.State != after.State || before.LastUpdateStatus != after.LastUpdateStatus {
						t.Fatalf("rejected attachment changed deployment: before=%+v after=%+v", before, after)
					}
				}
				if row.Operation == "create-function" {
					_, err := r.c.lambda.GetFunctionConfiguration(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
					assertAPIError(t, err, "ResourceNotFoundException")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if row.Operation == "invoke" {
				if actual["FunctionError"] != nil && actual["FunctionError"] != "" {
					t.Fatalf("runtime returned FunctionError: %#v", actual)
				}
				if actual["ExecutedVersion"] != row.Result.Output["ExecutedVersion"] || actual["StatusCode"] != row.Result.Output["StatusCode"] {
					t.Fatalf("invocation envelope = %#v; native = %#v", actual, row.Result.Output)
				}
				encoded, _ := actual["Payload"].(string)
				body, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				var payload map[string]any
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("runtime payload %s: %v", body, err)
				}
				want := row.Result.Output["DecodedPayload"].(map[string]any)
				for _, field := range strings.Fields("modules shared environment function_version machine") {
					if !reflect.DeepEqual(payload[field], want[field]) {
						t.Fatalf("runtime %s = %#v; native = %#v", field, payload[field], want[field])
					}
				}
				boot, _ := payload["boot"].(string)
				if boot == "" {
					t.Fatalf("runtime did not return boot identity: %s", body)
				}
				boots[row.Label] = boot
				if row.Label == "runtime-cold-after-layer-deletion" && boot == boots["runtime-existing-after-layer-deletion"] {
					t.Fatal("unrelated configuration update did not force a cold retained-layer import")
				}
				return
			}
			if strings.Contains(row.Operation, "function") || row.Operation == "publish-version" {
				lambdaLayerFunction(t, actual, row.Result.Output)
				if row.Operation == "create-function" || row.Operation == "update-function-configuration" || row.Operation == "publish-version" {
					r.ready(t, name)
				}
				return
			}
			lambdaLayerCompare(t, r, actual, row.Result.Output)
			if row.Operation == "get-layer-version" || row.Operation == "get-layer-version-by-arn" {
				lambdaLayerDownload(t, r, fixture, actual)
			}
		}) {
			t.FailNow()
		}
	}
}

func lambdaLayerFunction(t *testing.T, actual, want map[string]any) {
	t.Helper()
	if nested, ok := want["Configuration"].(map[string]any); ok {
		lambdaLayerFunction(t, actual["Configuration"].(map[string]any), nested)
		return
	}
	for _, field := range strings.Fields("FunctionName FunctionArn Runtime Role Handler CodeSize CodeSha256 Description Timeout MemorySize Version Architectures Environment Layers") {
		got, expected := actual[field], want[field]
		if field == "Layers" {
			// SDK adds nil optional members to each attachment. Ordered ARNs and
			// byte sizes are the public snapshot, including the empty clear case.
			local, _ := got.([]any)
			native, _ := expected.([]any)
			if len(local) != len(native) {
				t.Fatalf("attachment count = %#v; native = %#v", local, native)
			}
			for i := range native {
				a, b := local[i].(map[string]any), native[i].(map[string]any)
				if a["Arn"] != b["Arn"] || a["CodeSize"] != b["CodeSize"] {
					t.Fatalf("attachment %d = %#v; native = %#v", i, a, b)
				}
			}
			continue
		}
		if expected == nil {
			continue
		}
		if field == "Environment" {
			got = lambdaPolicyComparable(t, got.(map[string]any))
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("configuration %s = %#v; native = %#v", field, got, expected)
		}
	}
}

func lambdaLayerComparable(t *testing.T, value any) any {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, child := range value {
			if child == nil || key == "ResultMetadata" || key == "CreatedDate" || key == "Location" || key == "RevisionId" || key == "NextMarker" {
				continue
			}
			if key == "Policy" || key == "Statement" {
				var document any
				if err := json.Unmarshal([]byte(child.(string)), &document); err != nil {
					t.Fatal(err)
				}
				out[key] = document
			} else {
				out[key] = lambdaLayerComparable(t, child)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = lambdaLayerComparable(t, child)
		}
		return out
	default:
		return value
	}
}

func lambdaLayerCompare(t *testing.T, r *lambdaQualifiedReplay, actual, want map[string]any) {
	t.Helper()
	if revision, ok := want["RevisionId"].(string); ok {
		local, _ := actual["RevisionId"].(string)
		r.revisions.observe(t, revision, local)
	}
	marker, _ := actual["NextMarker"].(string)
	if native, ok := want["NextMarker"].(string); ok && native != "" {
		if marker == "" {
			t.Fatal("native continuation page was lost")
		}
		r.markers[native] = marker
	} else if marker != "" {
		t.Fatalf("terminal native page gained a continuation: %s", marker)
	}
	got, expected := lambdaLayerComparable(t, actual), lambdaLayerComparable(t, want)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("layer output = %#v; native = %#v", got, expected)
	}
}

// Native account inventory includes unrelated layers. Traverse every local page
// and compare the owned inventory, retaining empty-page continuation semantics.
func lambdaLayerPages(t *testing.T, r *lambdaQualifiedReplay, fixture lambdaLayerFixture, scenario string, pages []lambdaQualifiedRow) {
	t.Helper()
	owned := func(name string) bool {
		if scenario == "latest_filter" {
			return name == fixture.Provenance.Context.Prefix+"-filter"
		}
		return strings.HasPrefix(name, fixture.Provenance.Context.Prefix+"-")
	}
	want := map[string]any{}
	for _, page := range pages {
		for _, item := range page.Result.Output["Layers"].([]any) {
			layer := item.(map[string]any)
			name := layer["LayerName"].(string)
			if owned(name) {
				want[name] = layer
			}
		}
	}
	input := r.input(t, pages[0])
	delete(input, "Marker")
	got := map[string]any{}
	markers := map[string]bool{}
	emptyContinuation := false
	previous := ""
	for {
		r.status.status = 0
		out, err := lambdaPolicyBind(r.c.lambda.ListLayers)(t.Context(), input)
		if err != nil || r.status.status != pages[0].Result.HTTPStatus {
			t.Fatalf("ListLayers HTTP %d: %v", r.status.status, err)
		}
		layers, ok := out["Layers"].([]any)
		if !ok {
			t.Fatalf("ListLayers omitted its array: %#v", out)
		}
		for _, item := range layers {
			layer := item.(map[string]any)
			name := layer["LayerName"].(string)
			if name <= previous {
				t.Fatalf("catalog pages repeated or reordered %q after %q", name, previous)
			}
			previous = name
			if owned(name) {
				got[name] = layer
			}
		}
		marker, _ := out["NextMarker"].(string)
		if marker == "" {
			break
		}
		if markers[marker] {
			t.Fatalf("pagination repeated marker %q", marker)
		}
		markers[marker] = true
		emptyContinuation = emptyContinuation || len(layers) == 0
		input["Marker"] = marker
	}
	if !reflect.DeepEqual(lambdaLayerComparable(t, got), lambdaLayerComparable(t, want)) {
		t.Fatalf("owned catalog = %#v; native = %#v", got, want)
	}
	// A completely nonmatching filter still scans the owned seven-name
	// catalog in bounded pages. Native observed empty continuations as well.
	if scenario == "catalog" && len(want) == 0 && len(pages) > 1 && !emptyContinuation {
		t.Fatal("filtered pagination lost the empty continuation pages")
	}
}

func lambdaLayerDownload(t *testing.T, r *lambdaQualifiedReplay, fixture lambdaLayerFixture, output map[string]any) {
	t.Helper()
	content := output["Content"].(map[string]any)
	var expected []byte
	for _, artifact := range fixture.Artifacts {
		if artifact.CodeSHA256 == content["CodeSha256"] {
			expected = artifact.ZIP.Base64
			break
		}
	}
	if expected == nil {
		t.Fatalf("no native archive for layer content %#v", content)
	}
	location, _ := content["Location"].(string)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = request.URL.Host
	local, err := url.Parse(r.c.server.URL)
	if err != nil {
		t.Fatal(err)
	}
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
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, expected) {
		t.Fatalf("layer archive changed: HTTP %d, received %d bytes, native %d bytes", response.StatusCode, len(body), len(expected))
	}
}

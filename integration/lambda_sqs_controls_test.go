package stackd_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
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
	"stackd/internal/awstest"
	"stackd/storage"
)

// Requests, error classes and wire presence come from the capture, including its
// fresh-resource follow-up runs. Replaying their ordered setup avoids masking a
// validation failure with a missing function or an already-existing mapping.
type lambdaSQSControlFixture struct {
	Runs []lambdaSQSControlRun
}

type lambdaSQSControlRun struct {
	Account, Prefix string
	StartedAt       time.Time `json:"started_at"`
	Artifact        struct {
		ZIP string `json:"zip_base64"`
	}
	Observations  []lambdaSQSControlRow
	SetupContexts map[string]json.RawMessage `json:"setup_contexts"`
}

type lambdaSQSControlRow struct {
	lambdaURLRow
	Phase        string
	Wire         map[string]any `json:"wire_response_body"`
	SetupContext string         `json:"setup_context_ref"`
	References   struct {
		Caller string `json:"caller_observation"`
	} `json:"request_state_references"`
}

type lambdaSQSControlReplay struct {
	c            *lambdaEventsCloud
	clock        *clock.Manual
	fixture      lambdaSQSControlRun
	wire         *awstest.WireClient
	replacements []string
	keys         map[string]aws.Credentials
	identities   map[string]string
	timestamps   map[string]float64
}

func newLambdaSQSControlReplay(run lambdaSQSControlRun) *lambdaSQSControlReplay {
	// The captured administrative IAM user is the local administrative root.
	// Scoped callers still use real STS credentials and native policy documents.
	return &lambdaSQSControlReplay{
		fixture: run, clock: clock.NewManual(run.StartedAt),
		keys: map[string]aws.Credentials{}, identities: map[string]string{}, timestamps: map[string]float64{},
		replacements: []string{"arn:aws:iam::" + run.Account + ":user/Delegated", "arn:aws:iam::000000000000:root", run.Account, "000000000000"},
	}
}

func (r *lambdaSQSControlReplay) normalize() *strings.Replacer {
	return strings.NewReplacer(r.replacements...)
}

func (r *lambdaSQSControlReplay) connect(t *testing.T, backends *storage.Backends) {
	r.c = lambdaEventsConnect(t, backends, r.clock)
	r.wire = &awstest.WireClient{Client: r.c.server.Client()}
	options := r.c.lambda.Options()
	options.HTTPClient = r.wire
	r.c.lambda = awslambda.New(options)
}

func lambdaSQSControlOperations(c *awslambda.Client) map[string]lambdaPolicyOperation {
	ops := lambdaQualifiedOperations(c)
	ops["create-event-source-mapping"] = lambdaPolicyBind(c.CreateEventSourceMapping)
	ops["get-event-source-mapping"] = lambdaPolicyBind(c.GetEventSourceMapping)
	ops["list-event-source-mappings"] = lambdaPolicyBind(c.ListEventSourceMappings)
	ops["update-event-source-mapping"] = lambdaPolicyBind(c.UpdateEventSourceMapping)
	ops["delete-event-source-mapping"] = lambdaPolicyBind(c.DeleteEventSourceMapping)
	ops["untag-resource"] = lambdaPolicyBind(c.UntagResource)
	return ops
}

func (r *lambdaSQSControlReplay) command(t *testing.T, row lambdaSQSControlRow) {
	t.Helper()
	if _, ok := r.fixture.SetupContexts[row.SetupContext]; !ok {
		t.Fatalf("%s has no retained setup context", row.Label)
	}
	root := cloudClients{r.c.server}
	var err error
	switch row.Operation {
	case "create_role":
		input := lambdaStreamingInput[iam.CreateRoleInput](t, row.Input, r.normalize())
		_, err = root.iam("test", "test", "").CreateRole(t.Context(), &input)
	case "put_role_policy":
		input := lambdaStreamingInput[iam.PutRolePolicyInput](t, row.Input, r.normalize())
		_, err = root.iam("test", "test", "").PutRolePolicy(t.Context(), &input)
	case "create_queue":
		input := lambdaStreamingInput[sqs.CreateQueueInput](t, row.Input, r.normalize())
		var output *sqs.CreateQueueOutput
		output, err = r.c.queues.CreateQueue(t.Context(), &input)
		if err == nil {
			r.replacements = append(r.replacements, row.Result.Output["QueueUrl"].(string), aws.ToString(output.QueueUrl))
		}
	case "get_queue_attributes":
		input := lambdaStreamingInput[sqs.GetQueueAttributesInput](t, row.Input, r.normalize())
		var output *sqs.GetQueueAttributesOutput
		output, err = r.c.queues.GetQueueAttributes(t.Context(), &input)
		if err == nil {
			expected := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, row.Result.Output["Attributes"]), r.normalize())
			for _, field := range []string{"QueueArn", "VisibilityTimeout", "FifoQueue"} {
				if want, ok := expected[field]; ok && output.Attributes[field] != want {
					t.Fatalf("queue precondition %s=%q want %v", field, output.Attributes[field], want)
				}
			}
		}
	case "assume_role":
		input := lambdaStreamingInput[sts.AssumeRoleInput](t, row.Input, r.normalize())
		var output *sts.AssumeRoleOutput
		output, err = root.sts("test", "test", "").AssumeRole(t.Context(), &input)
		if err == nil {
			r.keys[row.Label] = aws.Credentials{AccessKeyID: aws.ToString(output.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(output.Credentials.SecretAccessKey), SessionToken: aws.ToString(output.Credentials.SessionToken)}
		}
	default:
		input := lambdaStreamingInput[map[string]any](t, row.Input, r.normalize())
		if row.Operation == "create_function" {
			input["Code"] = map[string]any{"ZipFile": r.fixture.Artifact.ZIP}
		}
		client := r.c.lambda
		if caller := row.References.Caller; caller != "" && caller != "identity" {
			key, ok := r.keys[caller]
			if !ok {
				t.Fatalf("missing actual STS credentials for %s", caller)
			}
			options := client.Options()
			options.Credentials = credentials.NewStaticCredentialsProvider(key.AccessKeyID, key.SecretAccessKey, key.SessionToken)
			client = awslambda.New(options)
		}
		mapping := strings.HasSuffix(row.Operation, "event_source_mapping")
		if mapping && (row.Operation == "create_event_source_mapping" || row.Operation == "update_event_source_mapping") {
			// Go's generated serializer drops explicit nulls. Use the native body
			// before signing, retaining the real SDK route, auth and deserializer.
			body := make(map[string]any, len(input))
			for key, value := range input {
				if key != "UUID" {
					body[key] = value
				}
			}
			payload := lambdaQualifiedJSON(t, body)
			options := client.Options()
			options.APIOptions = append(options.APIOptions, awstest.JSONBody(payload))
			client = awslambda.New(options)
		}
		operation := lambdaSQSControlOperations(client)[strings.ReplaceAll(row.Operation, "_", "-")]
		if operation == nil {
			t.Fatalf("unclassified native control operation %s", row.Operation)
		}
		_, err = operation(t.Context(), input)
		if err == nil && (mapping || row.Operation == "list_event_source_mappings" || row.Operation == "list_tags") {
			var actual map[string]any
			if e := json.Unmarshal(r.wire.Body, &actual); e != nil {
				t.Fatal(e)
			}
			if row.Operation == "create_event_source_mapping" {
				native := row.Wire["UUID"].(string)
				local, ok := actual["UUID"].(string)
				if !ok || local == "" {
					t.Fatalf("create omitted UUID: %s", r.wire.Body)
				}
				for previous, id := range r.identities {
					if previous != native && id == local {
						t.Fatal("mapping creation reused another mapping identity")
					}
				}
				r.identities[native] = local
				r.replacements = append(r.replacements, native, local)
			}
			expected := lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, row.Wire), r.normalize())
			if row.Wire == nil {
				expected = lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, row.Result.Output), r.normalize())
				delete(expected, "ResponseMetadata")
			}
			r.compare(t, actual, expected)
			if metadata, ok := row.Result.Output["ResponseMetadata"].(map[string]any); ok && r.wire.Status != int(metadata["HTTPStatusCode"].(float64)) {
				t.Fatalf("HTTP status %d want %v", r.wire.Status, metadata["HTTPStatusCode"])
			}
		}
		if err == nil && (row.Operation == "create_function" || row.Operation == "update_function_configuration") {
			name := input["FunctionName"].(string)
			if e := awslambda.NewFunctionActiveWaiter(r.c.lambda, fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); e != nil {
				t.Fatal(e)
			}
			if e := awslambda.NewFunctionUpdatedWaiter(r.c.lambda, fastLambdaUpdatedWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: &name}, time.Minute); e != nil {
				t.Fatal(e)
			}
		}
	}
	if row.Result.Code != "Success" {
		assertAPIError(t, err, row.Result.Code)
	} else if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
}

func (r *lambdaSQSControlReplay) compare(t *testing.T, actual, expected map[string]any) {
	t.Helper()
	if native, ok := expected["LastModified"].(float64); ok {
		local, present := actual["LastModified"].(float64)
		if !present || local <= 0 || local > float64(r.clock.Now().UnixNano())/float64(time.Second) {
			t.Fatalf("invalid LastModified: %v", actual["LastModified"])
		}
		key := fmt.Sprint(expected["UUID"], "/", native)
		if previous, seen := r.timestamps[key]; seen && previous != local {
			t.Fatalf("unchanged native revision changed LastModified: %v -> %v", previous, local)
		}
		r.timestamps[key] = local
		expected["LastModified"] = local
	}
	if values, ok := expected["EventSourceMappings"].([]any); ok {
		got, present := actual["EventSourceMappings"].([]any)
		if !present || len(got) != len(values) {
			t.Fatalf("mapping inventory got %v want %v", actual, expected)
		}
		order := func(rows []any) {
			sort.Slice(rows, func(i, j int) bool {
				return rows[i].(map[string]any)["UUID"].(string) < rows[j].(map[string]any)["UUID"].(string)
			})
		}
		order(got)
		order(values)
		for i := range values {
			r.compare(t, got[i].(map[string]any), values[i].(map[string]any))
		}
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("mapping wire differs:\ngot %s\nwant %s", lambdaQualifiedJSON(t, actual), lambdaQualifiedJSON(t, expected))
	}
}

// Native page membership is random. Replay a complete local traversal against the
// retained unpaginated inventory, and repeat each continuation before advancing.
func (r *lambdaSQSControlReplay) pagination(t *testing.T, row lambdaSQSControlRow) {
	t.Helper()
	input := lambdaStreamingInput[awslambda.ListEventSourceMappingsInput](t, row.Input, r.normalize())
	var expected map[string]any
	for _, candidate := range r.fixture.Observations {
		if candidate.Label == "list_function" {
			expected = lambdaStreamingInput[map[string]any](t, lambdaQualifiedJSON(t, candidate.Wire), r.normalize())
		}
	}
	if expected == nil {
		t.Fatal("missing native unpaginated inventory")
	}
	var all []any
	seenIDs, seenMarkers := map[string]bool{}, map[string]bool{}
	for {
		out, err := r.c.lambda.ListEventSourceMappings(t.Context(), &input)
		if err != nil {
			t.Fatal(err)
		}
		var page map[string]any
		if err := json.Unmarshal(r.wire.Body, &page); err != nil {
			t.Fatal(err)
		}
		rows := page["EventSourceMappings"].([]any)
		if input.MaxItems != nil && len(rows) > int(*input.MaxItems) {
			t.Fatal("page exceeded MaxItems")
		}
		for _, value := range rows {
			id := value.(map[string]any)["UUID"].(string)
			if seenIDs[id] {
				t.Fatalf("pagination duplicated %s", id)
			}
			seenIDs[id] = true
			all = append(all, value)
		}
		if input.Marker != nil {
			if _, err := r.c.lambda.ListEventSourceMappings(t.Context(), &input); err != nil {
				t.Fatal(err)
			}
			var repeated map[string]any
			if err := json.Unmarshal(r.wire.Body, &repeated); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(page, repeated) {
				t.Fatal("repeated continuation changed page")
			}
		}
		marker := aws.ToString(out.NextMarker)
		if marker == "" {
			break
		}
		if seenMarkers[marker] {
			t.Fatal("pagination cursor cycle")
		}
		seenMarkers[marker] = true
		input.Marker = &marker
	}
	actual := map[string]any{"EventSourceMappings": all, "NextMarker": nil}
	r.compare(t, actual, expected)
}

func TestLambdaSQSMappingDockerNativeControls(t *testing.T) {
	lambdaURLDocker(t)
	fixture := lambdaFixture[lambdaSQSControlFixture](t, "sqs_mapping_controls")
	for _, backend := range []string{"memory", "sqlite"} {
		for index, run := range fixture.Runs {
			t.Run(fmt.Sprintf("%s/run%d", backend, index+1), func(t *testing.T) {
				backends := storage.NewMemory()
				path := filepath.Join(t.TempDir(), "sqs-controls.sqlite")
				var closeDB func()
				if backend == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, path)
				}
				r := newLambdaSQSControlReplay(run)
				r.connect(t, backends)
				for _, row := range run.Observations {
					// Runtime identity invocation and native IAM/runtime propagation
					// polling belong to their dedicated suites, not ESM control timing.
					if row.Phase == "cleanup" || strings.HasPrefix(row.Label, "cleanup_") || row.Operation == "get_caller_identity" || row.Operation == "invoke" || row.Operation == "get_function_configuration" || row.Operation == "get_role_policy" {
						continue
					}
					if row.Operation == "create_function" && row.Result.Code != "Success" {
						continue
					}
					if row.Phase == "propagation" && row.Operation == "get_event_source_mapping" {
						state, _ := row.Result.Output["State"].(string)
						if state != "Enabled" && state != "Disabled" && row.Result.Code != "ResourceNotFoundException" {
							continue
						}
						advanceClock(t, r.clock, time.Second)
						if _, err := r.c.cloud.RunDueJobs(t.Context(), 256); err != nil {
							t.Fatal(err)
						}
					}
					if row.Label == "list_page_two" || row.Label == "list_page_two_repeated" {
						continue
					}
					if !t.Run(row.Label, func(t *testing.T) {
						if row.Label == "list_page_one" {
							r.pagination(t, row)
						} else {
							r.command(t, row)
						}
					}) {
						t.FailNow()
					}
					if backend == "sqlite" && (row.Label == "batch_eleven_without_window_state_unchanged" || row.Label == "get_after_configured_null") {
						if err := r.c.cloud.Close(); err != nil {
							t.Fatal(err)
						}
						r.c.server.Close()
						closeDB()
						backends, closeDB = openSQLiteBackends(t, path)
						r.connect(t, backends)
						if !t.Run(row.Label+"_after_restart", func(t *testing.T) { r.command(t, row) }) {
							t.FailNow()
						}
					}
				}
			})
		}
	}
}

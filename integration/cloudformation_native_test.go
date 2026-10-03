package stackd_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
)

type cloudFormationNativeCall struct {
	Label, Service, Operation, Code string
	Input, Output                   json.RawMessage
	HTTPStatus                      int `json:"http_status"`
}

// The native ledger retains polling samples, IDs and timestamps. Replay compares
// settled service contracts, not native wall-clock scheduling or generated UUIDs.
func TestCloudFormationNativeLifecycle(t *testing.T) {
	replayCloudFormationNative(t, "lifecycle.json")
}

func TestCloudFormationNativeNoEcho(t *testing.T) {
	fixtures, err := filepath.Glob("../testdata/aws/cloudformation/noecho_*.json")
	if err != nil || len(fixtures) == 0 {
		t.Fatalf("load native NoEcho fixtures: %v", err)
	}
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			replayCloudFormationNative(t, filepath.Base(fixture))
		})
	}
}

func replayCloudFormationNative(t *testing.T, name string) {
	t.Helper()
	var fixture struct {
		Account, Region, Prefix string
		WorkflowComplete        bool  `json:"workflow_complete"`
		ExportUpdateComplete    *bool `json:"export_update_complete"`
		SubscriptionComplete    *bool `json:"subscription_complete"`
		Cleanup                 struct{ Complete bool }
		Calls                   []cloudFormationNativeCall
	}
	awsReadFixture(t, "cloudformation/"+name, &fixture)
	if !fixture.WorkflowComplete || !fixture.Cleanup.Complete || fixture.ExportUpdateComplete != nil && !*fixture.ExportUpdateComplete || fixture.SubscriptionComplete != nil && !*fixture.SubscriptionComplete {
		t.Fatal("native CloudFormation fixture did not complete its workflow and exact-owned cleanup")
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			bindings := map[string]string{}
			call := func(row cloudFormationNativeCall) (any, error) {
				config := aws.Config{Region: fixture.Region, HTTPClient: clients.server.Client(), RetryMaxAttempts: 1,
					Credentials: credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")}
				endpoint := aws.String(clients.server.URL)
				var client any
				switch row.Service {
				case "cloudformation":
					client = cloudformation.NewFromConfig(config, func(o *cloudformation.Options) { o.BaseEndpoint = endpoint })
				case "sqs":
					client = sqs.NewFromConfig(config, func(o *sqs.Options) { o.BaseEndpoint = endpoint })
				case "sns":
					client = sns.NewFromConfig(config, func(o *sns.Options) { o.BaseEndpoint = endpoint })
				case "iam":
					client = iam.NewFromConfig(config, func(o *iam.Options) { o.BaseEndpoint = endpoint })
				case "s3":
					client = s3.NewFromConfig(config, func(o *s3.Options) { o.BaseEndpoint = endpoint; o.UsePathStyle = true })
				default:
					t.Fatalf("unhandled native CloudFormation dependency %q", row.Service)
				}
				input := cloudFormationSubstitute(row.Input, bindings)
				return awstest.CallSDK(t.Context(), client, row.Operation, input)
			}
			for _, row := range fixture.Calls {
				var native map[string]any
				if row.Code == "Success" {
					awsDecodeJSON(t, row.Output, &native)
				}
				if cloudFormationTransient(native) {
					continue // Native readiness polls are observations, not timing promises.
				}
				if !t.Run(row.Label, func(t *testing.T) {
					actual, err := call(row)
					if row.Code == "Success" && cloudFormationStatus(native) != "" {
						deadline := time.Now().Add(15 * time.Second)
						for err == nil && cloudFormationTransient(cloudFormationSDKObject(t, actual)) && time.Now().Before(deadline) {
							advanceClock(t, source, time.Second)
							if _, runErr := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(t.Context(), 1000); runErr != nil {
								t.Fatal(runErr)
							}
							time.Sleep(time.Millisecond)
							actual, err = call(row)
						}
					}
					cloudFormationNativeError(t, row, err)
					if err != nil {
						return
					}
					local := cloudFormationSDKObject(t, actual)
					cloudFormationBind(t, row.Operation, native, local, bindings)
					encoded, marshalErr := json.Marshal(native)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					awsDecodeJSON(t, cloudFormationSubstitute(encoded, bindings), &native)
					want := cloudFormationProjection(t, row.Operation, native, fixture.Prefix)
					got := cloudFormationProjection(t, row.Operation, local, fixture.Prefix)
					if !reflect.DeepEqual(want, got) {
						t.Fatalf("native decoded contract mismatch\nwant %#v\ngot  %#v", want, got)
					}
					if row.Operation == "DescribeStackEvents" {
						before := got
						clients = reopen()
						again, reopenErr := call(row)
						if reopenErr != nil {
							t.Fatal(reopenErr)
						}
						if after := cloudFormationProjection(t, row.Operation, cloudFormationSDKObject(t, again), fixture.Prefix); !reflect.DeepEqual(before, after) {
							t.Fatalf("persisted stack contract changed across restart\nbefore %#v\nafter %#v", before, after)
						}
					}
				}) {
					return
				}
			}
		})
	}
}

func cloudFormationSDKObject(t *testing.T, value any) map[string]any {
	t.Helper()
	body, err := awstest.MarshalSDK(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	awsDecodeJSON(t, body, &out)
	return out
}

func cloudFormationSubstitute(body []byte, bindings map[string]string) []byte {
	keys := make([]string, 0, len(bindings))
	for key := range bindings {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b string) int { return len(b) - len(a) })
	text := string(body)
	for _, key := range keys {
		text = strings.ReplaceAll(text, key, bindings[key])
	}
	return []byte(text)
}

func cloudFormationStatus(object map[string]any) string {
	if stacks, ok := object["Stacks"].([]any); ok && len(stacks) == 1 {
		status, _ := stacks[0].(map[string]any)["StackStatus"].(string)
		return status
	}
	for _, event := range cloudFormationObjects(object["StackEvents"]) {
		if event["ResourceType"] == "AWS::CloudFormation::Stack" {
			status, _ := event["ResourceStatus"].(string)
			return status
		}
	}
	status, _ := object["Status"].(string)
	return status
}

func cloudFormationTransient(object map[string]any) bool {
	status := cloudFormationStatus(object)
	return strings.HasSuffix(status, "_IN_PROGRESS") || status == "CREATE_PENDING"
}

func cloudFormationNativeError(t *testing.T, row cloudFormationNativeCall, err error) {
	t.Helper()
	code := row.Code
	// HeadBucket has no error document. Boto names the HTTP status whereas the
	// official Go SDK instantiates its modeled NotFound from the same HTTP 404.
	if row.Service == "s3" && row.Operation == "HeadBucket" && code == "404" {
		code = "NotFound"
	}
	observation := awsNativeObservation{Label: row.Label}
	observation.Result.Code = code
	observation.Result.HTTPStatus = row.HTTPStatus
	awsNativeResult(t, observation, err)
	switch code {
	case "AlreadyExistsException":
		var modeled *cfntypes.AlreadyExistsException
		if !errors.As(err, &modeled) {
			t.Fatalf("expected official SDK AlreadyExistsException, got %T", err)
		}
	case "TokenAlreadyExistsException":
		var modeled *cfntypes.TokenAlreadyExistsException
		if !errors.As(err, &modeled) {
			t.Fatalf("expected official SDK TokenAlreadyExistsException, got %T", err)
		}
	case "ChangeSetNotFound":
		var modeled *cfntypes.ChangeSetNotFoundException
		if !errors.As(err, &modeled) {
			t.Fatalf("expected official SDK ChangeSetNotFoundException, got %T", err)
		}
	case "InvalidChangeSetStatus":
		var modeled *cfntypes.InvalidChangeSetStatusException
		if !errors.As(err, &modeled) {
			t.Fatalf("expected official SDK InvalidChangeSetStatusException, got %T", err)
		}
	}
}

func cloudFormationBind(t *testing.T, operation string, native, local map[string]any, bindings map[string]string) {
	t.Helper()
	bind := func(from, to any) {
		a, aok := from.(string)
		b, bok := to.(string)
		if !aok || a == "" {
			return
		}
		if !bok || b == "" {
			t.Fatalf("missing decoded identity corresponding to %s", a)
		}
		switch {
		case strings.HasPrefix(a, "arn:aws:cloudformation:"):
			prefix := a[:strings.LastIndex(a, "/")+1]
			if !strings.HasPrefix(b, prefix) || b == prefix {
				t.Fatalf("stack/change-set identity changed scope or name: native %s local %s", a, b)
			}
		case strings.HasPrefix(a, "arn:aws:sns:") && strings.Count(a, ":") == 6:
			prefix := a[:strings.LastIndex(a, ":")+1]
			if !strings.HasPrefix(b, prefix) || b == prefix {
				t.Fatalf("subscription identity changed topic or scope: native %s local %s", a, b)
			}
		default:
			if cloudFormationQueueIdentity(a) != cloudFormationQueueIdentity(b) {
				t.Fatalf("named resource identity differs from native: native %s local %s", a, b)
			}
		}
		if previous, known := bindings[a]; known && cloudFormationQueueIdentity(previous) != cloudFormationQueueIdentity(b) {
			t.Fatalf("resource identity changed: native %s local %s => %s", a, previous, b)
		}
		bindings[a] = b
	}
	for _, key := range []string{"StackId", "Id", "ChangeSetId", "QueueUrl"} {
		bind(native[key], local[key])
	}
	if operation == "DescribeStacks" {
		for _, item := range cloudFormationObjects(native["Stacks"]) {
			other := cloudFormationFind(local["Stacks"], "StackName", item["StackName"])
			bind(item["StackId"], other["StackId"])
			for _, output := range cloudFormationObjects(item["Outputs"]) {
				value, ok := output["OutputValue"].(string)
				subscriptionARN := strings.HasPrefix(value, "arn:aws:sns:") && strings.Count(value, ":") == 6
				if ok && (strings.HasPrefix(value, "https://sqs.") || subscriptionARN) {
					matched := cloudFormationFind(other["Outputs"], "OutputKey", output["OutputKey"])
					bind(value, matched["OutputValue"])
				}
			}
		}
	}
	for _, key := range []string{"StackResources", "StackResourceSummaries"} {
		for _, item := range cloudFormationObjects(native[key]) {
			other := cloudFormationFind(local[key], "LogicalResourceId", item["LogicalResourceId"])
			bind(item["PhysicalResourceId"], other["PhysicalResourceId"])
		}
	}
}

func cloudFormationObjects(value any) []map[string]any {
	rows, _ := value.([]any)
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if object, ok := row.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func cloudFormationFind(value any, key string, wanted any) map[string]any {
	for _, row := range cloudFormationObjects(value) {
		if reflect.DeepEqual(row[key], wanted) {
			return row
		}
	}
	return nil
}

func cloudFormationFields(object map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, key := range keys {
		if value, ok := object[key]; ok && value != nil {
			if text, ok := value.(string); ok && text == "" && (key == "Replacement" || key == "PhysicalResourceId" || key == "AttributeChangeType") {
				continue // Optional Go SDK enums materialize as empty strings when absent on the wire.
			}
			out[key] = value
		}
	}
	return out
}

func cloudFormationRows(value any, keys ...string) []map[string]any {
	out := []map[string]any{}
	for _, row := range cloudFormationObjects(value) {
		out = append(out, cloudFormationFields(row, keys...))
	}
	slices.SortFunc(out, func(a, b map[string]any) int {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return strings.Compare(string(x), string(y))
	})
	return out
}

// The native SQS authority and each httptest listener differ. Account/name are
// the queue identity; the executable proof additionally checks real usable URLs.
func cloudFormationQueueIdentity(value string) string {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return value
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 || len(parts[0]) != 12 || parts[1] == "" {
		return value
	}
	for _, digit := range parts[0] {
		if digit < '0' || digit > '9' {
			return value
		}
	}
	return "sqs://" + strings.Join(parts, "/")
}

func cloudFormationPortable(value any) any {
	switch item := value.(type) {
	case string:
		return cloudFormationQueueIdentity(item)
	case []any:
		for i := range item {
			item[i] = cloudFormationPortable(item[i])
		}
	case map[string]any:
		for key, child := range item {
			item[key] = cloudFormationPortable(child)
		}
	}
	return value
}

func cloudFormationProjection(t *testing.T, operation string, object map[string]any, prefix string) any {
	t.Helper()
	cloudFormationPortable(object)
	switch operation {
	case "ValidateTemplate":
		return map[string]any{"Description": object["Description"], "Capabilities": object["Capabilities"],
			"Parameters": cloudFormationRows(object["Parameters"], "ParameterKey", "DefaultValue", "NoEcho")}
	case "CreateStack", "UpdateStack":
		return cloudFormationFields(object, "StackId")
	case "CreateChangeSet":
		return cloudFormationFields(object, "StackId", "Id")
	case "DescribeStacks":
		out := []map[string]any{}
		for _, stack := range cloudFormationObjects(object["Stacks"]) {
			row := cloudFormationFields(stack, "StackId", "StackName", "StackStatus", "Description")
			row["Parameters"] = cloudFormationRows(stack["Parameters"], "ParameterKey", "ParameterValue")
			row["Outputs"] = cloudFormationRows(stack["Outputs"], "OutputKey", "OutputValue", "ExportName", "Description")
			row["Tags"] = cloudFormationRows(stack["Tags"], "Key", "Value")
			out = append(out, row)
		}
		return out
	case "DescribeStackResources":
		return cloudFormationRows(object["StackResources"], "StackId", "StackName", "LogicalResourceId", "PhysicalResourceId", "ResourceType", "ResourceStatus")
	case "ListStackResources":
		return cloudFormationRows(object["StackResourceSummaries"], "LogicalResourceId", "PhysicalResourceId", "ResourceType", "ResourceStatus")
	case "DescribeStackResource":
		resource, _ := object["StackResourceDetail"].(map[string]any)
		return cloudFormationFields(resource, "StackId", "StackName", "LogicalResourceId", "PhysicalResourceId", "ResourceType", "ResourceStatus")
	case "DescribeStackEvents":
		// Independent resources may finish in a different order. Preserve the
		// terminal transition sequence for each logical resource, including its
		// physical incarnation and client request token, rather than pinning a
		// global interleaving or generated EventIds/timestamps/reason wording.
		out := map[string][]map[string]any{}
		for _, event := range cloudFormationObjects(object["StackEvents"]) {
			status, _ := event["ResourceStatus"].(string)
			if strings.HasSuffix(status, "_IN_PROGRESS") {
				continue
			}
			logical, _ := event["LogicalResourceId"].(string)
			row := cloudFormationFields(event, "ResourceType", "ResourceStatus", "PhysicalResourceId", "ClientRequestToken")
			if raw, ok := event["ResourceProperties"].(string); ok {
				var properties any
				awsDecodeJSON(t, []byte(raw), &properties)
				row["ResourceProperties"] = cloudFormationPortable(properties)
			}
			out[logical] = append(out[logical], row)
		}
		return out
	case "DescribeChangeSet":
		out := cloudFormationFields(object, "StackId", "StackName", "ChangeSetId", "ChangeSetName", "Status", "ExecutionStatus")
		changes := []map[string]any{}
		for _, change := range cloudFormationObjects(object["Changes"]) {
			resource, _ := change["ResourceChange"].(map[string]any)
			row := cloudFormationFields(resource, "Action", "LogicalResourceId", "PhysicalResourceId", "ResourceType", "Replacement")
			scope, _ := resource["Scope"].([]any)
			values := make([]string, 0, len(scope))
			for _, value := range scope {
				values = append(values, value.(string))
			}
			slices.Sort(values)
			row["Scope"] = values
			details := []map[string]any{}
			for _, detail := range cloudFormationObjects(resource["Details"]) {
				target, _ := detail["Target"].(map[string]any)
				item := cloudFormationFields(detail, "Evaluation", "ChangeSource", "CausingEntity")
				item["Target"] = cloudFormationFields(target, "Attribute", "Name", "RequiresRecreation", "Path", "BeforeValue", "AfterValue", "AttributeChangeType")
				details = append(details, item)
			}
			slices.SortFunc(details, func(a, b map[string]any) int {
				x, _ := json.Marshal(a)
				y, _ := json.Marshal(b)
				return strings.Compare(string(x), string(y))
			})
			row["Details"] = details
			for _, key := range []string{"BeforeContext", "AfterContext"} {
				if text, ok := resource[key].(string); ok && text != "" {
					var value any
					awsDecodeJSON(t, []byte(text), &value)
					row[key] = value
				}
			}
			changes = append(changes, row)
		}
		slices.SortFunc(changes, func(a, b map[string]any) int {
			return strings.Compare(a["LogicalResourceId"].(string), b["LogicalResourceId"].(string))
		})
		out["Changes"] = changes
		return out
	case "GetTemplate":
		var body any
		switch value := object["TemplateBody"].(type) {
		case string:
			awsDecodeJSON(t, []byte(value), &body)
		default:
			body = value
		}
		return body
	case "ListImports":
		return object["Imports"]
	case "ListExports":
		out := []map[string]any{}
		for _, export := range cloudFormationObjects(object["Exports"]) {
			if name, _ := export["Name"].(string); strings.HasPrefix(name, prefix) {
				out = append(out, cloudFormationFields(export, "Name", "Value", "ExportingStackId"))
			}
		}
		return out
	case "GetQueueUrl":
		return object["QueueUrl"]
	case "GetQueueAttributes":
		return object["Attributes"]
	case "ListQueueTags":
		tags, _ := object["Tags"].(map[string]any)
		// These reserved ownership tags are explicitly non-native metadata.
		for key := range tags {
			if strings.HasPrefix(key, "stackd:cloudformation:") {
				delete(tags, key)
			}
		}
		return tags
	case "GetTopicAttributes":
		attributes, _ := object["Attributes"].(map[string]any)
		return cloudFormationFields(attributes, "DisplayName", "TopicArn", "Owner")
	case "GetSubscriptionAttributes":
		attributes, _ := object["Attributes"].(map[string]any)
		return cloudFormationFields(attributes, "SubscriptionArn", "TopicArn", "Owner", "Endpoint", "Protocol")
	case "ExecuteChangeSet", "DeleteStack", "DeleteChangeSet":
		return nil // Subsequent settled reads and dependency absence prove effects.
	default:
		t.Fatalf("no consumer contract projection for successful %s", operation)
		return nil
	}
}

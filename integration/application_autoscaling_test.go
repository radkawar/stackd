package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aastypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/transport/http/protocol/awsquery"

	"stackd"
	"stackd/clock"
	"stackd/compute/docker"
	computeecs "stackd/compute/ecs"
	"stackd/compute/network"
	"stackd/internal/awstest"
)

type aasControlRow struct {
	Sequence                                int
	Label, Service, Operation, Region, Code string
	StartedAt                               time.Time
	Input, Output                           json.RawMessage
	RawResponse                             string
	HTTPStatus                              int `json:"http_status"`
	SignedHTTPStatus                        int `json:"httpStatus"`
}

type aasControlFixture struct {
	Account, Region string
	Calls           []aasControlRow
}

func aasFixture(t *testing.T, name string) aasControlFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/applicationautoscaling/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture aasControlFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for i := range fixture.Calls {
		row := &fixture.Calls[i]
		if row.HTTPStatus == 0 {
			row.HTTPStatus = row.SignedHTTPStatus
		}
	}
	return fixture
}

func aasExecutor(t *testing.T) computeecs.Executor {
	t.Helper()
	if os.Getenv("STACKD_ECS_DOCKER") != "1" {
		t.Skip("set STACKD_ECS_DOCKER=1 to provision real ECS execution dependencies")
	}
	engine, err := docker.New(t.Context(), docker.Config{Host: os.Getenv("DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	networks, err := network.NewBridges(engine)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := computeecs.NewDockerExecutor(t.Context(), computeecs.DockerConfig{Client: engine, Networks: networks})
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func (f aasControlFixture) row(t *testing.T, label string) aasControlRow {
	t.Helper()
	for _, row := range f.Calls {
		if row.Label == label {
			return row
		}
	}
	t.Fatalf("native control %q missing", label)
	return aasControlRow{}
}

func aasClient(c cloudClients, region, key, secret string, httpClient aws.HTTPClient) *applicationautoscaling.Client {
	return applicationautoscaling.New(applicationautoscaling.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: httpClient, RetryMaxAttempts: 1})
}

// These are native generated identity components, not whole ARNs: the fixed
// account/region/resource/name portions must still match. A bijection detects
// accidental reuse after deletion and identity churn during partial updates.
var aasIdentity = regexp.MustCompile(`0ec5[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func aasBind(t *testing.T, bindings map[string]string, native, actual string) {
	t.Helper()
	if prior, ok := bindings[native]; ok && prior != actual {
		t.Fatalf("identity %s changed: %s -> %s", native, prior, actual)
	}
	for other, prior := range bindings {
		if other != native && prior == actual {
			t.Fatalf("distinct identities %s and %s collapsed to %s", native, other, actual)
		}
	}
	bindings[native] = actual
}

func aasReplace(text string, bindings map[string]string) string {
	keys := make([]string, 0, len(bindings))
	for key := range bindings {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b string) int { return len(b) - len(a) })
	for _, key := range keys {
		text = strings.ReplaceAll(text, key, bindings[key])
	}
	return text
}

// AAS JSON wire comparison is exact, including absent optional fields. Only
// native allocation bytes and server-assigned instants are relocated. These
// instants remain bound across transitions, updates and reopened storage.
func aasCompare(t *testing.T, path string, native, actual any, bindings map[string]string, times map[float64]float64) {
	t.Helper()
	switch want := native.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok || len(want) != len(got) {
			t.Fatalf("%s native fields %v; got fields %v", path, reflect.ValueOf(want).MapKeys(), reflect.ValueOf(got).MapKeys())
		}
		keys := make([]string, 0, len(want))
		for key := range want {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			value, present := got[key]
			if !present {
				t.Fatalf("%s.%s missing", path, key)
			}
			if key == "NextToken" {
				before, beforeOK := want[key].(string)
				after, afterOK := value.(string)
				if !beforeOK || !afterOK {
					t.Fatalf("%s invalid continuation token: %#v", path, value)
				}
				// Opaque tokens bind requests, not resource identities. AWS may
				// mint different byte strings for the same continuation position.
				bindings[before] = after
				continue
			}
			if key == "CreationTime" || want["ActivityId"] != nil && (key == "StartTime" || key == "EndTime") {
				before, beforeOK := want[key].(float64)
				if text, ok := want[key].(string); ok {
					// CLI captures render the same AWS timestamp as RFC3339.
					parsed, err := time.Parse(time.RFC3339Nano, text)
					before, beforeOK = float64(parsed.UnixMilli())/1000, err == nil
				}
				after, afterOK := value.(float64)
				if !beforeOK || !afterOK || after <= 0 {
					t.Fatalf("%s.%s invalid timestamp: %#v", path, key, value)
				}
				if prior, ok := times[before]; ok && prior != after {
					t.Fatalf("%s.%s timestamp changed: %v -> %v", path, key, prior, after)
				}
				times[before] = after
				continue
			}
			aasCompare(t, path+"."+key, want[key], value, bindings, times)
		}
	case []any:
		got, ok := actual.([]any)
		if !ok || len(want) != len(got) {
			t.Fatalf("%s native list %#v; got %#v", path, want, actual)
		}
		// Describe order and alarm UUID order are not guaranteed. Match named
		// resources, retaining step-adjustment and metric-expression ordering.
		if strings.HasSuffix(path, ".ScalableTargets") || strings.HasSuffix(path, ".ScalingPolicies") || strings.HasSuffix(path, ".ScheduledActions") || strings.HasSuffix(path, ".Alarms") || strings.HasSuffix(path, ".MetricAlarms") || strings.HasSuffix(path, ".Dimensions") {
			order := func(a, b any) int {
				key := func(v any) string {
					m := v.(map[string]any)
					for _, field := range []string{"AlarmName", "PolicyName", "ScheduledActionName", "ResourceId", "Name"} {
						if text, ok := m[field].(string); ok {
							return aasReplace(text, bindings)
						}
					}
					return ""
				}
				return strings.Compare(key(a), key(b))
			}
			slices.SortFunc(want, order)
			slices.SortFunc(got, order)
		}
		for i, value := range want {
			aasCompare(t, fmt.Sprintf("%s[%d]", path, i), value, got[i], bindings, times)
		}
	case string:
		got, ok := actual.(string)
		if !ok {
			t.Fatalf("%s native %q; got %#v", path, want, actual)
		}
		before, after := aasIdentity.FindAllString(want, -1), aasIdentity.FindAllString(got, -1)
		if len(before) != len(after) {
			t.Fatalf("%s identity shape differs: %s / %s", path, want, got)
		}
		for i, id := range before {
			aasBind(t, bindings, id, after[i])
			if strings.HasPrefix(id, "0ec5") && len(id) == 36 {
				uuid := func(v string) string {
					v = v[4:]
					return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
				}
				aasBind(t, bindings, uuid(id), uuid(after[i]))
			}
		}
		if mapped := aasReplace(want, bindings); mapped != got {
			t.Fatalf("%s native %q; got %q", path, mapped, got)
		}
	default:
		if !reflect.DeepEqual(native, actual) {
			t.Fatalf("%s native %#v; got %#v", path, native, actual)
		}
	}
}

func aasInput(t *testing.T, row aasControlRow, bindings map[string]string) json.RawMessage {
	t.Helper()
	input := ecsControlBody(t, []byte(aasReplace(string(row.Input), bindings)))
	// Signed JSON fixtures use epoch seconds; the SDK's Go JSON decoder takes
	// RFC3339. Null remains null, and StartTime/EndTime absence remains absence.
	for _, key := range []string{"StartTime", "EndTime"} {
		if seconds, ok := input[key].(float64); ok {
			input[key] = time.UnixMilli(int64(seconds * 1000)).UTC().Format(time.RFC3339Nano)
		}
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func aasPrerequisite(t *testing.T, c cloudClients, row aasControlRow, bindings map[string]string) {
	t.Helper()
	input := aasInput(t, row, bindings)
	// Adapt only unsupported EC2/bridge execution prerequisites to the retained
	// Fargate setup. Native identities, zero capacity, and AAS oracles are unchanged.
	adapted := ecsControlBody(t, input)
	var template string
	var fields []string
	switch strings.ToLower(strings.ReplaceAll(row.Operation, "-", "")) {
	case "registertaskdefinition":
		if adapted["networkMode"] != "awsvpc" {
			template = "register-task-definition"
			fields = []string{"networkMode", "requiresCompatibilities", "cpu", "memory", "containerDefinitions"}
		}
	case "createservice":
		if adapted["launchType"] == "EC2" {
			template = "create-service"
			fields = []string{"launchType", "networkConfiguration"}
		}
	}
	if template != "" {
		setup := aasFixture(t, "controls")
		if template == "create-service" {
			for _, label := range []string{"create-vpc", "create-subnet"} {
				prerequisite := setup.row(t, label)
				native := ecsControlBody(t, prerequisite.Output)
				resource, field := "Vpc", "VpcId"
				if label == "create-subnet" {
					resource, field = "Subnet", "SubnetId"
				}
				id := native[resource].(map[string]any)[field].(string)
				if _, exists := bindings[id]; !exists {
					aasPrerequisite(t, c, prerequisite, bindings)
				}
			}
		}
		shape := ecsControlBody(t, aasInput(t, setup.row(t, template), bindings))
		for _, field := range fields {
			adapted[field] = shape[field]
		}
		var err error
		input, err = json.Marshal(adapted)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: adapted ECS prerequisite to Fargate; AAS rows replay unchanged", row.Label)
	}
	provider := credentials.NewStaticCredentialsProvider("test", "test", "")
	var client any
	if row.Service == "ecs" {
		client = ecs.New(ecs.Options{Region: row.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: provider, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	} else {
		client = ec2.New(ec2.Options{Region: row.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: provider, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	}
	result, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
	if err != nil {
		t.Fatalf("%s: %v", row.Label, err)
	}
	switch output := result.(type) {
	case *ec2.CreateVpcOutput:
		native := ecsControlBody(t, row.Output)["Vpc"].(map[string]any)
		bindings[native["VpcId"].(string)] = aws.ToString(output.Vpc.VpcId)
	case *ec2.CreateSubnetOutput:
		native := ecsControlBody(t, row.Output)["Subnet"].(map[string]any)
		bindings[native["SubnetId"].(string)] = aws.ToString(output.Subnet.SubnetId)
	case *ecs.RegisterTaskDefinitionOutput:
		native := ecsControlBody(t, row.Output)["taskDefinition"].(map[string]any)
		bindings[native["taskDefinitionArn"].(string)] = aws.ToString(output.TaskDefinition.TaskDefinitionArn)
	case *ecs.CreateServiceOutput:
		if output.Service.DesiredCount != 0 || output.Service.RunningCount != 0 || output.Service.PendingCount != 0 {
			t.Fatalf("zero-task prerequisite started capacity: %+v", output.Service)
		}
	case *ecs.DescribeServicesOutput:
		if len(output.Services) != 1 || output.Services[0].DesiredCount != 0 || output.Services[0].RunningCount != 0 || output.Services[0].PendingCount != 0 {
			t.Fatalf("service capacity: %+v", output)
		}
	}
}

func aasReplay(t *testing.T, c cloudClients, row aasControlRow, bindings map[string]string, times map[float64]float64) {
	t.Helper()
	wire := &awstest.WireClient{Client: c.server.Client()}
	client := aasClient(c, row.Region, "test", "test", wire)
	_, err := awstest.CallSDK(t.Context(), client, row.Operation, aasInput(t, row, bindings))
	if row.Code != "Success" {
		assertAPIError(t, err, row.Code)
	} else if err != nil {
		t.Fatal(err)
	}
	// CLI-only captures establish decoded outcomes, not an observed HTTP status.
	if row.HTTPStatus != 0 && wire.Status != row.HTTPStatus {
		t.Fatalf("HTTP %d, native %d", wire.Status, row.HTTPStatus)
	}
	if err == nil {
		aasCompare(t, row.Label, ecsControlBody(t, row.Output), ecsControlBody(t, wire.Body), bindings, times)
	}
}

func aasAlarms(t *testing.T, c cloudClients, row aasControlRow, bindings map[string]string, times map[float64]float64) {
	t.Helper()
	client := cloudwatch.New(cloudwatch.Options{Region: row.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	result, err := awstest.CallSDK(t.Context(), client, row.Operation, aasInput(t, row, bindings))
	if err != nil {
		t.Fatal(err)
	}
	got := ec2NetworkDocument(t, result)
	// Decode both CloudWatch sides through the SDK shape. Its nested pointers
	// serialize as null even when the native CLI omits those optional members.
	var captured any
	if row.RawResponse != "" {
		options := client.Options()
		options.HTTPClient = nativeXMLResponse(row.RawResponse)
		reference := cloudwatch.New(options, func(o *cloudwatch.Options) {
			o.Protocol = awsquery.New(&smithy.ServiceSchema{Version: cloudwatch.ServiceAPIVersion})
		})
		captured, err = awstest.CallSDK(t.Context(), reference, row.Operation, row.Input)
		if err != nil {
			t.Fatalf("decode retained native CloudWatch response: %v", err)
		}
	} else {
		output := new(cloudwatch.DescribeAlarmsOutput)
		if err := json.Unmarshal(row.Output, output); err != nil {
			t.Fatal(err)
		}
		captured = output
	}
	want := ec2NetworkDocument(t, captured)
	// CloudWatch CLI and SDK have different null/empty envelopes. Compare the
	// consumer-visible managed alarm configuration, not alarm diagnostic prose,
	// evaluation wall-clock timestamps, or unrelated alarm families.
	fields := []string{"AlarmName", "AlarmArn", "ActionsEnabled", "OKActions", "AlarmActions", "InsufficientDataActions", "MetricName", "Namespace", "Statistic", "Dimensions", "Period", "Unit", "EvaluationPeriods", "DatapointsToAlarm", "Threshold", "ComparisonOperator", "TreatMissingData", "Metrics"}
	project := func(document map[string]any) map[string]any {
		alarms := []any{}
		values, _ := document["MetricAlarms"].([]any)
		for _, value := range values {
			alarm := value.(map[string]any)
			selected := map[string]any{}
			for _, field := range fields {
				value, present := alarm[field]
				if (field == "Unit" || field == "Statistic") && value == "" {
					continue
				}
				if field == "OKActions" || field == "AlarmActions" || field == "InsufficientDataActions" || field == "Dimensions" {
					if value == nil {
						value, present = []any{}, true
					}
				}
				if present && value != nil {
					selected[field] = value
				}
			}
			alarms = append(alarms, selected)
		}
		return map[string]any{"MetricAlarms": alarms}
	}
	aasCompare(t, row.Label, project(want), project(got), bindings, times)
}

func aasFixtureRow(t *testing.T, c cloudClients, row aasControlRow, bindings map[string]string, times map[float64]float64) {
	t.Helper()
	switch row.Service {
	case "application-autoscaling":
		aasReplay(t, c, row, bindings, times)
	case "cloudwatch", "monitoring":
		aasAlarms(t, c, row, bindings, times)
	case "ecs", "ec2":
		aasPrerequisite(t, c, row, bindings)
	default:
		t.Fatalf("unselected service %q", row.Service)
	}
}

func TestApplicationAutoScalingNativeControlsAcrossReopen(t *testing.T) {
	fixture := aasFixture(t, "controls")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			source := clock.NewManual(fixture.Calls[0].StartedAt)
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source, ECSExecutor: aasExecutor(t), ComputeEndpoint: "http://stackd.invalid"})
			bindings, times := map[string]string{}, map[float64]float64{}
			for _, row := range fixture.Calls {
				// The controls and focused follow-up are separate owned resources.
				if !(row.Sequence >= 4 && row.Sequence <= 164 || row.Sequence >= 192 && row.Sequence <= 224) {
					continue
				}
				if row.Service == "iam" {
					continue
				}
				switch row.Label {
				case "tag-target-null", "untag-target-null":
					// Go SDK required-parameter validation prevents these signed-JSON
					// null requests from reaching HTTP. Empty collections still replay.
					continue
				case "register-mismatched-dimension":
					// Account-specific AccessDenied is not namespace validation evidence.
					continue
				case "policy-predictive-missing-config", "policy-predictive-forecast-only", "describe-all-policies", "describe-policy-type-filter":
					// Predictive admission is native-supported but outside stackd's ECS
					// execution contract. PolicyTypes is not an SDK input member.
					continue
				case "describe-policies-page-one", "describe-schedules-page-one", "edge-target-page-one", "edge-DescribeScalingPolicies-namespace-page-one", "edge-DescribeScheduledActions-namespace-page-one":
					// Retained observations have no continuation token and do not prove
					// stable ordering. Invalid-token and MaxResults=0 rows still replay.
					continue
				case "describe-all-schedules":
					// The immediately expired at(2020) action disappears here and
					// reappears in the next page observation: no stable inventory oracle.
					continue
				}
				if strings.HasPrefix(row.Label, "wait-service-inactive-") && row.Label != "wait-service-inactive-5" {
					continue
				}
				if row.StartedAt.After(source.Now()) {
					source.Advance(row.StartedAt.Sub(source.Now()))
				}
				if !t.Run(row.Label, func(t *testing.T) {
					aasFixtureRow(t, clients, row, bindings, times)
				}) {
					return
				}
				if row.Code == "Success" && !strings.HasPrefix(strings.ToLower(row.Operation), "describe") && !strings.HasPrefix(row.Operation, "List") {
					clients = reopen()
				}
				if row.Label == "deregister-target-with-dependencies" {
					row := fixture.row(t, "describe-alarms-after-policy-delete")
					client := cloudwatch.New(cloudwatch.Options{Region: row.Region, BaseEndpoint: aws.String(clients.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
					result, err := awstest.CallSDK(t.Context(), client, row.Operation, aasInput(t, row, bindings))
					if err != nil {
						t.Fatal(err)
					}
					if alarms := result.(*cloudwatch.DescribeAlarmsOutput).MetricAlarms; len(alarms) != 0 {
						t.Fatalf("target deletion retained managed alarms: %+v", alarms)
					}
				}
			}
		})
	}
}

// Native ecs_authorization.json establishes that denied forwarded ECS probes do
// not reject AAS registration. The remaining cases exercise current policy/tag
// decisions and scope isolation against the retained native target shapes.
func TestApplicationAutoScalingCurrentAuthorizationAndIsolation(t *testing.T) {
	fixture := aasFixture(t, "controls")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, ECSExecutor: aasExecutor(t), ComputeEndpoint: "http://stackd.invalid"})
			bindings, times := map[string]string{}, map[float64]float64{}
			// This test owns only the edge services, so provision the main capture's
			// Fargate network independently rather than relying on the replay test.
			for _, label := range []string{"edge-create-cluster", "create-vpc", "create-subnet", "edge-register-task", "edge-create-service-0"} {
				aasPrerequisite(t, clients, fixture.row(t, label), bindings)
			}
			row := fixture.row(t, "edge-register-target-0")
			aasReplay(t, clients, row, bindings, times)
			for _, label := range []string{"edge-step-create-explicit-optionals", "edge-schedule-create-0"} {
				aasReplay(t, clients, fixture.row(t, label), bindings, times)
			}
			var input applicationautoscaling.RegisterScalableTargetInput
			if err := json.Unmarshal(row.Input, &input); err != nil {
				t.Fatal(err)
			}
			root := func() *applicationautoscaling.Client {
				return aasClient(clients, fixture.Region, "test", "test", clients.server.Client())
			}
			query := &applicationautoscaling.DescribeScalableTargetsInput{ServiceNamespace: input.ServiceNamespace, ResourceIds: []string{aws.ToString(input.ResourceId)}, ScalableDimension: input.ScalableDimension}
			targets, err := root().DescribeScalableTargets(t.Context(), query)
			if err != nil || len(targets.ScalableTargets) != 1 {
				t.Fatalf("created target: %+v %v", targets, err)
			}
			arn := targets.ScalableTargets[0].ScalableTargetARN
			_, key, secret := clients.user(t, "test", "ScalingOperator")
			delegated := func() *applicationautoscaling.Client {
				return aasClient(clients, fixture.Region, key, secret, clients.server.Client())
			}
			_, err = delegated().DescribeScalableTargets(t.Context(), query)
			assertAPIError(t, err, "AccessDeniedException")
			policy := func(resource, owner string) string {
				return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"application-autoscaling:Describe*","Resource":"*"},{"Effect":"Allow","Action":["application-autoscaling:RegisterScalableTarget","application-autoscaling:DeregisterScalableTarget"],"Resource":%q,"Condition":{"StringEquals":{"application-autoscaling:service-namespace":"ecs","application-autoscaling:scalable-dimension":"ecs:service:DesiredCount","aws:ResourceTag/owner":%q}}},{"Effect":"Allow","Action":["ecs:DescribeServices","ecs:UpdateService"],"Resource":"*"}]}`, resource, owner)
			}
			putUserPolicy(t, clients.iam("test", "test", ""), "ScalingOperator", policy(aws.ToString(arn), "allowed"))
			_, err = root().TagResource(t.Context(), &applicationautoscaling.TagResourceInput{ResourceARN: arn, Tags: map[string]string{"owner": "allowed"}})
			if err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			before, err := delegated().DescribeScalableTargets(t.Context(), query)
			if err != nil || len(before.ScalableTargets) != 1 {
				t.Fatalf("wildcard Describe admission: %+v %v", before, err)
			}
			update := &applicationautoscaling.RegisterScalableTargetInput{ServiceNamespace: input.ServiceNamespace, ResourceId: input.ResourceId, ScalableDimension: input.ScalableDimension, SuspendedState: &aastypes.SuspendedState{DynamicScalingInSuspended: aws.Bool(true)}}
			// Native registration records the caller's denied forwarded probes,
			// then verifies access through its independent service-linked role.
			document := policy(aws.ToString(arn), "allowed")
			var restricted map[string]any
			if err := json.Unmarshal([]byte(document), &restricted); err != nil {
				t.Fatal(err)
			}
			statements := restricted["Statement"].([]any)
			restricted["Statement"] = statements[:len(statements)-1]
			withoutECS, err := json.Marshal(restricted)
			if err != nil {
				t.Fatal(err)
			}
			putUserPolicy(t, clients.iam("test", "test", ""), "ScalingOperator", string(withoutECS))
			_, err = delegated().RegisterScalableTarget(t.Context(), update)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := root().DescribeScalableTargets(t.Context(), query)
			if err != nil || len(changed.ScalableTargets) != 1 || !aws.ToBool(changed.ScalableTargets[0].SuspendedState.DynamicScalingInSuspended) {
				t.Fatalf("linked-role admission did not retain suspension: %+v %v", changed, err)
			}
			_, err = root().TagResource(t.Context(), &applicationautoscaling.TagResourceInput{ResourceARN: arn, Tags: map[string]string{"owner": "denied"}})
			if err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			update.SuspendedState.DynamicScalingInSuspended = aws.Bool(false)
			_, err = delegated().RegisterScalableTarget(t.Context(), update)
			assertAPIError(t, err, "AccessDeniedException")
			retained, err := root().DescribeScalableTargets(t.Context(), query)
			if err != nil || len(retained.ScalableTargets) != 1 || !aws.ToBool(retained.ScalableTargets[0].SuspendedState.DynamicScalingInSuspended) {
				t.Fatalf("denied mutation changed retained suspension: %+v %v", retained, err)
			}
			for _, scope := range []struct{ account, region string }{{fixture.Account, "us-west-2"}, {"111122223333", fixture.Region}} {
				foreign := aasClient(clients, scope.region, scope.account, "test", clients.server.Client())
				out, err := foreign.DescribeScalableTargets(t.Context(), query)
				if err != nil || len(out.ScalableTargets) != 0 {
					t.Fatalf("cross-scope target leak: %+v %v", out, err)
				}
				policies, err := foreign.DescribeScalingPolicies(t.Context(), &applicationautoscaling.DescribeScalingPoliciesInput{ServiceNamespace: input.ServiceNamespace})
				if err != nil || len(policies.ScalingPolicies) != 0 {
					t.Fatalf("cross-scope policy leak: %+v %v", policies, err)
				}
				schedules, err := foreign.DescribeScheduledActions(t.Context(), &applicationautoscaling.DescribeScheduledActionsInput{ServiceNamespace: input.ServiceNamespace})
				if err != nil || len(schedules.ScheduledActions) != 0 {
					t.Fatalf("cross-scope schedule leak: %+v %v", schedules, err)
				}
				_, err = foreign.ListTagsForResource(t.Context(), &applicationautoscaling.ListTagsForResourceInput{ResourceARN: arn})
				assertAPIError(t, err, "ResourceNotFoundException")
			}
			// Regranting current tags does not authorize a replacement incarnation
			// through the old target ARN retained in the user's policy.
			remove := &applicationautoscaling.DeregisterScalableTargetInput{ServiceNamespace: input.ServiceNamespace, ResourceId: input.ResourceId, ScalableDimension: input.ScalableDimension}
			_, err = root().DeregisterScalableTarget(t.Context(), remove)
			if err != nil {
				t.Fatal(err)
			}
			input.Tags = map[string]string{"owner": "allowed"}
			created, err := root().RegisterScalableTarget(t.Context(), &input)
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(created.ScalableTargetARN) == aws.ToString(arn) {
				t.Fatal("target recreation reused retired ARN")
			}
			clients = reopen()
			_, err = delegated().DeregisterScalableTarget(t.Context(), remove)
			assertAPIError(t, err, "AccessDeniedException")
			putUserPolicy(t, clients.iam("test", "test", ""), "ScalingOperator", policy(aws.ToString(created.ScalableTargetARN), "allowed"))
			_, err = delegated().DeregisterScalableTarget(t.Context(), remove)
			if err != nil {
				t.Fatal(err)
			}
			clients = reopen()
			empty, err := root().DescribeScalableTargets(t.Context(), query)
			if err != nil || len(empty.ScalableTargets) != 0 {
				t.Fatalf("authorized delete not retained: %+v %v", empty, err)
			}
		})
	}
}

func TestApplicationAutoScalingUnsupportedBranches(t *testing.T) {
	fixture := aasFixture(t, "controls")
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, ECSExecutor: aasExecutor(t), ComputeEndpoint: "http://stackd.invalid"})
			bindings, times := map[string]string{}, map[float64]float64{}
			for _, label := range []string{"create-cluster", "create-vpc", "create-subnet", "register-task-definition", "create-service"} {
				aasPrerequisite(t, clients, fixture.row(t, label), bindings)
			}
			aasReplay(t, clients, fixture.row(t, "register-target-defaults"), bindings, times)
			client := aasClient(clients, fixture.Region, "test", "test", clients.server.Client())
			// This native row succeeds on AWS. Assert stackd's explicit unsupported
			// boundary separately, never substitute a failure into native replay.
			predictive := fixture.row(t, "policy-predictive-forecast-only")
			_, err := awstest.CallSDK(t.Context(), client, predictive.Operation, aasInput(t, predictive, bindings))
			assertAPIError(t, err, "NotImplementedException")
			clients = reopen()
			client = aasClient(clients, fixture.Region, "test", "test", clients.server.Client())
			policies, err := client.DescribeScalingPolicies(t.Context(), &applicationautoscaling.DescribeScalingPoliciesInput{ServiceNamespace: aastypes.ServiceNamespaceEcs})
			if err != nil || len(policies.ScalingPolicies) != 0 {
				t.Fatalf("unsupported policy persisted: %+v %v", policies, err)
			}
			aasReplay(t, clients, fixture.row(t, "describe-target-defaults"), bindings, times)
		})
	}
}

func TestApplicationAutoScalingNativeMetricPoliciesAcrossReopen(t *testing.T) {
	for _, capture := range []struct {
		name   string
		ranges [][2]int
	}{
		{"metric_math", [][2]int{{4, 59}}},
		{"high_resolution", [][2]int{{4, 85}}},
		{"metric_identity", [][2]int{{4, 54}, {140, 192}}},
		// Custom Period probes use fields absent from the public Smithy model.
		// Retain their native rejection evidence without replaying a stripped request.
		{"metric_identity_followup", [][2]int{{4, 109}, {166, 221}}},
		{"identity_edges", [][2]int{{4, 263}, {267, 424}}},
	} {
		t.Run(capture.name, func(t *testing.T) {
			fixture := aasFixture(t, capture.name)
			for _, backend := range []string{"memory", "sqlite"} {
				t.Run(backend, func(t *testing.T) {
					source := clock.NewManual(fixture.Calls[0].StartedAt)
					clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: fixture.Account, Clock: source, ECSExecutor: aasExecutor(t), ComputeEndpoint: "http://stackd.invalid"})
					bindings, times := map[string]string{}, map[float64]float64{}
					for _, row := range fixture.Calls {
						if !slices.ContainsFunc(capture.ranges, func(interval [2]int) bool { return row.Sequence >= interval[0] && row.Sequence <= interval[1] }) {
							continue
						}
						// Revision detail is exercised by ECS fixtures; these captures
						// prove scaling policy transactions and owned alarm contracts.
						if row.Operation == "describe-service-revisions" {
							continue
						}
						if row.StartedAt.After(source.Now()) {
							source.Advance(row.StartedAt.Sub(source.Now()))
						}
						if !t.Run(row.Label, func(t *testing.T) {
							aasFixtureRow(t, clients, row, bindings, times)
						}) {
							return
						}
						operation := strings.ToLower(row.Operation)
						if row.Code == "Success" && !strings.HasPrefix(operation, "describe") && !strings.HasPrefix(operation, "list") {
							clients = reopen()
						}
					}
				})
			}
		})
	}
}

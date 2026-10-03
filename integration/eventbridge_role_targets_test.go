package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"stackd"
	"stackd/internal/awstest"
	"stackd/storage"
)

type ebTargetRoleObservation struct {
	Label, Service, Operation, Actor string
	Input, Output                    json.RawMessage
	Error                            *struct{ Code, Message string }
}

type ebTargetRoleReceipt struct {
	Queue, Body string
	Attributes  map[string]sqstypes.MessageAttributeValue
}

type ebTargetRoleCase struct {
	Name, Service  string
	Rule           eventbridge.PutRuleInput
	Target         eventtypes.Target
	Send           ebTargetRoleObservation
	Receipt        ebTargetRoleReceipt
	Mutations      []ebTargetRoleObservation
	SettledSend    ebTargetRoleObservation `json:"settled_send"`
	SettledReceipt ebTargetRoleReceipt     `json:"settled_receipt"`
}

type ebTargetRoleRun struct {
	Name  string
	Setup []ebTargetRoleObservation
	Cases []ebTargetRoleCase
}

type ebTargetRoleFixture struct {
	Account, Region string
	Admission       []struct {
		Name         string
		Setup, Steps []ebTargetRoleObservation
	}
	Runs []ebTargetRoleRun
}

func ebTargetRoleRead(t *testing.T) ebTargetRoleFixture {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/eventbridge/target_roles.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture ebTargetRoleFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

type ebTargetRoleReplay struct {
	cloud           *stackd.Stack
	clients         cloudClients
	account, region string
	actors          map[string]aws.Credentials
	queues          map[string]*string
	destinations    map[string]string
}

func ebTargetRoleNew(cloud *stackd.Stack, clients cloudClients, account, region string) *ebTargetRoleReplay {
	return &ebTargetRoleReplay{cloud: cloud, clients: clients, account: account, region: region,
		actors: map[string]aws.Credentials{"": {AccessKeyID: account, SecretAccessKey: "test"}},
		queues: make(map[string]*string), destinations: make(map[string]string)}
}

func (f *ebTargetRoleReplay) events(actor string) *eventbridge.Client {
	c := f.actors[actor]
	return eventbridge.New(eventbridge.Options{Region: f.region, BaseEndpoint: aws.String(f.clients.server.URL), HTTPClient: f.clients.server.Client(), RetryMaxAttempts: 1,
		Credentials: credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)})
}

func ebTargetRoleDecode(t *testing.T, data json.RawMessage, target any) {
	t.Helper()
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

func (f *ebTargetRoleReplay) call(t *testing.T, row ebTargetRoleObservation) any {
	t.Helper()
	c := f.actors[row.Actor]
	var client any
	switch row.Service {
	case "events":
		client = f.events(row.Actor)
	case "iam":
		client = f.clients.iam(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)
	case "sts":
		client = f.clients.sts(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)
	case "kms":
		client = f.clients.kms(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)
	case "sqs":
		client = f.clients.sqs(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)
	case "sns":
		client = admissionSNSClient(f.clients, f.account, f.region)
	case "lambda":
		client = awslambda.New(awslambda.Options{Region: f.region, BaseEndpoint: aws.String(f.clients.server.URL), HTTPClient: f.clients.server.Client(), RetryMaxAttempts: 1,
			Credentials: credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)})
	default:
		t.Fatalf("unsupported fixture service %q", row.Service)
	}
	output, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input, func(value any) {
		switch input := value.(type) {
		case *sqs.SetQueueAttributesInput:
			input.QueueUrl = f.queues[aws.ToString(input.QueueUrl)[strings.LastIndex(aws.ToString(input.QueueUrl), "/")+1:]]
		case *awslambda.CreateFunctionInput:
			name := input.Environment.Variables["QUEUE"]
			name = name[strings.LastIndex(name, "/")+1:]
			input.Environment.Variables["QUEUE"] = strings.Replace(aws.ToString(f.queues[name]), "127.0.0.1", "host.docker.internal", 1)
			input.Environment.Variables["AWS_ENDPOINT_URL"] = strings.Replace(f.clients.server.URL, "127.0.0.1", "host.docker.internal", 1)
		}
	})
	code := ""
	if err != nil {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatal(row.Label, err)
		}
		code = apiErr.ErrorCode()
	}
	wantCode := ""
	if row.Error != nil {
		wantCode = row.Error.Code
	}
	if code != wantCode {
		t.Fatalf("%s: native error=%q local=%q: %v", row.Label, wantCode, code, err)
	}
	if err != nil {
		return nil
	}
	switch out := output.(type) {
	case *sqs.CreateQueueOutput:
		var input sqs.CreateQueueInput
		ebTargetRoleDecode(t, row.Input, &input)
		f.queues[aws.ToString(input.QueueName)] = out.QueueUrl
	case *sns.SubscribeOutput:
		var input sns.SubscribeInput
		ebTargetRoleDecode(t, row.Input, &input)
		endpoint := aws.ToString(input.Endpoint)
		f.destinations[aws.ToString(input.TopicArn)] = endpoint[strings.LastIndex(endpoint, ":")+1:]
	case *awslambda.CreateFunctionOutput:
		var input awslambda.CreateFunctionInput
		ebTargetRoleDecode(t, row.Input, &input)
		queue := input.Environment.Variables["QUEUE"]
		f.destinations[aws.ToString(out.FunctionArn)] = queue[strings.LastIndex(queue, "/")+1:]
		if err := awslambda.NewFunctionActiveWaiter(client.(*awslambda.Client), fastLambdaActiveWaiter).Wait(t.Context(), &awslambda.GetFunctionConfigurationInput{FunctionName: out.FunctionName}, time.Minute); err != nil {
			t.Fatal(err)
		}
	case *sts.AssumeRoleOutput:
		f.actors[row.Label] = aws.Credentials{AccessKeyID: aws.ToString(out.Credentials.AccessKeyId), SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey), SessionToken: aws.ToString(out.Credentials.SessionToken)}
	case *eventbridge.PutRuleOutput:
		var want eventbridge.PutRuleOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if aws.ToString(out.RuleArn) != aws.ToString(want.RuleArn) {
			t.Fatalf("%s: rule ARN=%v want=%v", row.Label, out.RuleArn, want.RuleArn)
		}
	case *eventbridge.DescribeRuleOutput:
		var want eventbridge.DescribeRuleOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if !reflect.DeepEqual(out.RoleArn, want.RoleArn) || aws.ToString(out.Arn) != aws.ToString(want.Arn) || aws.ToString(out.EventPattern) != aws.ToString(want.EventPattern) {
			t.Fatalf("%s: native rule role/pattern not retained: got=%+v want=%+v", row.Label, out, want)
		}
	case *eventbridge.PutTargetsOutput:
		var want eventbridge.PutTargetsOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if out.FailedEntryCount != want.FailedEntryCount || len(out.FailedEntries) != len(want.FailedEntries) {
			t.Fatalf("%s: target admission=%+v want=%+v", row.Label, out, want)
		}
	case *eventbridge.ListTargetsByRuleOutput:
		var want eventbridge.ListTargetsByRuleOutput
		ebTargetRoleDecode(t, row.Output, &want)
		if !reflect.DeepEqual(out.Targets, want.Targets) {
			t.Fatalf("%s: native target readback differs: got=%+v want=%+v", row.Label, out.Targets, want.Targets)
		}
	case *eventbridge.PutEventsOutput:
		var input eventbridge.PutEventsInput
		ebTargetRoleDecode(t, row.Input, &input)
		var want eventbridge.PutEventsOutput
		if len(row.Output) != 0 {
			ebTargetRoleDecode(t, row.Output, &want)
		}
		if out.FailedEntryCount != want.FailedEntryCount || len(out.Entries) != len(input.Entries) {
			t.Fatalf("%s: event admission=%+v want=%+v", row.Label, out, want)
		}
		for i, entry := range out.Entries {
			wantCode := ""
			if i < len(want.Entries) {
				wantCode = aws.ToString(want.Entries[i].ErrorCode)
			}
			if aws.ToString(entry.ErrorCode) != wantCode || (aws.ToString(entry.EventId) != "") != (wantCode == "") {
				t.Fatalf("%s: event entry %d=%+v want error=%q", row.Label, i, entry, wantCode)
			}
		}
	}
	return output
}

func (f *ebTargetRoleReplay) setup(t *testing.T, rows []ebTargetRoleObservation, docker bool) {
	t.Helper()
	f.delegated(t, "arn:aws:iam::"+f.account+":role/stackd-eb-role-*-caller-*")
	for _, row := range rows {
		if row.Service == "lambda" && !docker {
			continue
		}
		f.call(t, row)
	}
}

func (f *ebTargetRoleReplay) delegated(t *testing.T, roleResource string) {
	t.Helper()
	root := f.clients.iam(f.account, "test", "")
	name := aws.String("Delegated")
	if _, err := root.CreateUser(t.Context(), &iam.CreateUserInput{UserName: name}); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the captured operator, not a different trust principal. Its
	// only local harness grant is permission to assume the fixture caller roles.
	resource, err := json.Marshal(roleResource)
	if err != nil {
		t.Fatal(err)
	}
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":` + string(resource) + `}]}`
	if _, err := root.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: name, PolicyName: aws.String("capture-operator"), PolicyDocument: aws.String(policy)}); err != nil {
		t.Fatal(err)
	}
	key, err := root.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: name})
	if err != nil {
		t.Fatal(err)
	}
	f.actors["delegated"] = aws.Credentials{AccessKeyID: aws.ToString(key.AccessKey.AccessKeyId), SecretAccessKey: aws.ToString(key.AccessKey.SecretAccessKey)}
}

func TestEventBridgeTargetRoleNativeAdmissionSDK(t *testing.T) {
	fixture := ebTargetRoleRead(t)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, group := range fixture.Admission {
			t.Run(backend+"/"+group.Name, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "roles.sqlite"))
				}
				cloud, clients, _ := startEventDeliveryCloud(t, backends, nil)
				f := ebTargetRoleNew(cloud, clients, fixture.Account, fixture.Region)
				f.setup(t, group.Setup, false)
				for _, row := range group.Steps {
					f.call(t, row)
				}
			})
		}
	}
}

func (f *ebTargetRoleReplay) observe(t *testing.T, tc ebTargetRoleCase, receipt ebTargetRoleReceipt, id string, before time.Time) {
	t.Helper()
	consumer := &lambdaEventsCloud{cloud: f.cloud, queues: f.clients.sqs(f.account, "test", "")}
	message := lambdaEventsReceive(t, consumer, f.queues[receipt.Queue], 1)[0]
	wantAttributes := make(map[string]string)
	for name, value := range receipt.Attributes {
		wantAttributes[name] = aws.ToString(value.StringValue)
	}
	// Compare error class and the complete attribute key set, including absence
	// of RETRY_ATTEMPTS/EXHAUSTED_RETRY_CONDITION; diagnostic prose is not stable.
	var diagnosis []string
	if native := wantAttributes["ERROR_MESSAGE"]; strings.HasPrefix(native, "User: ") {
		actor := strings.Fields(native)[1]
		if strings.Contains(actor, ":assumed-role/") {
			actor = actor[:strings.LastIndex(actor, "/")+1]
		}
		diagnosis = append(diagnosis, actor)
	}
	assertEventDeliveryAttributes(t, message.MessageAttributes, wantAttributes, diagnosis...)
	var got, want map[string]any
	ebTargetRoleDecode(t, []byte(aws.ToString(message.Body)), &got)
	ebTargetRoleDecode(t, []byte(receipt.Body), &want)
	actualEvent, nativeEvent := got, want
	if tc.Service == "lambda" && len(receipt.Attributes) == 0 {
		actualEvent, _ = got["event"].(map[string]any)
		nativeEvent, _ = want["event"].(map[string]any)
		// Handler request IDs are opaque, not part of role authority.
		delete(got, "aws_request_id")
		delete(want, "aws_request_id")
	}
	if actualEvent["id"] != id {
		t.Fatalf("destination lost admitted event identity: %v", got)
	}
	stamp, err := time.Parse(time.RFC3339Nano, actualEvent["time"].(string))
	if err != nil || stamp.Before(before.Truncate(time.Second)) || stamp.After(time.Now().Add(time.Second)) {
		t.Fatalf("destination changed event time: %v", actualEvent["time"])
	}
	actualEvent["id"], actualEvent["time"] = nativeEvent["id"], nativeEvent["time"]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("destination envelope differs from native:\ngot=%#v\nwant=%#v", got, want)
	}
	destination := f.destinations[aws.ToString(tc.Target.Arn)]
	if tc.Service == "sqs" {
		arn := aws.ToString(tc.Target.Arn)
		destination = arn[strings.LastIndex(arn, ":")+1:]
	}
	dlq := aws.ToString(tc.Target.DeadLetterConfig.Arn)
	dlq = dlq[strings.LastIndex(dlq, ":")+1:]
	lambdaEventsQuiet(t, consumer, f.queues[destination], f.queues[dlq])
}

func ebTargetRoleDeliveries(t *testing.T, docker bool) {
	t.Helper()
	fixture := ebTargetRoleRead(t)
	for _, backend := range []string{"memory", "sqlite"} {
		for _, run := range fixture.Runs {
			hasCase := false
			for _, tc := range run.Cases {
				hasCase = hasCase || (tc.Service == "lambda") == docker
			}
			if !hasCase {
				continue
			}
			t.Run(backend+"/"+run.Name, func(t *testing.T) {
				backends := storage.NewMemory()
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "roles.sqlite"))
				}
				var cloud *stackd.Stack
				var clients cloudClients
				if docker {
					var c cloudClients
					cloud, c.server = newLambdaDockerStack(t, stackd.Config{Storage: backends, Clock: nil}, nil)
					clients = c
				} else {
					cloud, clients, _ = startEventDeliveryCloud(t, backends, nil)
				}
				f := ebTargetRoleNew(cloud, clients, fixture.Account, fixture.Region)
				f.setup(t, run.Setup, docker)
				for _, tc := range run.Cases {
					if (tc.Service == "lambda") != docker {
						continue
					}
					if !t.Run(tc.Name, func(t *testing.T) {
						before := time.Now()
						out := f.call(t, tc.Send).(*eventbridge.PutEventsOutput)
						f.observe(t, tc, tc.Receipt, aws.ToString(out.Entries[0].EventId), before)
						if len(tc.Mutations) != 0 {
							for _, mutation := range tc.Mutations {
								f.call(t, mutation)
							}
							// Native immediate stale successes are retained as evidence,
							// not an invented credential-cache TTL for this emulator.
							before = time.Now()
							out = f.call(t, tc.SettledSend).(*eventbridge.PutEventsOutput)
							f.observe(t, tc, tc.SettledReceipt, aws.ToString(out.Entries[0].EventId), before)
						}
					}) {
						t.FailNow()
					}
				}
			})
		}
	}
}

func TestEventBridgeTargetRoleNativeSQSAndSNSSDK(t *testing.T) {
	ebTargetRoleDeliveries(t, false)
}

func TestEventBridgeTargetRoleNativeLambdaDockerSDK(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("set STACKD_LAMBDA_DOCKER=1 to exercise the real Docker Lambda runtime")
	}
	ebTargetRoleDeliveries(t, true)
}

func TestEventBridgeTargetRoleRetainedDeliverySDK(t *testing.T) {
	fixture := ebTargetRoleRead(t)
	run := fixture.Runs[0]
	for _, backend := range []string{"memory", "sqlite"} {
		for _, tc := range run.Cases {
			if len(tc.Mutations) == 0 {
				continue
			}
			t.Run(backend+"/"+tc.Name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "retained-role.sqlite")
				backends := storage.NewMemory()
				closeDB := func() {}
				if backend == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, path)
				}
				gate := &gatedQueueRepository{Repository: backends.SQS, entered: make(chan struct{}), release: make(chan struct{})}
				backends.SQS = gate
				t.Cleanup(gate.unblock)
				cloud, clients, closeCloud := startEventDeliveryCloud(t, backends, nil)
				f := ebTargetRoleNew(cloud, clients, fixture.Account, fixture.Region)
				f.setup(t, run.Setup, false)
				gate.armed.Store(true)
				before := time.Now()
				out := f.call(t, tc.Send).(*eventbridge.PutEventsOutput)
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				select {
				case <-gate.entered:
				case <-ctx.Done():
					t.Fatal("delivery did not reach the real SQS command", ctx.Err())
				}
				for _, mutation := range tc.Mutations {
					f.call(t, mutation)
				}
				// These source mutations are a local durability invariant, not an
				// additional AWS timing observation. The selected role must outlive
				// both its target entry and its rule; policy remains current.
				rule := tc.Rule
				rule.RoleArn = aws.String("arn:aws:iam::" + fixture.Account + ":role/stackd-eb-role-1384efbd-replacement-deny")
				rule.EventPattern = aws.String(`{"source":["no-longer-matches"]}`)
				if _, err := f.events("").PutRule(t.Context(), &rule); err != nil {
					t.Fatal(err)
				}
				removed, err := f.events("").RemoveTargets(t.Context(), &eventbridge.RemoveTargetsInput{EventBusName: rule.EventBusName, Rule: rule.Name, Ids: []string{aws.ToString(tc.Target.Id)}})
				if err != nil || removed.FailedEntryCount != 0 {
					t.Fatal(removed, err)
				}
				if _, err := f.events("").DeleteRule(t.Context(), &eventbridge.DeleteRuleInput{EventBusName: rule.EventBusName, Name: rule.Name}); err != nil {
					t.Fatal(err)
				}
				closeCloud()
				closeDB()
				backends.SQS = gate.Repository
				if backend == "sqlite" {
					backends, _ = openSQLiteBackends(t, path)
				}
				cloud, clients, _ = startEventDeliveryCloud(t, backends, nil)
				f.cloud, f.clients = cloud, clients
				for name := range f.queues {
					queue, err := clients.sqs(f.account, "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String(name)})
					if err != nil {
						t.Fatal(err)
					}
					f.queues[name] = queue.QueueUrl
				}
				receipt := tc.Receipt
				// Target replacement cannot change already selected authority.
				// Deletion/revocation of that authority must affect resumed work.
				for _, mutation := range tc.Mutations {
					if mutation.Service == "iam" {
						receipt.Queue, receipt.Attributes = tc.SettledReceipt.Queue, tc.SettledReceipt.Attributes
					}
				}
				f.observe(t, tc, receipt, aws.ToString(out.Entries[0].EventId), before)
			})
		}
	}
}

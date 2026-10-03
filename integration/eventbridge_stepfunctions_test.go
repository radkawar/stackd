package stackd_test

import (
	"encoding/json"
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
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
)

// The native fixture supplies real definitions and terminal workflow results.
// EventBridge admission, identity and DLQ checks compose that evidence with the
// documented PutTargets/StartExecution contract; they are not an inbound native
// capture or a claim about AWS retry timing or generated execution names.
func TestEventBridgeStepFunctionsFixtureAdmissionSDK(t *testing.T) {
	var fixture struct {
		Definitions map[string]string
		Outcomes    map[string]struct {
			Status, Input, Output string
		}
	}
	awsReadFixture(t, "stepfunctions/control_lifecycle.json", &fixture)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "workflow-target.sqlite"))
			}
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC))
			cloud, clients, _ := startEventDeliveryCloud(t, backends, source)
			const account = "000000000000"
			const region = "us-east-1"
			roles := clients.iam(account, "test", "")
			events := eventDeliveryClient(clients, account)
			workflows := sfn.New(sfn.Options{Region: region, BaseEndpoint: aws.String(clients.server.URL), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1,
				Credentials: credentials.NewStaticCredentialsProvider(account, "test", "")})
			worker, err := roles.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("workflow-worker"),
				AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			machine, err := workflows.CreateStateMachine(t.Context(), &sfn.CreateStateMachineInput{Name: aws.String("event-workflow"), RoleArn: worker.Role.Arn,
				Definition: aws.String(fixture.Definitions["initial"]), Publish: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := workflows.UpdateStateMachine(t.Context(), &sfn.UpdateStateMachineInput{StateMachineArn: machine.StateMachineArn, Definition: aws.String(fixture.Definitions["updated"]), Publish: true}); err != nil {
				t.Fatal(err)
			}
			alias, err := workflows.CreateStateMachineAlias(t.Context(), &sfn.CreateStateMachineAliasInput{Name: aws.String("live"),
				RoutingConfiguration: []sfntypes.RoutingConfigurationListItem{{StateMachineVersionArn: machine.StateMachineVersionArn, Weight: 100}}})
			if err != nil {
				t.Fatal(err)
			}
			rule, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("start-workflow"), EventPattern: aws.String(`{"source":["workflow.admission"]}`)})
			if err != nil {
				t.Fatal(err)
			}
			trust := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:SourceArn":"` + aws.ToString(rule.RuleArn) + `"}}}}`
			role, err := roles.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("event-workflow-starter"), AssumeRolePolicyDocument: aws.String(trust)})
			if err != nil {
				t.Fatal(err)
			}
			resources, err := json.Marshal([]string{aws.ToString(machine.StateMachineArn), aws.ToString(machine.StateMachineVersionArn), aws.ToString(alias.StateMachineAliasArn)})
			if err != nil {
				t.Fatal(err)
			}
			putRolePolicy(t, roles, "event-workflow-starter", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"states:StartExecution","Resource":`+string(resources)+`}}`)
			input := fixture.Outcomes["updated-unqualified-terminal"].Input
			targets := []eventtypes.Target{
				{Id: aws.String("latest"), Arn: machine.StateMachineArn, RoleArn: role.Role.Arn, Input: aws.String(input)},
				{Id: aws.String("version"), Arn: machine.StateMachineVersionArn, RoleArn: role.Role.Arn, InputPath: aws.String("$.detail")},
				{Id: aws.String("alias"), Arn: alias.StateMachineAliasArn, RoleArn: role.Role.Arn, InputTransformer: &eventtypes.InputTransformer{
					InputPathsMap: map[string]string{"probe": "$.detail.probe"}, InputTemplate: aws.String(`{"probe":<probe>}`)}},
				{Id: aws.String("envelope"), Arn: machine.StateMachineArn, RoleArn: role.Role.Arn},
			}
			out, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("start-workflow"), Targets: targets})
			if err != nil || out.FailedEntryCount != 0 {
				t.Fatal("admit unqualified, version and alias targets", out, err)
			}
			const trace = "Root=1-abcdef12-0123456789abcdef01234567;Parent=0123456789abcdef;Sampled=1"
			published, err := events.PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{
				Source: aws.String("workflow.admission"), DetailType: aws.String("workflow-input"), Detail: aws.String(input), TraceHeader: aws.String(trace)}}})
			if err != nil || published.FailedEntryCount != 0 || len(published.Entries) != 1 {
				t.Fatal(published, err)
			}
			if jobs, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || jobs.More {
				t.Fatal("admit target executions", jobs, err)
			}
			advanceClock(t, source, 12*time.Second)
			if jobs, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || jobs.More {
				t.Fatal("complete captured workflow waits", jobs, err)
			}
			list, err := workflows.ListExecutions(t.Context(), &sfn.ListExecutionsInput{StateMachineArn: machine.StateMachineArn})
			if err != nil || len(list.Executions) != len(targets) {
				t.Fatal("each accepted target starts one real execution", list, err)
			}
			started := make(map[string]bool)
			seen := make(map[string]bool)
			for _, execution := range list.Executions {
				got, err := workflows.DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: execution.ExecutionArn})
				if err != nil {
					t.Fatal(err)
				}
				kind, outcome := "latest", "updated-unqualified-terminal"
				switch {
				case got.StateMachineAliasArn != nil:
					kind, outcome = "alias", "alias-old-route-terminal"
					if aws.ToString(got.StateMachineAliasArn) != aws.ToString(alias.StateMachineAliasArn) || aws.ToString(got.StateMachineVersionArn) != aws.ToString(machine.StateMachineVersionArn) {
						t.Fatal("alias did not resolve its published version", got)
					}
				case got.StateMachineVersionArn != nil:
					kind, outcome = "version", "version-after-delete-terminal"
					if aws.ToString(got.StateMachineVersionArn) != aws.ToString(machine.StateMachineVersionArn) {
						t.Fatal("version target lost its qualifier", got)
					}
				default:
					var payload map[string]any
					awsDecodeJSON(t, []byte(aws.ToString(got.Input)), &payload)
					if payload["source"] == "workflow.admission" {
						kind = "envelope"
						if payload["id"] != aws.ToString(published.Entries[0].EventId) || payload["detail-type"] != "workflow-input" {
							t.Fatal("workflow received a different event envelope", payload)
						}
						detail, err := json.Marshal(payload["detail"])
						if err != nil {
							t.Fatal(err)
						}
						eventWorkflowJSONEqual(t, string(detail), input)
					}
				}
				want := fixture.Outcomes[outcome]
				if string(got.Status) != want.Status || aws.ToString(got.TraceHeader) != trace || aws.ToString(got.StateMachineArn) != aws.ToString(machine.StateMachineArn) || seen[kind] {
					t.Fatalf("%s: workflow outcome or trace mismatch: %+v", kind, got)
				}
				eventWorkflowJSONEqual(t, aws.ToString(got.Output), want.Output)
				if kind != "envelope" {
					eventWorkflowJSONEqual(t, aws.ToString(got.Input), input)
				}
				seen[kind], started[aws.ToString(got.ExecutionArn)] = true, true
			}
			rows, err := cloud.Events(t.Context(), 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				call := row.APICallCompleted
				if call == nil || call.EventName != "StartExecution" || call.EventSource != "states.amazonaws.com" {
					continue
				}
				var response struct {
					ExecutionARN string `json:"executionArn"`
				}
				awsDecodeJSON(t, call.ResponseElements, &response)
				if !started[response.ExecutionARN] || row.ParentEventID != aws.ToString(published.Entries[0].EventId) || call.ErrorCode != "" || call.Identity.Type != "AssumedRole" || call.Identity.IssuerARN != aws.ToString(role.Role.Arn) || call.SourceIPAddress != "events.amazonaws.com" {
					t.Fatalf("execution escaped the authoritative service-role audit path: %+v", row)
				}
				delete(started, response.ExecutionARN)
			}
			if len(started) != 0 {
				t.Fatal("executions missing an authoritative StartExecution outcome", started)
			}

			// Rejected authority must not become a successful delivery. Native
			// inbound error wording is unmeasured; protect existing error classes
			// and the absence of workflow admission rather than inventing text.
			deniedRule, err := events.PutRule(t.Context(), &eventbridge.PutRuleInput{Name: aws.String("deny-workflow"), EventPattern: aws.String(`{"source":["workflow.denial"]}`)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("deny-workflow"), Targets: []eventtypes.Target{{Id: aws.String("missing-role"), Arn: machine.StateMachineArn}}})
			assertAPIError(t, err, "ValidationException")
			queues := clients.sqs(account, "test", "")
			queueARN := "arn:aws:sqs:" + region + ":" + account + ":workflow-dlq"
			queuePolicy := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"` + queueARN + `","Condition":{"ArnEquals":{"aws:SourceArn":"` + aws.ToString(deniedRule.RuleArn) + `"}}}}`
			queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("workflow-dlq"), Attributes: map[string]string{"Policy": queuePolicy}})
			if err != nil {
				t.Fatal(err)
			}
			for _, denial := range []struct{ name, code string }{{"trust", "FAILED_TO_ASSUME_ROLE"}, {"permission", "NO_PERMISSIONS"}, {"deleted", "FAILED_TO_ASSUME_ROLE"}} {
				name := "workflow-denied-" + denial.name
				principal := "events.amazonaws.com"
				if denial.name == "trust" {
					principal = "states.amazonaws.com"
				}
				deniedRole, err := roles.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"` + principal + `"},"Action":"sts:AssumeRole"}}`)})
				if err != nil {
					t.Fatal(err)
				}
				if denial.name != "deleted" {
					effect := "Allow"
					if denial.name == "permission" {
						effect = "Deny"
					}
					putRolePolicy(t, roles, name, `{"Version":"2012-10-17","Statement":{"Effect":"`+effect+`","Action":"states:StartExecution","Resource":"`+aws.ToString(machine.StateMachineArn)+`"}}`)
				}
				target := eventtypes.Target{Id: aws.String("denied"), Arn: machine.StateMachineArn, RoleArn: deniedRole.Role.Arn, Input: aws.String(input), DeadLetterConfig: &eventtypes.DeadLetterConfig{Arn: aws.String(queueARN)}}
				out, err := events.PutTargets(t.Context(), &eventbridge.PutTargetsInput{Rule: aws.String("deny-workflow"), Targets: []eventtypes.Target{target}})
				if err != nil || out.FailedEntryCount != 0 {
					t.Fatal(out, err)
				}
				if denial.name == "deleted" {
					if _, err := roles.DeleteRole(t.Context(), &iam.DeleteRoleInput{RoleName: aws.String(name)}); err != nil {
						t.Fatal(err)
					}
				}
				sent, err := events.PutEvents(t.Context(), &eventbridge.PutEventsInput{Entries: []eventtypes.PutEventsRequestEntry{{Source: aws.String("workflow.denial"), DetailType: aws.String("denied"), Detail: aws.String(input)}}})
				if err != nil || sent.FailedEntryCount != 0 {
					t.Fatal(sent, err)
				}
				if jobs, err := cloud.RunDueJobs(t.Context(), 1000); err != nil || jobs.More {
					t.Fatal(jobs, err)
				}
				messages, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MessageAttributeNames: []string{"All"}})
				if err != nil || len(messages.Messages) != 1 {
					t.Fatal("denied workflow target did not reach DLQ", denial.name, messages, err)
				}
				message := messages.Messages[0]
				if aws.ToString(message.MessageAttributes["ERROR_CODE"].StringValue) != denial.code || aws.ToString(message.MessageAttributes["TARGET_ARN"].StringValue) != aws.ToString(machine.StateMachineArn) || message.MessageAttributes["RETRY_ATTEMPTS"].StringValue != nil {
					t.Fatal("nonretryable authority error changed delivery semantics", denial.name, message)
				}
				if _, err := queues.DeleteMessage(t.Context(), &sqs.DeleteMessageInput{QueueUrl: queue.QueueUrl, ReceiptHandle: message.ReceiptHandle}); err != nil {
					t.Fatal(err)
				}
				rows, err := cloud.Events(t.Context(), 0, 1000)
				if err != nil {
					t.Fatal(err)
				}
				var rejections int
				for _, row := range rows {
					call := row.APICallCompleted
					if row.ParentEventID != aws.ToString(sent.Entries[0].EventId) || call == nil || call.EventName != "StartExecution" || call.EventSource != "states.amazonaws.com" {
						continue
					}
					rejections++
					if denial.name != "permission" || !strings.Contains(call.ErrorCode, "AccessDenied") || call.Identity.IssuerARN != aws.ToString(deniedRole.Role.Arn) {
						t.Fatal("workflow denial was not authoritatively audited", row)
					}
				}
				if denial.name == "permission" && rejections != 1 || denial.name != "permission" && rejections != 0 {
					t.Fatal("role failure reached the wrong admission boundary", denial.name, rejections)
				}
			}
			list, err = workflows.ListExecutions(t.Context(), &sfn.ListExecutionsInput{StateMachineArn: machine.StateMachineArn})
			if err != nil || len(list.Executions) != len(targets) {
				t.Fatal("rejected targets admitted workflow executions", list, err)
			}
		})
	}
}

func eventWorkflowJSONEqual(t *testing.T, got, want string) {
	t.Helper()
	var actual, expected any
	awsDecodeJSON(t, []byte(got), &actual)
	awsDecodeJSON(t, []byte(want), &expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("workflow JSON = %s, want native %s", got, want)
	}
}

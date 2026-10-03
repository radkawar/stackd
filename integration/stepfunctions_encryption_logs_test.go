package stackd_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
)

func TestStepFunctionsNativeEncryptionLogging(t *testing.T) {
	var fixture struct {
		stepFunctionsNativeFixture
		Cases []struct {
			ID, Scenario string
			MachineARN   string `json:"machine_arn"`
			GroupName    string `json:"group_name"`
		}
	}
	awsReadFixture(t, "stepfunctions/encryption_logging.json", &fixture)
	fixture.Actors = map[string]stepFunctionsNativeActor{"default": {}}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			r := newStepFunctionsNativeReplay(t, fixture.stepFunctionsNativeFixture, backend)
			type invocation struct{ arn, input string }
			runs := map[string][]invocation{}
			var finished int64
			for _, row := range fixture.Observations {
				finished = max(finished, row.Finished)
				if row.Result.Code != "Success" {
					continue
				}
				switch row.Operation {
				case "create-key", "create-role", "put-role-policy", "create-log-group", "put-resource-policy", "create-state-machine", "start-execution", "start-sync-execution":
				default:
					continue
				}
				if !t.Run(row.Label, func(t *testing.T) { r.replay(t, row) }) {
					return
				}
				if row.Operation == "start-execution" || row.Operation == "start-sync-execution" {
					var input struct{ StateMachineArn, Input string }
					var output struct{ ExecutionArn string }
					awsDecodeJSON(t, row.Input, &input)
					awsDecodeJSON(t, row.Result.Output, &output)
					runs[input.StateMachineArn] = append(runs[input.StateMachineArn], invocation{r.boundString(output.ExecutionArn), input.Input})
				}
			}
			r.advance(t, time.UnixMilli(finished))
			identity := credentials.NewStaticCredentialsProvider(fixture.Account, "test", "")
			logs := cloudwatchlogs.New(cloudwatchlogs.Options{Region: fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: identity, HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
			workflows := sfn.New(sfn.Options{Region: fixture.Region, BaseEndpoint: aws.String(r.clients.server.URL), Credentials: identity, HTTPClient: r.clients.server.Client(), RetryMaxAttempts: 1})
			for _, scenario := range fixture.Cases {
				t.Run(scenario.ID+"-delivery", func(t *testing.T) {
					if len(runs[scenario.MachineARN]) == 0 {
						t.Fatal("captured case has no replayed execution")
					}
					type record struct {
						ExecutionARN string `json:"execution_arn"`
						Type         string
						Details      struct{ Output string }
					}
					byExecution := map[string][]record{}
					pages := cloudwatchlogs.NewFilterLogEventsPaginator(logs, &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &scenario.GroupName})
					for pages.HasMorePages() {
						page, err := pages.NextPage(t.Context())
						if err != nil {
							t.Fatal(err)
						}
						for _, event := range page.Events {
							var entry record
							if json.Unmarshal([]byte(aws.ToString(event.Message)), &entry) == nil && entry.ExecutionARN != "" {
								byExecution[entry.ExecutionARN] = append(byExecution[entry.ExecutionARN], entry)
							}
						}
					}
					for _, run := range runs[scenario.MachineARN] {
						if strings.Contains(run.arn, ":execution:") {
							out, err := workflows.DescribeExecution(t.Context(), &sfn.DescribeExecutionInput{ExecutionArn: &run.arn})
							if err != nil {
								t.Fatal(err)
							}
							if out.Status != "SUCCEEDED" {
								t.Fatalf("logging changed execution status: %s", out.Status)
							}
							r.compare(t, ".Output", run.input, aws.ToString(out.Output))
						}
						if scenario.Scenario != "positive" {
							if len(byExecution[run.arn]) != 0 {
								t.Fatal("denied log-key authority admitted workflow payloads")
							}
							continue
						}
						completed := false
						for _, entry := range byExecution[run.arn] {
							if entry.Type == "ExecutionSucceeded" {
								r.compare(t, ".Output", run.input, entry.Details.Output)
								completed = true
							}
						}
						if !completed {
							t.Fatal("authorized delivery lost the completed workflow output")
						}
					}
				})
			}
			t.Log("local delivery is deterministic; native initial Express nondelivery, sampling windows and unisolated initialization effects remain recorded, not latency guarantees")
		})
	}
}

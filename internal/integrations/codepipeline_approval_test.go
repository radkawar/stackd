package integrations

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"stackd/clock"
	pipelineapi "stackd/internal/awsapi/codepipeline"
	snsapi "stackd/internal/awsapi/sns"
	"stackd/internal/awsctx"
	"stackd/internal/services/codepipeline"
	"stackd/internal/services/sns"
)

func TestCodePipelineApprovalNativeTopicErrors(t *testing.T) {
	var native struct {
		Account, Region string
		Targets         map[string]string `json:"topic_error_targets"`
		Calls           []struct {
			Label, Operation string
			Parameters       json.RawMessage
			Output           struct {
				TopicARN    string `json:"TopicArn"`
				StageStates []struct {
					ActionStates []struct {
						ActionName      string
						LatestExecution struct{ ErrorDetails *pipelineapi.ErrorDetails }
					}
				}
			}
		}
	}
	data, err := os.ReadFile("../../testdata/aws/codepipeline/approval_notification_native_topic_errors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &native); err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{}
	for _, call := range native.Calls {
		if call.Label != "topic-errors/settled/state" {
			continue
		}
		for _, stage := range call.Output.StageStates {
			for _, action := range stage.ActionStates {
				if detail := action.LatestExecution.ErrorDetails; detail != nil {
					expected[action.ActionName] = pipelineString(detail.Code)
				}
			}
		}
	}
	for _, name := range []string{"Fifo", "Absent"} {
		t.Run(name, func(t *testing.T) {
			if native.Targets[name] == "" || expected[name] == "" {
				t.Fatal("native target failure is missing")
			}
			source := clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))
			owner := sns.New(sns.Config{Clock: source, PublicEndpoint: "http://127.0.0.1:4566"})
			t.Cleanup(func() { _ = owner.Close() })
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: native.Account, Region: native.Region, PrincipalARN: "arn:aws:iam::" + native.Account + ":root"})
			created := false
			for _, call := range native.Calls {
				if call.Operation != "CreateTopic" || call.Output.TopicARN != native.Targets[name] {
					continue
				}
				var input snsapi.CreateTopicInput
				if err := json.Unmarshal(call.Parameters, &input); err != nil {
					t.Fatal(err)
				}
				if _, err := pipelineCommand(ctx, owner, "sns", "CreateTopic", &input); err != nil {
					t.Fatal(err)
				}
				created = true
			}
			if created != (name == "Fifo") {
				t.Fatal("native replay did not establish the expected topic existence")
			}
			effects := CodePipelineActions{SNS: owner}
			result, err := effects.notifyApproval(ctx, codepipeline.ActionRequest{
				Scope:        codepipeline.Scope{Partition: "aws", AccountID: native.Account, Region: native.Region},
				PipelineName: "release", StageName: "Review", ApprovalToken: "approval", ApprovalExpiresAt: source.Now().Add(time.Hour),
				Action: pipelineapi.ActionDeclaration{Name: new(pipelineapi.ActionName(name)), Configuration: pipelineapi.ActionConfigurationMap{"NotificationArn": pipelineapi.ActionConfigurationValue(native.Targets[name])}},
			})
			if err != nil || result.Status != "Failed" || result.ErrorCode != expected[name] || result.ApprovalNotificationID != "" {
				t.Fatalf("notification target %s: %+v, %v; native code %s", name, result, err, expected[name])
			}
		})
	}
}

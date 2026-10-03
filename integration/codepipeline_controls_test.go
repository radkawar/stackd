package stackd_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	cptypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
	"stackd/clock"
)

func (c cloudClients) codepipeline(region, key, secret string) *codepipeline.Client {
	return codepipeline.New(codepipeline.Options{Region: region, BaseEndpoint: new(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func TestCodePipelineSignedSourceApprovalRetryAndRestart(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			manual := clock.NewManual(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))
			clients, reopen := retainedCloud(t, backend, stackd.Config{AccountID: account, Clock: manual}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) {
				return startPublicCloud(t, config)
			})
			cp := clients.codepipeline("us-east-1", account, "test")
			objects := func() *s3.Client {
				return s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: new(clients.server.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			}
			root := clients.iam(account, "test", "")
			role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: new("pipeline"), AssumeRolePolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("pipeline"), PolicyName: new("artifacts"), PolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:*","kms:*"],"Resource":"*"}}`)}); err != nil {
				t.Fatal(err)
			}
			for _, bucket := range []string{"pipeline-sources", "pipeline-artifacts"} {
				if _, err = objects().CreateBucket(ctx, &s3.CreateBucketInput{Bucket: new(bucket)}); err != nil {
					t.Fatal(err)
				}
				if _, err = objects().PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: new(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
					t.Fatal(err)
				}
			}
			var payload bytes.Buffer
			archive := zip.NewWriter(&payload)
			member, err := archive.Create("config.json")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = member.Write([]byte(`{"value":17}`)); err != nil {
				t.Fatal(err)
			}
			if err = archive.Close(); err != nil {
				t.Fatal(err)
			}
			source, err := objects().PutObject(ctx, &s3.PutObjectInput{Bucket: new("pipeline-sources"), Key: new("source.zip"), Body: bytes.NewReader(payload.Bytes())})
			if err != nil {
				t.Fatal(err)
			}
			topics := admissionSNSClient(clients, account, "us-east-1")
			topic, err := topics.CreateTopic(ctx, &sns.CreateTopicInput{Name: new("approvals")})
			if err != nil {
				t.Fatal(err)
			}
			_, queueURL, queueARN := snsControlQueue(t, clients, account, "approvals", aws.ToString(topic.TopicArn))
			snsControlSubscribe(t, topics, aws.ToString(topic.TopicArn), queueARN)
			if _, err = root.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("pipeline"), PolicyName: new("notifications"), PolicyDocument: new(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sns:Publish","Resource":%q}}`, aws.ToString(topic.TopicArn)))}); err != nil {
				t.Fatal(err)
			}
			notificationAccount := account
			receiveApproval := func(expectedToken string) string {
				t.Helper()
				messages := snsAdmissionReceive(t, clients.server.Config.Handler.(*stackd.Stack), clients.sqs(notificationAccount, "test", ""), queueURL)
				if expectedToken == "" {
					if len(messages) != 0 {
						t.Fatalf("reopen republished approval notification: %+v", messages)
					}
					return ""
				}
				if len(messages) != 1 {
					t.Fatalf("expected one approval notification, received %+v", messages)
				}
				var envelope struct{ Message string }
				var notification struct {
					Region   string
					Approval struct{ PipelineName, StageName, ActionName, Token, CustomData, ExternalEntityLink string }
				}
				if err := json.Unmarshal([]byte(aws.ToString(messages[0].Body)), &envelope); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(envelope.Message), &notification); err != nil {
					t.Fatal(err)
				}
				if notification.Region != "us-east-1" || notification.Approval.PipelineName != "release" ||
					notification.Approval.StageName != "Approve" || notification.Approval.ActionName != "Review" ||
					notification.Approval.Token != expectedToken || notification.Approval.CustomData != "Source "+aws.ToString(source.VersionId) ||
					notification.Approval.ExternalEntityLink != "https://example.com/review" {
					t.Fatalf("approval notification lost action identity or resolved configuration: %+v", notification)
				}
				return notification.Approval.Token
			}
			definition := &cptypes.PipelineDeclaration{
				Name: new("release"), RoleArn: role.Role.Arn, PipelineType: cptypes.PipelineTypeV2, ExecutionMode: cptypes.ExecutionModeQueued, ArtifactStore: &cptypes.ArtifactStore{Type: cptypes.ArtifactStoreTypeS3, Location: new("pipeline-artifacts")},
				Stages: []cptypes.StageDeclaration{
					{Name: new("Source"), Actions: []cptypes.ActionDeclaration{{Name: new("S3"), Namespace: new("SourceVariables"), ActionTypeId: &cptypes.ActionTypeId{Category: cptypes.ActionCategorySource, Owner: cptypes.ActionOwnerAws, Provider: new("S3"), Version: new("1")}, RunOrder: new(int32(1)), Configuration: map[string]string{"S3Bucket": "pipeline-sources", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, OutputArtifacts: []cptypes.OutputArtifact{{Name: new("Configuration")}}}}},
					{Name: new("Approve"), Actions: []cptypes.ActionDeclaration{{Name: new("Review"), ActionTypeId: &cptypes.ActionTypeId{Category: cptypes.ActionCategoryApproval, Owner: cptypes.ActionOwnerAws, Provider: new("Manual"), Version: new("1")}, RunOrder: new(int32(1)), Configuration: map[string]string{"CustomData": "Source #{SourceVariables.VersionId}"}}}},
				},
			}
			definition.Stages[1].Actions[0].Configuration["NotificationArn"] = aws.ToString(topic.TopicArn)
			definition.Stages[1].Actions[0].Configuration["ExternalEntityLink"] = "https://example.com/review"
			created, err := cp.CreatePipeline(ctx, &codepipeline.CreatePipelineInput{Pipeline: definition, Tags: []cptypes.Tag{{Key: new("team"), Value: new("payments")}}})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToInt32(created.Pipeline.Version) != 1 {
				t.Fatalf("initial pipeline version %d", aws.ToInt32(created.Pipeline.Version))
			}
			drain := func() {
				t.Helper()
				if _, err := clients.server.Config.Handler.(*stackd.Stack).RunDueJobs(ctx, 100); err != nil {
					t.Fatal(err)
				}
			}
			gate := func() (*cptypes.ActionExecution, string) {
				t.Helper()
				var lastState *codepipeline.GetPipelineStateOutput
				for range 20 {
					drain()
					state, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: new("release")})
					if err != nil {
						t.Fatal(err)
					}
					lastState = state
					if len(state.StageStates) == 2 && len(state.StageStates[1].ActionStates) == 1 {
						a := state.StageStates[1].ActionStates[0].LatestExecution
						if a != nil && aws.ToString(a.Token) != "" {
							revision := state.StageStates[0].ActionStates[0].CurrentRevision
							if revision == nil || revision.Created != nil || revision.RevisionChangeId != nil {
								t.Fatalf("S3 current revision invented optional source metadata: %+v", revision)
							}
							return a, aws.ToString(state.StageStates[1].LatestExecution.PipelineExecutionId)
						}
					}
					if err := manual.Advance(time.Second); err != nil {
						t.Fatal(err)
					}
				}
				state, err := json.Marshal(lastState)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("pipeline did not reach manual approval: %s", state)
				return nil, ""
			}
			approval, executionID := gate()
			token := aws.ToString(approval.Token)
			token = receiveApproval(token)
			history, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("release"), PipelineExecutionId: new(executionID)})
			if err != nil {
				t.Fatal(err)
			}
			if len(history.PipelineExecution.ArtifactRevisions) != 1 || aws.ToString(history.PipelineExecution.ArtifactRevisions[0].RevisionId) != aws.ToString(source.VersionId) {
				t.Fatalf("source version lineage %+v", history.PipelineExecution)
			}
			if revision := history.PipelineExecution.ArtifactRevisions[0]; revision.Created != nil || revision.RevisionChangeIdentifier != nil {
				t.Fatalf("S3 revision emitted an invented date or change identifier: %+v", revision)
			}
			actions, err := cp.ListActionExecutions(ctx, &codepipeline.ListActionExecutionsInput{PipelineName: new("release"), Filter: &cptypes.ActionExecutionFilter{PipelineExecutionId: new(executionID)}})
			if err != nil {
				t.Fatal(err)
			}
			var location *cptypes.S3Location
			for _, a := range actions.ActionExecutionDetails {
				if aws.ToString(a.ActionName) == "S3" {
					if a.Output.OutputVariables["VersionId"] != aws.ToString(source.VersionId) || a.Output.OutputVariables["ObjectKey"] != "source.zip" {
						t.Fatalf("native source output variables %+v", a.Output.OutputVariables)
					}
					location = a.Output.OutputArtifacts[0].S3location
				}
				if aws.ToString(a.ActionName) == "Review" && a.Input.ResolvedConfiguration["CustomData"] != "Source "+aws.ToString(source.VersionId) {
					t.Fatalf("namespace was not resolved: %+v", a.Input)
				}
			}
			if location == nil {
				t.Fatal("source artifact missing")
			}
			object, err := objects().GetObject(ctx, &s3.GetObjectInput{Bucket: location.Bucket, Key: location.Key})
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, payload.Bytes()) || len(object.Metadata) != 0 {
				t.Fatalf("artifact bytes or native metadata changed: metadata=%v", object.Metadata)
			}
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			recovered, recoveredID := gate()
			if aws.ToString(recovered.Token) != token || recoveredID != executionID {
				t.Fatal("restart replaced live approval/action identity")
			}
			receiveApproval("")
			if _, err = cp.StopPipelineExecution(ctx, &codepipeline.StopPipelineExecutionInput{PipelineName: new("release"), PipelineExecutionId: new(executionID), Abandon: false, Reason: new("hold")}); err != nil {
				t.Fatal(err)
			}
			drain()
			stopping, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("release"), PipelineExecutionId: new(executionID)})
			if err != nil {
				t.Fatal(err)
			}
			if stopping.PipelineExecution.Status != cptypes.PipelineExecutionStatusStopping {
				t.Fatalf("stop-and-wait did not retain approval: %+v", stopping.PipelineExecution)
			}
			approve := func(token string) {
				t.Helper()
				if _, err := cp.PutApprovalResult(ctx, &codepipeline.PutApprovalResultInput{PipelineName: new("release"), StageName: new("Approve"), ActionName: new("Review"), Token: new(token), Result: &cptypes.ApprovalResult{Status: cptypes.ApprovalStatusApproved, Summary: new("approved")}}); err != nil {
					t.Fatal(err)
				}
				drain()
			}
			approve(token)
			if _, err = cp.RetryStageExecution(ctx, &codepipeline.RetryStageExecutionInput{PipelineName: new("release"), PipelineExecutionId: new(executionID), StageName: new("Approve"), RetryMode: cptypes.StageRetryModeAllActions}); err != nil {
				t.Fatal(err)
			}
			retry, _ := gate()
			if aws.ToString(retry.Token) == token {
				t.Fatal("stage retry reused approval action identity")
			}
			receiveApproval(aws.ToString(retry.Token))
			approve(aws.ToString(retry.Token))
			finished, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("release"), PipelineExecutionId: new(executionID)})
			if err != nil {
				t.Fatal(err)
			}
			if finished.PipelineExecution.Status != cptypes.PipelineExecutionStatusSucceeded {
				t.Fatalf("retried pipeline did not succeed: %+v", finished.PipelineExecution)
			}
			assertHistory := func() {
				t.Helper()
				all, err := cp.ListActionExecutions(ctx, &codepipeline.ListActionExecutionsInput{PipelineName: new("release"), Filter: &cptypes.ActionExecutionFilter{PipelineExecutionId: new(executionID)}})
				if err != nil {
					t.Fatal(err)
				}
				if len(all.ActionExecutionDetails) != 3 {
					t.Fatalf("source and two approval attempts not retained: %+v", all.ActionExecutionDetails)
				}
				var allIDs, latestIDs []string
				for _, action := range all.ActionExecutionDetails {
					id := aws.ToString(action.ActionExecutionId)
					allIDs = append(allIDs, id)
					if aws.ToString(action.ActionName) == "S3" || id == aws.ToString(retry.ActionExecutionId) {
						latestIDs = append(latestIDs, id)
					}
				}
				if len(latestIDs) != 2 {
					t.Fatalf("latest approval identity missing from retained history: %+v", all.ActionExecutionDetails)
				}
				for _, selection := range []struct {
					timeRange cptypes.StartTimeRange
					want      []string
				}{{cptypes.StartTimeRangeAll, allIDs}, {cptypes.StartTimeRangeLatest, latestIDs}} {
					input := &codepipeline.ListActionExecutionsInput{PipelineName: new("release"), MaxResults: new(int32(1)), Filter: &cptypes.ActionExecutionFilter{LatestInPipelineExecution: &cptypes.LatestInPipelineExecutionFilter{PipelineExecutionId: new(executionID), StartTimeRange: selection.timeRange}}}
					paginator := codepipeline.NewListActionExecutionsPaginator(cp, input)
					var ids []string
					for paginator.HasMorePages() {
						page, err := paginator.NextPage(ctx)
						if err != nil {
							t.Fatal(err)
						}
						for _, action := range page.ActionExecutionDetails {
							ids = append(ids, aws.ToString(action.ActionExecutionId))
						}
						if selection.timeRange == cptypes.StartTimeRangeLatest && page.NextToken != nil {
							changed := *input
							changed.NextToken = page.NextToken
							changed.Filter = &cptypes.ActionExecutionFilter{PipelineExecutionId: new(executionID)}
							_, err = cp.ListActionExecutions(ctx, &changed)
							assertAPIError(t, err, "InvalidNextTokenException")
						}
					}
					slices.Sort(ids)
					slices.Sort(selection.want)
					if !slices.Equal(ids, selection.want) {
						t.Fatalf("%s history selected %v, want %v", selection.timeRange, ids, selection.want)
					}
				}
			}
			assertHistory()
			clients = reopen()
			cp = clients.codepipeline("us-east-1", account, "test")
			assertHistory()
			if _, err = clients.iam(account, "test", "").PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("pipeline"), PolicyName: new("notifications"), PolicyDocument: new(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"sns:Publish","Resource":%q}}`, aws.ToString(topic.TopicArn)))}); err != nil {
				t.Fatal(err)
			}
			first, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("release"), ClientRequestToken: new("idempotent-start")})
			if err != nil {
				t.Fatal(err)
			}
			second, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("release"), ClientRequestToken: new("idempotent-start")})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(first.PipelineExecutionId) != aws.ToString(second.PipelineExecutionId) {
				t.Fatal("client token admitted a duplicate execution")
			}
			for attempt := 0; ; attempt++ {
				drain()
				failed, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("release"), PipelineExecutionId: first.PipelineExecutionId})
				if err != nil {
					t.Fatal(err)
				}
				if failed.PipelineExecution.Status == cptypes.PipelineExecutionStatusFailed {
					break
				}
				if attempt == 20 {
					t.Fatalf("current SNS denial did not fail the approval action: %+v", failed.PipelineExecution)
				}
				if err := manual.Advance(time.Second); err != nil {
					t.Fatal(err)
				}
			}
			failedState, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: new("release")})
			if err != nil {
				t.Fatal(err)
			}
			refused := failedState.StageStates[1].ActionStates[0].LatestExecution
			if refused == nil || refused.ErrorDetails == nil || aws.ToString(refused.ErrorDetails.Code) != "PermissionError" || refused.Token != nil {
				t.Fatalf("notification denial exposed an approval token or lost PermissionError: %+v", refused)
			}
			_, err = cp.PutApprovalResult(ctx, &codepipeline.PutApprovalResultInput{PipelineName: new("release"), StageName: new("Approve"), ActionName: new("Review"), Token: refused.ActionExecutionId, Result: &cptypes.ApprovalResult{Status: cptypes.ApprovalStatusApproved, Summary: new("cannot approve failed notification")}})
			assertAPIError(t, err, "ApprovalAlreadyCompletedException")
			receiveApproval("")
			if _, err = clients.iam(account, "test", "").PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: new("pipeline"), PolicyName: new("notifications"), PolicyDocument: new(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sns:Publish","Resource":%q}}`, aws.ToString(topic.TopicArn)))}); err != nil {
				t.Fatal(err)
			}
			receiveApproval("")
			if _, err = cp.RetryStageExecution(ctx, &codepipeline.RetryStageExecutionInput{PipelineName: new("release"), PipelineExecutionId: first.PipelineExecutionId, StageName: new("Approve"), RetryMode: cptypes.StageRetryModeFailedActions}); err != nil {
				t.Fatal(err)
			}
			notified, _ := gate()
			approve(receiveApproval(aws.ToString(notified.Token)))
			fifo, err := admissionSNSClient(clients, account, "us-east-1").CreateTopic(ctx, &sns.CreateTopicInput{
				Name: new("approval-errors.fifo"), Attributes: map[string]string{"FifoTopic": "true"},
			})
			if err != nil {
				t.Fatal(err)
			}
			missingTopic := "arn:aws:sns:us-east-1:" + account + ":approval-missing"
			const foreignAccount = "444455556666"
			foreignTopics := admissionSNSClient(clients, foreignAccount, "us-east-1")
			foreignTopic, err := foreignTopics.CreateTopic(ctx, &sns.CreateTopicInput{Name: new("cross-approvals")})
			if err != nil {
				t.Fatal(err)
			}
			foreignARN := aws.ToString(foreignTopic.TopicArn)
			foreignAttributes, err := foreignTopics.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: foreignTopic.TopicArn})
			if err != nil {
				t.Fatal(err)
			}
			missingForeign := "arn:aws:sns:us-east-1:" + foreignAccount + ":approval-missing"
			_, queueURL, queueARN = snsControlQueue(t, clients, foreignAccount, "cross-approvals", foreignARN)
			snsControlSubscribe(t, foreignTopics, foreignARN, queueARN)
			if _, err = foreignTopics.SetTopicAttributes(ctx, &sns.SetTopicAttributesInput{
				TopicArn: foreignTopic.TopicArn, AttributeName: new("Policy"),
				AttributeValue: new(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sns:Publish","Resource":%q}}`, aws.ToString(role.Role.Arn), foreignARN)),
			}); err != nil {
				t.Fatal(err)
			}
			if _, err = clients.iam(account, "test", "").PutRolePolicy(ctx, &iam.PutRolePolicyInput{
				RoleName: new("pipeline"), PolicyName: new("notifications"),
				PolicyDocument: new(fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sns:Publish","Resource":[%q,%q,%q,%q]}}`, aws.ToString(fifo.TopicArn), missingTopic, foreignARN, missingForeign)),
			}); err != nil {
				t.Fatal(err)
			}
			definition.Stages[1].Actions[0].Configuration["NotificationArn"] = foreignARN
			if _, err = cp.UpdatePipeline(ctx, &codepipeline.UpdatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			if _, err = cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("release")}); err != nil {
				t.Fatal(err)
			}
			notificationAccount = foreignAccount
			foreignApproval, _ := gate()
			approve(receiveApproval(aws.ToString(foreignApproval.Token)))
			if _, err = foreignTopics.SetTopicAttributes(ctx, &sns.SetTopicAttributesInput{
				TopicArn: foreignTopic.TopicArn, AttributeName: new("Policy"),
				AttributeValue: new(foreignAttributes.Attributes["Policy"]),
			}); err != nil {
				t.Fatal(err)
			}
			for _, failure := range []struct{ target, code string }{
				{aws.ToString(fifo.TopicArn), "ConfigurationError"}, {missingTopic, "ConfigurationError"},
				{foreignARN, "PermissionError"}, {missingForeign, "PermissionError"},
			} {
				definition.Stages[1].Actions[0].Configuration["NotificationArn"] = failure.target
				if _, err = cp.UpdatePipeline(ctx, &codepipeline.UpdatePipelineInput{Pipeline: definition}); err != nil {
					t.Fatal(err)
				}
				started, err := cp.StartPipelineExecution(ctx, &codepipeline.StartPipelineExecutionInput{Name: new("release")})
				if err != nil {
					t.Fatal(err)
				}
				for attempt := 0; ; attempt++ {
					drain()
					state, err := cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{
						PipelineName: new("release"), PipelineExecutionId: started.PipelineExecutionId,
					})
					if err != nil {
						t.Fatal(err)
					}
					if state.PipelineExecution.Status == cptypes.PipelineExecutionStatusFailed {
						break
					}
					if attempt == 20 {
						t.Fatalf("invalid notification target did not fail execution: %s", failure.target)
					}
					if err := manual.Advance(time.Second); err != nil {
						t.Fatal(err)
					}
				}
				state, err := cp.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: new("release")})
				if err != nil {
					t.Fatal(err)
				}
				action := state.StageStates[1].ActionStates[0].LatestExecution
				if action == nil || action.ErrorDetails == nil || aws.ToString(action.ErrorDetails.Code) != failure.code || action.Token != nil {
					t.Fatalf("invalid notification target %s: %+v", failure.target, action)
				}
				receiveApproval("")
			}
			if _, err = cp.DeletePipeline(ctx, &codepipeline.DeletePipelineInput{Name: new("release")}); err != nil {
				t.Fatal(err)
			}
			if _, err = cp.CreatePipeline(ctx, &codepipeline.CreatePipelineInput{Pipeline: definition}); err != nil {
				t.Fatal(err)
			}
			_, err = cp.GetPipelineExecution(ctx, &codepipeline.GetPipelineExecutionInput{PipelineName: new("release"), PipelineExecutionId: new(executionID)})
			assertAPIError(t, err, "PipelineExecutionNotFoundException")
		})
	}
}

func TestCodePipelineEmptyTagsDoNotInventRequestContext(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			const account = "111122223333"
			ctx := t.Context()
			clients, _ := retainedCloud(t, backend, stackd.Config{AccountID: account})
			root := clients.iam(account, "test", "")
			role, err := root.CreateRole(ctx, &iam.CreateRoleInput{
				RoleName:                 new("tagless-pipeline"),
				AssumeRolePolicyDocument: new(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.CreateUser(ctx, &iam.CreateUserInput{UserName: new("creator")}); err != nil {
				t.Fatal(err)
			}
			document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"codepipeline:CreatePipeline","Resource":"*","Condition":{"Null":{"aws:TagKeys":"true"}}},{"Effect":"Allow","Action":"iam:PassRole","Resource":%q}]}`, aws.ToString(role.Role.Arn))
			if _, err := root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: new("creator"), PolicyName: new("tagless-only"), PolicyDocument: &document}); err != nil {
				t.Fatal(err)
			}
			key, err := root.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: new("creator")})
			if err != nil {
				t.Fatal(err)
			}
			caller := clients.codepipeline("us-east-1", aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey))
			owner := clients.codepipeline("us-east-1", account, "test")
			for _, tc := range []struct {
				name string
				tags []cptypes.Tag
				deny bool
			}{
				{name: "omitted"},
				{name: "empty", tags: []cptypes.Tag{}},
				{name: "present", tags: []cptypes.Tag{{Key: new("team"), Value: new("payments")}}, deny: true},
			} {
				definition := &cptypes.PipelineDeclaration{
					Name: &tc.name, RoleArn: role.Role.Arn,
					ArtifactStore: &cptypes.ArtifactStore{Type: cptypes.ArtifactStoreTypeS3, Location: new("artifact-bucket")},
					Stages: []cptypes.StageDeclaration{
						{Name: new("Source"), Actions: []cptypes.ActionDeclaration{{Name: new("Source"), ActionTypeId: &cptypes.ActionTypeId{Category: cptypes.ActionCategorySource, Owner: cptypes.ActionOwnerAws, Provider: new("S3"), Version: new("1")}, Configuration: map[string]string{"S3Bucket": "source-bucket", "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"}, OutputArtifacts: []cptypes.OutputArtifact{{Name: new("SourceZip")}}}}},
						{Name: new("Approval"), Actions: []cptypes.ActionDeclaration{{Name: new("Approve"), ActionTypeId: &cptypes.ActionTypeId{Category: cptypes.ActionCategoryApproval, Owner: cptypes.ActionOwnerAws, Provider: new("Manual"), Version: new("1")}}}},
					},
				}
				_, err := caller.CreatePipeline(ctx, &codepipeline.CreatePipelineInput{Pipeline: definition, Tags: tc.tags})
				if tc.deny {
					var response *smithyhttp.ResponseError
					if !errors.As(err, &response) || response.HTTPStatusCode() != 403 {
						t.Fatalf("%s: expected current tag-policy denial, got %v", tc.name, err)
					}
					_, err := owner.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: &tc.name})
					assertAPIError(t, err, "PipelineNotFoundException")
				} else if err != nil {
					t.Fatalf("%s: absent tag keys were treated as present: %v", tc.name, err)
				} else {
					got, err := owner.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: &tc.name})
					if err != nil || aws.ToString(got.Pipeline.Name) != tc.name {
						t.Fatalf("%s: authorized pipeline was not retained: %v", tc.name, err)
					}
				}
			}
		})
	}
}

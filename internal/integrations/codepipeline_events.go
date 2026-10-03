package integrations

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/clock"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/codepipeline"
	"stackd/internal/awsctx"
	"stackd/internal/services/codepipeline"
	"stackd/internal/services/eventbridge"
)

// CodePipelineEvents joins native lifecycle notifications to state commits.
type CodePipelineEvents struct {
	Publisher EventBridgeEventPublisher
	Clock     clock.Clock
}

type pipelineEventDetail struct {
	Pipeline    string      `json:"pipeline"`
	ExecutionID string      `json:"execution-id"`
	StartTime   string      `json:"start-time"`
	State       string      `json:"state"`
	Version     json.Number `json:"version"`
	Attempt     json.Number `json:"pipeline-execution-attempt"`
}
type pipelineEventTrigger struct {
	Type   string `json:"trigger-type"`
	Detail string `json:"trigger-detail,omitempty"`
}
type pipelineStateDetail struct {
	pipelineEventDetail
	Trigger       *pipelineEventTrigger `json:"execution-trigger,omitempty"`
	StopComments  string                `json:"stop-execution-comments,omitempty"`
	LastRetryTime string                `json:"last-retry-attempt-time,omitempty"`
}
type pipelineStageDetail struct {
	pipelineEventDetail
	Stage         string `json:"stage"`
	LastRetryTime string `json:"stage-last-retry-attempt-time,omitempty"`
}
type pipelineActionResult struct {
	ID        string `json:"external-execution-id,omitempty"`
	URL       string `json:"external-execution-url,omitempty"`
	Summary   string `json:"external-execution-summary,omitempty"`
	ErrorCode string `json:"error-code,omitempty"`
}
type pipelineActionDetail struct {
	pipelineEventDetail
	Stage           string                 `json:"stage"`
	Action          string                 `json:"action"`
	ActionID        string                 `json:"action-execution-id"`
	Region          string                 `json:"region"`
	Type            *api.ActionTypeId      `json:"type"`
	InputArtifacts  api.ArtifactDetailList `json:"input-artifacts,omitempty"`
	OutputArtifacts api.ArtifactDetailList `json:"output-artifacts,omitempty"`
	Result          *pipelineActionResult  `json:"execution-result,omitempty"`
}

func pipelineEventBase(p codepipeline.Pipeline, e codepipeline.Execution, state string) pipelineEventDetail {
	return pipelineEventDetail{Pipeline: p.Name, ExecutionID: e.ID, StartTime: pipelineEventTime(e.StartedAt), State: state, Version: pipelineEventNumber(e.Version), Attempt: pipelineEventNumber(e.Attempt)}
}

// EventBridge literal number patterns distinguish 1 from the native 1.0.
func pipelineEventNumber(value int32) json.Number {
	return json.Number(strconv.FormatInt(int64(value), 10) + ".0")
}

func pipelineEventTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000Z")
}

func (a CodePipelineEvents) PipelineStateChanged(ctx context.Context, p codepipeline.Pipeline, e codepipeline.Execution) error {
	state := strings.ToUpper(e.Status)
	if e.Status == "InProgress" {
		state = "STARTED"
		if e.Attempt > 1 {
			state = "RESUMED"
		}
	} else if e.Status == "Cancelled" {
		state = "CANCELED"
	}
	detail := pipelineStateDetail{pipelineEventDetail: pipelineEventBase(p, e, state)}
	if !e.LastRetryAt.IsZero() {
		detail.LastRetryTime = pipelineEventTime(e.LastRetryAt)
	}
	if state == "STARTED" {
		detail.Trigger = &pipelineEventTrigger{Type: e.TriggerType, Detail: e.TriggerDetail}
	}
	if state == "STOPPING" {
		detail.StopComments = e.StopReason
	}
	return a.publish(ctx, p, e, "CodePipeline Pipeline Execution State Change", detail)
}
func (a CodePipelineEvents) StageStateChanged(ctx context.Context, p codepipeline.Pipeline, e codepipeline.Execution, stage, state string) error {
	detail := pipelineStageDetail{pipelineEventDetail: pipelineEventBase(p, e, state), Stage: stage}
	detail.StartTime = pipelineEventTime(e.StageStartedAt)
	// Native stage events use zero before any pipeline retry, then the global attempt.
	if e.Attempt == 1 {
		detail.Attempt = pipelineEventNumber(0)
	}
	if !e.StageLastRetryAt.IsZero() {
		detail.LastRetryTime = pipelineEventTime(e.StageLastRetryAt)
	}
	return a.publish(ctx, p, e, "CodePipeline Stage Execution State Change", detail)
}
func (a CodePipelineEvents) ActionStateChanged(ctx context.Context, p codepipeline.Pipeline, e codepipeline.Execution, action codepipeline.ActionExecution, declaration api.ActionDeclaration) error {
	state := strings.ToUpper(action.Status)
	if action.Status == "InProgress" {
		state = "STARTED"
	}
	detail := pipelineActionDetail{pipelineEventDetail: pipelineEventBase(p, e, state), Stage: action.StageName, Action: action.ActionName, ActionID: action.ID, Region: p.Region, Type: declaration.ActionTypeId, InputArtifacts: codepipeline.ArtifactDetails(action.InputArtifacts)}
	detail.StartTime = pipelineEventTime(action.StartedAt)
	if state == "SUCCEEDED" {
		detail.OutputArtifacts = codepipeline.ArtifactDetails(action.OutputArtifacts)
	}
	if action.ExternalExecutionID != "" || action.ErrorCode != "" || action.Summary != "" {
		summary := action.Summary
		if summary == "" {
			summary = action.ErrorMessage
		}
		detail.Result = &pipelineActionResult{ID: action.ExternalExecutionID, URL: action.ExternalExecutionURL, Summary: summary, ErrorCode: action.ErrorCode}
		if state == "FAILED" && declaration.ActionTypeId != nil && pipelineString(declaration.ActionTypeId.Provider) == "Manual" {
			detail.Result.ErrorCode = "JobFailed"
		}
	}
	return a.publish(ctx, p, e, "CodePipeline Action Execution State Change", detail)
}
func (a CodePipelineEvents) publish(ctx context.Context, p codepipeline.Pipeline, e codepipeline.Execution, kind string, detail any) error {
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	origin := awsctx.FromContext(ctx)
	parent := apievents.EventID(ctx)
	if parent == "" {
		parent = e.ParentEventID
	}
	resource := codepipeline.ARN(p.Scope, p.Name)
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, RequestID: origin.RequestID, ParentEventID: parent, ServicePrincipal: awsctx.ServicePrincipal{Name: "codepipeline.amazonaws.com", SourceARN: resource, Type: "AWSService"}})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{ID: uuid.NewString(), Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: p.Partition, Account: p.AccountID, Region: p.Region}, Name: "default"}, Source: "aws.codepipeline", DetailType: kind, Detail: string(body), Resources: []string{resource}, Time: a.Clock.Now().UTC(), Account: p.AccountID, RequestID: origin.RequestID})
}

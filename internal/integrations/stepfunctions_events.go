package integrations

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/internal/services/eventbridge"
	"stackd/internal/services/stepfunctions"
)

// StepFunctionsEvents admits source-owned Standard status changes into the
// default bus. PublishEvent is an in-process transactional admission, never an
// external PutEvents request. Express workflows have no native status events.
// Native envelopes: testdata/aws/stepfunctions/observability.json; size contract:
// https://docs.aws.amazon.com/step-functions/latest/dg/eventbridge-integration.html.
type StepFunctionsEvents struct {
	Publisher EventBridgeEventPublisher
}

var _ stepfunctions.ExecutionEventPublisher = StepFunctionsEvents{}

type stepFunctionsEventDataDetails struct {
	Included bool `json:"included"`
}

type stepFunctionsStatusDetail struct {
	ExecutionARN           string                         `json:"executionArn"`
	StateMachineARN        string                         `json:"stateMachineArn"`
	Name                   string                         `json:"name"`
	Status                 string                         `json:"status"`
	StartDate              int64                          `json:"startDate"`
	StopDate               *int64                         `json:"stopDate"`
	Input                  *string                        `json:"input"`
	InputDetails           *stepFunctionsEventDataDetails `json:"inputDetails"`
	Output                 *string                        `json:"output"`
	OutputDetails          *stepFunctionsEventDataDetails `json:"outputDetails"`
	StateMachineVersionARN *string                        `json:"stateMachineVersionArn"`
	StateMachineAliasARN   *string                        `json:"stateMachineAliasArn"`
	RedriveCount           int64                          `json:"redriveCount"`
	RedriveDate            *int64                         `json:"redriveDate"`
	RedriveStatus          string                         `json:"redriveStatus"`
	RedriveStatusReason    *string                        `json:"redriveStatusReason"`
	Error                  *string                        `json:"error"`
	Cause                  *string                        `json:"cause"`
}

func (a StepFunctionsEvents) PublishExecutionState(ctx context.Context, execution stepfunctions.ExecutionRecord) error {
	if execution.Type != "STANDARD" || a.Publisher == nil {
		return nil
	}
	detail := stepFunctionsStatusDetail{
		ExecutionARN: execution.Key.ARN, StateMachineARN: execution.Machine.ARN(),
		Name: execution.Name, Status: execution.Status, StartDate: execution.Started.UnixMilli(),
		Input: new(execution.Input), InputDetails: &stepFunctionsEventDataDetails{Included: true},
		RedriveStatus: "NOT_REDRIVABLE",
	}
	if execution.Encrypted != nil && execution.Input == "" {
		detail.Input, detail.InputDetails.Included = nil, false
	}
	at := execution.Started
	if execution.Stopped != nil {
		at = *execution.Stopped
		detail.StopDate = new(at.UnixMilli())
	}
	switch execution.Status {
	case "RUNNING", "SUCCEEDED":
		detail.RedriveStatusReason = new("Execution is " + execution.Status + " and cannot be redriven")
	case "FAILED", "ABORTED", "TIMED_OUT":
		detail.RedriveStatus = "REDRIVABLE"
	default:
		return nil
	}
	if execution.Status == "SUCCEEDED" {
		detail.Output = new(execution.Output)
		detail.OutputDetails = &stepFunctionsEventDataDetails{Included: true}
		if execution.Encrypted != nil && execution.Output == "" {
			detail.Output, detail.OutputDetails.Included = nil, false
		}
	}
	if execution.Status == "FAILED" || execution.Status == "ABORTED" {
		if execution.Error != "" {
			detail.Error = new(execution.Error)
		}
		if execution.Cause != "" {
			detail.Cause = new(execution.Cause)
		}
	}
	if execution.VersionARN != "" {
		detail.StateMachineVersionARN = new(execution.VersionARN)
	}
	if execution.AliasARN != "" {
		detail.StateMachineAliasARN = new(execution.AliasARN)
	}
	// Compare escaped input+output before excluding either. An oversized output
	// excludes both fields, not just the output; null is distinct from JSON "null".
	const maxExecutionData = 248 * 1024
	inputBytes := stepFunctionsEscapedSize(execution.Input)
	outputBytes := 0
	if detail.Output != nil {
		outputBytes = stepFunctionsEscapedSize(*detail.Output)
	}
	if inputBytes+outputBytes > maxExecutionData {
		detail.Input, detail.InputDetails.Included = nil, false
	}
	if outputBytes > maxExecutionData {
		detail.Output, detail.OutputDetails.Included = nil, false
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	origin := awsctx.FromContext(ctx)
	parent := apievents.EventID(ctx)
	if parent == "" {
		parent = origin.ParentEventID
	}
	if parent == "" {
		parent = execution.ParentEventID
	}
	scope := execution.Key.Scope
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
		RequestID: origin.RequestID, ParentEventID: parent,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "states.amazonaws.com", SourceARN: execution.Machine.ARN(), Type: "AWSService"},
	})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID:     uuid.NewString(),
		Bus:    eventbridge.BusKey{Scope: eventbridge.Scope{Partition: scope.Partition, Account: scope.AccountID, Region: scope.Region}, Name: "default"},
		Source: "aws.states", DetailType: "Step Functions Execution Status Change", Detail: string(encoded),
		Resources: []string{execution.Key.ARN}, Time: at, Account: scope.AccountID, Region: scope.Region, RequestID: origin.RequestID,
	})
}

// Count JSON string content, without allocating a second copy of the payload.
// This agrees with encoding/json's escaping used by the emitted detail.
func stepFunctionsEscapedSize(value string) int {
	size := len(value)
	for _, r := range value {
		switch {
		case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
			size++
		case r < 0x20 || r == '<' || r == '>' || r == '&':
			size += 5
		case r == '\u2028' || r == '\u2029':
			size += 3
		}
	}
	return size
}

package integrations

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/services/athena"
	"stackd/internal/services/eventbridge"
)

// AthenaEvents admits documented query-state events through EventBridge in the
// caller's shared transaction. Delivery remains the EventBridge owner's effect.
type AthenaEvents struct {
	Publisher EventBridgeEventPublisher
	Clock     clock.Clock
}

var _ athena.QueryEvents = AthenaEvents{}

func (a AthenaEvents) Publish(ctx context.Context, event athena.QueryEvent) error {
	query := event.Query
	if a.Publisher == nil || query.Data.Status == nil || query.Data.Status.State == nil {
		return nil
	}
	var statement, workgroup string
	if query.Data.StatementType != nil {
		statement = string(*query.Data.StatementType)
	}
	if query.Data.WorkGroup != nil {
		workgroup = string(*query.Data.WorkGroup)
	}
	detail := struct {
		VersionID        string `json:"versionId"`
		CurrentState     string `json:"currentState"`
		PreviousState    string `json:"previousState,omitempty"`
		StatementType    string `json:"statementType"`
		QueryExecutionID string `json:"queryExecutionId"`
		WorkgroupName    string `json:"workgroupName"`
		SequenceNumber   string `json:"sequenceNumber"`
		AthenaError      *struct {
			ErrorCategory int32  `json:"errorCategory"`
			ErrorType     int32  `json:"errorType"`
			ErrorMessage  string `json:"errorMessage"`
			Retryable     bool   `json:"retryable"`
		} `json:"athenaError,omitempty"`
	}{VersionID: "0", CurrentState: string(*query.Data.Status.State), PreviousState: event.PreviousState, StatementType: statement, QueryExecutionID: query.Key.Name, WorkgroupName: workgroup, SequenceNumber: strconv.FormatInt(query.Version, 10)}
	if nativeError := query.Data.Status.AthenaError; detail.CurrentState == "FAILED" && nativeError != nil {
		detail.AthenaError = &struct {
			ErrorCategory int32  `json:"errorCategory"`
			ErrorType     int32  `json:"errorType"`
			ErrorMessage  string `json:"errorMessage"`
			Retryable     bool   `json:"retryable"`
		}{}
		if nativeError.ErrorCategory != nil {
			detail.AthenaError.ErrorCategory = int32(*nativeError.ErrorCategory)
		}
		if nativeError.ErrorType != nil {
			detail.AthenaError.ErrorType = int32(*nativeError.ErrorType)
		}
		if nativeError.ErrorMessage != nil {
			detail.AthenaError.ErrorMessage = string(*nativeError.ErrorMessage)
		}
		if nativeError.Retryable != nil {
			detail.AthenaError.Retryable = bool(*nativeError.Retryable)
		}
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	origin := awsctx.FromContext(ctx)
	metadata := awsctx.Metadata{Partition: query.Key.Partition, AccountID: query.Key.AccountID, Region: query.Key.Region, RequestID: origin.RequestID, ParentEventID: origin.ParentEventID, ServicePrincipal: awsctx.ServicePrincipal{Name: "athena.amazonaws.com", Type: "AWSService"}}
	return a.Publisher.PublishEvent(awsctx.WithMetadata(ctx, metadata), eventbridge.EventRecord{ID: uuid.NewString(), Bus: eventbridge.BusKey{Scope: eventbridge.Scope{Partition: query.Key.Partition, Account: query.Key.AccountID, Region: query.Key.Region}, Name: "default"}, Source: "aws.athena", DetailType: "Athena Query State Change", Detail: string(body), Resources: []string{}, Time: a.Clock.Now(), Account: query.Key.AccountID, RequestID: origin.RequestID})
}

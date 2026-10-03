package lambda

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Source batch identity commits with native Invoke before customer code runs.
func (s *Service) recordSourceBatchInvocation(ctx context.Context, mapping EventSourceMappingRecord, function FunctionRecord, recordIDs []string, wire *awswire.Error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		now := s.clock.Now()
		envelope := journal.Envelope{At: now, Partition: mapping.Key.Partition, AccountID: mapping.Key.Account, Region: mapping.Key.Region}
		if s.apiEvents != nil {
			call, err := projectLambdaCall(tx.Context(), "Invoke", &api.InvokeInput{
				FunctionName:   new(api.NamespacedFunctionName(mapping.Function.ARN())),
				InvocationType: new(api.InvocationType("RequestResponse")), LogType: new(api.LogType("None")),
			}, nil, wire)
			if err != nil {
				return err
			}
			parameters := struct {
				FunctionName   string `json:"functionName"`
				InvocationType string `json:"invocationType"`
				SourceARN      string `json:"sourceArn"`
				LogType        string `json:"logType"`
				ContentType    string `json:"contentType"`
				SourceAccount  string `json:"sourceAccount"`
			}{mapping.Function.ARN(), "RequestResponse", mapping.Key.ARN(), "None", "application/json", mapping.Key.Account}
			call.RequestParameters, err = json.Marshal(parameters)
			if err != nil {
				return err
			}
			call.EventResources = invocationResources(mapping.Function.FunctionKey)
			call.SharedEventID = uuid.NewString()
			if function.Key.Name != "" {
				call.AdditionalEventData, err = json.Marshal(struct {
					CustomerENIID   string `json:"customerEniId"`
					FunctionVersion string `json:"functionVersion"`
				}{FunctionVersion: function.Key.ARN() + ":" + versionName(function.Version)})
				if err != nil {
					return err
				}
			}
			if err := s.apiEvents.Record(tx.Context(), envelope, call); err != nil {
				return err
			}
		}
		if wire != nil {
			if wire.Code == "TooManyRequestsException" {
				return s.stageThrottleMetrics(tx, mapping.Function, now)
			}
			return nil
		}
		if s.events != nil {
			return s.events.AppendLambdaSourceBatchAccepted(tx.Context(), apievents.WithOrigin(tx.Context(), envelope), journal.LambdaSourceBatchAccepted{
				InvocationEventID: apievents.EventID(ctx), MappingARN: mapping.Key.ARN(), SourceARN: mapping.EventSourceARN, RecordIDs: recordIDs,
			})
		}
		return nil
	})
}

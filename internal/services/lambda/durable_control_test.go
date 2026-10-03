package lambda

import (
	"testing"
	"time"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
)

// Native durable_audit_final_workflow.json distinguishes these two APIs:
// GetDurableExecution includes data by default, but History omits it and marks
// payload wrappers truncated unless IncludeExecutionData is explicitly true.
func TestDurableHistoryDataRequiresExplicitInclusion(t *testing.T) {
	scope := Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: scope.Account})
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	key := FunctionVersionKey{FunctionKey: FunctionKey{Scope: scope, Name: "history-data"}, Version: 1}
	at := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	record := DurableExecutionRecord{
		ARN: key.ARN() + "/durable-execution/order/id", Name: "order", ID: "id", Function: key,
		Status: "FAILED", StartedAt: at, EndedAt: at.Add(time.Minute), ExecutionTimeout: 3600,
		Input: new(`{"order":42}`), Error: &api.ErrorObject{ErrorMessage: new(api.ErrorMessage("private failure"))},
		History: []DurableEventRecord{
			{ID: 1, At: at, Type: "ExecutionStarted", Operation: DurableOperationRecord{ID: "id", Type: "EXECUTION", Payload: new(`{"order":42}`)}},
			{ID: 2, At: at.Add(time.Second), Type: "StepSucceeded", Operation: DurableOperationRecord{ID: "step", Type: "STEP", Payload: new(`"private result"`), Attempt: 1}},
			{ID: 3, At: at.Add(time.Minute), Type: "ExecutionFailed", Operation: DurableOperationRecord{ID: "id", Type: "EXECUTION", Error: &api.ErrorObject{ErrorMessage: new(api.ErrorMessage("private failure"))}}},
		},
	}
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFunction(FunctionRecord{Key: key.FunctionKey}); err != nil {
			return err
		}
		return tx.PutDurableExecution(record)
	}); err != nil {
		t.Fatal(err)
	}
	get, rejected := service.getDurableExecution(ctx, &api.GetDurableExecutionInput{DurableExecutionArn: new(api.DurableExecutionArn(record.ARN))})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if get.InputPayload == nil || string(*get.InputPayload) != *record.Input || get.ExecutionDataIncluded == nil || !bool(*get.ExecutionDataIncluded) {
		t.Fatal("GetDurableExecution lost its independent include-data default")
	}
	for _, include := range []*api.IncludeExecutionData{nil, new(api.IncludeExecutionData(false)), new(api.IncludeExecutionData(true))} {
		out, rejected := service.getDurableExecutionHistory(ctx, &api.GetDurableExecutionHistoryInput{DurableExecutionArn: new(api.DurableExecutionArn(record.ARN)), IncludeExecutionData: include})
		if rejected != nil {
			t.Fatal(rejected)
		}
		if len(out.Events) != 3 {
			t.Fatalf("history events lost: %+v", out.Events)
		}
		input := out.Events[0].ExecutionStartedDetails.Input
		result := out.Events[1].StepSucceededDetails.Result
		failure := out.Events[2].ExecutionFailedDetails.Error
		data := include != nil && bool(*include)
		if input.Truncated == nil || result.Truncated == nil || failure.Truncated == nil || bool(*input.Truncated) == data || bool(*result.Truncated) == data || bool(*failure.Truncated) == data {
			t.Fatalf("history payload visibility has incorrect truncation markers for include=%v", include)
		}
		if data {
			if input.Payload == nil || string(*input.Payload) != *record.Input || result.Payload == nil || string(*result.Payload) != `"private result"` || failure.Payload == nil || failure.Payload.ErrorMessage == nil || string(*failure.Payload.ErrorMessage) != "private failure" {
				t.Fatal("explicit data inclusion lost execution payloads")
			}
		} else if input.Payload != nil || result.Payload != nil || failure.Payload != nil {
			t.Fatal("metadata-only history exposed execution payloads")
		}
	}
}

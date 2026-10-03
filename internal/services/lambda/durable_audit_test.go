package lambda

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/journal"
	"stackd/storage/memory"
)

func TestDurableTransitionsCommitProtectedDataEvents(t *testing.T) {
	domain := memory.NewDomain()
	repository := NewMemoryRepository(domain)
	events := journal.NewMemory(domain)
	at := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	service := New(Config{Repository: repository, APIEvents: apievents.New(events), Clock: clock.NewManual(at)})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: scope.Account})
	key := FunctionVersionKey{FunctionKey: FunctionKey{Scope: scope, Name: "audited"}, Version: 1}
	v := DurableExecutionRecord{ARN: key.ARN() + "/durable-execution/order/id", Name: "order", ID: "id", Function: key, Status: "RUNNING", StartedAt: at, Operations: []DurableOperationRecord{{ID: "callback", Type: "CALLBACK", Status: "STARTED", CallbackID: "private-callback-token"}}}
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFunction(FunctionRecord{Key: key.FunctionKey}); err != nil {
			return err
		}
		return tx.PutDurableExecution(v)
	}); err != nil {
		t.Fatal(err)
	}
	stop := &api.StopDurableExecutionInput{DurableExecutionArn: new(api.DurableExecutionArn(v.ARN)), Error: &api.ErrorObject{ErrorMessage: new(api.ErrorMessage("private stop reason"))}}
	abort := errors.New("abort stopping execution")
	if err := repository.Update(ctx, func(tx Transaction) error {
		if _, rejected := service.stopDurableExecution(tx.Context(), stop); rejected != nil {
			return rejected
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatalf("stop rollback: %v", err)
	}
	if committed, err := events.Read(ctx, 0, 10); err != nil || len(committed) != 0 {
		t.Fatalf("rolled-back stop published an event: %+v %v", committed, err)
	}
	if err := repository.View(ctx, func(r Reader) error {
		current, err := r.DurableExecution(v.ARN)
		if err == nil && current.Status != "RUNNING" {
			t.Fatal("rolled-back stop changed execution state")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, rejected := service.durableCallbackFailure(ctx, &api.SendDurableExecutionCallbackFailureInput{CallbackId: new(api.CallbackId("private-callback-token")), Error: &api.ErrorObject{ErrorMessage: new(api.ErrorMessage("private rejection"))}}); rejected != nil {
		t.Fatal(rejected)
	}
	if _, rejected := service.stopDurableExecution(ctx, stop); rejected != nil {
		t.Fatal(rejected)
	}
	committed, err := events.Read(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(committed) != 2 {
		t.Fatalf("accepted callback/stop transitions did not publish exactly their events: %+v", committed)
	}
	for i, name := range []string{"SendDurableExecutionCallbackFailure", "StopDurableExecution"} {
		call := committed[i].APICallCompleted
		if call == nil || call.EventName != name || call.Category != journal.CategoryData || call.ReadOnly {
			t.Fatalf("native durable event classification differs: %+v", call)
		}
		if len(call.EventResources) != 1 || call.EventResources[0].Type != "AWS::Lambda::Function" || call.EventResources[0].ARN != key.FunctionKey.ARN() || call.EventResources[0].AccountID != scope.Account {
			t.Fatalf("durable data event has wrong selector resource: %+v", call.EventResources)
		}
		var request, additional map[string]any
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			t.Fatal(err)
		}
		if request["error"] != "HIDDEN_DUE_TO_SECURITY_REASONS" {
			t.Fatalf("durable error payload was not protected: %s", call.RequestParameters)
		}
		if err := json.Unmarshal(call.AdditionalEventData, &additional); err != nil {
			t.Fatal(err)
		}
		if additional["functionVersion"] != key.ARN() {
			t.Fatalf("durable event lost admitted function version: %s", call.AdditionalEventData)
		}
		if name == "StopDurableExecution" {
			var response map[string]float64
			if err := json.Unmarshal(call.ResponseElements, &response); err != nil {
				t.Fatal(err)
			}
			if response["stopTimestamp"] != float64(at.Unix()) {
				t.Fatalf("stop outcome lost its committed timestamp: %s", call.ResponseElements)
			}
		}
	}
}

package athena

import (
	"context"
	"strings"
	"testing"

	api "stackd/internal/awsapi/athena"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/storage/memory"
)

type ctasAdmissionBoundary struct{}

func (ctasAdmissionBoundary) Execute(context.Context, ExecutionRequest, func(string) error) (ExecutionResult, error) {
	panic("admission test must not execute SQL")
}
func (ctasAdmissionBoundary) Cancel(context.Context, string) error {
	panic("admission test must not cancel SQL")
}
func (ctasAdmissionBoundary) Write(context.Context, QueryRecord, []byte) *awswire.Error {
	panic("admission test must not write results")
}
func (ctasAdmissionBoundary) Read(context.Context, QueryRecord) ([]byte, *awswire.Error) {
	panic("admission test must not read results")
}

func TestCTASDestinationEnforcementSnapshotsWorkgroupAdmission(t *testing.T) {
	repo := NewMemoryRepository(memory.NewDomain())
	service := New(Config{Repository: repo, Engine: ctasAdmissionBoundary{}, Results: ctasAdmissionBoundary{}})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := Scope{"aws", "123456789012", "us-east-1"}
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: scope.AccountID})
	group := WorkGroupRecord{Key: ResourceKey{Scope: scope, Name: "enforcing"}, Data: api.WorkGroup{Name: new(api.WorkGroupName("enforcing")), State: new(api.WorkGroupState("ENABLED")), Configuration: &api.WorkGroupConfiguration{EnforceWorkGroupConfiguration: new(api.BoxedBoolean(true)), ResultConfiguration: &api.ResultConfiguration{OutputLocation: new(api.ResultOutputLocation("s3://fixture-data/enforced/"))}}}}
	var key ResourceKey
	if err := repo.Update(ctx, func(tx Transaction) error {
		if err := tx.PutWorkGroup(group); err != nil {
			return err
		}
		result, err := service.startQueryExecution(ctx, tx, &api.StartQueryExecutionInput{ClientRequestToken: new(api.IdempotencyToken(strings.Repeat("a", 32))), WorkGroup: group.Data.Name, QueryString: new(api.QueryString("CREATE TABLE result AS SELECT 1 id")), ResultConfiguration: &api.ResultConfiguration{OutputLocation: new(api.ResultOutputLocation("s3://fixture-data/ignored/"))}})
		if err != nil {
			return err
		}
		key = ResourceKey{Scope: scope, Name: string(*result.QueryExecutionId)}
		group.Data.Configuration.EnforceWorkGroupConfiguration = new(api.BoxedBoolean(false))
		group.Data.Configuration.ResultConfiguration.OutputLocation = new(api.ResultOutputLocation("s3://fixture-data/changed/"))
		return tx.PutWorkGroup(group)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(ctx, func(reader Reader) error {
		query, err := reader.Query(key)
		if err != nil {
			return err
		}
		if !query.EnforceCTASDestination {
			t.Fatal("workgroup update changed admitted CTAS enforcement")
		}
		if got := value(query.Data.ResultConfiguration.OutputLocation); got != "s3://fixture-data/enforced/"+key.Name+".csv" {
			t.Fatalf("admitted output changed: %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

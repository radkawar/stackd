package lambda

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"stackd/iam/policy"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
	"stackd/storage/memory"
)

func aliasOwnerFixture(t *testing.T, repository Repository) (context.Context, FunctionReference) {
	t.Helper()
	scope := Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: scope.Account})
	ref := FunctionReference{FunctionKey: FunctionKey{Scope: scope, Name: "owned-function"}, Qualifier: "live"}
	if err := repository.Update(ctx, func(tx Transaction) error {
		function := FunctionRecord{Key: ref.FunctionKey, Role: "arn:aws:iam::111111111111:role/execution", State: "Active"}
		if err := tx.PutFunction(function); err != nil {
			return err
		}
		for _, version := range []uint64{1, 2} {
			function.Version = version
			if err := tx.PutFunctionVersion(function); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ctx, ref
}

func aliasOwnerService(t *testing.T, config Config) *Service {
	t.Helper()
	s := New(config)
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func aliasOwnerCommand(t *testing.T, s *Service, ctx context.Context, name string, input any) (any, *awswire.Error) {
	t.Helper()
	model, _ := awscatalog.LookupService("lambda")
	op, ok := model.Operation(name)
	if !ok {
		t.Fatalf("unknown Lambda operation %q", name)
	}
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
}

func aliasOwnerCreate(ref FunctionReference) *api.CreateAliasInput {
	return &api.CreateAliasInput{FunctionName: new(api.FunctionName(ref.Name)), Name: new(api.Alias(ref.Qualifier)), FunctionVersion: new(api.VersionWithLatestPublished("1")), Description: new(api.Description("initial")), RoutingConfig: &api.AliasRoutingConfiguration{AdditionalVersionWeights: api.AdditionalVersionWeights{"2": 0.1}}}
}

func aliasOwnerRecord(t *testing.T, repository Repository, ctx context.Context, ref FunctionReference) AliasRecord {
	t.Helper()
	var got AliasRecord
	if err := repository.View(ctx, func(r Reader) error {
		var err error
		got, err = r.Alias(ref)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func requireAliasOwnerCode(t *testing.T, wire *awswire.Error, code string) {
	t.Helper()
	if wire == nil || wire.Code != code {
		t.Fatalf("error = %v; want %s", wire, code)
	}
}

func TestAliasOwnerRecoveryPreservesRevisionRoutingAndNativeRetarget(t *testing.T) {
	repository := NewMemoryRepository(nil)
	ctx, ref := aliasOwnerFixture(t, repository)
	owner := AliasOwner{StackID: "stack-a", LogicalID: "Alias", Token: "create-a"}
	owned := WithAliasOwner(ctx, owner)
	s := aliasOwnerService(t, Config{Repository: repository})
	create := aliasOwnerCreate(ref)
	if _, wire := aliasOwnerCommand(t, s, owned, "CreateAlias", create); wire != nil {
		t.Fatal(wire)
	}
	initial := aliasOwnerRecord(t, repository, ctx, ref)
	if initial.Owner != owner || initial.FunctionVersion != 1 || initial.AdditionalVersion != 2 || initial.AdditionalWeight != 0.1 {
		t.Fatalf("owned creation lost routing or identity: %+v", initial)
	}
	// Recovery uses retained ownership, never an in-process request cache.
	restarted := aliasOwnerService(t, Config{Repository: repository})
	update := &api.UpdateAliasInput{FunctionName: create.FunctionName, Name: create.Name, FunctionVersion: new(api.VersionWithLatestPublished("2")), Description: new(api.Description("native retarget")), RoutingConfig: &api.AliasRoutingConfiguration{AdditionalVersionWeights: api.AdditionalVersionWeights{"1": 0.25}}}
	changed, wire := aliasOwnerCommand(t, restarted, ctx, "UpdateAlias", update)
	if wire != nil {
		t.Fatal(wire)
	}
	retargeted := aliasOwnerRecord(t, repository, ctx, ref)
	if retargeted.Owner != owner || retargeted.FunctionVersion != 2 || retargeted.AdditionalVersion != 1 || retargeted.AdditionalWeight != 0.25 || retargeted.Revision == initial.Revision {
		t.Fatalf("native retarget lost ownership or revision: %+v", retargeted)
	}
	recovered, wire := aliasOwnerCommand(t, restarted, owned, "CreateAlias", create)
	if wire != nil || !reflect.DeepEqual(recovered, changed) {
		t.Fatalf("create recovery did not return current alias: %+v %v; want %+v", recovered, wire, changed)
	}
	if got := aliasOwnerRecord(t, repository, ctx, ref); got != retargeted {
		t.Fatalf("recovery changed retained alias: %+v; want %+v", got, retargeted)
	}
	_, wire = aliasOwnerCommand(t, restarted, ctx, "CreateAlias", create)
	requireAliasOwnerCode(t, wire, "ResourceConflictException")
	_, wire = aliasOwnerCommand(t, restarted, owned, "UpdateAlias", &api.UpdateAliasInput{FunctionName: create.FunctionName, Name: create.Name, RevisionId: new(api.String(initial.Revision)), Description: new(api.Description("stale update"))})
	requireAliasOwnerCode(t, wire, "PreconditionFailedException")
	if _, wire := aliasOwnerCommand(t, restarted, ctx, "DeleteAlias", &api.DeleteAliasInput{FunctionName: create.FunctionName, Name: create.Name}); wire != nil {
		t.Fatal(wire)
	}
	if _, wire := aliasOwnerCommand(t, restarted, ctx, "CreateAlias", create); wire != nil {
		t.Fatal(wire)
	}
	unowned := aliasOwnerRecord(t, repository, ctx, ref)
	if unowned.Owner != (AliasOwner{}) || unowned.Revision == retargeted.Revision {
		t.Fatalf("native recreation retained an old ownership identity: %+v", unowned)
	}
	_, wire = aliasOwnerCommand(t, restarted, owned, "CreateAlias", create)
	requireAliasOwnerCode(t, wire, "ResourceConflictException")
	_, wire = aliasOwnerCommand(t, restarted, owned, "GetAlias", &api.GetAliasInput{FunctionName: create.FunctionName, Name: create.Name})
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	_, wire = aliasOwnerCommand(t, restarted, owned, "UpdateAlias", update)
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	_, wire = aliasOwnerCommand(t, restarted, owned, "DeleteAlias", &api.DeleteAliasInput{FunctionName: create.FunctionName, Name: create.Name})
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	if got := aliasOwnerRecord(t, repository, ctx, ref); got != unowned {
		t.Fatalf("old owner changed a native replacement: %+v", got)
	}
}

func TestAliasOwnerRejectsForeignAndIncompleteIdentityIncludingConcurrency(t *testing.T) {
	repository := NewMemoryRepository(nil)
	ctx, ref := aliasOwnerFixture(t, repository)
	owner := AliasOwner{StackID: "stack-a", LogicalID: "Alias", Token: "create-a"}
	owned := WithAliasOwner(ctx, owner)
	s := aliasOwnerService(t, Config{Repository: repository})
	create := aliasOwnerCreate(ref)
	if _, wire := aliasOwnerCommand(t, s, owned, "CreateAlias", create); wire != nil {
		t.Fatal(wire)
	}
	want := aliasOwnerRecord(t, repository, ctx, ref)
	pool := ProvisionedConcurrencyRecord{Key: ref, Requested: 3, Generation: "retained-generation", Status: "IN_PROGRESS", Modified: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutProvisionedConcurrency(pool) }); err != nil {
		t.Fatal(err)
	}
	operations := []struct {
		name string
		in   any
	}{
		{"GetAlias", &api.GetAliasInput{FunctionName: create.FunctionName, Name: create.Name}},
		{"UpdateAlias", &api.UpdateAliasInput{FunctionName: create.FunctionName, Name: create.Name, Description: new(api.Description("foreign update"))}},
		{"DeleteAlias", &api.DeleteAliasInput{FunctionName: create.FunctionName, Name: create.Name}},
		{"GetProvisionedConcurrencyConfig", &api.GetProvisionedConcurrencyConfigInput{FunctionName: create.FunctionName, Qualifier: new(api.Qualifier(ref.Qualifier))}},
		{"PutProvisionedConcurrencyConfig", &api.PutProvisionedConcurrencyConfigInput{FunctionName: create.FunctionName, Qualifier: new(api.Qualifier(ref.Qualifier)), ProvisionedConcurrentExecutions: new(api.PositiveInteger(7))}},
		{"DeleteProvisionedConcurrencyConfig", &api.DeleteProvisionedConcurrencyConfigInput{FunctionName: create.FunctionName, Qualifier: new(api.Qualifier(ref.Qualifier))}},
	}
	for _, tc := range []struct {
		name       string
		owner      AliasOwner
		incomplete bool
	}{
		{"stack", AliasOwner{"stack-b", owner.LogicalID, owner.Token}, false},
		{"logical", AliasOwner{owner.StackID, "OtherAlias", owner.Token}, false},
		{"token", AliasOwner{owner.StackID, owner.LogicalID, "create-b"}, false},
		{"missing-stack", AliasOwner{"", owner.LogicalID, owner.Token}, true},
		{"missing-logical", AliasOwner{owner.StackID, "", owner.Token}, true},
		{"missing-token", AliasOwner{owner.StackID, owner.LogicalID, ""}, true},
		{"empty", AliasOwner{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			constrained := WithAliasOwner(ctx, tc.owner)
			_, wire := aliasOwnerCommand(t, s, constrained, "CreateAlias", create)
			code := "ResourceConflictException"
			if tc.incomplete {
				code = "AccessDeniedException"
			}
			requireAliasOwnerCode(t, wire, code)
			for _, operation := range operations {
				_, wire := aliasOwnerCommand(t, s, constrained, operation.name, operation.in)
				requireAliasOwnerCode(t, wire, "AccessDeniedException")
			}
			if got := aliasOwnerRecord(t, repository, ctx, ref); got != want {
				t.Fatalf("rejected owner changed alias: %+v", got)
			}
			if err := repository.View(ctx, func(r Reader) error {
				got, err := r.ProvisionedConcurrency(ref)
				if err == nil && got != pool {
					t.Fatalf("rejected owner changed concurrency: %+v", got)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, allowed := range []context.Context{ctx, owned} {
		out, wire := aliasOwnerCommand(t, s, allowed, operations[3].name, operations[3].in)
		if wire != nil || int32(*out.(*api.GetProvisionedConcurrencyConfigOutput).RequestedProvisionedConcurrentExecutions) != pool.Requested {
			t.Fatalf("authorized concurrency read failed: %+v %v", out, wire)
		}
	}
	if _, wire := aliasOwnerCommand(t, s, owned, "DeleteAlias", operations[2].in); wire != nil {
		t.Fatal(wire)
	}
	if err := repository.View(ctx, func(r Reader) error {
		if _, err := r.Alias(ref); !errors.Is(err, ErrNotFound) {
			t.Fatalf("owned delete retained alias: %v", err)
		}
		if _, err := r.ProvisionedConcurrency(ref); !errors.Is(err, ErrNotFound) {
			t.Fatalf("owned delete retained concurrency: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, wire := aliasOwnerCommand(t, s, owned, "DeleteAlias", operations[2].in); wire != nil {
		t.Fatalf("owned delete lost native idempotence: %v", wire)
	}
}

type aliasOwnerPolicies struct{ allow bool }

func (p *aliasOwnerPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	if !p.allow {
		return authorization.PolicySet{}, nil
	}
	return authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"lambda:*","Resource":"*"}}`}}}, nil
}

func TestAliasOwnerRecoveryRechecksCurrentIAM(t *testing.T) {
	repository := NewMemoryRepository(nil)
	ctx, ref := aliasOwnerFixture(t, repository)
	identity := &aliasOwnerPolicies{allow: true}
	s := aliasOwnerService(t, Config{Repository: repository, Authorizer: authorization.New(identity, nil)})
	metadata := awsctx.FromContext(ctx)
	metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::111111111111:user/operator", "AIDA11111111111111111"
	owned := WithAliasOwner(awsctx.WithMetadata(ctx, metadata), AliasOwner{"stack-a", "Alias", "create-a"})
	create := aliasOwnerCreate(ref)
	if _, wire := aliasOwnerCommand(t, s, owned, "CreateAlias", create); wire != nil {
		t.Fatal(wire)
	}
	want := aliasOwnerRecord(t, repository, ctx, ref)
	identity.allow = false
	_, wire := aliasOwnerCommand(t, s, owned, "CreateAlias", create)
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	if got := aliasOwnerRecord(t, repository, ctx, ref); got != want {
		t.Fatalf("unauthorized recovery changed alias: %+v", got)
	}
}

func TestAliasOwnershipAndAPIEventRollbackTogether(t *testing.T) {
	domain := memory.NewDomain()
	repository := NewMemoryRepository(domain)
	events := journal.NewMemory(domain)
	ctx, ref := aliasOwnerFixture(t, repository)
	owned := WithAliasOwner(ctx, AliasOwner{"stack-a", "Alias", "create-a"})
	s := aliasOwnerService(t, Config{Repository: repository, APIEvents: apievents.New(events)})
	create := aliasOwnerCreate(ref)
	operations := []struct {
		name string
		in   any
	}{
		{"CreateAlias", create},
		{"UpdateAlias", &api.UpdateAliasInput{FunctionName: create.FunctionName, Name: create.Name, Description: new(api.Description("updated"))}},
		{"DeleteAlias", &api.DeleteAliasInput{FunctionName: create.FunctionName, Name: create.Name}},
	}
	abort := errors.New("abort alias mutation")
	for index, operation := range operations {
		var before AliasRecord
		if index != 0 {
			before = aliasOwnerRecord(t, repository, ctx, ref)
		}
		if err := repository.Update(owned, func(tx Transaction) error {
			if _, wire := aliasOwnerCommand(t, s, tx.Context(), operation.name, operation.in); wire != nil {
				return wire
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatalf("%s rollback: %v", operation.name, err)
		}
		if index == 0 {
			if err := repository.View(ctx, func(r Reader) error {
				_, err := r.Alias(ref)
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("rolled-back create retained ownership: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		} else if got := aliasOwnerRecord(t, repository, ctx, ref); got != before {
			t.Fatalf("rolled-back %s changed alias: %+v", operation.name, got)
		}
		if committed, err := events.Read(ctx, 0, 10); err != nil || len(committed) != index {
			t.Fatalf("rolled-back %s published an event: %+v %v", operation.name, committed, err)
		}
		if _, wire := aliasOwnerCommand(t, s, owned, operation.name, operation.in); wire != nil {
			t.Fatal(wire)
		}
	}
	committed, err := events.Read(ctx, 0, 10)
	if err != nil || len(committed) != len(operations) {
		t.Fatalf("committed alias mutations lost events: %+v %v", committed, err)
	}
	for _, event := range committed {
		if event.APICallCompleted == nil || event.APICallCompleted.ErrorCode != "" {
			t.Fatalf("alias mutation did not retain a successful API outcome: %+v", event.APICallCompleted)
		}
	}
}

type replacingAliasRepository struct {
	Repository
	beforeView, beforeUpdate func() error
}

func (r *replacingAliasRepository) View(ctx context.Context, fn func(Reader) error) error {
	if before := r.beforeView; before != nil {
		r.beforeView = nil
		if err := before(); err != nil {
			return err
		}
	}
	return r.Repository.View(ctx, fn)
}

func (r *replacingAliasRepository) Update(ctx context.Context, fn func(Transaction) error) error {
	if before := r.beforeUpdate; before != nil {
		r.beforeUpdate = nil
		if err := before(); err != nil {
			return err
		}
	}
	return r.Repository.Update(ctx, fn)
}

func TestAliasConcurrencyOwnerCheckedInStateTransaction(t *testing.T) {
	for _, name := range []string{"GetProvisionedConcurrencyConfig", "PutProvisionedConcurrencyConfig", "DeleteProvisionedConcurrencyConfig"} {
		t.Run(name, func(t *testing.T) {
			repository := NewMemoryRepository(nil)
			ctx, ref := aliasOwnerFixture(t, repository)
			owned := WithAliasOwner(ctx, AliasOwner{"stack-a", "Alias", "create-a"})
			native := aliasOwnerService(t, Config{Repository: repository})
			create := aliasOwnerCreate(ref)
			if _, wire := aliasOwnerCommand(t, native, owned, "CreateAlias", create); wire != nil {
				t.Fatal(wire)
			}
			if _, wire := aliasOwnerCommand(t, native, owned, "GetAlias", &api.GetAliasInput{FunctionName: create.FunctionName, Name: create.Name}); wire != nil {
				t.Fatal(wire)
			}
			foreignPool := ProvisionedConcurrencyRecord{Key: ref, Requested: 9, Generation: "foreign-generation", Status: "IN_PROGRESS", Modified: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
			replace := func() error {
				if _, wire := aliasOwnerCommand(t, native, ctx, "DeleteAlias", &api.DeleteAliasInput{FunctionName: create.FunctionName, Name: create.Name}); wire != nil {
					return wire
				}
				if _, wire := aliasOwnerCommand(t, native, ctx, "CreateAlias", create); wire != nil {
					return wire
				}
				return repository.Update(ctx, func(tx Transaction) error { return tx.PutProvisionedConcurrency(foreignPool) })
			}
			// Replace after a caller's ownership read, at the transaction entry.
			// A separate preflight View cannot protect the subsequent mutation.
			boundary := &replacingAliasRepository{Repository: repository}
			var input any
			switch name {
			case "GetProvisionedConcurrencyConfig":
				boundary.beforeView = replace
				input = &api.GetProvisionedConcurrencyConfigInput{FunctionName: create.FunctionName, Qualifier: new(api.Qualifier(ref.Qualifier))}
			case "PutProvisionedConcurrencyConfig":
				boundary.beforeUpdate = replace
				input = &api.PutProvisionedConcurrencyConfigInput{FunctionName: create.FunctionName, Qualifier: new(api.Qualifier(ref.Qualifier)), ProvisionedConcurrentExecutions: new(api.PositiveInteger(7))}
			case "DeleteProvisionedConcurrencyConfig":
				boundary.beforeUpdate = replace
				input = &api.DeleteProvisionedConcurrencyConfigInput{FunctionName: create.FunctionName, Qualifier: new(api.Qualifier(ref.Qualifier))}
			}
			s := aliasOwnerService(t, Config{Repository: boundary})
			_, wire := aliasOwnerCommand(t, s, owned, name, input)
			requireAliasOwnerCode(t, wire, "AccessDeniedException")
			if err := repository.View(ctx, func(r Reader) error {
				alias, err := r.Alias(ref)
				if err != nil {
					return err
				}
				if alias.Owner != (AliasOwner{}) {
					t.Fatalf("concurrency call adopted a replacement: %+v", alias)
				}
				pool, err := r.ProvisionedConcurrency(ref)
				if err == nil && pool != foreignPool {
					t.Fatalf("concurrency call changed replacement capacity: %+v", pool)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type rejectedAliasEvents struct{ apievents.Recorder }

func (r rejectedAliasEvents) Record(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if err := r.Recorder.Record(ctx, envelope, call); err != nil {
		return err
	}
	return errors.New("reject tentative API event")
}

func TestAliasEventFailureDoesNotCommitOwnership(t *testing.T) {
	domain := memory.NewDomain()
	repository := NewMemoryRepository(domain)
	events := journal.NewMemory(domain)
	ctx, ref := aliasOwnerFixture(t, repository)
	owned := WithAliasOwner(ctx, AliasOwner{"stack-a", "Alias", "create-a"})
	s := aliasOwnerService(t, Config{Repository: repository, APIEvents: rejectedAliasEvents{apievents.New(events)}})
	_, wire := s.createAlias(owned, aliasOwnerCreate(ref))
	requireAliasOwnerCode(t, wire, "ServiceException")
	if err := repository.View(ctx, func(r Reader) error {
		_, err := r.Alias(ref)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed API event committed alias ownership: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if committed, err := events.Read(ctx, 0, 10); err != nil || len(committed) != 0 {
		t.Fatalf("failed owned creation committed an API event: %+v %v", committed, err)
	}
}

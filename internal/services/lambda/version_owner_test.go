package lambda

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/journal"
	"stackd/storage/memory"
)

func versionOwnerFixture(t *testing.T, repository Repository) (context.Context, FunctionKey) {
	t.Helper()
	key := FunctionKey{Scope: Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "owned-publication"}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.Account, Region: key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: key.Account})
	if err := repository.Update(ctx, func(tx Transaction) error {
		return tx.PutFunction(FunctionRecord{Key: key, Role: "arn:aws:iam::111111111111:role/execution", Runtime: "nodejs22.x", Handler: "index.handler", Architecture: "x86_64", State: "Active", UpdateStatus: "Successful", Revision: "initial", DeploymentRevision: "first-deployment", CodeSHA256: "first-code", Variables: map[string]string{"ENV": "first"}})
	}); err != nil {
		t.Fatal(err)
	}
	return ctx, key
}

func TestVersionOwnerRecoveryIgnoresChangedLatestButRechecksCurrentIAM(t *testing.T) {
	repo := NewMemoryRepository(nil)
	ctx, key := versionOwnerFixture(t, repo)
	identity := &aliasOwnerPolicies{allow: true}
	s := aliasOwnerService(t, Config{Repository: repo, Authorizer: authorization.New(identity, nil)})
	metadata := awsctx.FromContext(ctx)
	metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::111111111111:user/operator", "AIDA11111111111111111"
	owned := WithVersionOwner(awsctx.WithMetadata(ctx, metadata), VersionOwner{"stack-a", "Version", "create-a"})
	in := &api.PublishVersionInput{FunctionName: new(api.FunctionName(key.Name)), RevisionId: new(api.String("initial")), CodeSha256: new(api.String("first-code")), Description: new(api.Description("immutable"))}
	first, wire := s.publishVersion(owned, in)
	if wire != nil {
		t.Fatal(wire)
	}
	if err := repo.Update(ctx, func(tx Transaction) error {
		latest, err := tx.Function(key)
		if err != nil {
			return err
		}
		latest.CodeSHA256, latest.Revision, latest.DeploymentRevision, latest.State, latest.UpdateStatus = "new-code", "new-revision", "new-deployment", "Pending", "InProgress"
		latest.Variables["ENV"] = "new"
		return tx.PutFunction(latest)
	}); err != nil {
		t.Fatal(err)
	}
	restarted := aliasOwnerService(t, Config{Repository: repo, Authorizer: authorization.New(identity, nil)})
	got, wire := restarted.publishVersion(owned, in)
	if wire != nil || !reflect.DeepEqual(got, first) {
		t.Fatalf("retry changed immutable publication: %+v %v; want %+v", got, wire, first)
	}
	identity.allow = false
	_, wire = restarted.publishVersion(owned, in)
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	_, wire = restarted.putRuntimeManagementConfig(owned, &api.PutRuntimeManagementConfigInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("1")), UpdateRuntimeOn: new(api.UpdateRuntimeOnFunctionUpdate)})
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	_, wire = restarted.deleteFunction(owned, &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("1"))})
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	if err := repo.View(ctx, func(r Reader) error {
		last, err := r.LastAllocatedVersion(key)
		if err != nil || last != 1 {
			t.Fatalf("recovery advanced allocation: %d %v", last, err)
		}
		v, err := r.FunctionVersion(FunctionVersionKey{FunctionKey: key, Version: 1})
		if err != nil || v.CodeSHA256 != "first-code" || v.Variables["ENV"] != "first" || v.Revision != value(first.RevisionId) {
			t.Fatalf("denied commands changed publication: %+v %v", v, err)
		}
		mode, err := r.RuntimeManagement(FunctionVersionKey{FunctionKey: key, Version: 1})
		if err != nil || mode != "Auto" {
			t.Fatalf("revoked IAM changed runtime mode: %s %v", mode, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVersionOwnerControlsRejectWrongIdentityAndRequestedResource(t *testing.T) {
	repo := NewMemoryRepository(nil)
	ctx, key := versionOwnerFixture(t, repo)
	owner := VersionOwner{"stack-a", "Version", "create-a"}
	owned := WithVersionOwner(ctx, owner)
	s := aliasOwnerService(t, Config{Repository: repo})
	if _, wire := s.publishVersion(owned, &api.PublishVersionInput{FunctionName: new(api.FunctionName(key.Name))}); wire != nil {
		t.Fatal(wire)
	}
	other := key
	other.Name = "native-function"
	if err := repo.Update(ctx, func(tx Transaction) error {
		v, err := tx.Function(key)
		if err != nil {
			return err
		}
		v.Version = 2
		if err := tx.PutFunctionVersion(v); err != nil {
			return err
		}
		v.Key, v.Version = other, 0
		if err := tx.PutFunction(v); err != nil {
			return err
		}
		v.Version = 1
		if err := tx.PutFunctionVersion(v); err != nil {
			return err
		}
		if err := tx.PutAlias(AliasRecord{Key: FunctionReference{FunctionKey: key, Qualifier: "live"}, FunctionVersion: 1}); err != nil {
			return err
		}
		return tx.PutProvisionedConcurrency(ProvisionedConcurrencyRecord{Key: FunctionReference{FunctionKey: key, Qualifier: "1"}, Requested: 5, Status: "IN_PROGRESS", Generation: "pool"})
	}); err != nil {
		t.Fatal(err)
	}
	operations := func(name, qualifier string) []struct {
		name string
		in   any
	} {
		function, q := new(api.FunctionName(name)), new(api.Qualifier(qualifier))
		return []struct {
			name string
			in   any
		}{
			{"DeleteFunction", &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier(qualifier))}},
			{"GetRuntimeManagementConfig", &api.GetRuntimeManagementConfigInput{FunctionName: new(api.NamespacedFunctionName(name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier(qualifier))}},
			{"PutRuntimeManagementConfig", &api.PutRuntimeManagementConfigInput{FunctionName: new(api.NamespacedFunctionName(name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier(qualifier)), UpdateRuntimeOn: new(api.UpdateRuntimeOnFunctionUpdate)}},
			{"GetProvisionedConcurrencyConfig", &api.GetProvisionedConcurrencyConfigInput{FunctionName: function, Qualifier: q}},
			{"PutProvisionedConcurrencyConfig", &api.PutProvisionedConcurrencyConfigInput{FunctionName: function, Qualifier: q, ProvisionedConcurrentExecutions: new(api.PositiveInteger(8))}},
			{"DeleteProvisionedConcurrencyConfig", &api.DeleteProvisionedConcurrencyConfigInput{FunctionName: function, Qualifier: q}},
			{"GetFunctionScalingConfig", &api.GetFunctionScalingConfigRequest{FunctionName: new(api.UnqualifiedFunctionName(name)), Qualifier: new(api.PublishedFunctionQualifier(qualifier))}},
			{"PutFunctionScalingConfig", &api.PutFunctionScalingConfigRequest{FunctionName: new(api.UnqualifiedFunctionName(name)), Qualifier: new(api.PublishedFunctionQualifier(qualifier)), FunctionScalingConfig: &api.FunctionScalingConfig{MinExecutionEnvironments: new(api.FunctionScalingConfigExecutionEnvironments(0)), MaxExecutionEnvironments: new(api.FunctionScalingConfigExecutionEnvironments(0))}}},
		}
	}
	for _, invalid := range []VersionOwner{{}, {StackID: "stack-a", LogicalID: "Version"}, {StackID: "stack-a", Token: "create-a"}, {LogicalID: "Version", Token: "create-a"}, {StackID: "stack-b", LogicalID: "Version", Token: "create-a"}, {StackID: "stack-a", LogicalID: "Other", Token: "create-a"}, {StackID: "stack-a", LogicalID: "Version", Token: "other"}} {
		for _, operation := range operations(key.Name, "1") {
			_, wire := aliasOwnerCommand(t, s, WithVersionOwner(ctx, invalid), operation.name, operation.in)
			requireAliasOwnerCode(t, wire, "AccessDeniedException")
		}
		if invalid.StackID == "" || invalid.LogicalID == "" || invalid.Token == "" {
			_, wire := s.publishVersion(WithVersionOwner(ctx, invalid), &api.PublishVersionInput{FunctionName: new(api.FunctionName(key.Name))})
			requireAliasOwnerCode(t, wire, "AccessDeniedException")
		}
	}
	for _, target := range []FunctionReference{{FunctionKey: key, Qualifier: "2"}, {FunctionKey: other, Qualifier: "1"}} {
		for _, operation := range operations(target.Name, target.Qualifier) {
			_, wire := aliasOwnerCommand(t, s, owned, operation.name, operation.in)
			requireAliasOwnerCode(t, wire, "AccessDeniedException")
		}
	}
	for _, qualifier := range []string{"", "$LATEST", "live"} {
		_, wire := s.putRuntimeManagementConfig(owned, &api.PutRuntimeManagementConfigInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier(qualifier)), UpdateRuntimeOn: new(api.UpdateRuntimeOnFunctionUpdate)})
		requireAliasOwnerCode(t, wire, "AccessDeniedException")
	}
	_, wire := s.deleteFunction(owned, &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name))})
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	for _, allowed := range []context.Context{ctx, owned} {
		out, wire := s.getProvisionedConcurrencyConfig(allowed, &api.GetProvisionedConcurrencyConfigInput{FunctionName: new(api.FunctionName(key.Name)), Qualifier: new(api.Qualifier("1"))})
		if wire != nil || int32(*out.RequestedProvisionedConcurrentExecutions) != 5 {
			t.Fatalf("rejected controls changed capacity: %+v %v", out, wire)
		}
	}
	if _, wire := s.putRuntimeManagementConfig(owned, &api.PutRuntimeManagementConfigInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("1")), UpdateRuntimeOn: new(api.UpdateRuntimeOnFunctionUpdate)}); wire != nil {
		t.Fatal(wire)
	}
	if err := repo.View(ctx, func(r Reader) error {
		mode, err := r.RuntimeManagement(FunctionVersionKey{FunctionKey: key, Version: 1})
		if err != nil || mode != "FunctionUpdate" {
			t.Fatalf("owner runtime update failed: %s %v", mode, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVersionOwnerDeletionRetryReportsAbsentPublication(t *testing.T) {
	repo := NewMemoryRepository(nil)
	ctx, key := versionOwnerFixture(t, repo)
	owned := WithVersionOwner(ctx, VersionOwner{"stack-a", "Version", "create-a"})
	s := aliasOwnerService(t, Config{Repository: repo})
	if _, wire := s.publishVersion(owned, &api.PublishVersionInput{FunctionName: new(api.FunctionName(key.Name))}); wire != nil {
		t.Fatal(wire)
	}
	in := &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("1"))}
	if _, wire := s.deleteFunction(owned, in); wire != nil {
		t.Fatal(wire)
	}
	// A controller can lose the successful delete response. The missing
	// publication is not a foreign resource and must remain retryable.
	_, wire := s.deleteFunction(owned, in)
	requireAliasOwnerCode(t, wire, "ResourceNotFoundException")
}

func TestVersionPublicationReceiptStateAndJournalRollbackTogether(t *testing.T) {
	domain := memory.NewDomain()
	repo := NewMemoryRepository(domain)
	events := journal.NewMemory(domain)
	ctx, key := versionOwnerFixture(t, repo)
	owner := VersionOwner{"stack-a", "Version", "request-a"}
	owned := WithVersionOwner(ctx, owner)
	s := aliasOwnerService(t, Config{Repository: repo, APIEvents: rejectedAliasEvents{apievents.New(events)}})
	in := &api.PublishVersionInput{FunctionName: new(api.FunctionName(key.Name))}
	_, wire := s.publishVersion(owned, in)
	requireAliasOwnerCode(t, wire, "ServiceException")
	if err := repo.View(ctx, func(r Reader) error {
		if _, err := r.OwnedFunctionVersion(key, owner); !errors.Is(err, ErrNotFound) {
			t.Fatalf("event failure retained receipt: %v", err)
		}
		if _, err := r.FunctionVersion(FunctionVersionKey{FunctionKey: key, Version: 1}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("event failure retained publication: %v", err)
		}
		last, err := r.LastAllocatedVersion(key)
		if err != nil || last != 0 {
			t.Fatalf("event failure advanced allocation: %d %v", last, err)
		}
		latest, err := r.Function(key)
		if err != nil || latest.Revision != "initial" {
			t.Fatalf("event failure changed latest: %+v %v", latest, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := events.Read(ctx, 0, 10); err != nil || len(got) != 0 {
		t.Fatalf("failed publication committed event: %+v %v", got, err)
	}
	s = aliasOwnerService(t, Config{Repository: repo, APIEvents: apievents.New(events)})
	if _, wire := s.publishVersion(owned, in); wire != nil {
		t.Fatal(wire)
	}
	abort := errors.New("abort owned deletion")
	if err := repo.Update(owned, func(tx Transaction) error {
		if _, wire := s.deleteFunction(tx.Context(), &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("1"))}); wire != nil {
			return wire
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if err := repo.View(ctx, func(r Reader) error {
		v, err := r.OwnedFunctionVersion(key, owner)
		if err != nil || v.Version != 1 || v.CodeSHA256 != "first-code" {
			t.Fatalf("rolled-back deletion lost receipt: %+v %v", v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	committed, err := events.Read(ctx, 0, 10)
	if err != nil || len(committed) != 1 || committed[0].APICallCompleted == nil || committed[0].APICallCompleted.ErrorCode != "" {
		t.Fatalf("receipt journal coupling = %+v %v", committed, err)
	}
}

type versionOwnerTagPolicies struct{}

func (versionOwnerTagPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"lambda:*","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/access":"allowed"}}}}`}}}, nil
}

func TestVersionOwnerScalingUsesCurrentBaseFunctionIAM(t *testing.T) {
	repo := NewMemoryRepository(nil)
	ctx, key := versionOwnerFixture(t, repo)
	owner := VersionOwner{StackID: "stack-a", LogicalID: "Version", Token: "request-a"}
	if err := repo.Update(ctx, func(tx Transaction) error {
		latest, err := tx.Function(key)
		if err != nil {
			return err
		}
		latest.Tags = map[string]string{"access": "allowed"}
		latest.Capacity = &CapacityFunctionConfig{ProviderARN: "arn:aws:lambda:us-east-1:111111111111:capacity-provider:pool"}
		if err := tx.PutFunction(latest); err != nil {
			return err
		}
		latest.Version = 1
		if err := tx.PutFunctionVersion(latest); err != nil {
			return err
		}
		return tx.PutFunctionVersionOwner(FunctionVersionKey{FunctionKey: key, Version: 1}, owner)
	}); err != nil {
		t.Fatal(err)
	}
	metadata := awsctx.FromContext(ctx)
	metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::111111111111:user/operator", "AIDA11111111111111111"
	owned := WithVersionOwner(awsctx.WithMetadata(ctx, metadata), owner)
	s := aliasOwnerService(t, Config{Repository: repo, Authorizer: authorization.New(versionOwnerTagPolicies{}, nil)})
	in := &api.PutFunctionScalingConfigRequest{FunctionName: new(api.UnqualifiedFunctionName(key.Name)), Qualifier: new(api.PublishedFunctionQualifier("1")), FunctionScalingConfig: &api.FunctionScalingConfig{MinExecutionEnvironments: new(api.FunctionScalingConfigExecutionEnvironments(3)), MaxExecutionEnvironments: new(api.FunctionScalingConfigExecutionEnvironments(10))}}
	if _, wire := s.putCapacityScaling(owned, in); wire != nil {
		t.Fatal(wire)
	}
	get := &api.GetFunctionScalingConfigRequest{FunctionName: in.FunctionName, Qualifier: in.Qualifier}
	out, wire := s.getCapacityScaling(owned, get)
	if wire != nil || int32(*out.RequestedFunctionScalingConfig.MaxExecutionEnvironments) != 10 {
		t.Fatalf("owned scaling ignored current base tags: %+v %v", out, wire)
	}
	if err := repo.Update(ctx, func(tx Transaction) error {
		latest, err := tx.Function(key)
		if err != nil {
			return err
		}
		latest.Tags["access"] = "revoked"
		return tx.PutFunction(latest)
	}); err != nil {
		t.Fatal(err)
	}
	in.FunctionScalingConfig.MaxExecutionEnvironments = new(api.FunctionScalingConfigExecutionEnvironments(20))
	_, wire = s.putCapacityScaling(owned, in)
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	_, wire = s.getCapacityScaling(owned, get)
	requireAliasOwnerCode(t, wire, "AccessDeniedException")
	if err := repo.View(ctx, func(r Reader) error {
		retained, err := r.CapacityScaling(FunctionReference{FunctionKey: key, Qualifier: "1"})
		if err != nil || retained.MinEnvironments != 3 || retained.MaxEnvironments != 10 {
			t.Fatalf("revoked IAM changed scaling: %+v %v", retained, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

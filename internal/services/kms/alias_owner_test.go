package kms

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func aliasOwnerCommand(t *testing.T, s *Service, ctx context.Context, name string, input any) (any, *awswire.Error) {
	t.Helper()
	model, _ := awscatalog.LookupService("kms")
	op, ok := model.Operation(name)
	if !ok {
		t.Fatalf("unknown KMS operation %q", name)
	}
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: input})
}

func aliasOwnerKey(t *testing.T, s *Service, ctx context.Context) *kmsapi.KeyIdType {
	t.Helper()
	out, err := aliasOwnerCommand(t, s, ctx, "CreateKey", &kmsapi.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	return out.(*kmsapi.CreateKeyOutput).KeyMetadata.KeyId
}

func aliasOwnerRecords(t *testing.T, backend Storage, ctx context.Context) []AliasRecord {
	t.Helper()
	var aliases []AliasRecord
	if err := backend.View(ctx, func(reader Reader) error {
		var err error
		aliases, err = reader.Aliases(storageScope(scopeFor(ctx)))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return aliases
}

func requireAliasOwnerCode(t *testing.T, err *awswire.Error, code string) {
	t.Helper()
	if err == nil || err.Code != code {
		t.Fatalf("error = %v; want %s", err, code)
	}
}

func TestAliasOwnerReplayAndNativeRecreation(t *testing.T) {
	backend := NewMemoryStorage(nil)
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	source := clock.NewManual(at)
	s := NewWithConfig(Config{Storage: backend, Clock: source})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), rootMetadata("111122223333", "us-east-1", "aws"))
	first, second := aliasOwnerKey(t, s, ctx), aliasOwnerKey(t, s, ctx)
	owner := AliasOwner{StackID: "stack-a", LogicalID: "Alias", Token: "create-a"}
	owned := WithAliasOwner(ctx, owner)
	name := ptr(kmsapi.AliasNameType("alias/owned"))
	create := &kmsapi.CreateAliasInput{AliasName: name, TargetKeyId: first}
	if _, err := aliasOwnerCommand(t, s, owned, "CreateAlias", create); err != nil {
		t.Fatal(err)
	}
	want := []AliasRecord{{Name: string(*name), KeyID: string(*first), Created: at, Updated: at, Owner: owner}}
	if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
		t.Fatalf("owned create = %+v; want %+v", got, want)
	}
	if err := source.Advance(time.Minute); err != nil {
		t.Fatal(err)
	}
	// Replacement services must recover from the stored identity, not process history.
	replacement := NewWithConfig(Config{Storage: backend, Clock: source})
	t.Cleanup(func() { _ = replacement.Close() })
	if _, err := aliasOwnerCommand(t, replacement, owned, "CreateAlias", create); err != nil {
		t.Fatal(err)
	}
	if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
		t.Fatalf("replay changed alias state: %+v", got)
	}
	_, err := aliasOwnerCommand(t, replacement, ctx, "CreateAlias", create)
	requireAliasOwnerCode(t, err, "AlreadyExistsException")
	if _, err := aliasOwnerCommand(t, replacement, ctx, "UpdateAlias", &kmsapi.UpdateAliasInput{AliasName: name, TargetKeyId: second}); err != nil {
		t.Fatal(err)
	}
	want[0].KeyID, want[0].Updated = string(*second), at.Add(time.Minute)
	if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
		t.Fatalf("native retarget lost owner or timestamps: %+v", got)
	}
	// Create recovery must not undo a later native retarget.
	if _, err := aliasOwnerCommand(t, replacement, owned, "CreateAlias", create); err != nil {
		t.Fatal(err)
	}
	if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
		t.Fatalf("replay undid native retarget: %+v", got)
	}
	if _, err := aliasOwnerCommand(t, replacement, ctx, "DeleteAlias", &kmsapi.DeleteAliasInput{AliasName: name}); err != nil {
		t.Fatal(err)
	}
	if _, err := aliasOwnerCommand(t, replacement, ctx, "CreateAlias", create); err != nil {
		t.Fatal(err)
	}
	want[0] = AliasRecord{Name: string(*name), KeyID: string(*first), Created: at.Add(time.Minute), Updated: at.Add(time.Minute)}
	if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
		t.Fatalf("native recreation retained prior identity: %+v", got)
	}
	_, err = aliasOwnerCommand(t, replacement, owned, "CreateAlias", create)
	requireAliasOwnerCode(t, err, "AlreadyExistsException")
	_, err = aliasOwnerCommand(t, replacement, owned, "UpdateAlias", &kmsapi.UpdateAliasInput{AliasName: name, TargetKeyId: second})
	requireAliasOwnerCode(t, err, "AccessDeniedException")
	_, err = aliasOwnerCommand(t, replacement, owned, "DeleteAlias", &kmsapi.DeleteAliasInput{AliasName: name})
	requireAliasOwnerCode(t, err, "AccessDeniedException")
	if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
		t.Fatalf("old owner adopted or changed recreated alias: %+v", got)
	}
}

func TestAliasOwnerRejectsForeignAndIncompleteIdentity(t *testing.T) {
	backend := NewMemoryStorage(nil)
	s := NewWithStorage(backend, nil)
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), rootMetadata("111122223333", "us-east-1", "aws"))
	first, second := aliasOwnerKey(t, s, ctx), aliasOwnerKey(t, s, ctx)
	owner := AliasOwner{StackID: "stack-a", LogicalID: "Alias", Token: "create-a"}
	name := ptr(kmsapi.AliasNameType("alias/owned"))
	create := &kmsapi.CreateAliasInput{AliasName: name, TargetKeyId: first}
	if _, err := aliasOwnerCommand(t, s, WithAliasOwner(ctx, owner), "CreateAlias", create); err != nil {
		t.Fatal(err)
	}
	want := aliasOwnerRecords(t, backend, ctx)
	for _, tc := range []struct {
		name       string
		owner      AliasOwner
		incomplete bool
	}{
		{"stack", AliasOwner{"stack-b", owner.LogicalID, owner.Token}, false},
		{"logical", AliasOwner{owner.StackID, "AnotherAlias", owner.Token}, false},
		{"token", AliasOwner{owner.StackID, owner.LogicalID, "create-b"}, false},
		{"missing-stack", AliasOwner{"", owner.LogicalID, owner.Token}, true},
		{"missing-logical", AliasOwner{owner.StackID, "", owner.Token}, true},
		{"missing-token", AliasOwner{owner.StackID, owner.LogicalID, ""}, true},
		{"empty", AliasOwner{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			constrained := WithAliasOwner(ctx, tc.owner)
			_, err := aliasOwnerCommand(t, s, constrained, "CreateAlias", create)
			code := "AlreadyExistsException"
			if tc.incomplete {
				code = "AccessDeniedException"
			}
			requireAliasOwnerCode(t, err, code)
			_, err = aliasOwnerCommand(t, s, constrained, "UpdateAlias", &kmsapi.UpdateAliasInput{AliasName: name, TargetKeyId: second})
			requireAliasOwnerCode(t, err, "AccessDeniedException")
			_, err = aliasOwnerCommand(t, s, constrained, "DeleteAlias", &kmsapi.DeleteAliasInput{AliasName: name})
			requireAliasOwnerCode(t, err, "AccessDeniedException")
			if tc.incomplete {
				_, err = aliasOwnerCommand(t, s, constrained, "CreateAlias", &kmsapi.CreateAliasInput{AliasName: ptr(kmsapi.AliasNameType("alias/new")), TargetKeyId: first})
				requireAliasOwnerCode(t, err, "AccessDeniedException")
			}
			if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
				t.Fatalf("rejected identity mutated aliases: %+v", got)
			}
		})
	}
	if _, err := aliasOwnerCommand(t, s, WithAliasOwner(ctx, owner), "UpdateAlias", &kmsapi.UpdateAliasInput{AliasName: name, TargetKeyId: second}); err != nil {
		t.Fatal(err)
	}
	got := aliasOwnerRecords(t, backend, ctx)
	if len(got) != 1 || got[0].KeyID != string(*second) || got[0].Owner != owner {
		t.Fatalf("owner update lost identity or target: %+v", got)
	}
	if _, err := aliasOwnerCommand(t, s, WithAliasOwner(ctx, owner), "DeleteAlias", &kmsapi.DeleteAliasInput{AliasName: name}); err != nil {
		t.Fatal(err)
	}
	if got := aliasOwnerRecords(t, backend, ctx); len(got) != 0 {
		t.Fatalf("owner delete retained alias: %+v", got)
	}
}

func TestAliasOwnerReplayRechecksCurrentIAM(t *testing.T) {
	identity := &testIdentity{principal: authorization.Principal{ARN: "arn:aws:iam::111122223333:user/alice", ID: "AIDA11111111111111111"}, policies: []string{`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"kms:CreateAlias","Resource":"*"}}`}}
	backend := NewMemoryStorage(nil)
	s := NewWithStorage(backend, authorization.New(identity, nil))
	t.Cleanup(func() { _ = s.Close() })
	root := rootMetadata("111122223333", "us-east-1", "aws")
	rootctx := awsctx.WithMetadata(t.Context(), root)
	keyID := aliasOwnerKey(t, s, rootctx)
	user := root
	user.PrincipalARN, user.PrincipalID = identity.principal.ARN, identity.principal.ID
	ctx := WithAliasOwner(awsctx.WithMetadata(t.Context(), user), AliasOwner{"stack-a", "Alias", "create-a"})
	create := &kmsapi.CreateAliasInput{AliasName: ptr(kmsapi.AliasNameType("alias/owned")), TargetKeyId: keyID}
	if _, err := aliasOwnerCommand(t, s, ctx, "CreateAlias", create); err != nil {
		t.Fatal(err)
	}
	want := aliasOwnerRecords(t, backend, rootctx)
	for _, resource := range []string{"arn:aws:kms:us-east-1:111122223333:alias/*", "arn:aws:kms:us-east-1:111122223333:key/*"} {
		s.mu.Lock()
		identity.policies = []string{fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"kms:CreateAlias","Resource":%q}}`, resource)}
		s.mu.Unlock()
		_, err := aliasOwnerCommand(t, s, ctx, "CreateAlias", create)
		requireAliasOwnerCode(t, err, "AccessDeniedException")
		if got := aliasOwnerRecords(t, backend, rootctx); !slices.Equal(got, want) {
			t.Fatalf("unauthorized replay changed alias: %+v", got)
		}
	}
}

type failAliasWrites struct{ Storage }

func (s failAliasWrites) Attempt(ctx context.Context, fn func(Transaction) error) error {
	return s.Storage.Attempt(ctx, func(tx Transaction) error { return fn(failAliasTransaction{tx}) })
}

type failAliasTransaction struct{ Transaction }

func (tx failAliasTransaction) PutAlias(sc StorageScope, a AliasRecord) error {
	if err := tx.Transaction.PutAlias(sc, a); err != nil {
		return err
	}
	return errors.New("injected failure after tentative alias write")
}

func (tx failAliasTransaction) DeleteAlias(sc StorageScope, name string) error {
	if err := tx.Transaction.DeleteAlias(sc, name); err != nil {
		return err
	}
	return errors.New("injected failure after tentative alias deletion")
}

func TestAliasOwnerMutationRollback(t *testing.T) {
	backend := NewMemoryStorage(nil)
	s := NewWithStorage(backend, nil)
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), rootMetadata("111122223333", "us-east-1", "aws"))
	first, second := aliasOwnerKey(t, s, ctx), aliasOwnerKey(t, s, ctx)
	ctx = WithAliasOwner(ctx, AliasOwner{"stack-a", "Alias", "create-a"})
	name := ptr(kmsapi.AliasNameType("alias/owned"))
	create := &kmsapi.CreateAliasInput{AliasName: name, TargetKeyId: first}
	failing := NewWithStorage(failAliasWrites{backend}, nil)
	t.Cleanup(func() { _ = failing.Close() })
	_, err := aliasOwnerCommand(t, failing, ctx, "CreateAlias", create)
	requireAliasOwnerCode(t, err, "KMSInternalException")
	if got := aliasOwnerRecords(t, backend, ctx); len(got) != 0 {
		t.Fatalf("failed create committed alias owner: %+v", got)
	}
	if _, err := aliasOwnerCommand(t, s, ctx, "CreateAlias", create); err != nil {
		t.Fatal(err)
	}
	want := aliasOwnerRecords(t, backend, ctx)
	_, err = aliasOwnerCommand(t, failing, ctx, "UpdateAlias", &kmsapi.UpdateAliasInput{AliasName: name, TargetKeyId: second})
	requireAliasOwnerCode(t, err, "KMSInternalException")
	if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
		t.Fatalf("failed update changed owner or target: %+v", got)
	}
	_, err = aliasOwnerCommand(t, failing, ctx, "DeleteAlias", &kmsapi.DeleteAliasInput{AliasName: name})
	requireAliasOwnerCode(t, err, "KMSInternalException")
	if got := aliasOwnerRecords(t, backend, ctx); !slices.Equal(got, want) {
		t.Fatalf("failed delete lost alias owner: %+v", got)
	}
}

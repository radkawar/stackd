package apigateway

import (
	"context"
	"errors"
	"testing"

	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awsctx"
)

func TestAccountNilReplaceClearsOnlyModeledLoggingRole(t *testing.T) {
	s := New(Config{})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	other := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "222222222222", Region: "us-east-1", PrincipalARN: "arn:aws:iam::222222222222:root", PrincipalID: "222222222222"})
	role := "arn:aws:iam::111111111111:role/logging"
	otherRole := "arn:aws:iam::222222222222:role/logging"
	for _, setup := range []struct {
		ctx  context.Context
		role string
	}{{ctx, role}, {other, otherRole}} {
		if err := s.repository.Update(setup.ctx, func(tx Transaction) error {
			return tx.PutAccount(AccountRecord{Scope: scopeFor(setup.ctx), CloudWatchRoleARN: setup.role})
		}); err != nil {
			t.Fatal(err)
		}
	}
	patch := api.PatchOperation{Op: new(api.Op("replace")), Path: ptr("/cloudwatchRoleArn")}
	update := func(ctx context.Context, patches api.ListOfPatchOperation) error {
		return s.repository.Update(ctx, func(tx Transaction) error {
			_, err := s.updateAccount(tx, &api.UpdateAccountRequest{PatchOperations: patches})
			return err
		})
	}
	for _, invalid := range []api.PatchOperation{
		{Op: new(api.Op("remove")), Path: patch.Path},
		{Op: patch.Op, Path: patch.Path, From: ptr("/other")},
		{Op: patch.Op, Path: ptr("/unsupported")},
	} {
		if err := update(ctx, api.ListOfPatchOperation{patch, invalid}); err == nil {
			t.Fatal("invalid later operation did not reject the complete patch")
		}
		if retained, err := s.CloudWatchRole(ctx); err != nil || retained != role {
			t.Fatalf("failed patch changed the logging role: %q %v", retained, err)
		}
	}
	denied := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:user/unprivileged", PrincipalID: "unprivileged"})
	if err := update(denied, api.ListOfPatchOperation{patch}); err == nil {
		t.Fatal("nil reset bypassed caller authorization")
	}
	if retained, err := s.CloudWatchRole(ctx); err != nil || retained != role {
		t.Fatalf("denied reset changed the logging role: %q %v", retained, err)
	}
	rollback := errors.New("abort account reset")
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := s.updateAccount(tx, &api.UpdateAccountRequest{PatchOperations: api.ListOfPatchOperation{patch}}); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if retained, err := s.CloudWatchRole(ctx); err != nil || retained != role {
		t.Fatalf("rolled-back reset changed the logging role: %q %v", retained, err)
	}
	if err := update(ctx, api.ListOfPatchOperation{patch}); err != nil {
		t.Fatal(err)
	}
	if retained, err := s.CloudWatchRole(ctx); err != nil || retained != "" {
		t.Fatalf("nil replace did not clear the role: %q %v", retained, err)
	}
	if retained, err := s.CloudWatchRole(other); err != nil || retained != otherRole {
		t.Fatalf("reset changed another account: %q %v", retained, err)
	}
	if err := update(ctx, api.ListOfPatchOperation{patch}); err != nil {
		t.Fatalf("repeated empty reset failed: %v", err)
	}
	var ordinary string
	if err := replace(api.PatchOperation{Op: patch.Op, Path: ptr("/name")}, &ordinary); err == nil {
		t.Fatal("ordinary nil replace was relaxed")
	}
}

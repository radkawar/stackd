package iam_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/services/iam"
)

func TestIAMRepositoryRollbackAndDetachedRecords(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	record := iam.User{UserName: "alice", UserId: "AIDAEXAMPLE", Arn: "arn:aws:iam::123456789012:user/alice", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"Allow": "original"}, Attached: map[string]struct{}{}}}
	ctx := context.Background()
	if err := repository.Update(ctx, func(tx iam.WriteTx) error { return tx.PutUser(scope, record) }); err != nil {
		t.Fatal(err)
	}
	record.Inline["Allow"] = "mutated outside transaction"
	var escaped iam.ReadTx
	if err := repository.View(ctx, func(tx iam.ReadTx) error {
		escaped = tx
		u, err := tx.User(scope, "ALICE")
		if err != nil {
			return err
		}
		if u.Inline["Allow"] != "original" {
			t.Fatal("caller mutated stored input")
		}
		u.Inline["Allow"] = "mutated result"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := escaped.User(scope, "alice"); !errors.Is(err, iam.ErrClosedTransaction) {
		t.Fatalf("escaped transaction accepted: %v", err)
	}
	rollback := errors.New("rollback")
	err := repository.Update(ctx, func(tx iam.WriteTx) error {
		u, err := tx.User(scope, "alice")
		if err != nil {
			return err
		}
		if u.Inline["Allow"] != "original" {
			t.Fatal("read result mutation affected stored state")
		}
		u.Inline["Allow"] = "changed"
		if err := tx.PutUser(scope, u); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	err = repository.Update(canceled, func(tx iam.WriteTx) error {
		if err := tx.DeleteUser(scope, "alice"); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transaction=%v", err)
	}
	if err := repository.View(ctx, func(tx iam.ReadTx) error {
		u, err := tx.User(scope, "alice")
		if err != nil {
			return err
		}
		if u.Inline["Allow"] != "original" {
			t.Fatal("failed transaction was committed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIAMRepositorySharedAcrossProviders(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	first := clientFor(t, iam.NewWithRepository(nil, repository), "123456789012", "us-east-1")
	second := clientFor(t, iam.NewWithRepository(nil, repository), "123456789012", "eu-west-2")
	ctx := context.Background()
	created, err := first.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("shared")})
	if err != nil {
		t.Fatal(err)
	}
	read, err := second.GetUser(ctx, &sdkiam.GetUserInput{UserName: aws.String("shared")})
	if err != nil || aws.ToString(read.User.UserId) != aws.ToString(created.User.UserId) {
		t.Fatalf("shared backend read=%+v err=%v", read, err)
	}
	_, err = second.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("shared")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = first.GetUser(ctx, &sdkiam.GetUserInput{UserName: aws.String("shared")})
	requireCode(t, err, "NoSuchEntity")
}

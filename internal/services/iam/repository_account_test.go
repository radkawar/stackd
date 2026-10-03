package iam_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/services/iam"
)

func TestPasswordRecordsHashIsolationAndRollback(t *testing.T) {
	ctx := context.Background()
	repository := &failingIAMRepository{Repository: iam.NewMemoryRepository(nil)}
	service := iam.NewWithRepository(nil, repository)
	root := clientFor(t, service, "123456789012", "us-east-1")
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("atomic-password")})
	if err != nil {
		t.Fatal(err)
	}
	for _, canceled := range []bool{false, true} {
		repository.fail, repository.cancel = !canceled, canceled
		_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordA)})
		requireCode(t, err, "ServiceFailure")
		repository.fail, repository.cancel = false, false
		_, err = root.GetLoginProfile(ctx, &sdkiam.GetLoginProfileInput{UserName: u.User.UserName})
		requireCode(t, err, "NoSuchEntity")
	}
	_, err = root.CreateLoginProfile(ctx, &sdkiam.CreateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordA)})
	if err != nil {
		t.Fatal(err)
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	err = repository.View(ctx, func(tx iam.ReadTx) error {
		profile, err := tx.LoginProfile(scope, aws.ToString(u.User.UserId))
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(profile)
		if err != nil {
			return err
		}
		if bytes.Contains(encoded, []byte(loginPasswordA)) || len(profile.Password.Salt) < 16 || len(profile.Password.Hash) < 32 {
			t.Fatal("profile persisted plaintext or an invalid salted password hash")
		}
		profile.Password.Hash[0] ^= 1
		profile.Password.Salt[0] ^= 1
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.fail = true
	_, err = root.UpdateLoginProfile(ctx, &sdkiam.UpdateLoginProfileInput{UserName: u.User.UserName, Password: aws.String(loginPasswordB)})
	requireCode(t, err, "ServiceFailure")
	repository.fail = false
	if _, err := service.VerifyPassword(ctx, scope, "atomic-password", loginPasswordA); err != nil {
		t.Fatalf("detached mutation or failed commit changed password: %v", err)
	}
	if _, err := service.VerifyPassword(ctx, scope, "atomic-password", loginPasswordB); !errors.Is(err, iam.ErrInvalidPassword) {
		t.Fatalf("uncommitted password became valid: %v", err)
	}
	repository.fail = true
	_, err = root.CreateAccountAlias(ctx, &sdkiam.CreateAccountAliasInput{AccountAlias: aws.String("uncommitted")})
	requireCode(t, err, "ServiceFailure")
	repository.fail = false
	if _, err := service.ResolveAccountAlias(ctx, "aws", "uncommitted"); !errors.Is(err, iam.ErrRecordNotFound) {
		t.Fatalf("alias survived failed commit: %v", err)
	}
}

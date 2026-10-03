package iam_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

type failingIAMRepository struct {
	iam.Repository
	fail     bool
	cancel   bool
	observed []string
}

func (r *failingIAMRepository) Update(ctx context.Context, fn func(iam.WriteTx) error) error {
	return r.write(ctx, fn, r.Repository.Update)
}

func (r *failingIAMRepository) Attempt(ctx context.Context, fn func(iam.WriteTx) error) error {
	return r.write(ctx, fn, r.Repository.Attempt)
}

func (r *failingIAMRepository) write(ctx context.Context, fn func(iam.WriteTx) error, transaction func(context.Context, func(iam.WriteTx) error) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return transaction(ctx, func(tx iam.WriteTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		users, err := tx.Users(iam.Scope{Partition: "aws", AccountID: "123456789012"})
		if err != nil {
			return err
		}
		for _, u := range users {
			records, err := tx.PrincipalCredentials("123456789012", u.UserId)
			if err != nil {
				return err
			}
			for _, record := range records {
				r.observed = append(r.observed, record.Credential.AccessKeyID)
			}
		}
		if r.fail {
			return errors.New("injected commit failure")
		}
		if r.cancel {
			cancel()
		}
		return nil
	})
}

func TestIAMCredentialsShareResourceCommit(t *testing.T) {
	repository := &failingIAMRepository{Repository: iam.NewMemoryRepository(nil)}
	credentials := identity.NewWithRepository("123456789012", iam.NewCredentialRepository(repository, nil))
	service := iam.NewWithRepository(credentials, repository)
	client := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	user, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("atomic")})
	if err != nil {
		t.Fatal(err)
	}
	for _, cancel := range []bool{false, true} {
		repository.fail = !cancel
		repository.cancel = cancel
		_, err = client.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: aws.String("atomic")})
		requireCode(t, err, "ServiceFailure")
		repository.fail = false
		repository.cancel = false
		for _, key := range repository.observed {
			if _, err := credentials.Resolve(ctx, key); !errors.Is(err, identity.ErrNotFound) {
				t.Fatalf("rolled-back key was published: %v", err)
			}
		}
		keys, err := client.ListAccessKeys(ctx, &sdkiam.ListAccessKeysInput{UserName: aws.String("atomic")})
		if err != nil || len(keys.AccessKeyMetadata) != 0 {
			t.Fatalf("rolled-back key listing=%+v err=%v", keys, err)
		}
	}
	created, err := client.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: aws.String("atomic")})
	if err != nil {
		t.Fatal(err)
	}
	key := aws.ToString(created.AccessKey.AccessKeyId)
	repository.fail = true
	_, err = client.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: aws.String("atomic"), NewUserName: aws.String("renamed")})
	requireCode(t, err, "ServiceFailure")
	repository.fail = false
	resolved, err := credentials.Resolve(ctx, key)
	if err != nil || resolved.UserName != "atomic" || resolved.PrincipalARN != aws.ToString(user.User.Arn) {
		t.Fatalf("rolled-back rename changed credential: %+v %v", resolved, err)
	}
	current, err := client.GetUser(ctx, &sdkiam.GetUserInput{UserName: aws.String("atomic")})
	if err != nil || aws.ToString(current.User.UserName) != "atomic" {
		t.Fatalf("rolled-back rename changed user: %+v %v", current, err)
	}
	_, err = client.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: aws.String("atomic"), NewUserName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = credentials.Resolve(ctx, key)
	if err != nil || resolved.UserName != "renamed" {
		t.Fatalf("successful rename not shared: %+v %v", resolved, err)
	}
}

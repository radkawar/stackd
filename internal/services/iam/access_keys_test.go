package iam_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func TestAccessKeyLifecycleThroughSDK(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	store := identity.NewWithRepository("123456789012", iam.NewCredentialRepository(repository, nil))
	s := iam.NewWithRepository(store, repository)
	c := clientFor(t, s, "123456789012", "us-east-1")
	otherRegion := clientFor(t, s, "123456789012", "eu-west-1")
	otherAccount := clientFor(t, s, "999999999999", "us-east-1")
	ctx := context.Background()
	u, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("KeyOwner")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("OtherOwner")})
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: aws.String("KeyOwner")})
	if err != nil {
		t.Fatal(err)
	}
	key := aws.ToString(first.AccessKey.AccessKeyId)
	if first.AccessKey.Status != types.StatusTypeActive || first.AccessKey.CreateDate == nil || len(aws.ToString(first.AccessKey.SecretAccessKey)) != 40 {
		t.Fatal("invalid access key response")
	}
	resolved, err := store.Resolve(ctx, key)
	if err != nil || resolved.PrincipalID != aws.ToString(u.User.UserId) || resolved.SecretAccessKey != aws.ToString(first.AccessKey.SecretAccessKey) {
		t.Fatalf("credential store principal = %v, %v", resolved, err)
	}
	unused, err := c.GetAccessKeyLastUsed(ctx, &sdkiam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(key)})
	if err != nil || unused.AccessKeyLastUsed.LastUsedDate != nil || aws.ToString(unused.AccessKeyLastUsed.ServiceName) != "N/A" {
		t.Fatalf("unused key metadata: %+v, %v", unused, err)
	}
	if err := store.RecordUsage(ctx, key, "sts", "eu-west-1"); err != nil {
		t.Fatal(err)
	}
	used, err := c.GetAccessKeyLastUsed(ctx, &sdkiam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(key)})
	if err != nil || used.AccessKeyLastUsed.LastUsedDate == nil || aws.ToString(used.AccessKeyLastUsed.ServiceName) != "sts" || aws.ToString(used.AccessKeyLastUsed.Region) != "eu-west-1" {
		t.Fatalf("used key metadata: %+v, %v", used, err)
	}
	_, err = c.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: aws.String("KeyOwner")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{UserName: aws.String("KeyOwner")})
	requireCode(t, err, "LimitExceeded")
	_, err = c.UpdateAccessKey(ctx, &sdkiam.UpdateAccessKeyInput{UserName: aws.String("KeyOwner"), AccessKeyId: aws.String(key), Status: types.StatusTypeInactive})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Resolve(ctx, key)
	if !errors.Is(err, identity.ErrInactive) {
		t.Fatalf("inactive key resolved: %v", err)
	}
	_, err = c.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("KeyOwner")})
	requireCode(t, err, "DeleteConflict")
	_, err = c.DeleteAccessKey(ctx, &sdkiam.DeleteAccessKeyInput{UserName: aws.String("OtherOwner"), AccessKeyId: aws.String(key)})
	requireCode(t, err, "NoSuchEntity")
	_, err = otherAccount.GetAccessKeyLastUsed(ctx, &sdkiam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(key)})
	requireCode(t, err, "NoSuchEntity")
	_, err = c.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: aws.String("KeyOwner"), NewUserName: aws.String("Renamed"), NewPath: aws.String("/staff/")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.UpdateAccessKey(ctx, &sdkiam.UpdateAccessKeyInput{UserName: aws.String("Renamed"), AccessKeyId: aws.String(key), Status: types.StatusTypeActive})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = store.Resolve(ctx, key)
	if err != nil || resolved.UserName != "Renamed" || resolved.PrincipalARN != "arn:aws:iam::123456789012:user/staff/Renamed" {
		t.Fatalf("renamed credentials: %v, %v", resolved, err)
	}
	pager := sdkiam.NewListAccessKeysPaginator(otherRegion, &sdkiam.ListAccessKeysInput{UserName: aws.String("Renamed"), MaxItems: aws.Int32(1)})
	count := 0
	for pager.HasMorePages() {
		out, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, metadata := range out.AccessKeyMetadata {
			if aws.ToString(metadata.UserName) != "Renamed" {
				t.Fatalf("key owner not renamed: %+v", metadata)
			}
			_, err = c.DeleteAccessKey(ctx, &sdkiam.DeleteAccessKeyInput{UserName: aws.String("Renamed"), AccessKeyId: metadata.AccessKeyId})
			if err != nil {
				t.Fatal(err)
			}
			count++
		}
	}
	if count != 2 {
		t.Fatalf("listed %d keys, want 2", count)
	}
	_, err = store.Resolve(ctx, key)
	if !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("deleted key resolved: %v", err)
	}
	_, err = c.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("Renamed")})
	if err != nil {
		t.Fatal(err)
	}
}

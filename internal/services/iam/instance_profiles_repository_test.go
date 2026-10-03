package iam_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/services/iam"
)

func TestInstanceProfileRepositoryTransactions(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	record := iam.InstanceProfile{InstanceProfileName: "Profile", InstanceProfileId: "AIPAIMMUTABLE", Path: "/", Arn: "arn:aws:iam::123456789012:instance-profile/Profile", CreateDate: time.Now().UTC(), Tags: []iam.Tag{{Key: "team", Value: "original"}}}
	ctx := context.Background()
	if err := repository.Update(ctx, func(tx iam.WriteTx) error { return tx.PutInstanceProfile(scope, record) }); err != nil {
		t.Fatal(err)
	}
	record.Tags[0].Value = "external mutation"
	var escaped iam.ReadTx
	if err := repository.View(ctx, func(tx iam.ReadTx) error {
		escaped = tx
		got, err := tx.InstanceProfile(scope, "PROFILE")
		if err != nil || got.Tags[0].Value != "original" {
			t.Fatalf("detached record = %+v, %v", got, err)
		}
		got.Tags[0].Value = "snapshot mutation"
		_, err = tx.InstanceProfile(iam.Scope{Partition: "aws-cn", AccountID: scope.AccountID}, "Profile")
		if !errors.Is(err, iam.ErrRecordNotFound) {
			t.Fatalf("cross-partition record error = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := escaped.InstanceProfile(scope, "Profile"); !errors.Is(err, iam.ErrClosedTransaction) {
		t.Fatalf("escaped transaction error = %v", err)
	}
	failure := errors.New("injected transaction failure")
	if err := repository.Update(ctx, func(tx iam.WriteTx) error {
		if err := tx.DeleteInstanceProfile(scope, "profile"); err != nil {
			return err
		}
		return failure
	}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	if err := repository.Update(canceled, func(tx iam.WriteTx) error {
		got, err := tx.InstanceProfile(scope, "profile")
		if err != nil {
			return err
		}
		got.Tags[0].Value = "canceled"
		if err := tx.PutInstanceProfile(scope, got); err != nil {
			return err
		}
		cancel()
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled update = %v", err)
	}
	if err := repository.View(ctx, func(tx iam.ReadTx) error {
		profiles, err := tx.InstanceProfiles(scope)
		if err != nil || len(profiles) != 1 || profiles[0].Tags[0].Value != "original" {
			t.Fatalf("rollback state = %+v, %v", profiles, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type rejectProfileRepository struct{ iam.Repository }

func (r rejectProfileRepository) Update(ctx context.Context, fn func(iam.WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx iam.WriteTx) error { return fn(rejectProfileTx{tx}) })
}

type rejectProfileTx struct{ iam.WriteTx }

func (tx rejectProfileTx) PutInstanceProfile(scope iam.Scope, record iam.InstanceProfile) error {
	if err := tx.WriteTx.PutInstanceProfile(scope, record); err != nil {
		return err
	}
	return errors.New("injected instance profile persistence failure")
}

func TestInstanceProfileMembershipPersistenceFailure(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	c := clientFor(t, iam.NewWithRepository(nil, repository), "123456789012", "us-east-1")
	ctx := context.Background()
	if _, err := c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("Atomic")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("Compute"), AssumeRolePolicyDocument: aws.String(trustEC2)}); err != nil {
		t.Fatal(err)
	}
	failing := clientFor(t, iam.NewWithRepository(nil, rejectProfileRepository{repository}), "123456789012", "us-east-1")
	_, err := failing.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String("Atomic"), RoleName: aws.String("Compute")})
	requireCode(t, err, "ServiceFailure")
	got, err := c.GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String("Atomic")})
	if err != nil || len(got.InstanceProfile.Roles) != 0 {
		t.Fatalf("failed association published state: %+v, %v", got, err)
	}
	if _, err := c.DeleteRole(ctx, &sdkiam.DeleteRoleInput{RoleName: aws.String("Compute")}); err != nil {
		t.Fatalf("failed association blocked role deletion: %v", err)
	}
}

func TestInstanceProfileDefaultQuota(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	ctx := context.Background()
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	if err := repository.Update(ctx, func(tx iam.WriteTx) error {
		for i := range 1000 {
			name := fmt.Sprintf("Profile%04d", i)
			p := iam.InstanceProfile{InstanceProfileName: name, InstanceProfileId: fmt.Sprintf("AIPA%017d", i), Path: "/", Arn: "arn:aws:iam::123456789012:instance-profile/" + name, CreateDate: time.Now().UTC()}
			if err := tx.PutInstanceProfile(scope, p); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c := clientFor(t, iam.NewWithRepository(nil, repository), scope.AccountID, "us-east-1")
	_, err := c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("Excess")})
	requireCode(t, err, "LimitExceeded")
	if _, err := c.DeleteInstanceProfile(ctx, &sdkiam.DeleteInstanceProfileInput{InstanceProfileName: aws.String("Profile0000")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("Replacement")}); err != nil {
		t.Fatalf("delete did not release quota: %v", err)
	}
}

package iam_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"stackd/internal/services/iam"
)

func newServiceCredentialTestService(t *testing.T) (*iam.Service, *sdkiam.Client) {
	t.Helper()
	service := iam.New()
	return service, clientFor(t, service, "123456789012", "us-east-1")
}

func TestIAMServiceCredentialsRepositoryRollbackExpiryAndIdentity(t *testing.T) {
	repository := &failingIAMRepository{Repository: iam.NewMemoryRepository(nil)}
	service := iam.NewWithRepository(nil, repository)
	root := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("atomic-service-credential")})
	if err != nil {
		t.Fatal(err)
	}
	create := &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String("logs.amazonaws.com"), CredentialAgeDays: aws.Int32(1)}
	for _, canceled := range []bool{false, true} {
		repository.fail, repository.cancel = !canceled, canceled
		_, err = root.CreateServiceSpecificCredential(ctx, create)
		requireCode(t, err, "ServiceFailure")
		repository.fail, repository.cancel = false, false
		listed, err := root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: u.User.UserName})
		if err != nil || len(listed.ServiceSpecificCredentials) != 0 {
			t.Fatalf("uncommitted secret became visible: %+v %v", listed, err)
		}
	}
	created, err := root.CreateServiceSpecificCredential(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	credential := created.ServiceSpecificCredential
	identifier, secret := serviceCredentialMaterial(credential)
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	id := aws.ToString(credential.ServiceSpecificCredentialId)
	err = repository.View(ctx, func(tx iam.ReadTx) error {
		record, err := tx.ServiceCredential(scope, id)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if bytes.Contains(encoded, []byte(secret)) || record.SecretDigest == [32]byte{} {
			t.Fatal("service credential persisted plaintext or an empty verifier")
		}
		record.SecretDigest[0] ^= 1
		*record.ExpirationDate = time.Now().Add(-time.Hour)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.fail = true
	_, err = root.ResetServiceSpecificCredential(ctx, &sdkiam.ResetServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId})
	requireCode(t, err, "ServiceFailure")
	repository.fail = false
	if _, err := service.VerifyServiceCredential(ctx, scope, "logs.amazonaws.com", identifier, secret); err != nil {
		t.Fatalf("detached mutation or rollback changed the live credential: %v", err)
	}
	err = repository.Update(ctx, func(tx iam.WriteTx) error {
		record, err := tx.ServiceCredential(scope, id)
		if err != nil {
			return err
		}
		expiration := time.Now().UTC().Add(-time.Second)
		record.ExpirationDate = &expiration
		return tx.PutServiceCredential(scope, record)
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.VerifyServiceCredential(ctx, scope, "logs.amazonaws.com", identifier, secret)
	if !errors.Is(err, iam.ErrInvalidServiceCredential) {
		t.Fatal("expired credential authenticated")
	}
	listed, err := root.ListServiceSpecificCredentials(ctx, &sdkiam.ListServiceSpecificCredentialsInput{UserName: u.User.UserName})
	if err != nil || len(listed.ServiceSpecificCredentials) != 1 || listed.ServiceSpecificCredentials[0].Status != types.StatusTypeExpired {
		t.Fatalf("expired credential metadata: %+v %v", listed, err)
	}
	_, err = root.ResetServiceSpecificCredential(ctx, &sdkiam.ResetServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId})
	requireCode(t, err, "InvalidInput")
	_, err = root.UpdateServiceSpecificCredential(ctx, &sdkiam.UpdateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceSpecificCredentialId: credential.ServiceSpecificCredentialId, Status: types.StatusTypeActive})
	requireCode(t, err, "InvalidInput")
	// A detached credential record cannot authenticate a replacement identity
	// even if an external repository removes its owner without the API guard.
	err = repository.Update(ctx, func(tx iam.WriteTx) error {
		record, err := tx.ServiceCredential(scope, id)
		if err != nil {
			return err
		}
		record.ExpirationDate = nil
		if err := tx.PutServiceCredential(scope, record); err != nil {
			return err
		}
		return tx.DeleteUser(scope, aws.ToString(u.User.UserName))
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: u.User.UserName})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.VerifyServiceCredential(ctx, scope, "logs.amazonaws.com", identifier, secret)
	if !errors.Is(err, iam.ErrInvalidServiceCredential) {
		t.Fatal("deleted user credential authenticated a replacement identity")
	}
}

func TestIAMServiceCredentialsConcurrentQuota(t *testing.T) {
	_, root := newServiceCredentialTestService(t)
	ctx := context.Background()
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("concurrent-service-user")})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		workers.Go(func() {
			_, err := root.CreateServiceSpecificCredential(ctx, &sdkiam.CreateServiceSpecificCredentialInput{UserName: u.User.UserName, ServiceName: aws.String("cassandra.amazonaws.com")})
			results <- err
		})
	}
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "LimitExceeded" {
			t.Fatalf("unexpected concurrent create error: %v", err)
		}
	}
	if successes != 2 {
		t.Fatalf("concurrent quota admitted %d credentials, want 2", successes)
	}
}

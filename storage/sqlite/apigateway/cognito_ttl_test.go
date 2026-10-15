package apigateway_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	domain "stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/storage/sqlite"
	store "stackd/storage/sqlite/apigateway"
)

func TestCognitoTTLNullZeroAndPatchedValueSurviveReopen(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "cognito.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	repository := store.New(db)
	key := domain.APIKey{Scope: domain.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, ID: "api"}
	rows := []domain.AuthorizerRecord{
		{Key: domain.AuthorizerKey{APIKey: key, AuthorizerID: "omitted"}, Name: "omitted", ProviderARNs: []string{"arn:aws:cognito-idp:us-east-1:111111111111:userpool/us-east-1_NativePool"}},
		{Key: domain.AuthorizerKey{APIKey: key, AuthorizerID: "zero"}, Name: "zero", CognitoTTLSeconds: new(int32(0)), ProviderARNs: []string{"arn:aws:cognito-idp:us-east-1:111111111111:userpool/us-east-1_NativePool"}},
		{Key: domain.AuthorizerKey{APIKey: key, AuthorizerID: "patched"}, Name: "patched", CognitoTTLSeconds: new(int32(300)), ProviderARNs: []string{"arn:aws:cognito-idp:us-east-1:111111111111:userpool/us-east-1_NativePool"}},
		{Key: domain.AuthorizerKey{APIKey: key, AuthorizerID: "lambda"}, Name: "lambda", LambdaAuthorizer: &apigatewayexec.LambdaAuthorizer{Type: "TOKEN", FunctionARN: "arn:aws:lambda:us-east-1:111111111111:function:authorizer", IdentitySources: []string{"method.request.header.Authorization"}, TTLSeconds: 60}},
	}
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		if err := tx.PutAPI(domain.APIRecord{Key: key, Name: "cognito", Created: time.Date(2035, 1, 2, 0, 0, 0, 0, time.UTC)}); err != nil {
			return err
		}
		for _, row := range rows {
			if err := tx.PutAuthorizer(row); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository = store.New(db)
	rollback := errors.New("abort retained Cognito TTL")
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		row, err := tx.Authorizer(rows[2].Key)
		if err != nil {
			return err
		}
		row.CognitoTTLSeconds = new(int32(0))
		if err := tx.PutAuthorizer(row); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if err := repository.View(ctx, func(r domain.Reader) error {
		for _, expected := range rows {
			actual, err := r.Authorizer(expected.Key)
			if err != nil {
				return err
			}
			if (actual.CognitoTTLSeconds == nil) != (expected.CognitoTTLSeconds == nil) || actual.CognitoTTLSeconds != nil && *actual.CognitoTTLSeconds != *expected.CognitoTTLSeconds {
				t.Fatalf("nullable TTL changed across reopen/rollback: %#v", actual)
			}
			if (actual.LambdaAuthorizer == nil) != (expected.LambdaAuthorizer == nil) || actual.LambdaAuthorizer != nil && actual.LambdaAuthorizer.TTLSeconds != 60 {
				t.Fatalf("Cognito control TTL changed Lambda cache configuration: %#v", actual)
			}
		}
		foreign := rows[2].Key
		foreign.AccountID = "222222222222"
		if _, err := r.Authorizer(foreign); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("account isolation: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(ctx, func(tx domain.Transaction) error {
		row, err := tx.Authorizer(rows[2].Key)
		if err != nil {
			return err
		}
		row.CognitoTTLSeconds = nil
		return tx.PutAuthorizer(row)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(ctx, func(r domain.Reader) error {
		row, err := r.Authorizer(rows[2].Key)
		if err == nil && row.CognitoTTLSeconds != nil {
			t.Fatal("nullable upsert retained stale TTL")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

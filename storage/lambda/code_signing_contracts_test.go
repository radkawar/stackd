package lambda_test

import (
	"errors"
	"path/filepath"
	"testing"

	"stackd/storage/lambda"
	"stackd/storage/sqlite"
	sqllambda "stackd/storage/sqlite/lambda"
)

func TestCodeSigningAttachmentRollbackAndFunctionDeletion(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		function := deployment()
		config := lambda.CodeSigningConfigRecord{Key: lambda.CodeSigningConfigKey{Scope: function.Key.Scope, ID: "csc-0123456789abcdef0"}, Policy: "Enforce", Publishers: []string{"arn:aws:signer:us-east-1:111111111111:/signing-profiles/publisher/0123456789"}, Tags: map[string]string{"team": "release"}, Modified: function.Modified}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(function); err != nil {
				return err
			}
			if err := tx.PutCodeSigningConfig(config); err != nil {
				return err
			}
			return tx.PutFunctionCodeSigningConfig(function.Key, config.Key)
		}); err != nil {
			t.Fatal(err)
		}
		abort := errors.New("abort deployment change")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			changed := config
			changed.Policy = "Warn"
			if err := tx.PutCodeSigningConfig(changed); err != nil {
				return err
			}
			if err := tx.DeleteFunction(function.Key); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			stored, err := r.CodeSigningConfig(config.Key)
			if err != nil {
				return err
			}
			if stored.Policy != "Enforce" {
				t.Fatalf("aborted update weakened policy: %q", stored.Policy)
			}
			attached, err := r.FunctionCodeSigningConfig(function.Key)
			if err != nil {
				return err
			}
			if attached != config.Key {
				t.Fatalf("aborted deletion lost attachment: %#v", attached)
			}
			foreign := config.Key.Scope
			foreign.Account = "222222222222"
			configs, err := r.CodeSigningConfigs(foreign)
			if err != nil {
				return err
			}
			if len(configs) != 0 {
				t.Fatal("code signing configuration crossed accounts")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteFunction(function.Key); err != nil {
				return err
			}
			if _, err := tx.FunctionCodeSigningConfig(function.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("deleted function retained attachment: %v", err)
			}
			functions, err := tx.FunctionsByCodeSigningConfig(config.Key)
			if err != nil {
				return err
			}
			if len(functions) != 0 {
				t.Fatal("deleted function blocks configuration cleanup")
			}
			return tx.DeleteCodeSigningConfig(config.Key)
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCodeSigningConfigurationSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "code-signing.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	function := deployment()
	config := lambda.CodeSigningConfigRecord{Key: lambda.CodeSigningConfigKey{Scope: function.Key.Scope, ID: "csc-0123456789abcdef0"}, Description: "release admission", Policy: "Enforce", Publishers: []string{"arn:aws:signer:us-east-1:111111111111:/signing-profiles/publisher/0123456789"}, Tags: map[string]string{"team": "release"}, Modified: function.Modified}
	err = sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutFunction(function); err != nil {
			return err
		}
		if err := tx.PutCodeSigningConfig(config); err != nil {
			return err
		}
		return tx.PutFunctionCodeSigningConfig(function.Key, config.Key)
	})
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := sqllambda.New(db).View(t.Context(), func(r lambda.Reader) error {
		v, err := r.CodeSigningConfig(config.Key)
		if err != nil {
			return err
		}
		if v.Policy != "Enforce" || v.Description != config.Description || len(v.Publishers) != 1 || v.Publishers[0] != config.Publishers[0] || v.Tags["team"] != "release" {
			t.Fatalf("reopened admission policy differs: %#v", v)
		}
		attached, err := r.FunctionCodeSigningConfig(function.Key)
		if err != nil {
			return err
		}
		if attached != config.Key {
			t.Fatalf("reopened attachment differs: %#v", attached)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

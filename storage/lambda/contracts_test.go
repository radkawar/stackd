package lambda_test

import (
	"bytes"
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/storage/lambda"
	"stackd/storage/sqlite"
	sqllambda "stackd/storage/sqlite/lambda"
)

func forRepositories(t *testing.T, run func(*testing.T, lambda.Repository)) {
	t.Helper()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "memory" {
				run(t, lambda.NewMemory(nil))
				return
			}
			db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "lambda.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Error(err)
				}
			})
			run(t, sqllambda.New(db))
		})
	}
}

func deployment() lambda.FunctionRecord {
	return lambda.FunctionRecord{
		Key:     lambda.FunctionKey{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "function"},
		Runtime: "nodejs22.x", Handler: "index.handler", Role: "arn:aws:iam::111111111111:role/execution", Description: "deployment", Architecture: "x86_64",
		CodeSize: 4, CodeSHA256: "hash", Variables: map[string]string{"ENV": "old"}, Tags: map[string]string{"tag": "old"},
		Timeout: 10, MemoryMB: 256, EphemeralMB: 512, Revision: "revision", Modified: time.Date(2026, 9, 13, 12, 0, 0, 123000000, time.UTC),
		State: "Pending", StateReason: "Creating", StateReasonCode: "Creating", UpdateStatus: "InProgress", UpdateReason: "Updating",
	}
}

func TestDeploymentCollectionsAreDetachedAndReplacedAtomically(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		v := deployment()
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(v); err != nil {
				return err
			}
			v.Variables["ENV"] = "caller mutation"
			v.Tags["tag"] = "caller mutation"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				got, err := r.Function(v.Key)
				if err != nil {
					return err
				}
				if got.Variables["ENV"] != "old" || got.Tags["tag"] != "old" {
					t.Fatal("caller or reader mutation changed stored collections")
				}
				got.Variables["ENV"] = "reader mutation"
				got.Tags["tag"] = "reader mutation"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		replacement := deployment()
		replacement.CodeSHA256 = "replacement-hash"
		replacement.CodeSize = 7
		replacement.Variables = map[string]string{"NEW": "value"}
		replacement.Tags = nil
		replacement.Revision = "replacement"
		abort := errors.New("abort deployment")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(replacement); err != nil {
				return err
			}
			if err := tx.DeleteFunction(v.Key); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal("rollback error:", err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			got, err := r.Function(v.Key)
			if err == nil && (got.CodeSHA256 != deployment().CodeSHA256 || got.Variables["ENV"] != "old" || got.Tags["tag"] != "old") {
				t.Fatal("rollback lost the original deployment or child collections")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutFunction(replacement) }); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			got, err := r.Function(v.Key)
			if err == nil && (got.CodeSHA256 != replacement.CodeSHA256 || !maps.Equal(got.Variables, replacement.Variables) || len(got.Tags) != 0 || got.Revision != replacement.Revision) {
				t.Fatal("overwrite retained an obsolete artifact or collection entry")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.DeleteFunction(v.Key) }); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			if _, err := r.Function(v.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatal("deleted deployment is still available:", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// Re-creation must not encounter surviving child keys or restore old values.
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutFunction(deployment()) }); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDeploymentScopeOrderingAndTransactionBoundaries(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		keys := []lambda.FunctionKey{
			{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "a"},
			{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "z"},
			{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-west-2"}, Name: "a"},
			{Scope: lambda.Scope{Partition: "aws", Account: "222222222222", Region: "us-east-1"}, Name: "a"},
			{Scope: lambda.Scope{Partition: "aws-cn", Account: "111111111111", Region: "us-east-1"}, Name: "a"},
		}
		var escaped lambda.Transaction
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			escaped = tx
			for i := len(keys) - 1; i >= 0; i-- {
				v := deployment()
				v.Key = keys[i]
				if err := tx.PutFunction(v); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := escaped.DeleteFunction(keys[0]); err == nil {
			t.Fatal("escaped transaction deleted a function")
		}
		if _, err := escaped.AllFunctions(); err == nil {
			t.Fatal("escaped transaction read functions")
		}
		var escapedReader lambda.Reader
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			escapedReader = r
			if _, ok := r.(lambda.Transaction); ok {
				t.Fatal("read-only callback exposes writer methods")
			}
			if err := repo.Update(r.Context(), func(tx lambda.Transaction) error { return tx.DeleteFunction(keys[0]) }); err == nil {
				t.Fatal("read-only context acquired a writer")
			}
			all, err := r.AllFunctions()
			if err != nil {
				return err
			}
			got := make([]lambda.FunctionKey, len(all))
			for i, v := range all {
				got[i] = v.Key
			}
			if !reflect.DeepEqual(got, keys) {
				t.Fatalf("scope/name order: got %v want %v", got, keys)
			}
			local, err := r.Functions(keys[0].Scope)
			if err != nil {
				return err
			}
			if len(local) != 2 || local[0].Key != keys[0] || local[1].Key != keys[1] {
				t.Fatalf("scope isolation or name ordering failed: %v", local)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := escapedReader.Function(keys[0]); err == nil {
			t.Fatal("escaped reader read a deployment")
		}
	})
}

func TestPendingDeploymentIsolationPromotionAndDeletion(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		active := deployment()
		candidate := deployment()
		candidate.CodeSHA256 = "candidate-hash"
		candidate.CodeSize = 13
		candidate.Variables = map[string]string{"NEXT": "candidate"}
		candidate.Tags = map[string]string{"tag": "candidate"}
		candidate.Revision = "candidate"
		other := deployment()
		other.Key.Name = "z-pending-only"
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(active); err != nil {
				return err
			}
			if err := tx.PutPendingFunction(other); err != nil {
				return err
			}
			if err := tx.PutPendingFunction(candidate); err != nil {
				return err
			}
			candidate.Variables["NEXT"] = "mutated"
			candidate.Tags["tag"] = "mutated"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := repo.View(t.Context(), func(r lambda.Reader) error {
				got, err := r.Function(active.Key)
				if err != nil {
					return err
				}
				if got.CodeSHA256 != active.CodeSHA256 || !maps.Equal(got.Variables, active.Variables) || !maps.Equal(got.Tags, active.Tags) {
					t.Fatal("staging changed the active deployment")
				}
				pending, err := r.PendingFunction(active.Key)
				if err != nil {
					return err
				}
				if pending.CodeSHA256 != "candidate-hash" || pending.Variables["NEXT"] != "candidate" || pending.Tags["tag"] != "candidate" {
					t.Fatal("candidate artifact or child collections were aliased or mixed with active state")
				}
				pending.Variables["NEXT"] = "mutated"
				pending.Tags["tag"] = "mutated"
				all, err := r.AllFunctions()
				if err != nil {
					return err
				}
				local, err := r.Functions(active.Key.Scope)
				if err != nil {
					return err
				}
				if len(all) != 1 || all[0].Key != active.Key || len(local) != 1 || local[0].Revision != active.Revision {
					t.Fatal("active lists exposed pending deployments")
				}
				if _, err := r.Function(other.Key); !errors.Is(err, lambda.ErrNotFound) {
					t.Fatal("pending-only deployment appeared active:", err)
				}
				candidates, err := r.PendingFunctions()
				if err != nil {
					return err
				}
				if len(candidates) != 2 || candidates[0].Key != active.Key || candidates[1].Key != other.Key || candidates[0].Revision != "candidate" {
					t.Fatal("recovery list lost or misordered candidate deployments")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		promote := func(tx lambda.Transaction) error {
			pending, err := tx.PendingFunction(active.Key)
			if err != nil {
				return err
			}
			if err := tx.PutFunction(pending); err != nil {
				return err
			}
			return tx.DeletePendingFunction(active.Key)
		}
		abort := errors.New("abort promotion")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := promote(tx); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal("promotion rollback:", err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			got, err := r.Function(active.Key)
			if err != nil {
				return err
			}
			pending, err := r.PendingFunction(active.Key)
			if err == nil && (got.Revision != active.Revision || pending.Revision != "candidate") {
				t.Fatal("aborted promotion published active state or lost candidate")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), promote); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			got, err := r.Function(active.Key)
			if err != nil {
				return err
			}
			if got.CodeSHA256 != "candidate-hash" || got.Variables["NEXT"] != "candidate" || len(got.Variables) != 1 || got.Tags["tag"] != "candidate" {
				t.Fatal("promotion did not replace active artifact and collections")
			}
			if _, err := r.PendingFunction(active.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatal("promotion retained candidate:", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutPendingFunction(active); err != nil {
				return err
			}
			return tx.DeleteFunction(active.Key)
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			if _, err := r.Function(active.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatal("delete retained active deployment:", err)
			}
			if _, err := r.PendingFunction(active.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatal("delete retained candidate deployment:", err)
			}
			pending, err := r.PendingFunctions()
			if err == nil && (len(pending) != 1 || pending[0].Key != other.Key) {
				t.Fatal("delete affected another function's candidate")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCodeArchivesRetainBothDeploymentSlotsAndIsolateScopes(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		active := deployment()
		pending := deployment()
		pending.CodeSHA256, pending.CodeSize = "pending", 9
		now := active.Modified
		activeKey := lambda.CodeArchiveKey{Scope: active.Key.Scope, SHA256: active.CodeSHA256}
		pendingKey := lambda.CodeArchiveKey{Scope: active.Key.Scope, SHA256: pending.CodeSHA256}
		foreignKey := activeKey
		foreignKey.Region = "us-west-2"
		signing := lambda.CodeSigningKey{Scope: active.Key.Scope, AccessKeyID: "download", SecretAccessKey: "secret"}
		until := now.Add(time.Minute)
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			for _, archive := range []lambda.CodeArchive{
				{Key: activeKey, Code: []byte("ZIP!"), CreatedAt: now, RetainUntil: until},
				{Key: pendingKey, Code: []byte("candidate"), CreatedAt: now, RetainUntil: now},
				{Key: foreignKey, Code: []byte("foreign"), CreatedAt: now, RetainUntil: now},
			} {
				if err := tx.PutCodeArchive(archive); err != nil {
					return err
				}
			}
			if err := tx.PutFunction(active); err != nil {
				return err
			}
			if err := tx.PutPendingFunction(pending); err != nil {
				return err
			}
			return tx.PutCodeSigningKey(signing)
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			deleted, err := tx.DeleteExpiredCodeArchives(now.Add(time.Nanosecond))
			if err != nil {
				return err
			}
			if deleted != 1 {
				t.Fatalf("collection crossed deployment slots or scopes: deleted %d", deleted)
			}
			if _, err := tx.CodeArchive(foreignKey); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("unreferenced foreign archive survived: %v", err)
			}
			for _, key := range []lambda.CodeArchiveKey{activeKey, pendingKey} {
				if _, err := tx.CodeArchive(key); err != nil {
					return err
				}
			}
			if _, found, err := tx.NextCodeArchiveDeadline(); err != nil || found {
				t.Fatalf("referenced archive scheduled for collection: found=%v err=%v", found, err)
			}
			usage, err := tx.AccountUsage(active.Key.Scope)
			if err != nil {
				return err
			}
			if usage.FunctionCount != 1 || usage.TotalCodeSize != 4 {
				t.Fatalf("usage included retained archives or pending code: %+v", usage)
			}
			return tx.DeleteFunction(active.Key)
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			deadline, found, err := tx.NextCodeArchiveDeadline()
			if err != nil || !found || !deadline.Equal(now.Add(time.Nanosecond)) {
				t.Fatalf("released candidate deadline: %v %v %v", deadline, found, err)
			}
			deleted, err := tx.DeleteExpiredCodeArchives(until)
			if err != nil || deleted != 1 {
				t.Fatalf("strict retention boundary: deleted=%d err=%v", deleted, err)
			}
			archive, err := tx.CodeArchive(activeKey)
			if err != nil || string(archive.Code) != "ZIP!" {
				t.Fatalf("function deletion revoked retained code: %+v %v", archive, err)
			}
			deadline, found, err = tx.NextCodeArchiveDeadline()
			if err != nil || !found || !deadline.Equal(until.Add(time.Nanosecond)) {
				t.Fatalf("retained URL deadline: %v %v %v", deadline, found, err)
			}
			deleted, err = tx.DeleteExpiredCodeArchives(deadline)
			if err != nil || deleted != 1 {
				t.Fatalf("expired archive was not collected: deleted=%d err=%v", deleted, err)
			}
			if _, err := tx.CodeArchive(activeKey); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("collected archive remains readable: %v", err)
			}
			if _, found, err := tx.NextCodeArchiveDeadline(); err != nil || found {
				t.Fatalf("empty archive repository retained a deadline: %v %v", found, err)
			}
			key, err := tx.CodeSigningKey(signing.Scope)
			if err != nil || key != signing {
				t.Fatalf("function/archive deletion revoked signing key: %+v %v", key, err)
			}
			if _, err := tx.CodeSigningKey(foreignKey.Scope); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("signing key leaked across scopes: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCodeArchiveImmutabilityRetentionAndRollback(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		function := deployment()
		key := lambda.CodeArchiveKey{Scope: function.Key.Scope, SHA256: function.CodeSHA256}
		now := function.Modified
		original := []byte{'P', 'K', 0, 255}
		until := now.Add(time.Minute)
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			input := bytes.Clone(original)
			if err := tx.PutCodeArchive(lambda.CodeArchive{Key: key, Code: input, CreatedAt: now, RetainUntil: now}); err != nil {
				return err
			}
			input[0] = 'X'
			if err := tx.RetainCodeArchive(key, until); err != nil {
				return err
			}
			if err := tx.PutCodeArchive(lambda.CodeArchive{Key: key, Code: []byte("replacement"), CreatedAt: until, RetainUntil: now}); err != nil {
				return err
			}
			return tx.RetainCodeArchive(key, now)
		}); err != nil {
			t.Fatal(err)
		}
		check := func(r lambda.Reader) error {
			archive, err := r.CodeArchive(key)
			if err != nil {
				return err
			}
			if !bytes.Equal(archive.Code, original) || !archive.CreatedAt.Equal(now) || !archive.RetainUntil.Equal(until) {
				t.Fatalf("archive mutated or retention shortened: %+v", archive)
			}
			archive.Code[0] = 'X'
			return nil
		}
		for range 2 {
			if err := repo.View(t.Context(), check); err != nil {
				t.Fatal(err)
			}
		}
		missing := key
		missing.SHA256 = "aborted"
		abort := errors.New("abort archive transaction")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.RetainCodeArchive(key, until.Add(time.Hour)); err != nil {
				return err
			}
			if err := tx.PutCodeArchive(lambda.CodeArchive{Key: missing, Code: []byte("aborted"), CreatedAt: now}); err != nil {
				return err
			}
			if err := tx.PutFunction(function); err != nil {
				return err
			}
			if err := tx.PutCodeSigningKey(lambda.CodeSigningKey{Scope: key.Scope, AccessKeyID: "aborted", SecretAccessKey: "aborted"}); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatalf("archive rollback: %v", err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			if err := check(r); err != nil {
				return err
			}
			if _, err := r.CodeArchive(missing); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("aborted archive committed: %v", err)
			}
			if _, err := r.Function(function.Key); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("aborted deployment committed: %v", err)
			}
			if _, err := r.CodeSigningKey(key.Scope); !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("aborted signing key committed: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			return tx.RetainCodeArchive(missing, until)
		}); !errors.Is(err, lambda.ErrNotFound) {
			t.Fatalf("retention manufactured a missing archive: %v", err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if _, err := tx.DeleteExpiredCodeArchives(until.Add(time.Second)); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatalf("collection rollback: %v", err)
		}
		if err := repo.View(t.Context(), check); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSQLiteCodeDownloadCapabilitySurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lambda.sqlite")
	function := deployment()
	key := lambda.CodeArchiveKey{Scope: function.Key.Scope, SHA256: function.CodeSHA256}
	signing := lambda.CodeSigningKey{Scope: key.Scope, AccessKeyID: "download", SecretAccessKey: "retained"}
	until := function.Modified.Add(time.Minute)
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutCodeArchive(lambda.CodeArchive{Key: key, Code: []byte("ZIP!"), CreatedAt: function.Modified, RetainUntil: until}); err != nil {
			return err
		}
		if err := tx.PutCodeSigningKey(signing); err != nil {
			return err
		}
		if err := tx.PutFunction(function); err != nil {
			return err
		}
		return tx.DeleteFunction(function.Key)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
		if err := tx.PutCodeSigningKey(lambda.CodeSigningKey{Scope: key.Scope, AccessKeyID: "replacement", SecretAccessKey: "replacement"}); err != nil {
			return err
		}
		recovered, err := tx.CodeSigningKey(key.Scope)
		if err != nil || recovered != signing {
			t.Fatalf("reopen or duplicate insertion revoked signing material: %+v %v", recovered, err)
		}
		archive, err := tx.CodeArchive(key)
		if err != nil || string(archive.Code) != "ZIP!" || !archive.RetainUntil.Equal(until) {
			t.Fatalf("deleted function download lost on reopen: %+v %v", archive, err)
		}
		deadline, found, err := tx.NextCodeArchiveDeadline()
		if err != nil || !found || !deadline.Equal(until.Add(time.Nanosecond)) {
			t.Fatalf("reopen lost archive collection deadline: %v %v %v", deadline, found, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

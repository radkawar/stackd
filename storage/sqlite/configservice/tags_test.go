package configservice_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	domain "stackd/storage/configservice"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/configservice"
)

const tagARN = "arn:aws:config:us-east-1:111122223333:config-rule/config-rule-test"

func assertTags(t *testing.T, r domain.Reader, scope domain.Scope, arn string, want map[string]string) {
	t.Helper()
	got, err := r.Tags(scope, arn)
	check(t, err)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tags for %v %s = %#v, want %#v", scope, arn, got, want)
	}
}

func TestTagsCloningReplacementAndScope(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository) {
		scopes := []domain.Scope{testScope, {Partition: "aws-cn", AccountID: testScope.AccountID, Region: testScope.Region}, {Partition: "aws", AccountID: "444455556666", Region: testScope.Region}, {Partition: "aws", AccountID: testScope.AccountID, Region: "us-west-2"}}
		original := map[string]string{"environment": "production", "remove": "old"}
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			for _, scope := range scopes {
				assertTags(t, tx, scope, tagARN, nil)
				check(t, tx.PutTags(scope, tagARN, original))
			}
			check(t, tx.PutTags(testScope, tagARN+"-other", map[string]string{"other": "resource"}))
			original["environment"] = "mutated-input"
			got, err := tx.Tags(testScope, tagARN)
			check(t, err)
			got["environment"] = "mutated-output"
			assertTags(t, tx, testScope, tagARN, map[string]string{"environment": "production", "remove": "old"})
			return tx.PutTags(testScope, tagARN, map[string]string{"replacement": "value"})
		}))
		check(t, repo.View(t.Context(), func(r domain.Reader) error {
			assertTags(t, r, testScope, tagARN, map[string]string{"replacement": "value"})
			for _, scope := range scopes[1:] {
				assertTags(t, r, scope, tagARN, map[string]string{"environment": "production", "remove": "old"})
			}
			assertTags(t, r, testScope, tagARN+"-other", map[string]string{"other": "resource"})
			got, err := r.Tags(testScope, tagARN)
			check(t, err)
			delete(got, "replacement")
			return nil
		}))
		check(t, repo.View(t.Context(), func(r domain.Reader) error {
			assertTags(t, r, testScope, tagARN, map[string]string{"replacement": "value"})
			return nil
		}))
		for _, empty := range []map[string]string{nil, {}} {
			check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
				check(t, tx.PutTags(testScope, tagARN, map[string]string{"clear": "me"}))
				return tx.PutTags(testScope, tagARN, empty)
			}))
			check(t, repo.View(t.Context(), func(r domain.Reader) error {
				assertTags(t, r, testScope, tagARN, nil)
				assertTags(t, r, testScope, tagARN+"-other", map[string]string{"other": "resource"})
				return nil
			}))
		}
	})
}

func TestTagsJoinedOwnerRollback(t *testing.T) {
	repositories(t, func(t *testing.T, repo domain.Repository) {
		check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
			check(t, tx.PutRecorder(domain.Recorder{Scope: testScope, Name: "original"}))
			return tx.PutTags(testScope, tagARN, map[string]string{"state": "original"})
		}))
		aborted := errors.New("abort owner transaction")
		for _, update := range []func(context.Context, func(domain.Transaction) error) error{repo.Update, repo.Attempt} {
			err := update(t.Context(), func(tx domain.Transaction) error {
				check(t, tx.PutRecorder(domain.Recorder{Scope: testScope, Name: "changed"}))
				check(t, repo.Update(tx.Context(), func(joined domain.Transaction) error {
					return joined.PutTags(testScope, tagARN, map[string]string{"state": "changed"})
				}))
				assertTags(t, tx, testScope, tagARN, map[string]string{"state": "changed"})
				return aborted
			})
			if !errors.Is(err, aborted) {
				t.Fatalf("rollback error = %v", err)
			}
			check(t, repo.View(t.Context(), func(r domain.Reader) error {
				assertTags(t, r, testScope, tagARN, map[string]string{"state": "original"})
				recorder, ok, err := r.Recorder(testScope)
				check(t, err)
				if !ok || recorder.Name != "original" {
					t.Fatalf("owner escaped rollback: %+v, found %v", recorder, ok)
				}
				return nil
			}))
		}
	})
}

func TestTagsSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config-tags.db")
	db, err := sqlite.Open(t.Context(), path)
	check(t, err)
	repo := backend.New(db)
	check(t, repo.Update(t.Context(), func(tx domain.Transaction) error {
		check(t, tx.PutTags(testScope, tagARN, map[string]string{"persisted": "value"}))
		check(t, tx.PutTags(testScope, tagARN+"-cleared", map[string]string{"removed": "value"}))
		return tx.PutTags(testScope, tagARN+"-cleared", nil)
	}))
	check(t, db.Close())
	db, err = sqlite.Open(t.Context(), path)
	check(t, err)
	t.Cleanup(func() { check(t, db.Close()) })
	check(t, backend.New(db).View(t.Context(), func(r domain.Reader) error {
		assertTags(t, r, testScope, tagARN, map[string]string{"persisted": "value"})
		assertTags(t, r, testScope, tagARN+"-cleared", nil)
		return nil
	}))
}

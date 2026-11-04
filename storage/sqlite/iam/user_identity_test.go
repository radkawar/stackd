package iam

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	domain "stackd/storage/iam"
	sqlitestore "stackd/storage/sqlite"
)

func TestUserIDExistsUsesScopedImmutableIdentity(t *testing.T) {
	db, err := sqlitestore.Open(t.Context(), filepath.Join(t.TempDir(), "identity.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	repository, err := New(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	scope := domain.Scope{Partition: "aws", AccountID: "123456789012"}
	otherAccount := domain.Scope{Partition: "aws", AccountID: "999999999999"}
	otherPartition := domain.Scope{Partition: "aws-cn", AccountID: scope.AccountID}
	user := domain.User{UserName: "before", UserId: "AIDAORIGINAL", Arn: "arn:aws:iam::123456789012:user/before", Path: "/", CreateDate: time.Unix(1, 0).UTC()}
	if err := repository.Update(t.Context(), func(tx domain.WriteTx) error {
		if err := tx.PutUser(scope, user); err != nil {
			return err
		}
		foreign := user
		foreign.UserId = "AIDAOTHERACCOUNT"
		if err := tx.PutUser(otherAccount, foreign); err != nil {
			return err
		}
		foreign.UserId = "AIDAOTHERPARTITION"
		return tx.PutUser(otherPartition, foreign)
	}); err != nil {
		t.Fatal(err)
	}
	assertExists := func(id string, want bool) {
		t.Helper()
		if err := repository.View(t.Context(), func(tx domain.ReadTx) error {
			got, err := tx.UserIDExists(scope, id)
			if err == nil && got != want {
				t.Errorf("UserIDExists(%q) = %t, want %t", id, got, want)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertExists(user.UserId, true)
	assertExists(strings.ToLower(user.UserId), false)
	assertExists("AIDAOTHERACCOUNT", false)
	assertExists("AIDAOTHERPARTITION", false)
	assertExists("AIDAMISSING", false)
	if err := repository.Update(t.Context(), func(tx domain.WriteTx) error {
		if err := tx.DeleteUser(scope, user.UserName); err != nil {
			return err
		}
		user.UserName, user.Arn = "after", "arn:aws:iam::123456789012:user/after"
		return tx.PutUser(scope, user)
	}); err != nil {
		t.Fatal(err)
	}
	assertExists(user.UserId, true)
	if err := repository.Update(t.Context(), func(tx domain.WriteTx) error {
		if err := tx.DeleteUser(scope, user.UserName); err != nil {
			return err
		}
		user.UserId = "AIDAREPLACEMENT"
		return tx.PutUser(scope, user)
	}); err != nil {
		t.Fatal(err)
	}
	assertExists("AIDAORIGINAL", false)
	assertExists(user.UserId, true)

	var id, parent, auxiliary int
	var detail string
	if err := db.QueryRowContext(t.Context(), "EXPLAIN QUERY PLAN SELECT user_id FROM iam_user WHERE partition = ? AND account = ? AND user_id = ? LIMIT 1", scope.Partition, scope.AccountID, user.UserId).Scan(&id, &parent, &auxiliary, &detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "COVERING INDEX iam_user_immutable_identity") {
		t.Fatalf("immutable identity check does not use its covering index: %s", detail)
	}
}

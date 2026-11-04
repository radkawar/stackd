package iam_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	sqlitestore "stackd/storage/sqlite"
)

func TestAsyncActivityCrashBeforeFlushLosesOnlyReportingUpdates(t *testing.T) {
	const crashPathEnvironment = "STACKD_IAM_ACTIVITY_CRASH_PATH"
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	key := identity.Credential{AccessKeyID: "AKIACRASH", AccountID: scope.AccountID, PrincipalID: "AIDACRASH", PrincipalARN: "arn:aws:iam::123456789012:user/crash", UserName: "crash"}
	if path := os.Getenv(crashPathEnvironment); path != "" {
		db, err := sqlitestore.Open(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		repository := &asyncActivityRepository{Repository: newSQLiteIAMRepository(t, db)}
		// The authoritative resource/credential transition commits normally.
		if err := repository.Repository.Update(context.Background(), func(tx iam.WriteTx) error {
			if err := tx.PutUser(scope, iam.User{UserId: key.PrincipalID, UserName: key.UserName, Arn: key.PrincipalARN}); err != nil {
				return err
			}
			return tx.PutCredential(identity.Record{Credential: key, Status: identity.Active})
		}); err != nil {
			t.Fatal(err)
		}
		// Even if the test process is delayed beyond the ordinary flush tick,
		// no reporting transaction can enter SQLite before process exit.
		repository.gate.Store(&activityWriteGate{entered: make(chan struct{}, 1), release: make(chan struct{})})
		service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(time.Time{})})
		if err := service.RecordActivity(activityContext(context.Background(), key, "aws", "eu-west-1"), "s3", "GetObject"); err != nil {
			t.Fatal(err)
		}
		// Deliberately bypass both service and repository shutdown in this
		// isolated child. SQLite must recover committed state, not the buffer.
		os.Exit(0)
	}

	path := filepath.Join(t.TempDir(), "crash.sqlite")
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAsyncActivityCrashBeforeFlushLosesOnlyReportingUpdates$")
	child.Env = append(os.Environ(), crashPathEnvironment+"="+path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("crash-boundary child: %v\n%s", err, output)
	}
	db, err := sqlitestore.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := newSQLiteIAMRepository(t, db)
	if err := repository.View(t.Context(), func(tx iam.ReadTx) error {
		user, err := tx.User(scope, key.UserName)
		if err != nil {
			return err
		}
		if user.UserId != key.PrincipalID || user.Arn != key.PrincipalARN {
			t.Fatalf("crash lost authoritative resource state: %+v", user)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if used := bufferedCredential(t, repository, key.AccessKeyID).LastUsed; used.Recorded() {
		t.Fatalf("crash durably invented an unflushed credential observation: %+v", used)
	}
	if rows := activityRows(t, repository, scope, key.PrincipalID); len(rows) != 0 {
		t.Fatalf("crash durably invented unflushed activity: %+v", rows)
	}
	// A recovered owner has no lost process-local buffer to replay. A newly
	// observed attempt is persisted by joined shutdown, at its own timestamp.
	recovered := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(time.Unix(0, 0).UTC())})
	t.Cleanup(func() { _ = recovered.Close() })
	if err := recovered.RecordActivity(activityContext(t.Context(), key, "aws", "us-east-1"), "kms", "Decrypt"); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	rows := activityRows(t, repository, scope, key.PrincipalID)
	if len(rows) != 1 || rows[0].ServiceNamespace != "kms" || rows[0].Region != "us-east-1" || !rows[0].LastAuthenticated.Equal(time.Unix(0, 0)) {
		t.Fatalf("recovered owner replayed lost observations or failed shutdown flush: %+v", rows)
	}
}

package stackd_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/journal"
	iamstore "stackd/storage/iam"
)

type exitAfterSessionEvent struct{ journal.Storage }

func (j exitAfterSessionEvent) AppendSessionIssued(ctx context.Context, envelope journal.Envelope, session journal.SessionIssued) error {
	if err := j.Storage.AppendSessionIssued(ctx, envelope, session); err != nil {
		return err
	}
	os.Exit(37) // The outer IAM transaction has not committed.
	return nil
}

func TestSessionJournalProcessExit(t *testing.T) {
	if path := os.Getenv("STACKD_SESSION_EVENT_CRASH_DB"); path != "" {
		backends, _ := openSQLiteBackends(t, path)
		backends.Journal = exitAfterSessionEvent{backends.Journal}
		c := clockCloud(t, stackd.Config{Storage: backends})
		_, err := c.sts("test", "test", "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
		t.Fatal("process did not exit inside session event publication", err)
	}
	path := filepath.Join(t.TempDir(), "state.sqlite")
	var committed []journal.Event
	t.Run("committed", func(t *testing.T) {
		backends, _ := openSQLiteBackends(t, path)
		c := clockCloud(t, stackd.Config{Storage: backends})
		if _, err := c.sts("test", "test", "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)}); err != nil {
			t.Fatal(err)
		}
		var err error
		committed, err = backends.Journal.Read(t.Context(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
	}) // Join the stack before the child opens the same database.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSessionJournalProcessExit$")
	command.Env = append(os.Environ(), "STACKD_SESSION_EVENT_CRASH_DB="+path)
	output, err := command.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 37 {
		t.Fatalf("session crash child: %v\n%s", err, output)
	}
	backends, _ := openSQLiteBackends(t, path)
	rows, err := backends.Journal.Read(t.Context(), 0, 100)
	if err != nil || !reflect.DeepEqual(rows, committed) {
		t.Fatal("crash exposed an uncommitted event or lost committed history", rows, err)
	}
	if err := backends.IAM.View(t.Context(), func(reader iamstore.ReadTx) error {
		records, err := reader.PrincipalCredentials("000000000000", "000000000000")
		if err == nil && len(records) != 1 {
			t.Error("credential state did not recover with event history", len(records))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	c := clockCloud(t, stackd.Config{Storage: backends})
	if _, err := c.sts("test", "test", "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)}); err != nil {
		t.Fatal(err)
	}
	rows, err = backends.Journal.Read(t.Context(), committed[len(committed)-1].Sequence, 100)
	sessions := credentialEvents(rows)
	if err != nil || len(sessions) != 1 || sessions[0].SessionIssued.SessionType != "GetSessionToken" || sessions[0].Sequence <= committed[len(committed)-1].Sequence {
		t.Fatal("recovered journal did not continue session issuance after the committed prefix", rows, err)
	}
}

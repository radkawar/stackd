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
	"github.com/aws/aws-sdk-go-v2/service/organizations"

	"stackd/clock"
	"stackd/journal"
	iamstore "stackd/storage/iam"
)

type exitAfterCreationEvent struct{ journal.Storage }

func (s exitAfterCreationEvent) AppendAccountCreationChanged(ctx context.Context, envelope journal.Envelope, change journal.AccountCreationChanged) error {
	if err := s.Storage.AppendAccountCreationChanged(ctx, envelope, change); err != nil {
		return err
	}
	if change.State == "SUCCEEDED" {
		os.Exit(38) // Membership, IAM roles and the event are still uncommitted.
	}
	return nil
}

func TestOrganizationCreationJournalProcessExit(t *testing.T) {
	epoch := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
	if path := os.Getenv("STACKD_CREATION_EVENT_CRASH_DB"); path != "" {
		backends, _ := openSQLiteBackends(t, path)
		backends.Journal = exitAfterCreationEvent{backends.Journal}
		cloud, _, _ := creationEventCloud(t, backends, clock.NewManual(epoch.Add(time.Second)))
		_, err := cloud.RunDueJobs(t.Context(), 10)
		t.Fatal("process did not exit during account publication", err)
	}
	path := filepath.Join(t.TempDir(), "state.sqlite")
	var baseline []journal.Event
	t.Run("accepted", func(t *testing.T) {
		backends, _ := openSQLiteBackends(t, path)
		source := clock.NewManual(epoch)
		_, c, _ := creationEventCloud(t, backends, source)
		f := organizationFixture(t, c, source)
		if _, err := f.org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("crash-member"), Email: aws.String("crash@example.test")}); err != nil {
			t.Fatal(err)
		}
		baseline = lifecycleEvents(t, backends.Journal)
	})
	if len(baseline) != 1 || baseline[0].Sequence <= 0 || baseline[0].AccountCreationChanged.State != "IN_PROGRESS" || baseline[0].AccountCreationChanged.CreationRequestID == "" || baseline[0].RequestID == "" || !baseline[0].At.Equal(epoch) {
		t.Fatal("accepted command was not recorded exactly once", baseline)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOrganizationCreationJournalProcessExit$")
	command.Env = append(os.Environ(), "STACKD_CREATION_EVENT_CRASH_DB="+path)
	output, err := command.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 38 {
		t.Fatalf("account crash child: %v\n%s", err, output)
	}
	backends, _ := openSQLiteBackends(t, path)
	if rows := lifecycleEvents(t, backends.Journal); !reflect.DeepEqual(rows, baseline) {
		t.Fatal("crash exposed uncommitted completion", rows)
	}
	state, _, err := backends.Organizations.Load(t.Context(), "aws")
	if err != nil || len(state.Organizations) != 1 || len(state.Organizations[0].Accounts) != 1 || len(state.Organizations[0].Creations) != 1 || state.Organizations[0].Creations[0].State != "IN_PROGRESS" {
		t.Fatal("crash did not retain only the accepted intent", state, err)
	}
	if err := backends.IAM.View(t.Context(), func(tx iamstore.ReadTx) error {
		roles, err := tx.Roles(iamstore.Scope{Partition: "aws", AccountID: "100000000001"})
		if len(roles) != 0 {
			t.Error("crash exposed uncommitted roles", roles)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	source := clock.NewManual(epoch.Add(2 * time.Second))
	cloud, c, _ := creationEventCloud(t, backends, source)
	if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	status, err := c.organizations("test", "test").DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: aws.String(baseline[0].AccountCreationChanged.CreationRequestID)})
	if err != nil || status.CreateAccountStatus.State != "SUCCEEDED" || aws.ToString(status.CreateAccountStatus.AccountId) == "" {
		t.Fatal("crash recovery did not finish the accepted command", status, err)
	}
	rows := lifecycleEvents(t, backends.Journal)
	if len(rows) != 2 || rows[1].Sequence <= baseline[0].Sequence {
		t.Fatal("crash recovery did not commit exactly one later completion", rows)
	}
	completed := baseline[0]
	completed.Sequence, completed.At = rows[1].Sequence, source.Now()
	completed.AccountCreationChanged.State = "SUCCEEDED"
	completed.AccountCreationChanged.AccountID = aws.ToString(status.CreateAccountStatus.AccountId)
	if !reflect.DeepEqual(rows, []journal.Event{baseline[0], completed}) {
		t.Fatal("crash recovery did not continue the accepted command", rows)
	}
}

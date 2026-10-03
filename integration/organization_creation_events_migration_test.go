package stackd_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"

	"stackd/clock"
	"stackd/internal/awstest"
)

func TestOrganizationCreationEventMigrationRecoversPendingJob(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	backends, closeDB := openSQLiteBackends(t, path)
	_, c, close := creationEventCloud(t, backends, source)
	f := organizationFixture(t, c, source)
	accepted, err := f.org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("legacy"), Email: aws.String("legacy@example.test")})
	if err != nil {
		t.Fatal(err)
	}
	close()
	current := path
	path = filepath.Join(t.TempDir(), "version9.sqlite")
	// Version 9 retains the provisioning job but has no creation origin or events.
	db := awstest.HistoricalSQLite(t, path, "../storage/sqlite/schema", 9, current, map[string]string{
		"kernel_events": "SELECT * FROM fixture.kernel_events WHERE 0",
	})
	closeDB()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	backends, _ = openSQLiteBackends(t, path)
	if rows := lifecycleEvents(t, backends.Journal); len(rows) != 0 {
		t.Fatal("migration invented historical events", rows)
	}
	advanceClock(t, source, time.Second)
	cloud, c, _ := creationEventCloud(t, backends, source)
	if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	status, err := c.organizations("test", "test").DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: accepted.CreateAccountStatus.Id})
	if err != nil {
		t.Fatal(err)
	}
	rows := lifecycleEvents(t, backends.Journal)
	if len(rows) != 1 || rows[0].AccountCreationChanged.State != "SUCCEEDED" || rows[0].AccountCreationChanged.AccountID != aws.ToString(status.CreateAccountStatus.AccountId) || rows[0].AccountCreationChanged.CreationRequestID != aws.ToString(accepted.CreateAccountStatus.Id) || rows[0].RequestID != "" || rows[0].ActorARN != "" || rows[0].Region != "" {
		t.Fatal("migration lost the pending job or invented its request origin", rows)
	}
}

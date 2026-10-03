package stackd_test

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/journal"
)

func TestOrganizationsHandshakeMigrationPreservesInvitationAndJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version13.sqlite")
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	backends, closeDB := openSQLiteBackends(t, path)
	_, c, close := creationEventCloud(t, backends, source)
	f := consolidatedOrganization(t, c, source)
	invited, err := f.org.InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: aws.String("222222222222")}, Tags: []orgtypes.Tag{{Key: aws.String("retained"), Value: aws.String("yes")}}})
	if err != nil {
		t.Fatal(err)
	}
	var original journal.Event
	for _, event := range lifecycleEvents(t, backends.Journal) {
		if event.HandshakeChanged.HandshakeID == *invited.Handshake.Id && event.HandshakeChanged.State == "OPEN" {
			original = event
		}
	}
	if original.Sequence == 0 {
		t.Fatal("missing invitation event")
	}
	close()
	current := path
	path = filepath.Join(t.TempDir(), "historical13.sqlite")
	// The historical fixture retains the invitation's original tables and event kind.
	db := awstest.HistoricalSQLite(t, path, "../storage/sqlite/schema", 13, current, map[string]string{
		"org_invitations":       "SELECT * FROM fixture.org_handshakes",
		"org_invitation_tags":   "SELECT *, handshake_id AS invitation_id FROM fixture.org_handshake_tags",
		"org_invitation_events": "SELECT * FROM fixture.org_handshake_events",
		"kernel_events": `SELECT sequence, occurred_at, partition, account_id, region, request_id, actor_arn,
			'organizations.invitation.changed.v1' AS event_type FROM fixture.kernel_events
			WHERE event_type='organizations.handshake.changed.v1'`,
	})
	closeDB()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	backends, _ = openSQLiteBackends(t, path)
	_, c, _ = creationEventCloud(t, backends, source)
	f.org = c.organizations("test", "test")
	history := lifecycleEvents(t, backends.Journal)
	if len(history) != 1 || !reflect.DeepEqual(history[0], original) {
		t.Fatal("migration changed retained event content", history, original)
	}
	pending, err := f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: invited.Handshake.Id})
	if err != nil || pending.Handshake.Action != orgtypes.ActionType("INVITE") || pending.Handshake.State != orgtypes.HandshakeStateOpen {
		t.Fatal("migration lost invitation", pending, err)
	}
	if _, err := c.organizations("222222222222", "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: invited.Handshake.Id}); err != nil {
		t.Fatal(err)
	}
	tags, err := f.org.ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: aws.String("222222222222")})
	if err != nil || len(tags.Tags) != 1 || *tags.Tags[0].Value != "yes" {
		t.Fatal("migration lost staged tags", tags, err)
	}
	migration, err := f.org.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
	if err != nil || migration.Handshake.State != orgtypes.HandshakeStateRequested {
		t.Fatal("migrated membership did not require consent", migration, err)
	}
	rows := lifecycleEvents(t, backends.Journal)
	if rows[len(rows)-1].Sequence <= original.Sequence {
		t.Fatal("journal sequence did not continue")
	}
}

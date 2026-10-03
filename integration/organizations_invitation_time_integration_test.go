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
	"stackd/storage"
)

func TestOrganizationsInvitationExpiryRetentionAndPaginationRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "time.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			open := func() {
				if backend == "sqlite" {
					backends, closeDB = openSQLiteBackends(t, path)
				}
			}
			open()
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			_, c, close := creationEventCloud(t, backends, source)
			f := organizationFixture(t, c, source)
			const member = "222222222222"
			invite := func(target string) *orgtypes.Handshake {
				t.Helper()
				out, err := f.org.InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: &target}})
				if err != nil {
					t.Fatal(err)
				}
				return out.Handshake
			}
			first := invite(member)
			second := invite("333333333333")
			if _, err := f.org.CancelHandshake(t.Context(), &organizations.CancelHandshakeInput{HandshakeId: second.Id}); err != nil {
				t.Fatal(err)
			}
			page, err := f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{MaxResults: aws.Int32(1)})
			if err != nil || len(page.Handshakes) != 1 || page.NextToken == nil {
				t.Fatal("first page", page, err)
			}
			next, err := f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{MaxResults: aws.Int32(1), NextToken: page.NextToken})
			if err != nil || len(next.Handshakes) != 1 || next.NextToken != nil || *next.Handshakes[0].Id == *page.Handshakes[0].Id {
				t.Fatal("next page", next, err)
			}
			_, err = c.organizations(member, "test").ListHandshakesForAccount(t.Context(), &organizations.ListHandshakesForAccountInput{NextToken: page.NextToken})
			assertAPIError(t, err, "InvalidInputException")
			close()
			closeDB()
			open()
			advanceClock(t, source, 15*24*time.Hour)
			cloud, c, close := creationEventCloud(t, backends, source)
			f.org = c.organizations("test", "test")
			if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			expired, err := f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: first.Id})
			if err != nil || expired.Handshake.State != orgtypes.HandshakeStateExpired {
				t.Fatal("expiration", expired, err)
			}
			_, err = c.organizations(member, "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: first.Id})
			assertAPIError(t, err, "InvalidHandshakeTransitionException")
			rows := lifecycleEvents(t, backends.Journal)
			states := []string{}
			origin := ""
			for _, row := range rows {
				if row.HandshakeChanged.HandshakeID == *first.Id {
					states = append(states, row.HandshakeChanged.State)
					if origin == "" {
						origin = row.RequestID
					} else if origin != row.RequestID {
						t.Fatal("expiry lost original request")
					}
					if row.HandshakeChanged.State == "EXPIRED" && !row.At.Equal(*first.ExpirationTimestamp) {
						t.Fatal("expiration time", row)
					}
				}
			}
			if !reflect.DeepEqual(states, []string{"OPEN", "EXPIRED"}) {
				t.Fatal("expiry events", states)
			}
			advanceClock(t, source, 15*24*time.Hour)
			if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			_, err = f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: second.Id})
			assertAPIError(t, err, "HandshakeNotFoundException")
			if _, err := f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: first.Id}); err != nil {
				t.Fatal("expired invitation purged early", err)
			}
			close()
			closeDB()
			open()
			advanceClock(t, source, 15*24*time.Hour)
			cloud, c, _ = creationEventCloud(t, backends, source)
			if _, err := cloud.RunDueJobs(t.Context(), 10); err != nil {
				t.Fatal(err)
			}
			_, err = c.organizations("test", "test").DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: first.Id})
			assertAPIError(t, err, "HandshakeNotFoundException")
			if !reflect.DeepEqual(lifecycleEvents(t, backends.Journal), rows) {
				t.Fatal("handshake retention mutated committed history")
			}
		})
	}
}

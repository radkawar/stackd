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

func TestOrganizationsFeatureCancellationExpiryAndMembership(t *testing.T) {
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	cloud, c, _ := creationEventCloud(t, storage.NewMemory(), source)
	f := consolidatedOrganization(t, c, source)
	const member = "222222222222"
	inviteExistingAccount(t, f, member)
	invite := func(id string) *orgtypes.Handshake {
		t.Helper()
		out, err := f.org.InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: &id}})
		if err != nil {
			t.Fatal(err)
		}
		return out.Handshake
	}
	check := func(id *string, state orgtypes.HandshakeState) {
		t.Helper()
		out, err := f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: id})
		if err != nil || out.Handshake.State != state {
			t.Fatal("handshake state", out, err, state)
		}
	}
	before := invite("333333333333")
	started, err := f.org.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
	if err != nil {
		t.Fatal(err)
	}
	check(before.Id, orgtypes.HandshakeStateCanceled)
	_, err = f.org.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
	assertAPIError(t, err, "HandshakeConstraintViolationException")
	during := invite("444444444444")
	advertised := ""
	for _, resource := range during.Resources {
		for _, child := range resource.Resources {
			if child.Type == orgtypes.HandshakeResourceTypeOrganizationFeatureSet {
				advertised = *child.Value
			}
		}
	}
	if advertised != "ALL" {
		t.Fatal("migration invitation offered", advertised)
	}
	children, err := f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{Filter: &orgtypes.HandshakeFilter{ParentHandshakeId: started.Handshake.Id}})
	if err != nil || len(children.Handshakes) != 1 {
		t.Fatal(children, err)
	}
	child := children.Handshakes[0]
	if _, err := c.organizations(member, "test").DeclineHandshake(t.Context(), &organizations.DeclineHandshakeInput{HandshakeId: child.Id}); err != nil {
		t.Fatal(err)
	}
	check(started.Handshake.Id, orgtypes.HandshakeStateRequested)
	if _, err := f.org.CancelHandshake(t.Context(), &organizations.CancelHandshakeInput{HandshakeId: started.Handshake.Id}); err != nil {
		t.Fatal(err)
	}
	check(during.Id, orgtypes.HandshakeStateCanceled)
	check(child.Id, orgtypes.HandshakeStateDeclined)
	again, err := f.org.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
	if err != nil {
		t.Fatal(err)
	}
	children, err = f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{Filter: &orgtypes.HandshakeFilter{ParentHandshakeId: again.Handshake.Id}})
	if err != nil || len(children.Handshakes) != 1 {
		t.Fatal(children, err)
	}
	child = children.Handshakes[0]
	// Invitations issued late in migration remain within their own 15-day life
	// when the parent expires. They must be canceled with that parent.
	advanceClock(t, source, 89*24*time.Hour)
	late := invite("555555555555")
	advanceClock(t, source, 24*time.Hour)
	check(again.Handshake.Id, orgtypes.HandshakeStateExpired)
	check(child.Id, orgtypes.HandshakeStateCanceled)
	check(late.Id, orgtypes.HandshakeStateCanceled)
	// A new attempt at the same manual instant must survive draining the old one.
	fresh, err := f.org.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
	if err != nil {
		t.Fatal(err)
	}
	newer := invite("666666666666")
	if _, err := cloud.RunDueJobs(t.Context(), 50); err != nil {
		t.Fatal(err)
	}
	check(newer.Id, orgtypes.HandshakeStateOpen)
	if _, err := c.organizations("666666666666", "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: newer.Id}); err != nil {
		t.Fatal(err)
	}
	current, err := f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{Filter: &orgtypes.HandshakeFilter{ParentHandshakeId: fresh.Handshake.Id}})
	if err != nil || len(current.Handshakes) != 1 {
		t.Fatal("new member was asked to consent twice", current, err)
	}
	// Removing the sole outstanding voter makes the migration ready; the newly
	// invited account already accepted the ALL offer as part of its invitation.
	if _, err := f.org.RemoveAccountFromOrganization(t.Context(), &organizations.RemoveAccountFromOrganizationInput{AccountId: aws.String(member)}); err != nil {
		t.Fatal(err)
	}
	check(current.Handshakes[0].Id, orgtypes.HandshakeStateCanceled)
	check(fresh.Handshake.Id, orgtypes.HandshakeStateOpen)
	if _, err := f.org.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: fresh.Handshake.Id}); err != nil {
		t.Fatal(err)
	}
}

func TestOrganizationsFeatureCommitRollback(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			backends := storage.NewMemory()
			if backend == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "rollback.sqlite"))
			}
			fault := &creationCommitFailure{Storage: backends.Organizations}
			backends.Organizations = fault
			source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
			_, c, _ := creationEventCloud(t, backends, source)
			f := consolidatedOrganization(t, c, source)
			pending, err := f.org.InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: aws.String("222222222222")}})
			if err != nil {
				t.Fatal(err)
			}
			before := lifecycleEvents(t, backends.Journal)
			for _, mode := range []int32{1, 2} {
				fault.mode.Store(mode)
				_, err := f.org.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
				assertAPIError(t, err, "ServiceException")
				listed, err := f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{})
				if err != nil || len(listed.Handshakes) != 1 || *listed.Handshakes[0].Id != *pending.Handshake.Id || listed.Handshakes[0].State != orgtypes.HandshakeStateOpen || !reflect.DeepEqual(lifecycleEvents(t, backends.Journal), before) {
					t.Fatal("failed migration leaked transitions", listed, err)
				}
			}
			fault.mode.Store(0)
			migration, err := f.org.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
			if err != nil {
				t.Fatal(err)
			}
			canceled, err := f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: pending.Handshake.Id})
			if err != nil || canceled.Handshake.State != orgtypes.HandshakeStateCanceled {
				t.Fatal(canceled, err)
			}
			before = lifecycleEvents(t, backends.Journal)
			fault.mode.Store(1)
			_, err = f.org.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: migration.Handshake.Id})
			assertAPIError(t, err, "ServiceException")
			description, err := f.org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
			if err != nil || description.Organization.FeatureSet != orgtypes.OrganizationFeatureSetConsolidatedBilling || !reflect.DeepEqual(lifecycleEvents(t, backends.Journal), before) {
				t.Fatal("failed finalization leaked", description, err)
			}
			fault.mode.Store(0)
			if _, err := f.org.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: migration.Handshake.Id}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

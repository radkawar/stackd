package stackd_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
)

func consolidatedOrganization(t *testing.T, c cloudClients, source *clock.Manual) organizationReportFixture {
	t.Helper()
	org := c.organizations("test", "test")
	created, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: orgtypes.OrganizationFeatureSetConsolidatedBilling})
	if err != nil {
		t.Fatal(err)
	}
	roots, err := org.ListRoots(t.Context(), &organizations.ListRootsInput{})
	if err != nil {
		t.Fatal(err)
	}
	id := *roots.Roots[0].Id
	return organizationReportFixture{cloud: c, clock: source, org: org, iam: c.iam("test", "test", ""), rootID: id, rootPath: *created.Organization.Id + "/" + id}
}

func inviteExistingAccount(t *testing.T, f organizationReportFixture, id string) *orgtypes.Handshake {
	t.Helper()
	invited, err := f.org.InviteAccountToOrganization(t.Context(), &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: &id}})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := f.cloud.organizations(id, "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: invited.Handshake.Id})
	if err != nil {
		t.Fatal(err)
	}
	return accepted.Handshake
}

func deleteOrganizationsRole(t *testing.T, c cloudClients, id string) {
	t.Helper()
	client := c.iam(id, "test", "")
	removed, err := client.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: aws.String("AWSServiceRoleForOrganizations")})
	if err != nil {
		t.Fatal(err)
	}
	status := waitOrganizationRoleDeletion(t, client, removed.DeletionTaskId)
	if string(status.Status) != "SUCCEEDED" {
		t.Fatalf("service role deletion: %+v", status)
	}
}

func TestOrganizationsFeaturesConsentRecoveryAndIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "features.sqlite")
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
			f := consolidatedOrganization(t, c, source)
			const first = "222222222222"
			const second = "333333333333"
			inviteExistingAccount(t, f, first)
			inviteExistingAccount(t, f, second)
			created := f.account(t, f.rootID, "created-needs-role")
			deleteOrganizationsRole(t, c, first)
			deleteOrganizationsRole(t, c, created)
			migration, err := f.org.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
			if err != nil {
				t.Fatal(err)
			}
			parent := migration.Handshake
			if parent.State != orgtypes.HandshakeStateRequested || parent.Action != orgtypes.ActionTypeEnableAllFeatures || parent.ExpirationTimestamp.Sub(*parent.RequestedTimestamp) != 90*24*time.Hour {
				t.Fatal("parent handshake", parent)
			}
			_, err = f.org.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: parent.Id})
			assertAPIError(t, err, "InvalidHandshakeTransitionException")
			children, err := f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{Filter: &orgtypes.HandshakeFilter{ParentHandshakeId: parent.Id}})
			if err != nil || len(children.Handshakes) != 3 {
				t.Fatal("consent requests", children, err)
			}
			byAccount := map[string]orgtypes.Handshake{}
			for _, child := range children.Handshakes {
				for _, party := range child.Parties {
					if party.Type == orgtypes.HandshakePartyTypeAccount {
						byAccount[*party.Id] = child
					}
				}
			}
			if byAccount[first].Action != orgtypes.ActionTypeApproveAllFeatures || byAccount[second].Action != orgtypes.ActionTypeApproveAllFeatures || byAccount[created].Action != orgtypes.ActionTypeAddOrganizationsServiceLinkedRole {
				t.Fatal("wrong consent actions", byAccount)
			}
			_, key, secret := c.user(t, first, "feature-approver")
			putUserPolicy(t, c.iam(first, "test", ""), "feature-approver", allow(`"organizations:AcceptHandshake"`, "*"))
			caller := c.organizations(key, secret)
			_, err = caller.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: byAccount[first].Id})
			assertAPIError(t, err, "AccessDeniedForDependencyException")
			putUserPolicy(t, c.iam(first, "test", ""), "feature-approver", allow(`["organizations:AcceptHandshake","iam:CreateServiceLinkedRole"]`, "*"))
			if _, err := caller.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: byAccount[first].Id}); err != nil {
				t.Fatal(err)
			}
			// An existing role requires no additional IAM create permission.
			_, key, secret = c.user(t, second, "existing-role-approver")
			putUserPolicy(t, c.iam(second, "test", ""), "existing-role-approver", allow(`"organizations:AcceptHandshake"`, "*"))
			if _, err := c.organizations(key, secret).AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: byAccount[second].Id}); err != nil {
				t.Fatal(err)
			}
			close()
			closeDB()
			open()
			advanceClock(t, source, 31*24*time.Hour)
			cloud, c, close := creationEventCloud(t, backends, source)
			f.org = c.organizations("test", "test")
			if _, err := cloud.RunDueJobs(t.Context(), 20); err != nil {
				t.Fatal(err)
			}
			remaining, err := f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{Filter: &orgtypes.HandshakeFilter{ParentHandshakeId: parent.Id}})
			if err != nil || len(remaining.Handshakes) != 1 {
				t.Fatal("child retention", remaining, err)
			}
			if _, err := c.organizations(created, "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: byAccount[created].Id}); err != nil {
				t.Fatal(err)
			}
			ready, err := f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: parent.Id})
			if err != nil || ready.Handshake.State != orgtypes.HandshakeStateOpen {
				t.Fatal("expired child history lost consent", ready, err)
			}
			_, err = c.organizations(first, "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: parent.Id})
			assertAPIError(t, err, "AccessDeniedException")
			finalized, err := f.org.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: parent.Id})
			if err != nil || finalized.Handshake.State != orgtypes.HandshakeStateAccepted {
				t.Fatal("finalize", finalized, err)
			}
			described, err := f.org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
			if err != nil || described.Organization.FeatureSet != orgtypes.OrganizationFeatureSetAll {
				t.Fatal("feature set", described, err)
			}
			roots, err := f.org.ListRoots(t.Context(), &organizations.ListRootsInput{})
			if err != nil || len(roots.Roots[0].PolicyTypes) != 0 {
				t.Fatal("migration enabled a root policy without a request", roots, err)
			}
			if _, err := f.org.EnablePolicyType(t.Context(), &organizations.EnablePolicyTypeInput{RootId: &f.rootID, PolicyType: orgtypes.PolicyTypeServiceControlPolicy}); err != nil {
				t.Fatal(err)
			}
			f.policy(t, "migrated-controls", `{"Statement":{"Effect":"Deny","Action":"sqs:CreateQueue","Resource":"*"}}`, f.rootID)
			_, err = c.sqs(first, "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("denied-after-migration")})
			assertAPIError(t, err, "AccessDenied")
			states := []string{}
			for _, event := range lifecycleEvents(t, backends.Journal) {
				if event.HandshakeChanged.HandshakeID == *parent.Id {
					states = append(states, event.HandshakeChanged.State)
				}
			}
			if len(states) != 3 || states[0] != "REQUESTED" || states[1] != "OPEN" || states[2] != "ACCEPTED" {
				t.Fatal("parent journal transitions", states)
			}
			close()
			closeDB()
			open()
			_, c, _ = creationEventCloud(t, backends, source)
			restored, err := c.organizations("test", "test").DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
			if err != nil || restored.Organization.FeatureSet != orgtypes.OrganizationFeatureSetAll {
				t.Fatal("finalization recovery", restored, err)
			}
		})
	}
}

func TestOrganizationsEnableAllFeaturesReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../testdata/aws/iam/organizations_features.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Case, Code string
			Output     struct{ Reason string }
		}
	}
	if err = json.Unmarshal(raw, &capture); err != nil {
		t.Fatal(err)
	}
	f := newOrganizationReportFixture(t, nil)
	member := f.account(t, f.rootID, "existing-all-member")
	for _, row := range capture.Observations {
		if row.Case == "ignored-field" {
			continue
		}
		t.Run(row.Case, func(t *testing.T) {
			caller := f.org
			if row.Case == "member" {
				caller = f.cloud.organizations(member, "test")
			}
			_, err := caller.EnableAllFeatures(t.Context(), &organizations.EnableAllFeaturesInput{})
			assertAPIError(t, err, row.Code)
			if row.Output.Reason != "" {
				var constraint *orgtypes.HandshakeConstraintViolationException
				if !errors.As(err, &constraint) || string(constraint.Reason) != row.Output.Reason {
					t.Fatal("native reason", err)
				}
			}
		})
	}
}

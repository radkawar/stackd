package stackd_test

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd/clock"
	"stackd/storage"
)

func TestOrganizationsInvitationJoinAuthorizationAndRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invitations.sqlite")
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
			memberIAM := c.iam(member, "test", "")
			_, key, secret := c.user(t, member, "invitee")
			memberOrg := c.organizations(key, secret)
			userBefore, err := memberIAM.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("invitee")})
			if err != nil {
				t.Fatal(err)
			}
			memberAccount := c.account(member, "test", "")
			if _, err := memberAccount.PutAccountName(t.Context(), &account.PutAccountNameInput{AccountName: aws.String("Existing identity")}); err != nil {
				t.Fatal(err)
			}
			if _, err := memberAccount.PutContactInformation(t.Context(), &account.PutContactInformationInput{ContactInformation: primaryContact()}); err != nil {
				t.Fatal(err)
			}
			infoBefore, err := memberAccount.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{})
			if err != nil {
				t.Fatal(err)
			}
			input := &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: aws.String(member)}, Tags: []orgtypes.Tag{{Key: aws.String("owner"), Value: aws.String("joined")}}}
			invited, err := f.org.InviteAccountToOrganization(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			id := invited.Handshake.Id
			_, err = memberOrg.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: id})
			assertAPIError(t, err, "AccessDeniedException")
			putUserPolicy(t, memberIAM, "invitee", allow(`"organizations:AcceptHandshake"`, *invited.Handshake.Arn))
			_, err = memberOrg.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: id})
			assertAPIError(t, err, "AccessDeniedForDependencyException")
			pending, err := f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: id})
			if err != nil || pending.Handshake.State != orgtypes.HandshakeStateOpen {
				t.Fatal("denial consumed invitation", pending, err)
			}
			_, err = f.org.DescribeAccount(t.Context(), &organizations.DescribeAccountInput{AccountId: aws.String(member)})
			assertAPIError(t, err, "AccountNotFoundException")
			putUserPolicy(t, memberIAM, "invitee", allow(`["organizations:AcceptHandshake","iam:CreateServiceLinkedRole"]`, "*"))
			boundary, err := memberIAM.CreatePolicy(t.Context(), &iam.CreatePolicyInput{PolicyName: aws.String("invitation-boundary"), PolicyDocument: aws.String(allow(`"iam:*"`, "*"))})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := memberIAM.PutUserPermissionsBoundary(t.Context(), &iam.PutUserPermissionsBoundaryInput{UserName: aws.String("invitee"), PermissionsBoundary: boundary.Policy.Arn}); err != nil {
				t.Fatal(err)
			}
			_, err = memberOrg.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: id})
			assertAPIError(t, err, "AccessDeniedException")
			if _, err := memberIAM.DeleteUserPermissionsBoundary(t.Context(), &iam.DeleteUserPermissionsBoundaryInput{UserName: aws.String("invitee")}); err != nil {
				t.Fatal(err)
			}
			// Reopening must retain staged tags and authorization, not pre-create roles.
			close()
			closeDB()
			open()
			_, c, close = creationEventCloud(t, backends, source)
			root := c.organizations("test", "test")
			memberOrg = c.organizations(key, secret)
			memberIAM = c.iam(member, "test", "")
			memberAccount = c.account(member, "test", "")
			advanceClock(t, source, time.Hour)
			accepted, err := memberOrg.AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: id})
			if err != nil || accepted.Handshake.State != orgtypes.HandshakeStateAccepted {
				t.Fatal("accept", accepted, err)
			}
			memberDescription, err := root.DescribeAccount(t.Context(), &organizations.DescribeAccountInput{AccountId: aws.String(member)})
			if err != nil {
				t.Fatal(err)
			}
			if memberDescription.Account.JoinedMethod != orgtypes.AccountJoinedMethodInvited || *memberDescription.Account.Name != "Existing identity" || !memberDescription.Account.JoinedTimestamp.Equal(source.Now()) {
				t.Fatal("joined identity", memberDescription.Account)
			}
			tags, err := root.ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: aws.String(member)})
			if err != nil || !reflect.DeepEqual(tags.Tags, input.Tags) {
				t.Fatal("staged tags", tags, err)
			}
			userAfter, err := memberIAM.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("invitee")})
			if err != nil || !reflect.DeepEqual(userAfter.User, userBefore.User) {
				t.Fatal("existing IAM identity changed", err)
			}
			infoAfter, err := memberAccount.GetAccountInformation(t.Context(), &account.GetAccountInformationInput{})
			if err != nil || !infoBefore.AccountCreatedDate.Equal(*infoAfter.AccountCreatedDate) {
				t.Fatal("account creation date changed", err)
			}
			contact, err := memberAccount.GetContactInformation(t.Context(), &account.GetContactInformationInput{})
			if err != nil || !reflect.DeepEqual(contact.ContactInformation, primaryContact()) {
				t.Fatal("contact changed", err)
			}
			if _, err := memberIAM.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("AWSServiceRoleForOrganizations")}); err != nil {
				t.Fatal("missing protected service role", err)
			}
			_, err = memberIAM.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")})
			assertAPIError(t, err, "NoSuchEntity")
			// The joined account is immediately governed by the root SCP hierarchy.
			f.cloud, f.org, f.iam = c, root, c.iam("test", "test", "")
			f.policy(t, "joined-deny", `{"Statement":{"Effect":"Deny","Action":"sqs:CreateQueue","Resource":"*"}}`, f.rootID)
			_, err = c.sqs(member, "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("must-deny")})
			assertAPIError(t, err, "AccessDenied")
			rows := lifecycleEvents(t, backends.Journal)
			states := []string{}
			for _, row := range rows {
				if row.HandshakeChanged.HandshakeID == *id {
					states = append(states, row.HandshakeChanged.State)
					if row.RequestID == "" || row.AccountID != "000000000000" {
						t.Fatal("missing event origin", row)
					}
				}
			}
			if !reflect.DeepEqual(states, []string{"OPEN", "ACCEPTED"}) {
				t.Fatal("denials published events", states)
			}
			close()
			closeDB()
			open()
			_, c, _ = creationEventCloud(t, backends, source)
			retained, err := c.organizations("test", "test").DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: id})
			if err != nil || retained.Handshake.State != orgtypes.HandshakeStateAccepted {
				t.Fatal("retained handshake", retained, err)
			}
		})
	}
}

func TestOrganizationsInvitationCommitRollback(t *testing.T) {
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
			f := organizationFixture(t, c, source)
			const member = "222222222222"
			in := &organizations.InviteAccountToOrganizationInput{Target: &orgtypes.HandshakeParty{Type: orgtypes.HandshakePartyTypeAccount, Id: aws.String(member)}}
			before := lifecycleEvents(t, backends.Journal)
			fault.mode.Store(1)
			_, err := f.org.InviteAccountToOrganization(t.Context(), in)
			assertAPIError(t, err, "ServiceException")
			listed, err := f.org.ListHandshakesForOrganization(t.Context(), &organizations.ListHandshakesForOrganizationInput{})
			if err != nil || len(listed.Handshakes) != 0 || !reflect.DeepEqual(lifecycleEvents(t, backends.Journal), before) {
				t.Fatal("failed invitation leaked", listed, err)
			}
			fault.mode.Store(0)
			opened, err := f.org.InviteAccountToOrganization(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			before = lifecycleEvents(t, backends.Journal)
			for _, mode := range []int32{1, 2} {
				fault.mode.Store(mode)
				_, err = c.organizations(member, "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: opened.Handshake.Id})
				assertAPIError(t, err, "ServiceException")
				pending, err := f.org.DescribeHandshake(t.Context(), &organizations.DescribeHandshakeInput{HandshakeId: opened.Handshake.Id})
				if err != nil || pending.Handshake.State != orgtypes.HandshakeStateOpen {
					t.Fatal("failed commit consumed invitation", err)
				}
				_, err = c.iam(member, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("AWSServiceRoleForOrganizations")})
				assertAPIError(t, err, "NoSuchEntity")
				_, err = f.org.DescribeAccount(t.Context(), &organizations.DescribeAccountInput{AccountId: aws.String(member)})
				assertAPIError(t, err, "AccountNotFoundException")
				if !reflect.DeepEqual(lifecycleEvents(t, backends.Journal), before) {
					t.Fatal("failed join leaked journal event")
				}
			}
			fault.mode.Store(0)
			if _, err := c.organizations(member, "test").AcceptHandshake(t.Context(), &organizations.AcceptHandshakeInput{HandshakeId: opened.Handshake.Id}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

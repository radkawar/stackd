package organizations_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	provider "stackd/internal/services/organizations"
)

func TestInvitationReservationsCoordinateCreationAndAcceptanceSDK(t *testing.T) {
	quotas, err := provider.NewAccountQuotas([]provider.AccountQuota{{Partition: "aws", ManagementAccountID: managementID, Maximum: 2}})
	if err != nil {
		t.Fatal(err)
	}
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	service := provider.NewWithConfig(provider.Config{Clock: source, AccountQuotas: quotas})
	service.SetAccountProvisioner(accountProvisioningOnly{})
	root := fixedClient(t, service, orgRoot(managementID, "aws"))
	createOrg(t, root)
	const member = "222222222222"
	target := &types.HandshakeParty{Type: types.HandshakePartyTypeAccount, Id: aws.String(member)}
	pending, err := root.CreateAccount(t.Context(), &sdk.CreateAccountInput{AccountName: aws.String("competing"), Email: aws.String("competing@example.test")})
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := root.InviteAccountToOrganization(t.Context(), &sdk.InviteAccountToOrganizationInput{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateAccount(t.Context(), &sdk.CreateAccountInput{AccountName: aws.String("blocked"), Email: aws.String("blocked@example.test")})
	requireCode(t, err, "ConstraintViolationException")
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := service.JobDriver().RunDue(t.Context(), 10); err != nil {
		t.Fatal(err)
	}
	status, err := root.DescribeCreateAccountStatus(t.Context(), &sdk.DescribeCreateAccountStatusInput{CreateAccountRequestId: pending.CreateAccountStatus.Id})
	if err != nil || status.CreateAccountStatus.FailureReason != types.CreateAccountFailureReasonAccountLimitExceeded {
		t.Fatal("reservation failed to protect capacity", status, err)
	}
	recipient := fixedClient(t, service, orgRoot(member, "aws"))
	if _, err := recipient.AcceptHandshake(t.Context(), &sdk.AcceptHandshakeInput{HandshakeId: invitation.Handshake.Id}); err != nil {
		t.Fatal("own reservation counted twice", err)
	}
	_, err = root.InviteAccountToOrganization(t.Context(), &sdk.InviteAccountToOrganizationInput{Target: &types.HandshakeParty{Type: types.HandshakePartyTypeAccount, Id: aws.String("333333333333")}})
	requireCode(t, err, "ConstraintViolationException")
}

func TestInvitationCancellationReleasesCapacityButRetainsDailyAttemptSDK(t *testing.T) {
	quotas, err := provider.NewAccountQuotas([]provider.AccountQuota{{Partition: "aws", ManagementAccountID: managementID, Maximum: 2}})
	if err != nil {
		t.Fatal(err)
	}
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	service := provider.NewWithConfig(provider.Config{Clock: source, AccountQuotas: quotas})
	service.SetAccountProvisioner(accountProvisioningOnly{})
	root := fixedClient(t, service, orgRoot(managementID, "aws"))
	createOrg(t, root)
	for i := range 20 {
		opened, err := root.InviteAccountToOrganization(t.Context(), &sdk.InviteAccountToOrganizationInput{Target: &types.HandshakeParty{Type: types.HandshakePartyTypeAccount, Id: aws.String(fmt.Sprintf("%012d", 222222222222+i))}})
		if err != nil {
			t.Fatal(i, err)
		}
		if _, err := root.CancelHandshake(t.Context(), &sdk.CancelHandshakeInput{HandshakeId: opened.Handshake.Id}); err != nil {
			t.Fatal(err)
		}
	}
	input := &sdk.InviteAccountToOrganizationInput{Target: &types.HandshakeParty{Type: types.HandshakePartyTypeAccount, Id: aws.String("333333333333")}}
	_, err = root.InviteAccountToOrganization(t.Context(), input)
	requireCode(t, err, "ConstraintViolationException")
	if err := source.Advance(24*time.Hour + time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if _, err := root.InviteAccountToOrganization(t.Context(), input); err != nil {
		t.Fatal("daily quota did not recover", err)
	}
}

package organizations_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/clock"
	provider "stackd/internal/services/organizations"
)

func TestAccountQuotaIsScopedByPartitionSDK(t *testing.T) {
	quotas, err := provider.NewAccountQuotas([]provider.AccountQuota{
		{Partition: "aws", ManagementAccountID: managementID, Maximum: 2},
		{Partition: "aws-us-gov", ManagementAccountID: managementID, Maximum: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	source := clock.NewManual(time.Unix(0, 0))
	service := provider.NewWithConfig(provider.Config{Clock: source, AccountQuotas: quotas})
	service.SetAccountProvisioner(accountProvisioningOnly{})
	commercial := fixedClient(t, service, orgRoot(managementID, "aws"))
	government := fixedClient(t, service, orgRoot(managementID, "aws-us-gov"))
	createOrg(t, commercial)
	createOrg(t, government)
	in := &sdk.CreateAccountInput{AccountName: aws.String("member"), Email: aws.String("member@example.test")}
	_, err = government.CreateAccount(t.Context(), in)
	requireCode(t, err, "ConstraintViolationException")
	accepted, err := commercial.CreateAccount(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	status := waitAccount(t, commercial, accepted.CreateAccountStatus)
	if status.State != types.CreateAccountStateSucceeded {
		t.Fatalf("other partition's quota applied: %+v", status)
	}
}

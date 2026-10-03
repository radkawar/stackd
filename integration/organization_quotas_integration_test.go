package stackd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
	iamstore "stackd/storage/iam"
)

func quotaOrganization(t *testing.T, c cloudClients, owner string) *organizations.Client {
	t.Helper()
	client := c.organizations(owner, "test")
	if _, err := client.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	return client
}

func quotaAccount(t *testing.T, client *organizations.Client, name string) *orgtypes.CreateAccountStatus {
	t.Helper()
	out, err := client.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: &name, Email: aws.String(name + "@example.test")})
	if err != nil {
		t.Fatal(err)
	}
	return out.CreateAccountStatus
}

func assertAccountQuotaError(t *testing.T, err error) {
	t.Helper()
	var constraint *orgtypes.ConstraintViolationException
	if !errors.As(err, &constraint) || constraint.Reason != orgtypes.ConstraintViolationExceptionReasonAccountNumberLimitExceeded {
		t.Fatalf("account quota error = %v", err)
	}
}

func TestOrganizationAccountQuotaAWSDefaultsAndAppliedOverrideSDK(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/organizations_quotas.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations struct{ Default, Applied struct{ Value float64 } }
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	standard, applied := int(fixture.Observations.Default.Value), int(fixture.Observations.Applied.Value)
	for _, useApplied := range []bool{false, true} {
		t.Run(fmt.Sprint(useApplied), func(t *testing.T) {
			source := clock.NewManual(time.Unix(0, 0))
			config := stackd.Config{Clock: source}
			members := standard - 1
			if useApplied {
				config.OrganizationAccountQuotas = []stackd.OrganizationAccountQuota{{Partition: "aws", ManagementAccountID: "000000000000", Maximum: applied}}
				members = standard // Cross the default limit using the captured applied quota.
			}
			c := clockCloud(t, config)
			org := quotaOrganization(t, c, "test")
			for i := range members {
				status := waitAccountCreation(t, org, quotaAccount(t, org, fmt.Sprintf("member-%d", i)), source)
				if status.State != orgtypes.CreateAccountStateSucceeded {
					t.Fatalf("creation failed: %+v", status)
				}
			}
			accounts, err := org.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
			if err != nil || len(accounts.Accounts) != members+1 {
				t.Fatalf("accounts: %+v, %v", accounts, err)
			}
			if !useApplied {
				_, err := org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("over-limit"), Email: aws.String("over-limit@example.test")})
				assertAccountQuotaError(t, err)
				statuses, err := org.ListCreateAccountStatus(t.Context(), &organizations.ListCreateAccountStatusInput{})
				if err != nil || len(statuses.CreateAccountStatuses) != members {
					t.Fatalf("rejected request created a job: %+v, %v", statuses, err)
				}
			}
		})
	}
}

func TestOrganizationAccountQuotaCountsManagementAndClosedAccountsSDK(t *testing.T) {
	source := clock.NewManual(time.Unix(0, 0))
	overrides := []stackd.OrganizationAccountQuota{{Partition: "aws", ManagementAccountID: "000000000000", Maximum: 2}}
	c := clockCloud(t, stackd.Config{Clock: source, OrganizationAccountQuotas: overrides})
	overrides[0].Maximum = 100 // Configuration is detached at construction.
	org := quotaOrganization(t, c, "test")
	created := waitAccountCreation(t, org, quotaAccount(t, org, "only-member"), source)
	if created.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("creation failed: %+v", created)
	}
	if _, err := org.CloseAccount(t.Context(), &organizations.CloseAccountInput{AccountId: created.AccountId}); err != nil {
		t.Fatal(err)
	}
	// The same management account cannot evade a global quota through a region.
	regional := organizations.New(organizations.Options{Region: "eu-west-2", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	_, err := regional.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("closed-slot"), Email: aws.String("closed-slot@example.test")})
	assertAccountQuotaError(t, err)
	// The override applies only to its management account; another organization
	// in the same partition can still exceed two total accounts.
	other := quotaOrganization(t, c, "111111111111")
	for i := range 2 {
		status := waitAccountCreation(t, other, quotaAccount(t, other, fmt.Sprintf("other-%d", i)), source)
		if status.State != orgtypes.CreateAccountStateSucceeded {
			t.Fatalf("foreign quota applied: %+v", status)
		}
	}
}

func TestOrganizationAccountQuotaCompetingCreationsSDK(t *testing.T) {
	source := clock.NewManual(time.Unix(0, 0))
	backends := storage.NewMemory()
	c := clockCloud(t, stackd.Config{Clock: source, Storage: backends, OrganizationAccountQuotas: []stackd.OrganizationAccountQuota{{Partition: "aws", ManagementAccountID: "000000000000", Maximum: 2}}})
	org := quotaOrganization(t, c, "test")
	jobs := []*orgtypes.CreateAccountStatus{quotaAccount(t, org, "first"), quotaAccount(t, org, "second")}
	advanceClock(t, source, time.Second)
	successes, failedID := 0, ""
	for _, job := range jobs {
		status := waitAccountCreation(t, org, job, nil)
		switch status.State {
		case orgtypes.CreateAccountStateSucceeded:
			successes++
		case orgtypes.CreateAccountStateFailed:
			if status.FailureReason != orgtypes.CreateAccountFailureReasonAccountLimitExceeded || status.AccountId != nil || status.CompletedTimestamp == nil {
				t.Fatalf("quota failure result: %+v", status)
			}
			failedID = aws.ToString(status.Id)
		default:
			t.Fatalf("unfinished creation: %+v", status)
		}
	}
	if successes != 1 || failedID == "" {
		t.Fatalf("quota outcomes: successes=%d failed=%s", successes, failedID)
	}
	record, _, err := backends.Organizations.Load(t.Context(), "aws")
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Organizations[0].Accounts) != 2 {
		t.Fatalf("quota exceeded: %+v", record.Organizations[0].Accounts)
	}
	for _, job := range record.Organizations[0].Creations {
		if job.ID != failedID {
			continue
		}
		if err := backends.IAM.View(t.Context(), func(tx iamstore.ReadTx) error {
			roles, err := tx.Roles(iamstore.Scope{Partition: "aws", AccountID: job.AccountID})
			if len(roles) != 0 {
				t.Fatalf("failed account left roles: %+v", roles)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrganizationAccountQuotaReconfigurationAndRecoverySDK(t *testing.T) {
	source := clock.NewManual(time.Unix(0, 0))
	backends := storage.NewMemory()
	config := stackd.Config{Clock: source, Storage: backends, OrganizationAccountQuotas: []stackd.OrganizationAccountQuota{{Partition: "aws", ManagementAccountID: "000000000000", Maximum: 3}}}
	first := clockCloud(t, config)
	org := quotaOrganization(t, first, "test")
	member := waitAccountCreation(t, org, quotaAccount(t, org, "retained"), source)
	pending := quotaAccount(t, org, "pending")
	if err := first.server.Config.Handler.(*stackd.Stack).Close(); err != nil {
		t.Fatal(err)
	}
	config.OrganizationAccountQuotas[0].Maximum = 1
	advanceClock(t, source, time.Second)
	reduced := clockCloud(t, config)
	status := waitAccountCreation(t, reduced.organizations("test", "test"), pending, nil)
	if status.State != orgtypes.CreateAccountStateFailed || status.FailureReason != orgtypes.CreateAccountFailureReasonAccountLimitExceeded {
		t.Fatalf("recovery ignored applied quota: %+v", status)
	}
	if _, err := reduced.iam(*member.AccountId, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("OrganizationAccountAccessRole")}); err != nil {
		t.Fatal("quota decrease removed existing access", err)
	}
	if err := reduced.server.Config.Handler.(*stackd.Stack).Close(); err != nil {
		t.Fatal(err)
	}
	config.OrganizationAccountQuotas[0].Maximum = 3
	raised := clockCloud(t, config)
	client := raised.organizations("test", "test")
	retried := waitAccountCreation(t, client, quotaAccount(t, client, "pending"), source)
	if retried.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("quota increase did not allow retry: %+v", retried)
	}
	previous, err := client.DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: pending.Id})
	if err != nil || previous.CreateAccountStatus.State != orgtypes.CreateAccountStateFailed {
		t.Fatalf("quota increase rewrote completed failure: %+v, %v", previous, err)
	}
}

func TestOrganizationAccountQuotaConfigurationRejectsInvalidScopesAndLimits(t *testing.T) {
	valid := stackd.OrganizationAccountQuota{Partition: "aws", ManagementAccountID: "000000000000", Maximum: 10}
	for _, change := range []func(*stackd.OrganizationAccountQuota){
		func(q *stackd.OrganizationAccountQuota) { q.Partition = "" },
		func(q *stackd.OrganizationAccountQuota) { q.Partition = "aws/other" },
		func(q *stackd.OrganizationAccountQuota) { q.ManagementAccountID = "test" },
		func(q *stackd.OrganizationAccountQuota) { q.ManagementAccountID = "00000000000x" },
		func(q *stackd.OrganizationAccountQuota) { q.Maximum = 0 },
		func(q *stackd.OrganizationAccountQuota) { q.Maximum = -1 },
		func(q *stackd.OrganizationAccountQuota) { q.Maximum = 50001 },
	} {
		invalid := valid
		change(&invalid)
		service, err := stackd.New(stackd.Config{OrganizationAccountQuotas: []stackd.OrganizationAccountQuota{invalid}})
		if err == nil {
			_ = service.Close()
			t.Fatalf("accepted invalid quota: %+v", invalid)
		}
	}
	if service, err := stackd.New(stackd.Config{OrganizationAccountQuotas: []stackd.OrganizationAccountQuota{valid, valid}}); err == nil {
		_ = service.Close()
		t.Fatal("accepted duplicate quota scopes")
	}
}

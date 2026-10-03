package stackd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd"
	"stackd/clock"
	"stackd/storage"
)

func waitAccountCreation(t *testing.T, client *organizations.Client, status *orgtypes.CreateAccountStatus, source *clock.Manual) *orgtypes.CreateAccountStatus {
	t.Helper()
	if source != nil {
		advanceClock(t, source, time.Second)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for status.State == orgtypes.CreateAccountStateInProgress {
		out, err := client.DescribeCreateAccountStatus(ctx, &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: status.Id})
		if err != nil {
			t.Fatal(err)
		}
		status = out.CreateAccountStatus
		if status.State != orgtypes.CreateAccountStateInProgress {
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	return status
}

func TestOrganizationAccountCreationAWSFailureReplaySDK(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/iam/organizations_account_creation.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations struct {
			Requests []struct {
				Initial map[string]any
				Polls   []map[string]any
			}
			ListedFailures []map[string]any `json:"listed_failures"`
		}
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	f := newOrganizationReportFixture(t, nil)
	org, err := f.org.DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	in := &organizations.CreateAccountInput{AccountName: aws.String("OWNED_REQUEST"), Email: org.Organization.MasterAccountEmail}
	created, err := f.org.CreateAccount(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	assertCapturedAccountStatus(t, created.CreateAccountStatus, capture.Observations.Requests[0].Initial)
	_, err = f.org.CreateAccount(t.Context(), in)
	assertAPIError(t, err, "ConcurrentModificationException")
	_, err = f.org.DeleteOrganization(t.Context(), &organizations.DeleteOrganizationInput{})
	assertAPIError(t, err, "ConcurrentModificationException")
	// Reads cannot initialize an account or advance the caller's service clock.
	advanceClock(t, f.clock, time.Second-time.Nanosecond)
	described, err := f.org.DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: created.CreateAccountStatus.Id})
	if err != nil {
		t.Fatal(err)
	}
	assertCapturedAccountStatus(t, described.CreateAccountStatus, capture.Observations.Requests[0].Initial)
	advanceClock(t, f.clock, time.Nanosecond)
	status := waitAccountCreation(t, f.org, created.CreateAccountStatus, nil)
	assertCapturedAccountStatus(t, status, capture.Observations.Requests[0].Polls[0])
	if !status.CompletedTimestamp.Equal(f.clock.Now()) {
		t.Fatalf("completion timestamp = %v", status.CompletedTimestamp)
	}
	listed, err := f.org.ListCreateAccountStatus(t.Context(), &organizations.ListCreateAccountStatusInput{States: []orgtypes.CreateAccountState{orgtypes.CreateAccountStateFailed}})
	if err != nil || len(listed.CreateAccountStatuses) != 1 {
		t.Fatalf("failed statuses = %+v, %v", listed, err)
	}
	assertCapturedAccountStatus(t, &listed.CreateAccountStatuses[0], capture.Observations.ListedFailures[0])
	accounts, err := f.org.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
	if err != nil || len(accounts.Accounts) != 1 {
		t.Fatalf("failed creation changed accounts: %+v, %v", accounts, err)
	}
}

func assertCapturedAccountStatus(t *testing.T, status *orgtypes.CreateAccountStatus, want map[string]any) {
	t.Helper()
	if string(status.State) != want["State"] || aws.ToString(status.AccountName) != want["AccountName"] {
		t.Fatalf("status = %+v, capture = %+v", status, want)
	}
	for field, present := range map[string]bool{"Id": status.Id != nil, "AccountId": status.AccountId != nil, "RequestedTimestamp": status.RequestedTimestamp != nil, "CompletedTimestamp": status.CompletedTimestamp != nil, "FailureReason": status.FailureReason != ""} {
		if _, expected := want[field]; present != expected {
			t.Errorf("%s presence = %v, want %v", field, present, expected)
		}
	}
	if reason, ok := want["FailureReason"]; ok && string(status.FailureReason) != reason {
		t.Errorf("failure = %s, want %s", status.FailureReason, reason)
	}
}

func TestOrganizationAccountCreationPendingQuotaAndIsolationSDK(t *testing.T) {
	f := newOrganizationReportFixture(t, nil)
	var pending []*orgtypes.CreateAccountStatus
	for i := range 5 {
		out, err := f.org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String(fmt.Sprintf("member-%d", i)), Email: aws.String(fmt.Sprintf("member-%d@example.test", i))})
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, out.CreateAccountStatus)
	}
	in := &organizations.CreateAccountInput{AccountName: aws.String("sixth"), Email: aws.String("sixth@example.test")}
	_, err := f.org.CreateAccount(t.Context(), in)
	assertAPIError(t, err, "ConstraintViolationException")
	var limit *orgtypes.ConstraintViolationException
	if !errors.As(err, &limit) || limit.Reason != orgtypes.ConstraintViolationExceptionReasonAccountCreationRateLimitExceeded {
		t.Fatalf("pending quota reason: %v", err)
	}
	accounts, err := f.org.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
	if err != nil || len(accounts.Accounts) != 1 {
		t.Fatalf("pending accounts became visible: %+v, %v", accounts, err)
	}
	other := f.cloud.organizations("333333333333", "test")
	if _, err := other.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	_, err = other.DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: pending[0].Id})
	assertAPIError(t, err, "CreateAccountStatusNotFoundException")
	pager := organizations.NewListCreateAccountStatusPaginator(f.org, &organizations.ListCreateAccountStatusInput{MaxResults: aws.Int32(2), States: []orgtypes.CreateAccountState{orgtypes.CreateAccountStateInProgress}})
	seen := map[string]bool{}
	for pager.HasMorePages() {
		page, err := pager.NextPage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range page.CreateAccountStatuses {
			id := aws.ToString(status.Id)
			if seen[id] || status.State != orgtypes.CreateAccountStateInProgress {
				t.Fatalf("repeated/nonpending status: %+v", status)
			}
			seen[id] = true
		}
	}
	if len(seen) != 5 {
		t.Fatalf("pending count = %d", len(seen))
	}
	advanceClock(t, f.clock, time.Second)
	for _, status := range pending {
		if status = waitAccountCreation(t, f.org, status, nil); status.State != orgtypes.CreateAccountStateSucceeded {
			t.Fatalf("creation failed: %+v", status)
		}
	}
	next, err := f.org.CreateAccount(t.Context(), in)
	if err != nil {
		t.Fatal("completion did not release a pending slot", err)
	}
	status := waitAccountCreation(t, f.org, next.CreateAccountStatus, f.clock)
	if status.State != orgtypes.CreateAccountStateSucceeded || aws.ToString(status.AccountId) != "100000000006" {
		t.Fatalf("rejected request consumed allocation: %+v", status)
	}
}

func TestOrganizationAccountCreationRecoversRetainedBackendSDK(t *testing.T) {
	backends := storage.NewMemory()
	f := newOrganizationReportFixture(t, backends)
	created, err := f.org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("recovered"), Email: aws.String("recovered@example.test"), RoleName: aws.String("RecoveredAccess"), Tags: []orgtypes.Tag{{Key: aws.String("team"), Value: aws.String("original")}}})
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := backends.Organizations.Load(t.Context(), "aws")
	if err != nil {
		t.Fatal(err)
	}
	record.Organizations[0].Creations[0].Tags["team"] = "changed outside storage"
	if err := f.cloud.server.Config.Handler.(*stackd.Stack).Close(); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, f.clock, 3*time.Second)
	c := clockCloud(t, stackd.Config{Storage: backends, Clock: f.clock})
	org := c.organizations("test", "test")
	status := waitAccountCreation(t, org, created.CreateAccountStatus, nil)
	if status.State != orgtypes.CreateAccountStateSucceeded || !status.CompletedTimestamp.Equal(f.clock.Now()) {
		t.Fatalf("recovered status: %+v", status)
	}
	tags, err := org.ListTagsForResource(t.Context(), &organizations.ListTagsForResourceInput{ResourceId: status.AccountId})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Value) != "original" {
		t.Fatalf("recovered tags: %+v, %v", tags, err)
	}
	role, err := c.iam(*status.AccountId, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String("RecoveredAccess")})
	if err != nil || !role.Role.CreateDate.Equal(*status.CompletedTimestamp) {
		t.Fatalf("recovered IAM role: %+v, %v", role, err)
	}
	// Reopening a completed job cannot recreate or overwrite the IAM role.
	if _, err := c.iam(*status.AccountId, "test", "").UpdateRoleDescription(t.Context(), &iam.UpdateRoleDescriptionInput{RoleName: role.Role.RoleName, Description: aws.String("customer edit")}); err != nil {
		t.Fatal(err)
	}
	if err := c.server.Config.Handler.(*stackd.Stack).Close(); err != nil {
		t.Fatal(err)
	}
	again := clockCloud(t, stackd.Config{Storage: backends, Clock: f.clock})
	current, err := again.iam(*status.AccountId, "test", "").GetRole(t.Context(), &iam.GetRoleInput{RoleName: role.Role.RoleName})
	if err != nil || aws.ToString(current.Role.Description) != "customer edit" || aws.ToString(current.Role.RoleId) != aws.ToString(role.Role.RoleId) {
		t.Fatalf("replayed completed job: %+v, %v", current, err)
	}
}

func TestOrganizationAccountCreationProvisioningConflictSDK(t *testing.T) {
	backends := storage.NewMemory()
	f := newOrganizationReportFixture(t, backends)
	member := f.cloud.iam("100000000001", "test", "")
	existing, err := member.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("OrganizationAccountAccessRole"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("collision"), Email: aws.String("collision@example.test")})
	if err != nil {
		t.Fatal(err)
	}
	status := waitAccountCreation(t, f.org, created.CreateAccountStatus, f.clock)
	if status.State != orgtypes.CreateAccountStateFailed || status.FailureReason != orgtypes.CreateAccountFailureReasonInternalFailure || status.AccountId != nil {
		t.Fatalf("provisioning conflict: %+v", status)
	}
	roles, err := member.ListRoles(t.Context(), &iam.ListRolesInput{})
	if err != nil || len(roles.Roles) != 1 || aws.ToString(roles.Roles[0].RoleId) != aws.ToString(existing.Role.RoleId) {
		t.Fatalf("conflict altered existing role or retained partial service role: %+v, %v", roles, err)
	}
	accounts, err := f.org.ListAccounts(t.Context(), &organizations.ListAccountsInput{})
	if err != nil || len(accounts.Accounts) != 1 {
		t.Fatalf("failed provisioning retained membership: %+v, %v", accounts, err)
	}
	rows := lifecycleEvents(t, backends.Journal)
	if len(rows) != 2 || rows[0].AccountCreationChanged.State != "IN_PROGRESS" || rows[1].AccountCreationChanged.State != "FAILED" || rows[1].AccountCreationChanged.FailureReason != "INTERNAL_FAILURE" || rows[1].AccountCreationChanged.AccountID != "" || !rows[1].At.Equal(f.clock.Now()) {
		t.Fatal("permanent IAM rejection did not publish only its terminal failure", rows)
	}
}

func TestOrganizationAccountCreationRejectsInvalidAdmissionSDK(t *testing.T) {
	backends := storage.NewMemory()
	orgs := &accountCreationStorage{Storage: backends.Organizations}
	backends.Organizations = orgs
	f := newOrganizationReportFixture(t, backends)
	for _, test := range []struct {
		name   string
		change func(*organizations.CreateAccountInput)
	}{
		{"non-ASCII name", func(in *organizations.CreateAccountInput) { in.AccountName = aws.String("équipe") }},
		{"empty role", func(in *organizations.CreateAccountInput) { in.RoleName = aws.String("") }},
		{"reserved role", func(in *organizations.CreateAccountInput) { in.RoleName = aws.String("AWSServiceRoleForOther") }},
		{"invalid email", func(in *organizations.CreateAccountInput) { in.Email = aws.String(".name@example.test") }},
		{"billing enum", func(in *organizations.CreateAccountInput) {
			in.IamUserAccessToBilling = orgtypes.IAMUserAccessToBilling("INVALID")
		}},
		{"reserved tag", func(in *organizations.CreateAccountInput) {
			in.Tags = []orgtypes.Tag{{Key: aws.String("aws:reserved"), Value: aws.String("value")}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := &organizations.CreateAccountInput{AccountName: aws.String("admission"), Email: aws.String("admission@example.test")}
			test.change(in)
			_, err := f.org.CreateAccount(t.Context(), in)
			assertAPIError(t, err, "InvalidInputException")
		})
	}
	orgs.fail.Store(true)
	in := &organizations.CreateAccountInput{AccountName: aws.String("admission"), Email: aws.String("admission@example.test")}
	_, err := f.org.CreateAccount(t.Context(), in)
	assertAPIError(t, err, "ServiceException")
	orgs.fail.Store(false)
	listed, err := f.org.ListCreateAccountStatus(t.Context(), &organizations.ListCreateAccountStatusInput{})
	if err != nil || len(listed.CreateAccountStatuses) != 0 {
		t.Fatalf("rejected admission retained a job: %+v, %v", listed, err)
	}
	accepted, err := f.org.CreateAccount(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	status := waitAccountCreation(t, f.org, accepted.CreateAccountStatus, f.clock)
	if status.State != orgtypes.CreateAccountStateSucceeded || aws.ToString(status.AccountId) != "100000000001" {
		t.Fatalf("rejected admission consumed account identity: %+v", status)
	}
}

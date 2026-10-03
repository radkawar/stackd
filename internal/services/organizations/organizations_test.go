package organizations_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"

	iampolicy "stackd/iam/policy"
	"stackd/internal/awsctx"
	provider "stackd/internal/services/organizations"
)

const managementID = "111111111111"

var credentialPattern = regexp.MustCompile(`Credential=([^/]+)/`)

// These tests isolate Organizations state and authorization. The root SDK
// integration tests exercise actual IAM provisioning and shared rollback.
type accountProvisioningOnly struct{}

func (accountProvisioningOnly) WithAccountProvisioning(ctx context.Context, _ provider.AccountProvisioning, commit func(context.Context) error) error {
	return commit(ctx)
}

func organizationsOnly(storage provider.Storage) *provider.Service {
	service := provider.NewWithStorage(storage)
	service.SetAccountProvisioner(accountProvisioningOnly{})
	return service
}

func setup(t *testing.T) (*provider.Service, func(string, string) *sdk.Client) {
	t.Helper()
	service := organizationsOnly(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		match := credentialPattern.FindStringSubmatch(r.Header.Get("Authorization"))
		if len(match) != 2 {
			t.Error("SDK request did not include SigV4 credentials")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		meta := awsctx.Metadata{AccountID: match[1], Region: "us-east-1", Partition: "aws", RequestID: "organizations-test", PrincipalARN: "arn:aws:iam::" + match[1] + ":root", PrincipalID: match[1]}
		service.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), meta)))
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = service.Close() })
	return service, func(account, region string) *sdk.Client {
		return sdk.New(sdk.Options{Region: region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider(account, "local-secret", ""), RetryMaxAttempts: 1})
	}
}

func controlLevels(t *testing.T, service *provider.Service, account string) []iampolicy.PolicyLevel {
	t.Helper()
	levels, err := service.ServiceControlPolicies(awsctx.WithMetadata(context.Background(), awsctx.Metadata{AccountID: account, Partition: "aws"}), account)
	if err != nil {
		t.Fatal(err)
	}
	return levels
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func createOrg(t *testing.T, client *sdk.Client) string {
	t.Helper()
	result, err := client.CreateOrganization(context.Background(), &sdk.CreateOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(result.Organization.MasterAccountId) != managementID || result.Organization.FeatureSet != types.OrganizationFeatureSetAll {
		t.Fatalf("unexpected organization: %#v", result.Organization)
	}
	roots, err := client.ListRoots(context.Background(), &sdk.ListRootsInput{})
	if err != nil || len(roots.Roots) != 1 {
		t.Fatalf("roots: %v, %v", roots, err)
	}
	if len(roots.Roots[0].PolicyTypes) != 1 || roots.Roots[0].PolicyTypes[0].Type != types.PolicyTypeServiceControlPolicy {
		t.Fatalf("SCP not enabled by default: %#v", roots.Roots[0])
	}
	return aws.ToString(roots.Roots[0].Id)
}

func createAccount(t *testing.T, client *sdk.Client, name string) string {
	t.Helper()
	result, err := client.CreateAccount(context.Background(), &sdk.CreateAccountInput{AccountName: aws.String(name), Email: aws.String(name + "@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	status := waitAccount(t, client, result.CreateAccountStatus)
	if status.State != types.CreateAccountStateSucceeded || status.RequestedTimestamp == nil || status.CompletedTimestamp == nil {
		t.Fatalf("bad account status: %#v", status)
	}
	described, err := client.DescribeCreateAccountStatus(context.Background(), &sdk.DescribeCreateAccountStatusInput{CreateAccountRequestId: status.Id})
	if err != nil || aws.ToString(described.CreateAccountStatus.AccountId) != aws.ToString(status.AccountId) {
		t.Fatalf("describe status: %v %v", described, err)
	}
	return aws.ToString(status.AccountId)
}

func TestAccountCreationRequiresIdentityProvisioner(t *testing.T) {
	service := organizationsOnly(nil)
	client := fixedClient(t, service, orgRoot(managementID, "aws"))
	createOrg(t, client)
	service.SetAccountProvisioner(nil)
	_, err := client.CreateAccount(t.Context(), &sdk.CreateAccountInput{AccountName: aws.String("unprovisioned"), Email: aws.String("unprovisioned@example.test")})
	requireCode(t, err, "ServiceException")
	accounts, err := client.ListAccounts(t.Context(), &sdk.ListAccountsInput{})
	if err != nil || len(accounts.Accounts) != 1 {
		t.Fatalf("account created without IAM: %+v, %v", accounts, err)
	}
	statuses, err := client.ListCreateAccountStatus(t.Context(), &sdk.ListCreateAccountStatusInput{})
	if err != nil || len(statuses.CreateAccountStatuses) != 0 {
		t.Fatalf("status retained without IAM: %+v, %v", statuses, err)
	}
}

func TestOrganizationAccountHierarchyLifecycle(t *testing.T) {
	_, clientFor := setup(t)
	ctx := context.Background()
	client := clientFor(managementID, "us-east-1")
	root := createOrg(t, client)
	_, err := client.CreateOrganization(ctx, &sdk.CreateOrganizationInput{})
	requireCode(t, err, "AlreadyInOrganizationException")
	unit, err := client.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(root), Name: aws.String("Engineering")})
	if err != nil {
		t.Fatal(err)
	}
	unitID := unit.OrganizationalUnit.Id
	_, err = client.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(root), Name: aws.String("Engineering")})
	requireCode(t, err, "DuplicateOrganizationalUnitException")
	accountID := createAccount(t, client, "development")
	account, err := client.DescribeAccount(ctx, &sdk.DescribeAccountInput{AccountId: aws.String(accountID)})
	if err != nil || account.Account.JoinedTimestamp == nil || account.Account.State != types.AccountStateActive {
		t.Fatalf("account: %v %v", account, err)
	}
	member := clientFor(accountID, "eu-west-2")
	if _, err := member.DescribeOrganization(ctx, &sdk.DescribeOrganizationInput{}); err != nil {
		t.Fatalf("membership must be region global: %v", err)
	}
	_, err = member.ListAccounts(ctx, &sdk.ListAccountsInput{})
	requireCode(t, err, "AccessDeniedException")
	_, err = clientFor("999999999999", "us-east-1").DescribeOrganization(ctx, &sdk.DescribeOrganizationInput{})
	requireCode(t, err, "AWSOrganizationsNotInUseException")
	_, err = client.MoveAccount(ctx, &sdk.MoveAccountInput{AccountId: aws.String(accountID), SourceParentId: aws.String(root), DestinationParentId: unitID})
	if err != nil {
		t.Fatal(err)
	}
	parents, err := client.ListParents(ctx, &sdk.ListParentsInput{ChildId: aws.String(accountID)})
	if err != nil || len(parents.Parents) != 1 || aws.ToString(parents.Parents[0].Id) != aws.ToString(unitID) {
		t.Fatalf("parents: %v %v", parents, err)
	}
	children, err := client.ListChildren(ctx, &sdk.ListChildrenInput{ParentId: unitID, ChildType: types.ChildTypeAccount})
	if err != nil || len(children.Children) != 1 || aws.ToString(children.Children[0].Id) != accountID {
		t.Fatalf("children: %v %v", children, err)
	}
	_, err = client.DeleteOrganizationalUnit(ctx, &sdk.DeleteOrganizationalUnitInput{OrganizationalUnitId: unitID})
	requireCode(t, err, "OrganizationalUnitNotEmptyException")
	_, err = client.DeleteOrganization(ctx, &sdk.DeleteOrganizationInput{})
	requireCode(t, err, "OrganizationNotEmptyException")
	paginator := sdk.NewListAccountsPaginator(client, &sdk.ListAccountsInput{MaxResults: aws.Int32(1)})
	seen := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range page.Accounts {
			id := aws.ToString(a.Id)
			if seen[id] {
				t.Fatalf("duplicate paginated account: %s", id)
			}
			seen[id] = true
		}
	}
	if len(seen) != 2 {
		t.Fatalf("accounts = %v", seen)
	}
	_, err = member.LeaveOrganization(ctx, &sdk.LeaveOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = member.DescribeOrganization(ctx, &sdk.DescribeOrganizationInput{})
	requireCode(t, err, "AWSOrganizationsNotInUseException")
	newOrg, err := member.CreateOrganization(ctx, &sdk.CreateOrganizationInput{})
	if err != nil || aws.ToString(newOrg.Organization.MasterAccountEmail) != "development@example.com" {
		t.Fatalf("standalone account identity was not preserved: %v %v", newOrg, err)
	}
	if _, err := client.DeleteOrganizationalUnit(ctx, &sdk.DeleteOrganizationalUnitInput{OrganizationalUnitId: unitID}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteOrganization(ctx, &sdk.DeleteOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	_, err = client.DescribeOrganization(ctx, &sdk.DescribeOrganizationInput{})
	requireCode(t, err, "AWSOrganizationsNotInUseException")
}

func TestPolicyAttachmentsInheritanceAndTypeReset(t *testing.T) {
	service, clientFor := setup(t)
	ctx := context.Background()
	client := clientFor(managementID, "us-east-1")
	root := createOrg(t, client)
	accountID := createAccount(t, client, "policy-member")
	_, err := client.DetachPolicy(ctx, &sdk.DetachPolicyInput{PolicyId: aws.String("p-FullAWSAccess"), TargetId: aws.String(accountID)})
	requireCode(t, err, "ConstraintViolationException")
	var constraint *types.ConstraintViolationException
	if !errors.As(err, &constraint) || constraint.Reason != types.ConstraintViolationExceptionReasonMinPolicyTypeAttachmentLimitExceeded {
		t.Fatalf("typed constraint reason: %v", err)
	}
	content := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	created, err := client.CreatePolicy(ctx, &sdk.CreatePolicyInput{Name: aws.String("S3Only"), Description: aws.String("Only S3"), Type: types.PolicyTypeServiceControlPolicy, Content: aws.String(content), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}})
	if err != nil {
		t.Fatal(err)
	}
	policyID := created.Policy.PolicySummary.Id
	if aws.ToString(created.Policy.Content) != content || created.Policy.PolicySummary.AwsManaged {
		t.Fatalf("bad policy: %#v", created.Policy)
	}
	if _, err := client.AttachPolicy(ctx, &sdk.AttachPolicyInput{PolicyId: policyID, TargetId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	_, err = client.AttachPolicy(ctx, &sdk.AttachPolicyInput{PolicyId: policyID, TargetId: aws.String(accountID)})
	requireCode(t, err, "DuplicatePolicyAttachmentException")
	if _, err := client.DetachPolicy(ctx, &sdk.DetachPolicyInput{PolicyId: aws.String("p-FullAWSAccess"), TargetId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	_, err = client.DeletePolicy(ctx, &sdk.DeletePolicyInput{PolicyId: policyID})
	requireCode(t, err, "PolicyInUseException")
	if levels := controlLevels(t, service, accountID); len(levels) != 2 || len(levels[1].Documents) != 1 || levels[1].Documents[0].Document != content {
		t.Fatalf("policy hierarchy: %#v", levels)
	}
	if levels := controlLevels(t, service, managementID); len(levels) != 0 {
		t.Fatal("management account must be exempt from SCPs")
	}
	if _, err := client.EnablePolicyType(ctx, &sdk.EnablePolicyTypeInput{RootId: aws.String(root), PolicyType: types.PolicyTypeTagPolicy}); err != nil {
		t.Fatal(err)
	}
	attached, err := client.ListPoliciesForTarget(ctx, &sdk.ListPoliciesForTargetInput{TargetId: aws.String(accountID), Filter: types.PolicyTypeServiceControlPolicy})
	if err != nil || len(attached.Policies) != 1 || aws.ToString(attached.Policies[0].Id) != aws.ToString(policyID) {
		t.Fatalf("enabling unrelated type changed SCPs: %v %v", attached, err)
	}
	_, err = client.UpdatePolicy(ctx, &sdk.UpdatePolicyInput{PolicyId: policyID, Name: aws.String("InvalidUpdate"), Content: aws.String(`{"Statement":[{"Effect":"No","Action":"*","Resource":"*"}]}`)})
	requireCode(t, err, "MalformedPolicyDocumentException")
	described, err := client.DescribePolicy(ctx, &sdk.DescribePolicyInput{PolicyId: policyID})
	if err != nil || aws.ToString(described.Policy.PolicySummary.Name) != "S3Only" {
		t.Fatal("invalid update was not atomic")
	}
	if _, err := client.DisablePolicyType(ctx, &sdk.DisablePolicyTypeInput{RootId: aws.String(root), PolicyType: types.PolicyTypeServiceControlPolicy}); err != nil {
		t.Fatal(err)
	}
	if levels := controlLevels(t, service, accountID); len(levels) != 0 {
		t.Fatal("disabled SCPs still returned")
	}
	if _, err := client.EnablePolicyType(ctx, &sdk.EnablePolicyTypeInput{RootId: aws.String(root), PolicyType: types.PolicyTypeServiceControlPolicy}); err != nil {
		t.Fatal(err)
	}
	attached, err = client.ListPoliciesForTarget(ctx, &sdk.ListPoliciesForTargetInput{TargetId: aws.String(accountID), Filter: types.PolicyTypeServiceControlPolicy})
	if err != nil || len(attached.Policies) != 1 || aws.ToString(attached.Policies[0].Id) != "p-FullAWSAccess" {
		t.Fatalf("SCP reset: %v %v", attached, err)
	}
	if _, err := client.DeletePolicy(ctx, &sdk.DeletePolicyInput{PolicyId: policyID}); err != nil {
		t.Fatal(err)
	}
}

func TestTagsDelegationAndAccountClose(t *testing.T) {
	_, clientFor := setup(t)
	ctx := context.Background()
	client := clientFor(managementID, "us-east-1")
	createOrg(t, client)
	accountID := createAccount(t, client, "security")
	principal := aws.String("guardduty.amazonaws.com")
	_, err := client.RegisterDelegatedAdministrator(ctx, &sdk.RegisterDelegatedAdministratorInput{AccountId: aws.String(accountID), ServicePrincipal: principal})
	requireCode(t, err, "ConstraintViolationException")
	if _, err := client.EnableAWSServiceAccess(ctx, &sdk.EnableAWSServiceAccessInput{ServicePrincipal: principal}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RegisterDelegatedAdministrator(ctx, &sdk.RegisterDelegatedAdministratorInput{AccountId: aws.String(accountID), ServicePrincipal: principal}); err != nil {
		t.Fatal(err)
	}
	delegate := clientFor(accountID, "eu-west-2")
	if _, err := delegate.ListAccounts(ctx, &sdk.ListAccountsInput{}); err != nil {
		t.Fatalf("delegated administrator should have Organizations read access: %v", err)
	}
	_, err = delegate.CreateAccount(ctx, &sdk.CreateAccountInput{AccountName: aws.String("Forbidden"), Email: aws.String("forbidden@example.com")})
	requireCode(t, err, "AccessDeniedException")
	delegates, err := client.ListDelegatedAdministrators(ctx, &sdk.ListDelegatedAdministratorsInput{ServicePrincipal: principal})
	if err != nil || len(delegates.DelegatedAdministrators) != 1 || aws.ToString(delegates.DelegatedAdministrators[0].Id) != accountID || delegates.DelegatedAdministrators[0].DelegationEnabledDate == nil {
		t.Fatalf("delegates: %v %v", delegates, err)
	}
	_, err = client.RemoveAccountFromOrganization(ctx, &sdk.RemoveAccountFromOrganizationInput{AccountId: aws.String(accountID)})
	requireCode(t, err, "ConstraintViolationException")
	tags := []types.Tag{{Key: aws.String("team"), Value: aws.String("security")}}
	if _, err := client.TagResource(ctx, &sdk.TagResourceInput{ResourceId: aws.String(accountID), Tags: tags}); err != nil {
		t.Fatal(err)
	}
	_, err = client.TagResource(ctx, &sdk.TagResourceInput{ResourceId: aws.String(accountID), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("changed")}, {Key: aws.String("aws:invalid"), Value: aws.String("x")}}})
	requireCode(t, err, "InvalidInputException")
	listed, err := client.ListTagsForResource(ctx, &sdk.ListTagsForResourceInput{ResourceId: aws.String(accountID)})
	if err != nil || len(listed.Tags) != 1 || aws.ToString(listed.Tags[0].Value) != "security" {
		t.Fatalf("invalid tag update was not atomic: %v %v", listed, err)
	}
	if _, err := client.DeregisterDelegatedAdministrator(ctx, &sdk.DeregisterDelegatedAdministratorInput{AccountId: aws.String(accountID), ServicePrincipal: principal}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CloseAccount(ctx, &sdk.CloseAccountInput{AccountId: aws.String(accountID)}); err != nil {
		t.Fatal(err)
	}
	a, err := client.DescribeAccount(ctx, &sdk.DescribeAccountInput{AccountId: aws.String(accountID)})
	if err != nil || a.Account.State != types.AccountStateClosed {
		t.Fatalf("closed account: %v %v", a, err)
	}
	_, err = client.CloseAccount(ctx, &sdk.CloseAccountInput{AccountId: aws.String(accountID)})
	requireCode(t, err, "AccountAlreadyClosedException")
}

func TestOUConstraintsAndPaginationScope(t *testing.T) {
	_, clientFor := setup(t)
	ctx := context.Background()
	client := clientFor(managementID, "us-east-1")
	root := createOrg(t, client)
	parent := root
	for depth := range 5 {
		unit, err := client.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(parent), Name: aws.String(fmt.Sprintf("Depth%d", depth))})
		if err != nil {
			t.Fatal(err)
		}
		parent = aws.ToString(unit.OrganizationalUnit.Id)
	}
	_, err := client.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(parent), Name: aws.String("TooDeep")})
	requireCode(t, err, "ConstraintViolationException")
	createAccount(t, client, "page-one")
	createAccount(t, client, "page-two")
	page, err := client.ListAccounts(ctx, &sdk.ListAccountsInput{MaxResults: aws.Int32(1)})
	if err != nil || page.NextToken == nil {
		t.Fatalf("missing token: %v %v", page, err)
	}
	_, err = client.ListAccountsForParent(ctx, &sdk.ListAccountsForParentInput{ParentId: aws.String(root), NextToken: page.NextToken})
	requireCode(t, err, "InvalidInputException")
	_, err = client.ListAccounts(ctx, &sdk.ListAccountsInput{NextToken: aws.String(aws.ToString(page.NextToken) + "x")})
	requireCode(t, err, "InvalidInputException")
	other := clientFor("222222222222", "us-west-2")
	if _, err := other.CreateOrganization(ctx, &sdk.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	_, err = other.ListAccounts(ctx, &sdk.ListAccountsInput{NextToken: page.NextToken})
	requireCode(t, err, "InvalidInputException")
}

func TestConcurrentAccountEmailUniqueness(t *testing.T) {
	_, clientFor := setup(t)
	client := clientFor(managementID, "us-east-1")
	createOrg(t, client)
	const requests = 12
	var wg sync.WaitGroup
	results := make(chan *types.CreateAccountStatus, requests)
	for range requests {
		wg.Go(func() {
			result, err := client.CreateAccount(t.Context(), &sdk.CreateAccountInput{AccountName: aws.String("Unique"), Email: aws.String("same@example.com")})
			if err != nil {
				requireCode(t, err, "ConcurrentModificationException")
				return
			}
			results <- result.CreateAccountStatus
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for status := range results {
		if waitAccount(t, client, status).State == types.CreateAccountStateSucceeded {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("succeeded=%d", successes)
	}
}

func waitAccount(t *testing.T, client *sdk.Client, status *types.CreateAccountStatus) *types.CreateAccountStatus {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for status.State == types.CreateAccountStateInProgress {
		out, err := client.DescribeCreateAccountStatus(ctx, &sdk.DescribeCreateAccountStatusInput{CreateAccountRequestId: status.Id})
		if err != nil {
			t.Fatal(err)
		}
		status = out.CreateAccountStatus
		if status.State != types.CreateAccountStateInProgress {
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

func TestMalformedJSONAndUnknownOperations(t *testing.T) {
	service := organizationsOnly(nil)
	for _, body := range []string{`[]`, `null`, `{} {}`, `{`} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		request.Header.Set("X-Amz-Target", "AWSOrganizationsV20161128.CreateOrganization")
		service.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "InvalidInputException") {
			t.Fatalf("body %s: %d %s", body, recorder.Code, recorder.Body.String())
		}
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	request.Header.Set("X-Amz-Target", "AWSOrganizationsV20161128.UnknownAction")
	service.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "UnknownOperationException") {
		t.Fatalf("unknown action: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestSCPQuotaBoundaries(t *testing.T) {
	_, clientFor := setup(t)
	ctx := context.Background()
	client := clientFor(managementID, "us-east-1")
	root := createOrg(t, client)
	content := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	// Current AWS quotas allow 10,240 characters and 10 direct SCP attachments.
	// SDK content retains whitespace, unlike console-compacted policy documents.
	padded := strings.Repeat(" ", 6000-len(content)) + content
	for index := range 10 {
		created, err := client.CreatePolicy(ctx, &sdk.CreatePolicyInput{
			Name: aws.String(fmt.Sprintf("Policy%d", index)), Description: aws.String("Quota test"),
			Type: types.PolicyTypeServiceControlPolicy, Content: aws.String(padded),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.AttachPolicy(ctx, &sdk.AttachPolicyInput{PolicyId: created.Policy.PolicySummary.Id, TargetId: aws.String(root)})
		if index < 9 {
			if err != nil {
				t.Fatalf("attachment %d should fit: %v", index+2, err)
			}
		} else {
			requireCode(t, err, "ConstraintViolationException")
			var constraint *types.ConstraintViolationException
			if !errors.As(err, &constraint) || constraint.Reason != types.ConstraintViolationExceptionReasonMaxPolicyTypeAttachmentLimitExceeded {
				t.Fatalf("attachment limit reason: %v", err)
			}
		}
	}
	oversized := strings.Repeat(" ", 10241-len(content)) + content
	_, err := client.CreatePolicy(ctx, &sdk.CreatePolicyInput{Name: aws.String("TooLarge"), Description: aws.String("Quota test"), Type: types.PolicyTypeServiceControlPolicy, Content: aws.String(oversized)})
	requireCode(t, err, "ConstraintViolationException")
	var constraint *types.ConstraintViolationException
	if !errors.As(err, &constraint) || constraint.Reason != types.ConstraintViolationExceptionReasonPolicyContentLimitExceeded {
		t.Fatalf("content limit reason: %v", err)
	}
}

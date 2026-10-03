package organizations_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	provider "stackd/internal/services/organizations"
)

type identityPolicies struct {
	mu        sync.RWMutex
	documents []string
}

func (s *identityPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := authorization.PolicySet{}
	for _, doc := range s.documents {
		set.Identity = append(set.Identity, iampolicy.Policy{Document: doc})
	}
	return set, nil
}
func (s *identityPolicies) set(documents ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents = documents
}

type orgControlSource struct{ service *provider.Service }

func (s orgControlSource) ServiceControlPolicies(ctx context.Context) ([]iampolicy.PolicyLevel, error) {
	return s.service.ServiceControlPolicies(ctx, awsctx.FromContext(ctx).AccountID)
}

func fixedClient(t *testing.T, s *provider.Service, m awsctx.Metadata) *sdk.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), m)))
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = s.Close() })
	return sdk.New(sdk.Options{Region: m.Region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
}

func orgRoot(account, partition string) awsctx.Metadata {
	return awsctx.Metadata{AccountID: account, Partition: partition, Region: "us-east-1", PrincipalARN: "arn:" + partition + ":iam::" + account + ":root", PrincipalID: account}
}

func allowAction(action, resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":%q,"Resource":%q}]}`, action, resource)
}

func TestSDKOrganizationsIdentityResourcesAndRequestConditions(t *testing.T) {
	ctx := context.Background()
	s := organizationsOnly(nil)
	identities := &identityPolicies{}
	s.SetAuthorizer(authorization.New(identities, orgControlSource{s}))
	rootMeta := orgRoot(managementID, "aws")
	root := fixedClient(t, s, rootMeta)
	userMeta := rootMeta
	userMeta.PrincipalARN = "arn:aws:iam::" + managementID + ":user/operator"
	userMeta.PrincipalID = "AIDA11111111111111111"
	user := fixedClient(t, s, userMeta)
	_, err := user.CreateOrganization(ctx, &sdk.CreateOrganizationInput{})
	requireCode(t, err, "AccessDeniedException")
	rootID := createOrg(t, root)
	created, err := root.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(rootID), Name: aws.String("platform"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = user.DescribeOrganizationalUnit(ctx, &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: created.OrganizationalUnit.Id})
	requireCode(t, err, "AccessDeniedException")
	policy := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"organizations:DescribeOrganizationalUnit","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"platform"}}}]}`, *created.OrganizationalUnit.Arn)
	identities.set(policy)
	if _, err := user.DescribeOrganizationalUnit(ctx, &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: created.OrganizationalUnit.Id}); err != nil {
		t.Fatal(err)
	}
	other, err := root.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(rootID), Name: aws.String("other")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = user.DescribeOrganizationalUnit(ctx, &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: other.OrganizationalUnit.Id})
	requireCode(t, err, "AccessDeniedException")
	identities.set(allowAction("organizations:UpdateOrganizationalUnit", *created.OrganizationalUnit.Arn), `{"Statement":[{"Effect":"Deny","Action":"organizations:UpdateOrganizationalUnit","Resource":"*"}]}`)
	_, err = user.UpdateOrganizationalUnit(ctx, &sdk.UpdateOrganizationalUnitInput{OrganizationalUnitId: created.OrganizationalUnit.Id, Name: aws.String("forbidden")})
	requireCode(t, err, "AccessDeniedException")
	described, err := root.DescribeOrganizationalUnit(ctx, &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: created.OrganizationalUnit.Id})
	if err != nil || aws.ToString(described.OrganizationalUnit.Name) != "platform" {
		t.Fatalf("denied mutation changed state: %+v, %v", described, err)
	}
	roots, err := root.ListRoots(ctx, &sdk.ListRootsInput{})
	if err != nil {
		t.Fatal(err)
	}
	identities.set(allowAction("organizations:CreateOrganizationalUnit", *roots.Roots[0].Arn), `{"Statement":[{"Effect":"Allow","Action":"organizations:TagResource","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/team":"platform"}}}]}`)
	_, err = user.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(rootID), Name: aws.String("bad-tags"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("finance")}}})
	requireCode(t, err, "AccessDeniedException")
	if _, err := user.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(rootID), Name: aws.String("allowed-tags"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}}); err != nil {
		t.Fatal(err)
	}
	identities.set(`{"Statement":[{"Effect":"Allow","Action":"organizations:EnableAWSServiceAccess","Resource":"*","Condition":{"StringEquals":{"organizations:ServicePrincipal":"kms.amazonaws.com"}}}]}`)
	_, err = user.EnableAWSServiceAccess(ctx, &sdk.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("config.amazonaws.com")})
	requireCode(t, err, "AccessDeniedException")
	if _, err := user.EnableAWSServiceAccess(ctx, &sdk.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("kms.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	memberID := createAccount(t, root, "move-resource-check")
	member, err := root.DescribeAccount(ctx, &sdk.DescribeAccountInput{AccountId: aws.String(memberID)})
	if err != nil {
		t.Fatal(err)
	}
	identities.set(fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"organizations:MoveAccount","Resource":[%q,%q]}]}`, *member.Account.Arn, *roots.Roots[0].Arn))
	_, err = user.MoveAccount(ctx, &sdk.MoveAccountInput{AccountId: aws.String(memberID), SourceParentId: aws.String(rootID), DestinationParentId: other.OrganizationalUnit.Id})
	requireCode(t, err, "AccessDeniedException")
	parents, err := root.ListParents(ctx, &sdk.ListParentsInput{ChildId: aws.String(memberID)})
	if err != nil || len(parents.Parents) != 1 || aws.ToString(parents.Parents[0].Id) != rootID {
		t.Fatalf("missing destination permission changed parent: %+v, %v", parents, err)
	}
	identities.set(fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"organizations:MoveAccount","Resource":[%q,%q,%q]}]}`, *member.Account.Arn, *roots.Roots[0].Arn, *other.OrganizationalUnit.Arn))
	if _, err := user.MoveAccount(ctx, &sdk.MoveAccountInput{AccountId: aws.String(memberID), SourceParentId: aws.String(rootID), DestinationParentId: other.OrganizationalUnit.Id}); err != nil {
		t.Fatal(err)
	}
}

func TestSDKOrganizationsSCPAndDelegatedReadAuthorization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := organizationsOnly(nil)
	identities := &identityPolicies{}
	s.SetAuthorizer(authorization.New(identities, orgControlSource{s}))
	root := fixedClient(t, s, orgRoot(managementID, "aws"))
	createOrg(t, root)
	memberID := createAccount(t, root, "scp-member")
	member := fixedClient(t, s, orgRoot(memberID, "aws"))
	deny, err := root.CreatePolicy(ctx, &sdk.CreatePolicyInput{Name: aws.String("NoLeave"), Description: aws.String("prevent departure"), Type: types.PolicyTypeServiceControlPolicy, Content: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"organizations:LeaveOrganization","Resource":"*"}]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.AttachPolicy(ctx, &sdk.AttachPolicyInput{PolicyId: deny.Policy.PolicySummary.Id, TargetId: aws.String(memberID)}); err != nil {
		t.Fatal(err)
	}
	_, err = member.LeaveOrganization(ctx, &sdk.LeaveOrganizationInput{})
	requireCode(t, err, "AccessDeniedException")
	if _, err := member.DescribeOrganization(ctx, &sdk.DescribeOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.EnableAWSServiceAccess(ctx, &sdk.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("config.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.RegisterDelegatedAdministrator(ctx, &sdk.RegisterDelegatedAdministratorInput{AccountId: aws.String(memberID), ServicePrincipal: aws.String("config.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	delegatedMeta := orgRoot(memberID, "aws")
	delegatedMeta.PrincipalARN = "arn:aws:iam::" + memberID + ":user/delegated"
	delegatedMeta.PrincipalID = "AIDA22222222222222222"
	delegated := fixedClient(t, s, delegatedMeta)
	_, err = delegated.DescribeAccount(ctx, &sdk.DescribeAccountInput{AccountId: aws.String(managementID)})
	requireCode(t, err, "AccessDeniedException")
	account, err := root.DescribeAccount(ctx, &sdk.DescribeAccountInput{AccountId: aws.String(managementID)})
	if err != nil {
		t.Fatal(err)
	}
	identities.set(allowAction("organizations:DescribeAccount", *account.Account.Arn))
	if _, err := delegated.DescribeAccount(ctx, &sdk.DescribeAccountInput{AccountId: aws.String(managementID)}); err != nil {
		t.Fatal(err)
	}
	identities.set(allowAction("organizations:*", "*"))
	_, err = delegated.CreateAccount(ctx, &sdk.CreateAccountInput{AccountName: aws.String("unauthorized"), Email: aws.String("forbidden@example.com")})
	requireCode(t, err, "AccessDeniedException")
	if _, err := root.DeregisterDelegatedAdministrator(ctx, &sdk.DeregisterDelegatedAdministratorInput{AccountId: aws.String(memberID), ServicePrincipal: aws.String("config.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.DetachPolicy(ctx, &sdk.DetachPolicyInput{PolicyId: deny.Policy.PolicySummary.Id, TargetId: aws.String(memberID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := member.LeaveOrganization(ctx, &sdk.LeaveOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	_, err = member.DescribeOrganization(ctx, &sdk.DescribeOrganizationInput{})
	requireCode(t, err, "AWSOrganizationsNotInUseException")
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("recursive authorization blocked on its own Organizations state")
	}
}

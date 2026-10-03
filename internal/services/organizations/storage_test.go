package organizations_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"stackd/internal/authorization"
	provider "stackd/internal/services/organizations"
)

func TestStorageReplacementPartitionIsolationAndCopies(t *testing.T) {
	ctx := context.Background()
	store := provider.NewMemoryStorage(nil)
	service := organizationsOnly(store)
	awsRoot := fixedClient(t, service, orgRoot(managementID, "aws"))
	govRoot := fixedClient(t, service, orgRoot(managementID, "aws-us-gov"))
	root := createOrg(t, awsRoot)
	createOrg(t, govRoot)
	awsMember := createAccount(t, awsRoot, "identical-email")
	govMember := createAccount(t, govRoot, "identical-email")
	if awsMember != govMember {
		t.Fatal("test needs identical account IDs to exercise independent partition membership")
	}
	unit, err := awsRoot.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(root), Name: aws.String("persistent")})
	if err != nil {
		t.Fatal(err)
	}
	record, revision, err := store.Load(ctx, "aws")
	if err != nil {
		t.Fatal(err)
	}
	record.Organizations[0].Units[0].Name = "uncommitted"
	replacement := provider.NewWithStorage(store)
	restored := fixedClient(t, replacement, orgRoot(managementID, "aws"))
	out, err := restored.DescribeOrganizationalUnit(ctx, &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: unit.OrganizationalUnit.Id})
	if err != nil || aws.ToString(out.OrganizationalUnit.Name) != "persistent" {
		t.Fatalf("state replacement/copy failed: %+v, %v", out, err)
	}
	if committed, err := store.CompareAndSwap(ctx, "aws", revision+1, record, nil); err != nil || committed {
		t.Fatalf("stale revision committed: %v, %v", committed, err)
	}
	_, err = govRoot.DescribeOrganizationalUnit(ctx, &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: unit.OrganizationalUnit.Id})
	requireCode(t, err, "OrganizationalUnitNotFoundException")
	page, err := awsRoot.ListAccounts(ctx, &sdk.ListAccountsInput{MaxResults: aws.Int32(1)})
	if err != nil || page.NextToken == nil {
		t.Fatalf("pagination: %+v, %v", page, err)
	}
	_, err = govRoot.ListAccounts(ctx, &sdk.ListAccountsInput{NextToken: page.NextToken})
	requireCode(t, err, "InvalidInputException")
	govClient := fixedClient(t, replacement, orgRoot(govMember, "aws-us-gov"))
	if _, err := govClient.LeaveOrganization(ctx, &sdk.LeaveOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.DescribeAccount(ctx, &sdk.DescribeAccountInput{AccountId: aws.String(awsMember)}); err != nil {
		t.Fatal("leaving another partition removed account:", err)
	}
	failedService := provider.NewWithStorage(failingStore{Storage: store})
	failedClient := fixedClient(t, failedService, orgRoot(managementID, "aws"))
	_, err = failedClient.UpdateOrganizationalUnit(ctx, &sdk.UpdateOrganizationalUnitInput{OrganizationalUnitId: unit.OrganizationalUnit.Id, Name: aws.String("failed-write")})
	requireCode(t, err, "ServiceException")
	out, err = restored.DescribeOrganizationalUnit(ctx, &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: unit.OrganizationalUnit.Id})
	if err != nil || aws.ToString(out.OrganizationalUnit.Name) != "persistent" {
		t.Fatalf("failed write mutated state: %+v, %v", out, err)
	}
}

type failingStore struct{ provider.Storage }

func (s failingStore) CompareAndSwap(context.Context, string, uint64, provider.PartitionRecord, func(context.Context) error) (bool, error) {
	return false, errors.New("injected storage failure")
}

// revokeDuringCommit simulates a concurrent tag change after authorization.
type revokeDuringCommit struct {
	provider.Storage
	mu     sync.Mutex
	target string
}

func (s *revokeDuringCommit) CompareAndSwap(ctx context.Context, partition string, revision uint64, record provider.PartitionRecord, commit func(context.Context) error) (bool, error) {
	s.mu.Lock()
	target := s.target
	s.target = ""
	s.mu.Unlock()
	if target != "" {
		current, version, err := s.Storage.Load(ctx, partition)
		if err != nil {
			return false, err
		}
		for i := range current.Organizations {
			for j := range current.Organizations[i].Tags {
				tag := &current.Organizations[i].Tags[j]
				if tag.ResourceID == target && tag.Key == "team" {
					tag.Value = "revoked"
				}
			}
		}
		if _, err := s.Storage.CompareAndSwap(ctx, partition, version, current, nil); err != nil {
			return false, err
		}
	}
	return s.Storage.CompareAndSwap(ctx, partition, revision, record, commit)
}

func TestStorageConflictReauthorizesBeforeMutation(t *testing.T) {
	ctx := context.Background()
	backend := &revokeDuringCommit{Storage: provider.NewMemoryStorage(nil)}
	service := organizationsOnly(backend)
	identities := &identityPolicies{}
	service.SetAuthorizer(authorization.New(identities, orgControlSource{service}))
	meta := orgRoot(managementID, "aws")
	root := fixedClient(t, service, meta)
	rootID := createOrg(t, root)
	unit, err := root.CreateOrganizationalUnit(ctx, &sdk.CreateOrganizationalUnitInput{ParentId: aws.String(rootID), Name: aws.String("stable"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("allowed")}}})
	if err != nil {
		t.Fatal(err)
	}
	identities.set(fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"organizations:UpdateOrganizationalUnit","Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/team":"allowed"}}}]}`, *unit.OrganizationalUnit.Arn))
	meta.PrincipalARN = "arn:aws:iam::" + managementID + ":user/operator"
	meta.PrincipalID = "AIDA11111111111111111"
	user := fixedClient(t, service, meta)
	backend.mu.Lock()
	backend.target = *unit.OrganizationalUnit.Id
	backend.mu.Unlock()
	_, err = user.UpdateOrganizationalUnit(ctx, &sdk.UpdateOrganizationalUnitInput{OrganizationalUnitId: unit.OrganizationalUnit.Id, Name: aws.String("must-not-commit")})
	requireCode(t, err, "AccessDeniedException")
	out, err := root.DescribeOrganizationalUnit(ctx, &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: unit.OrganizationalUnit.Id})
	if err != nil || aws.ToString(out.OrganizationalUnit.Name) != "stable" {
		t.Fatalf("stale authorization committed: %+v, %v", out, err)
	}
}

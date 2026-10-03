package organizations_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"stackd/internal/awsctx"
)

func TestPrincipalOrganizationPinsMembershipWithPolicies(t *testing.T) {
	s := organizationsOnly(nil)
	client := fixedClient(t, s, orgRoot(managementID, "aws"))
	rootID := createOrg(t, client)
	member := createAccount(t, client, "claims-member")
	organization, err := client.DescribeOrganization(t.Context(), &sdk.DescribeOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	orgID := aws.ToString(organization.Organization.Id)
	ou, err := client.CreateOrganizationalUnit(t.Context(), &sdk.CreateOrganizationalUnitInput{ParentId: &rootID, Name: aws.String("workloads")})
	if err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(t.Context(), orgRoot(member, "aws"))
	initialPath := orgID + "/" + rootID + "/"
	err = s.WithPolicySnapshot(ctx, func(snapshot context.Context) error {
		id, path, err := s.PrincipalOrganization(snapshot)
		if err != nil || id != orgID || path != initialPath {
			t.Fatalf("initial membership: %q %q %v", id, path, err)
		}
		_, err = client.MoveAccount(t.Context(), &sdk.MoveAccountInput{AccountId: &member, SourceParentId: &rootID, DestinationParentId: ou.OrganizationalUnit.Id})
		if err != nil {
			return err
		}
		id, path, err = s.PrincipalOrganization(snapshot)
		if err != nil || id != orgID || path != initialPath {
			t.Fatalf("mixed membership snapshot: %q %q %v", id, path, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	id, path, err := s.PrincipalOrganization(ctx)
	if err != nil || id != orgID || path != initialPath+aws.ToString(ou.OrganizationalUnit.Id)+"/" {
		t.Fatalf("new ancestry: %q %q %v", id, path, err)
	}
	for _, m := range []struct{ account, partition string }{{"999999999999", "aws"}, {member, "aws-cn"}} {
		id, path, err = s.PrincipalOrganization(awsctx.WithMetadata(t.Context(), orgRoot(m.account, m.partition)))
		if err != nil || id != "" || path != "" {
			t.Fatalf("membership leaked: %q %q %v", id, path, err)
		}
	}
}

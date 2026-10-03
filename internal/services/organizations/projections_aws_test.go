package organizations_test

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	api "stackd/internal/awsapi/organizations"
)

type organizationPathCapture struct {
	Path          string
	Paths         []string
	State, Status string
}

func TestOrganizationsProjectionsReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/iam/organizations_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ResponseFollowup struct {
			Observations []struct {
				Action string
				Input  json.RawMessage
				Output struct {
					OrganizationalUnit *api.OrganizationalUnit
					Policy             *api.Policy
				}
			}
		} `json:"response_followup"`
		HierarchyPaths map[string]organizationPathCapture `json:"hierarchy_paths"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			client := organizationsInputClient(t, endpoint)
			root := createOrg(t, client)
			org, err := client.DescribeOrganization(t.Context(), &sdk.DescribeOrganizationInput{})
			if err != nil {
				t.Fatal(err)
			}
			parent, err := client.CreateOrganizationalUnit(t.Context(), &sdk.CreateOrganizationalUnitInput{ParentId: &root, Name: aws.String("OWNED_NAME")})
			if err != nil {
				t.Fatal(err)
			}
			child, err := client.CreateOrganizationalUnit(t.Context(), &sdk.CreateOrganizationalUnitInput{ParentId: parent.OrganizationalUnit.Id, Name: aws.String("child")})
			if err != nil {
				t.Fatal(err)
			}
			replacement := strings.NewReplacer("ORGANIZATION_ID", *org.Organization.Id, "ROOT_ID", root,
				"PARENT_ID", *parent.OrganizationalUnit.Id, "CHILD_ID", *child.OrganizationalUnit.Id, "ACCOUNT_ID", managementID)
			checkPath := func(label string, got organizationPathCapture) {
				t.Helper()
				want := fixture.HierarchyPaths[label]
				want.Path = replacement.Replace(want.Path)
				if want.Paths != nil {
					paths := make([]string, len(want.Paths))
					for i, path := range want.Paths {
						paths[i] = replacement.Replace(path)
					}
					want.Paths = paths
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s = %#v, want %#v", label, got, want)
				}
			}
			checkPath("parent_create", organizationPathCapture{Path: aws.ToString(parent.OrganizationalUnit.Path)})
			checkPath("child_create", organizationPathCapture{Path: aws.ToString(child.OrganizationalUnit.Path)})
			described, err := client.DescribeOrganizationalUnit(t.Context(), &sdk.DescribeOrganizationalUnitInput{OrganizationalUnitId: child.OrganizationalUnit.Id})
			if err != nil {
				t.Fatal(err)
			}
			checkPath("child_describe", organizationPathCapture{Path: aws.ToString(described.OrganizationalUnit.Path)})
			listed, err := client.ListOrganizationalUnitsForParent(t.Context(), &sdk.ListOrganizationalUnitsForParentInput{ParentId: parent.OrganizationalUnit.Id})
			if err != nil || len(listed.OrganizationalUnits) != 1 {
				t.Fatalf("units = %v, %v", listed, err)
			}
			checkPath("child_list", organizationPathCapture{Path: aws.ToString(listed.OrganizationalUnits[0].Path)})
			account, err := client.DescribeAccount(t.Context(), &sdk.DescribeAccountInput{AccountId: aws.String(managementID)})
			if err != nil {
				t.Fatal(err)
			}
			accountPath := func(account types.Account) organizationPathCapture {
				return organizationPathCapture{Paths: account.Paths, State: string(account.State), Status: string(account.Status)}
			}
			checkPath("account_describe", accountPath(*account.Account))
			accounts, err := client.ListAccounts(t.Context(), &sdk.ListAccountsInput{})
			if err != nil || len(accounts.Accounts) != 1 {
				t.Fatalf("accounts = %v, %v", accounts, err)
			}
			checkPath("account_list", accountPath(accounts.Accounts[0]))
			forParent, err := client.ListAccountsForParent(t.Context(), &sdk.ListAccountsForParentInput{ParentId: &root})
			if err != nil || len(forParent.Accounts) != 1 {
				t.Fatalf("accounts for parent = %v, %v", forParent, err)
			}
			checkPath("account_list_for_parent", accountPath(forParent.Accounts[0]))

			content := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
			policy, err := client.CreatePolicy(t.Context(), &sdk.CreatePolicyInput{Name: aws.String("OWNED_NAME"), Description: aws.String("initial"), Type: types.PolicyTypeServiceControlPolicy, Content: &content})
			if err != nil {
				t.Fatal(err)
			}
			for i, row := range fixture.ResponseFollowup.Observations {
				t.Run(fmt.Sprintf("%02d/%s", i+1, row.Action), func(t *testing.T) {
					if row.Action == "UpdateOrganizationalUnit" {
						in := sdk.UpdateOrganizationalUnitInput{OrganizationalUnitId: parent.OrganizationalUnit.Id}
						if err := json.Unmarshal(row.Input, &in); err != nil {
							t.Fatal(err)
						}
						got, err := client.UpdateOrganizationalUnit(t.Context(), &in)
						if err != nil {
							t.Fatal(err)
						}
						unit := got.OrganizationalUnit
						if !reflect.DeepEqual(unit.Name, (*string)(row.Output.OrganizationalUnit.Name)) ||
							aws.ToString(unit.Id) != *parent.OrganizationalUnit.Id || aws.ToString(unit.Arn) != *parent.OrganizationalUnit.Arn ||
							aws.ToString(unit.Path) != *parent.OrganizationalUnit.Path {
							t.Fatalf("unit response = %#v, want captured name and retained hierarchy", unit)
						}
						return
					}
					in := sdk.UpdatePolicyInput{PolicyId: policy.Policy.PolicySummary.Id}
					if err := json.Unmarshal(row.Input, &in); err != nil {
						t.Fatal(err)
					}
					got, err := client.UpdatePolicy(t.Context(), &in)
					if err != nil {
						t.Fatal(err)
					}
					want := row.Output.Policy
					actual := got.Policy.PolicySummary
					if !reflect.DeepEqual(actual.Name, (*string)(want.PolicySummary.Name)) || !reflect.DeepEqual(actual.Description, (*string)(want.PolicySummary.Description)) ||
						!reflect.DeepEqual(got.Policy.Content, (*string)(want.Content)) || string(actual.Type) != string(*want.PolicySummary.Type) || actual.AwsManaged != bool(*want.PolicySummary.AwsManaged) ||
						aws.ToString(actual.Id) != *policy.Policy.PolicySummary.Id || aws.ToString(actual.Arn) != *policy.Policy.PolicySummary.Arn {
						t.Fatalf("policy response = %#v, want captured optional fields and retained policy identity", got.Policy)
					}
				})
			}
			stored, err := client.DescribePolicy(t.Context(), &sdk.DescribePolicyInput{PolicyId: policy.Policy.PolicySummary.Id})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(stored.Policy.PolicySummary.Name) != "changed" || aws.ToString(stored.Policy.PolicySummary.Description) != "next" {
				t.Fatalf("stored policy = %#v", stored.Policy.PolicySummary)
			}
		})
	}
}

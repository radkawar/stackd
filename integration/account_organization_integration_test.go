package stackd_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/storage"
)

func TestAccountOrganizationRegionAccessMatchesAWS(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/account/organization_regions.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct{ Observations []struct{ Case, Code string } }
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	codes := make(map[string]string)
	for _, row := range capture.Observations {
		codes[row.Case] = row.Code
	}
	f := newOrganizationReportFixture(t, storage.NewMemory())
	ctx := t.Context()
	member := f.account(t, f.rootID, "account-settings")
	management := f.cloud.account("test", "test", "")
	roleARN := "arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole"
	delegate := func(document *string) *account.Client {
		t.Helper()
		out, err := f.cloud.sts("test", "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &roleARN, RoleSessionName: aws.String("account-settings"), Policy: document})
		if err != nil {
			t.Fatal(err)
		}
		return f.cloud.account(aws.ToString(out.Credentials.AccessKeyId), aws.ToString(out.Credentials.SecretAccessKey), aws.ToString(out.Credentials.SessionToken))
	}
	memberClient := delegate(nil)
	query := &account.GetRegionOptStatusInput{AccountId: &member, RegionName: aws.String("us-east-1")}
	check := func(name string, client *account.Client, input *account.GetRegionOptStatusInput) {
		t.Helper()
		want, ok := codes[name]
		if !ok {
			t.Fatal("missing native observation", name)
		}
		_, err := client.GetRegionOptStatus(ctx, input)
		if want == "Success" {
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return
		}
		assertAPIError(t, err, want)
	}
	check("initial_management_target", management, query)
	check("initial_member_explicit_self", memberClient, query)
	if _, err := f.org.EnableAWSServiceAccess(ctx, &organizations.EnableAWSServiceAccessInput{ServicePrincipal: aws.String("account.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	check("trusted_management_target", management, query)
	check("trusted_management_explicit_self", management, &account.GetRegionOptStatusInput{AccountId: aws.String("000000000000"), RegionName: query.RegionName})
	check("trusted_member_explicit_self", memberClient, query)
	if _, err := f.org.RegisterDelegatedAdministrator(ctx, &organizations.RegisterDelegatedAdministratorInput{AccountId: &member, ServicePrincipal: aws.String("account.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	check("delegated_member_explicit_self", memberClient, query)
	organization, err := f.org.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	resource := fmt.Sprintf("arn:aws:account::000000000000:account/%s/%s", aws.ToString(organization.Organization.Id), member)
	document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"account:GetRegionOptStatus","Resource":%q,"Condition":{"StringEquals":{"account:TargetRegion":"us-east-1"}}}}`, resource)
	limited := delegate(&document)
	check("delegated_scoped_allow", limited, query)
	check("delegated_wrong_region", limited, &account.GetRegionOptStatusInput{AccountId: &member, RegionName: aws.String("eu-west-1")})
	check("delegated_wrong_arn_mode", limited, &account.GetRegionOptStatusInput{RegionName: query.RegionName})
	setTag := func(value string) {
		t.Helper()
		if _, err := f.org.TagResource(ctx, &organizations.TagResourceInput{ResourceId: &member, Tags: []orgtypes.Tag{{Key: aws.String("project"), Value: &value}}}); err != nil {
			t.Fatal(err)
		}
	}
	setTag("blue")
	document = fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"account:GetRegionOptStatus","Resource":%q,"Condition":{"ForAnyValue:StringEquals":{"account:AccountResourceOrgTags/project":"blue","account:AccountResourceOrgPaths":%q}}}}`, resource, f.rootPath+"/")
	limited = delegate(&document)
	if _, err := limited.GetRegionOptStatus(ctx, query); err != nil {
		t.Fatal("organization context", err)
	}
	setTag("red")
	_, err = limited.GetRegionOptStatus(ctx, query)
	assertAPIError(t, err, "AccessDeniedException")
	setTag("blue")
	unit := f.unit(t, f.rootID, "moved")
	if _, err := f.org.MoveAccount(ctx, &organizations.MoveAccountInput{AccountId: &member, SourceParentId: &f.rootID, DestinationParentId: &unit}); err != nil {
		t.Fatal(err)
	}
	_, err = limited.GetRegionOptStatus(ctx, query)
	assertAPIError(t, err, "AccessDeniedException")
	if _, err := f.org.DeregisterDelegatedAdministrator(ctx, &organizations.DeregisterDelegatedAdministratorInput{AccountId: &member, ServicePrincipal: aws.String("account.amazonaws.com")}); err != nil {
		t.Fatal(err)
	}
	_, err = memberClient.GetRegionOptStatus(ctx, query)
	assertAPIError(t, err, "AccessDeniedException")
}

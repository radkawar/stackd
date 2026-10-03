package stackd_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const organizationsRoleName = "AWSServiceRoleForOrganizations"

type organizationRoleCapture struct {
	Role struct {
		Path, RoleName, Arn      string
		AssumeRolePolicyDocument any
		Description              *string
		MaxSessionDuration       int32
	}
	AttachedPolicies  []iamtypes.AttachedPolicy
	InlinePolicyNames []string
	SessionArn        string
}

type organizationRoleCaptures struct {
	AccessRole, MemberServiceRole, ManagementServiceRole organizationRoleCapture
}

func loadOrganizationRoleCapture(t *testing.T, member, accessRoleName string) organizationRoleCaptures {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/iam/organizations_roles.json")
	if err != nil {
		t.Fatal(err)
	}
	normalized := strings.NewReplacer("111111111111", "000000000000", "222222222222", member, "OrganizationAccountAccessRole", accessRoleName).Replace(string(data))
	var fixture struct{ Observations organizationRoleCaptures }
	if err := json.Unmarshal([]byte(normalized), &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Observations
}

func assertOrganizationRoleCapture(t *testing.T, client *iam.Client, want organizationRoleCapture) *iamtypes.Role {
	t.Helper()
	got, err := client.GetRole(t.Context(), &iam.GetRoleInput{RoleName: &want.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	r := got.Role
	if aws.ToString(r.Path) != want.Role.Path || aws.ToString(r.RoleName) != want.Role.RoleName || aws.ToString(r.Arn) != want.Role.Arn || aws.ToInt32(r.MaxSessionDuration) != want.Role.MaxSessionDuration || !reflect.DeepEqual(r.Description, want.Role.Description) {
		t.Fatalf("role = %+v, want %+v", r, want.Role)
	}
	decoded, err := url.QueryUnescape(aws.ToString(r.AssumeRolePolicyDocument))
	if err != nil {
		t.Fatal(err)
	}
	var trust any
	if err := json.Unmarshal([]byte(decoded), &trust); err != nil || !reflect.DeepEqual(trust, want.Role.AssumeRolePolicyDocument) {
		t.Fatalf("trust = %s, err=%v", decoded, err)
	}
	attached, err := client.ListAttachedRolePolicies(t.Context(), &iam.ListAttachedRolePoliciesInput{RoleName: &want.Role.RoleName})
	if err != nil || !reflect.DeepEqual(attached.AttachedPolicies, want.AttachedPolicies) {
		t.Fatalf("attachments = %+v, err=%v", attached, err)
	}
	inline, err := client.ListRolePolicies(t.Context(), &iam.ListRolePoliciesInput{RoleName: &want.Role.RoleName})
	if err != nil || len(inline.PolicyNames) != len(want.InlinePolicyNames) {
		t.Fatalf("inline policies = %+v, err=%v", inline, err)
	}
	return r
}

func (c cloudClients) organizations(key, secret string) *organizations.Client {
	return organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func waitOrganizationRoleDeletion(t *testing.T, client *iam.Client, id *string) *iam.GetServiceLinkedRoleDeletionStatusOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		out, err := client.GetServiceLinkedRoleDeletionStatus(ctx, &iam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: id})
		if err != nil {
			t.Fatal(err)
		}
		if out.Status == iamtypes.DeletionTaskStatusTypeSucceeded || out.Status == iamtypes.DeletionTaskStatusTypeFailed {
			return out
		}
	}
}

func TestOrganizationsServiceRoleProvisioningAndMembershipSDK(t *testing.T) {
	for _, features := range []orgtypes.OrganizationFeatureSet{orgtypes.OrganizationFeatureSetAll, orgtypes.OrganizationFeatureSetConsolidatedBilling} {
		t.Run(string(features), func(t *testing.T) {
			c := newCloudClients(t)
			org := c.organizations("test", "test")
			if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{FeatureSet: features}); err != nil {
				t.Fatal(err)
			}
			created, err := org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("service-role-member"), Email: aws.String("service-role-member@example.test")})
			if err != nil {
				t.Fatal(err)
			}
			created.CreateAccountStatus = waitAccountCreation(t, org, created.CreateAccountStatus, nil)
			member := aws.ToString(created.CreateAccountStatus.AccountId)
			fixture := loadOrganizationRoleCapture(t, member, "OrganizationAccountAccessRole")
			for _, test := range []struct {
				account string
				want    organizationRoleCapture
			}{{"test", fixture.ManagementServiceRole}, {member, fixture.MemberServiceRole}} {
				client := c.iam(test.account, "test", "")
				role := assertOrganizationRoleCapture(t, client, test.want)
				_, err := client.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: role.RoleName, PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
				assertAPIError(t, err, "UnmodifiableEntity")
				_, err = client.DetachRolePolicy(t.Context(), &iam.DetachRolePolicyInput{RoleName: role.RoleName, PolicyArn: test.want.AttachedPolicies[0].PolicyArn})
				assertAPIError(t, err, "UnmodifiableEntity")
				_, err = c.sts(test.account, "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Arn, RoleSessionName: aws.String("not-organizations")})
				assertAPIError(t, err, "AccessDenied")
				deletion, err := client.DeleteServiceLinkedRole(t.Context(), &iam.DeleteServiceLinkedRoleInput{RoleName: role.RoleName})
				if err != nil {
					t.Fatal(err)
				}
				status := waitOrganizationRoleDeletion(t, client, deletion.DeletionTaskId)
				if features == orgtypes.OrganizationFeatureSetAll {
					if status.Status != iamtypes.DeletionTaskStatusTypeFailed {
						t.Fatalf("required role deletion = %+v", status)
					}
					assertOrganizationRoleCapture(t, client, test.want)
				} else {
					if status.Status != iamtypes.DeletionTaskStatusTypeSucceeded {
						t.Fatalf("unused role deletion = %+v", status)
					}
					_, err := client.GetRole(t.Context(), &iam.GetRoleInput{RoleName: role.RoleName})
					assertAPIError(t, err, "NoSuchEntity")
					// The normal IAM API restores the same sourced definition.
					if _, err := client.CreateServiceLinkedRole(t.Context(), &iam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("organizations.amazonaws.com")}); err != nil {
						t.Fatal(err)
					}
					assertOrganizationRoleCapture(t, client, test.want)
				}
			}
		})
	}
}

func TestCreateOrganizationIAMDependencyPermissionsSDK(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "organization-creator")
	putUserPolicy(t, root, "organization-creator", allow(`"organizations:CreateOrganization"`, "*"))
	org := c.organizations(key, secret)
	_, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	assertAPIError(t, err, "AccessDeniedForDependencyException")
	_, err = c.organizations("test", "test").DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	assertAPIError(t, err, "AWSOrganizationsNotInUseException")
	_, err = root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(organizationsRoleName)})
	assertAPIError(t, err, "NoSuchEntity")
	roleARN := "arn:aws:iam::000000000000:role/aws-service-role/organizations.amazonaws.com/" + organizationsRoleName
	for _, principal := range []string{"ecs.amazonaws.com", "organizations.amazonaws.com"} {
		policy := `{"Statement":[{"Effect":"Allow","Action":"organizations:CreateOrganization","Resource":"*"},{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"` + roleARN + `","Condition":{"StringEquals":{"iam:AWSServiceName":"` + principal + `"}}}]}`
		putUserPolicy(t, root, "organization-creator", policy)
		_, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
		if principal != "organizations.amazonaws.com" {
			assertAPIError(t, err, "AccessDeniedForDependencyException")
		} else if err != nil {
			t.Fatal(err)
		}
	}
	// An existing owned role retains its identity and customer description
	// when a later organization reuses it; no IAM create permission is needed.
	before, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(organizationsRoleName)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.UpdateRoleDescription(t.Context(), &iam.UpdateRoleDescriptionInput{RoleName: before.Role.RoleName, Description: aws.String("retained description")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.organizations("test", "test").DeleteOrganization(t.Context(), &organizations.DeleteOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	putUserPolicy(t, root, "organization-creator", allow(`"organizations:CreateOrganization"`, "*"))
	if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	after, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: before.Role.RoleName})
	if err != nil || aws.ToString(after.Role.RoleId) != aws.ToString(before.Role.RoleId) || aws.ToString(after.Role.Description) != "retained description" {
		t.Fatalf("existing role was replaced: %+v, %v", after, err)
	}
}

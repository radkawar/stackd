package iam_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type policyManagementFixture struct {
	ListPolicies []struct {
		OnlyAttached *bool `json:"only_attached"`
		Usage        string
		Code         string
		Policies     []string
	} `json:"list_policies"`
	Entities []struct {
		Policy, Filter, Usage, Code string
		Users, Groups, Roles        int
	}
	Inline []struct {
		Kind           string
		Names          []string
		GetCode        string   `json:"get_mixed_code"`
		DeleteCode     string   `json:"delete_mixed_code"`
		RemainingNames []string `json:"remaining_names"`
		ReturnedName   string   `json:"returned_name"`
		Effect         string
	}
	DetachMissing         []struct{ Kind, Code string } `json:"detach_missing"`
	DeleteBoundaryMissing []struct{ Kind, Code string } `json:"delete_boundary_missing"`
	Counts                map[string]struct{ AttachmentCount, PermissionsBoundaryUsageCount int32 }
}

func loadPolicyManagementFixture(t *testing.T) policyManagementFixture {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/aws/iam/policy_management.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture policyManagementFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestManagedPolicyFiltersReplayAWS(t *testing.T) {
	fixture := loadPolicyManagementFixture(t)
	client := newActivityFixture(t, nil, time.Unix(0, 0).UTC()).root
	ctx := t.Context()
	name, path := aws.String("observed"), aws.String("/native/")
	_, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: name, Path: path})
	requireCode(t, err, "Success")
	_, err = client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: name, Path: path})
	requireCode(t, err, "Success")
	_, err = client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: name, Path: path, AssumeRolePolicyDocument: aws.String(trustEC2)})
	requireCode(t, err, "Success")
	policies := make(map[string]*string)
	for _, label := range []string{"unused", "attached", "boundary", "both"} {
		out, err := client.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("observed-" + label), Path: path, PolicyDocument: aws.String(allowRead)})
		requireCode(t, err, "Success")
		policies[label] = out.Policy.Arn
	}
	for _, row := range fixture.DetachMissing {
		switch row.Kind {
		case "User":
			_, err = client.DetachUserPolicy(ctx, &sdkiam.DetachUserPolicyInput{UserName: name, PolicyArn: policies["unused"]})
		case "Group":
			_, err = client.DetachGroupPolicy(ctx, &sdkiam.DetachGroupPolicyInput{GroupName: name, PolicyArn: policies["unused"]})
		case "Role":
			_, err = client.DetachRolePolicy(ctx, &sdkiam.DetachRolePolicyInput{RoleName: name, PolicyArn: policies["unused"]})
		}
		requireCode(t, err, row.Code)
	}
	for _, row := range fixture.DeleteBoundaryMissing {
		if row.Kind == "User" {
			_, err = client.DeleteUserPermissionsBoundary(ctx, &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: name})
		} else {
			_, err = client.DeleteRolePermissionsBoundary(ctx, &sdkiam.DeleteRolePermissionsBoundaryInput{RoleName: name})
		}
		requireCode(t, err, row.Code)
	}
	_, err = client.AttachUserPolicy(ctx, &sdkiam.AttachUserPolicyInput{UserName: name, PolicyArn: policies["attached"]})
	requireCode(t, err, "Success")
	_, err = client.AttachGroupPolicy(ctx, &sdkiam.AttachGroupPolicyInput{GroupName: name, PolicyArn: policies["attached"]})
	requireCode(t, err, "Success")
	_, err = client.AttachRolePolicy(ctx, &sdkiam.AttachRolePolicyInput{RoleName: name, PolicyArn: policies["attached"]})
	requireCode(t, err, "Success")
	_, err = client.AttachGroupPolicy(ctx, &sdkiam.AttachGroupPolicyInput{GroupName: name, PolicyArn: policies["both"]})
	requireCode(t, err, "Success")
	for range 2 {
		_, err = client.PutUserPermissionsBoundary(ctx, &sdkiam.PutUserPermissionsBoundaryInput{UserName: name, PermissionsBoundary: policies["boundary"]})
		requireCode(t, err, "Success")
		_, err = client.PutRolePermissionsBoundary(ctx, &sdkiam.PutRolePermissionsBoundaryInput{RoleName: name, PermissionsBoundary: policies["both"]})
		requireCode(t, err, "Success")
	}
	for i, row := range fixture.ListPolicies {
		t.Run(fmt.Sprintf("list_%d", i), func(t *testing.T) {
			out, err := client.ListPolicies(ctx, &sdkiam.ListPoliciesInput{Scope: types.PolicyScopeTypeLocal, PathPrefix: path, OnlyAttached: aws.ToBool(row.OnlyAttached), PolicyUsageFilter: types.PolicyUsageType(row.Usage)})
			requireCode(t, err, row.Code)
			var labels []string
			for _, policy := range out.Policies {
				labels = append(labels, strings.TrimPrefix(aws.ToString(policy.PolicyName), "observed-"))
			}
			slices.Sort(labels)
			if !slices.Equal(labels, row.Policies) {
				t.Fatalf("listed policies = %v; AWS = %v", labels, row.Policies)
			}
		})
	}
	for i, row := range fixture.Entities {
		t.Run(fmt.Sprintf("entities_%d", i), func(t *testing.T) {
			out, err := client.ListEntitiesForPolicy(ctx, &sdkiam.ListEntitiesForPolicyInput{PolicyArn: policies[row.Policy], EntityFilter: types.EntityType(row.Filter), PolicyUsageFilter: types.PolicyUsageType(row.Usage)})
			requireCode(t, err, row.Code)
			if len(out.PolicyUsers) != row.Users || len(out.PolicyGroups) != row.Groups || len(out.PolicyRoles) != row.Roles {
				t.Fatalf("entities = %d/%d/%d users/groups/roles; AWS = %d/%d/%d", len(out.PolicyUsers), len(out.PolicyGroups), len(out.PolicyRoles), row.Users, row.Groups, row.Roles)
			}
		})
	}
	for label, counts := range fixture.Counts {
		out, err := client.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: policies[label]})
		requireCode(t, err, "Success")
		if aws.ToInt32(out.Policy.AttachmentCount) != counts.AttachmentCount || aws.ToInt32(out.Policy.PermissionsBoundaryUsageCount) != counts.PermissionsBoundaryUsageCount {
			t.Fatalf("%s policy counts = %+v; AWS = %+v", label, out.Policy, counts)
		}
	}
}

func TestInlinePolicyNamesReplayAWS(t *testing.T) {
	fixture := loadPolicyManagementFixture(t)
	client := newActivityFixture(t, nil, time.Unix(0, 0).UTC()).root
	ctx := t.Context()
	name := aws.String("inline-owner")
	_, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: name})
	requireCode(t, err, "Success")
	_, err = client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: name})
	requireCode(t, err, "Success")
	_, err = client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: name, AssumeRolePolicyDocument: aws.String(trustEC2)})
	requireCode(t, err, "Success")
	for _, row := range fixture.Inline {
		t.Run(row.Kind, func(t *testing.T) {
			put := func(policyName, document string) {
				t.Helper()
				var err error
				switch row.Kind {
				case "User":
					_, err = client.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: name, PolicyName: &policyName, PolicyDocument: &document})
				case "Group":
					_, err = client.PutGroupPolicy(ctx, &sdkiam.PutGroupPolicyInput{GroupName: name, PolicyName: &policyName, PolicyDocument: &document})
				case "Role":
					_, err = client.PutRolePolicy(ctx, &sdkiam.PutRolePolicyInput{RoleName: name, PolicyName: &policyName, PolicyDocument: &document})
				}
				requireCode(t, err, "Success")
			}
			list := func() []string {
				t.Helper()
				switch row.Kind {
				case "User":
					out, err := client.ListUserPolicies(ctx, &sdkiam.ListUserPoliciesInput{UserName: name})
					requireCode(t, err, "Success")
					return out.PolicyNames
				case "Group":
					out, err := client.ListGroupPolicies(ctx, &sdkiam.ListGroupPoliciesInput{GroupName: name})
					requireCode(t, err, "Success")
					return out.PolicyNames
				default:
					out, err := client.ListRolePolicies(ctx, &sdkiam.ListRolePoliciesInput{RoleName: name})
					requireCode(t, err, "Success")
					return out.PolicyNames
				}
			}
			put("MixedName", allowRead)
			put("mixedname", strings.Replace(allowRead, `"Effect":"Allow"`, `"Effect":"Deny"`, 1))
			if names := list(); !slices.Equal(names, row.Names) {
				t.Fatalf("policy names = %v; AWS = %v", names, row.Names)
			}
			var returnedName, document *string
			var getErr, deleteErr error
			switch row.Kind {
			case "User":
				out, err := client.GetUserPolicy(ctx, &sdkiam.GetUserPolicyInput{UserName: name, PolicyName: aws.String("MIXEDNAME")})
				getErr = err
				if err == nil {
					returnedName, document = out.PolicyName, out.PolicyDocument
				}
				_, deleteErr = client.DeleteUserPolicy(ctx, &sdkiam.DeleteUserPolicyInput{UserName: name, PolicyName: aws.String("mIxEdNaMe")})
			case "Group":
				out, err := client.GetGroupPolicy(ctx, &sdkiam.GetGroupPolicyInput{GroupName: name, PolicyName: aws.String("MIXEDNAME")})
				getErr = err
				if err == nil {
					returnedName, document = out.PolicyName, out.PolicyDocument
				}
				_, deleteErr = client.DeleteGroupPolicy(ctx, &sdkiam.DeleteGroupPolicyInput{GroupName: name, PolicyName: aws.String("mIxEdNaMe")})
			case "Role":
				out, err := client.GetRolePolicy(ctx, &sdkiam.GetRolePolicyInput{RoleName: name, PolicyName: aws.String("MIXEDNAME")})
				getErr = err
				if err == nil {
					returnedName, document = out.PolicyName, out.PolicyDocument
				}
				_, deleteErr = client.DeleteRolePolicy(ctx, &sdkiam.DeleteRolePolicyInput{RoleName: name, PolicyName: aws.String("mIxEdNaMe")})
			}
			requireCode(t, getErr, row.GetCode)
			requireCode(t, deleteErr, row.DeleteCode)
			decoded, err := url.QueryUnescape(aws.ToString(document))
			if err != nil {
				t.Fatal(err)
			}
			var policy struct{ Statement []struct{ Effect string } }
			if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
				t.Fatal(err)
			}
			if aws.ToString(returnedName) != row.ReturnedName || len(policy.Statement) != 1 || policy.Statement[0].Effect != row.Effect {
				t.Fatalf("returned name/document = %q/%s; AWS = %q/%s", aws.ToString(returnedName), decoded, row.ReturnedName, row.Effect)
			}
			if names := list(); !slices.Equal(names, row.RemainingNames) {
				t.Fatalf("remaining policy names = %v; AWS = %v", names, row.RemainingNames)
			}
		})
	}
}

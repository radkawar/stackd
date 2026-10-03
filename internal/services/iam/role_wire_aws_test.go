package iam_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

func TestRoleWireAWSFieldPresence(t *testing.T) {
	data, err := os.ReadFile("testdata/role_wire_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Name  string `json:"name"`
			Role  map[string]json.RawMessage
			Roles []map[string]json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]map[string]json.RawMessage)
	for _, observation := range fixture.Observations {
		if observation.Role != nil {
			byName[observation.Name] = observation.Role
		} else if len(observation.Roles) == 1 {
			byName[observation.Name] = observation.Roles[0]
		}
	}
	assertFields := func(name string, role *types.Role) {
		t.Helper()
		want := byName[name]
		if want == nil || role == nil {
			t.Fatalf("missing role observation %q: %+v", name, role)
		}
		present := map[string]bool{"Description": role.Description != nil, "MaxSessionDuration": role.MaxSessionDuration != nil, "PermissionsBoundary": role.PermissionsBoundary != nil, "Tags": len(role.Tags) > 0, "RoleLastUsed": role.RoleLastUsed != nil}
		for field, got := range present {
			if _, expected := want[field]; got != expected {
				t.Errorf("%s response %s presence = %v, AWS = %v", name, field, got, expected)
			}
		}
		for field, actual := range map[string]string{"RoleName": aws.ToString(role.RoleName), "Path": aws.ToString(role.Path), "Arn": aws.ToString(role.Arn)} {
			var expected string
			if err := json.Unmarshal(want[field], &expected); err != nil {
				t.Fatal(err)
			}
			if actual != expected {
				t.Errorf("%s %s = %q, AWS = %q", name, field, actual, expected)
			}
		}
		if role.CreateDate == nil || role.RoleId == nil || len(aws.ToString(role.RoleId)) != 21 || role.AssumeRolePolicyDocument == nil {
			t.Fatalf("%s lost basic role fields: %+v", name, role)
		}
		if raw, ok := want["Description"]; ok {
			var description string
			if err := json.Unmarshal(raw, &description); err != nil {
				t.Fatal(err)
			}
			if aws.ToString(role.Description) != description {
				t.Fatalf("%s description = %q, AWS = %q", name, aws.ToString(role.Description), description)
			}
		}
		if role.PermissionsBoundary != nil && aws.ToString(role.PermissionsBoundary.PermissionsBoundaryArn) != "arn:aws:iam::aws:policy/ReadOnlyAccess" {
			t.Fatalf("%s boundary: %+v", name, role.PermissionsBoundary)
		}
		if len(role.Tags) > 0 && (len(role.Tags) != 1 || aws.ToString(role.Tags[0].Key) != "team" || aws.ToString(role.Tags[0].Value) != "probe") {
			t.Fatalf("%s tags: %+v", name, role.Tags)
		}
	}
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	created, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("stackdprobe"), Path: aws.String("/stackdprobe/"), AssumeRolePolicyDocument: aws.String(trustEC2), Description: aws.String("created-description"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("probe")}}, PermissionsBoundary: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")})
	if err != nil {
		t.Fatal(err)
	}
	assertFields("create", created.Role)
	get, err := c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: created.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	assertFields("get", get.Role)
	list, err := c.ListRoles(ctx, &sdkiam.ListRolesInput{PathPrefix: aws.String("/stackdprobe/")})
	if err != nil || len(list.Roles) != 1 {
		t.Fatalf("list response: %+v, %v", list, err)
	}
	assertFields("list", &list.Roles[0])
	updated, err := c.UpdateRoleDescription(ctx, &sdkiam.UpdateRoleDescriptionInput{RoleName: created.Role.RoleName, Description: aws.String("updated-description")})
	if err != nil {
		t.Fatal(err)
	}
	assertFields("update-description", updated.Role)
	get, err = c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: created.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	assertFields("get-after-description", get.Role)
	if aws.ToString(get.Role.RoleId) != aws.ToString(created.Role.RoleId) {
		t.Fatal("description update replaced immutable role identity")
	}
}

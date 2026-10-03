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

// The fixture was captured from owned AWS IAM resources and their complete
// cleanup. Replay these decisions through the generated Query frontend and SDK.
func TestInstanceProfileAWSParity(t *testing.T) {
	data, err := os.ReadFile("testdata/instance_profiles_aws.json")
	if err != nil {
		t.Fatal(err)
	}
	type profileObservation struct {
		Path, InstanceProfileName, Arn string
		Roles                          []struct {
			RoleName           string
			Tags               []types.Tag
			Description        *string
			MaxSessionDuration *int32
		}
		Tags []types.Tag
	}
	var fixture struct {
		Observations []struct {
			Name     string `json:"name"`
			Error    string `json:"error"`
			Response struct {
				InstanceProfile  profileObservation
				InstanceProfiles []profileObservation
			} `json:"response"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	name, path := "profile-probe-Profile", "/profile-probe/"
	roleName, otherRole := "profile-probe-Role", "profile-probe-Other"
	for _, role := range []string{roleName, otherRole} {
		if _, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String(role), Path: aws.String(path), AssumeRolePolicyDocument: aws.String(trustEC2), Description: aws.String("Probe description"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("compute")}}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, observation := range fixture.Observations {
		t.Run(observation.Name, func(t *testing.T) {
			var profiles []types.InstanceProfile
			var expected []profileObservation
			var err error
			switch observation.Name {
			case "create":
				var out *sdkiam.CreateInstanceProfileOutput
				out, err = c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String(name), Path: aws.String(path), Tags: []types.Tag{{Key: aws.String("Team"), Value: aws.String("one")}, {Key: aws.String("team"), Value: aws.String("two")}}})
				if err == nil {
					profiles = []types.InstanceProfile{*out.InstanceProfile}
					expected = []profileObservation{observation.Response.InstanceProfile}
				}
			case "remove-unattached-from-empty", "remove", "repeat-remove":
				_, err = c.RemoveRoleFromInstanceProfile(ctx, &sdkiam.RemoveRoleFromInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: aws.String(roleName)})
			case "add", "duplicate-add":
				_, err = c.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: aws.String(roleName)})
			case "add-second-role":
				_, err = c.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: aws.String(otherRole)})
			case "remove-different-role":
				_, err = c.RemoveRoleFromInstanceProfile(ctx, &sdkiam.RemoveRoleFromInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: aws.String(otherRole)})
			case "get":
				var out *sdkiam.GetInstanceProfileOutput
				out, err = c.GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String(name)})
				if err == nil {
					profiles = []types.InstanceProfile{*out.InstanceProfile}
					expected = []profileObservation{observation.Response.InstanceProfile}
				}
			case "list":
				var out *sdkiam.ListInstanceProfilesOutput
				out, err = c.ListInstanceProfiles(ctx, &sdkiam.ListInstanceProfilesInput{PathPrefix: aws.String(path)})
				if err == nil {
					profiles = out.InstanceProfiles
					expected = observation.Response.InstanceProfiles
				}
			case "list-for-role":
				var out *sdkiam.ListInstanceProfilesForRoleOutput
				out, err = c.ListInstanceProfilesForRole(ctx, &sdkiam.ListInstanceProfilesForRoleInput{RoleName: aws.String(roleName)})
				if err == nil {
					profiles = out.InstanceProfiles
					expected = observation.Response.InstanceProfiles
				}
			case "delete-populated-profile":
				_, err = c.DeleteInstanceProfile(ctx, &sdkiam.DeleteInstanceProfileInput{InstanceProfileName: aws.String(name)})
			case "delete-associated-role":
				_, err = c.DeleteRole(ctx, &sdkiam.DeleteRoleInput{RoleName: aws.String(roleName)})
			default:
				t.Fatalf("unrecognized AWS fixture observation %q", observation.Name)
			}
			if observation.Error != "" {
				requireCode(t, err, observation.Error)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(profiles) != len(expected) {
				t.Fatalf("profile count = %d; AWS returned %d", len(profiles), len(expected))
			}
			for i, actual := range profiles {
				want := expected[i]
				if aws.ToString(actual.Path) != want.Path || aws.ToString(actual.InstanceProfileName) != want.InstanceProfileName || aws.ToString(actual.Arn) != want.Arn || len(actual.Tags) != len(want.Tags) || len(actual.Roles) != len(want.Roles) {
					t.Fatalf("profile projection = %+v; AWS returned %+v", actual, want)
				}
				for j, role := range actual.Roles {
					if aws.ToString(role.RoleName) != want.Roles[j].RoleName || role.Description != nil || role.MaxSessionDuration != nil || len(role.Tags) != 0 {
						t.Fatalf("nested role projection differs from AWS: %+v", role)
					}
				}
			}
		})
	}
}

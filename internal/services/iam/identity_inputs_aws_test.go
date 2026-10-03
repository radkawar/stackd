package iam_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"stackd/internal/services/iam"
)

func TestIdentityInputsReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/iam/identity_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	type observation struct {
		Kind       string
		Path       *string
		NameLength int    `json:"name_length"`
		NameSuffix string `json:"name_suffix"`
		LookupCode string `json:"lookup_code"`
		Code       string
		StoredPath string `json:"stored_path"`
	}
	var fixture struct {
		Creates []observation
		Updates []observation
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"standalone", "gateway"} {
		t.Run(endpoint, func(t *testing.T) {
			var client *sdkiam.Client
			if endpoint == "gateway" {
				client = newActivityFixture(t, nil, time.Unix(0, 0).UTC()).root
			} else {
				service := iam.New()
				t.Cleanup(func() { _ = service.Close() })
				client = clientFor(t, service, "123456789012", "us-east-1")
			}
			ctx := t.Context()
			for i, row := range fixture.Creates {
				t.Run(fmt.Sprintf("create_%s_%d", row.Kind, i), func(t *testing.T) {
					name := fmt.Sprintf("captured-%d", i)
					if row.NameLength != 0 {
						name = strings.Repeat("x", row.NameLength)
					}
					name += row.NameSuffix
					var path string
					var err error
					if row.Kind == "User" {
						out, createErr := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: &name, Path: row.Path})
						err = createErr
						if err == nil {
							path = aws.ToString(out.User.Path)
						}
					} else {
						out, createErr := client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: &name, Path: row.Path})
						err = createErr
						if err == nil {
							path = aws.ToString(out.Group.Path)
						}
					}
					if row.Code != "Success" {
						requireCode(t, err, row.Code)
						if row.Path != nil || row.LookupCode != "" {
							if row.Kind == "User" {
								_, err = client.GetUser(ctx, &sdkiam.GetUserInput{UserName: &name})
							} else {
								_, err = client.GetGroup(ctx, &sdkiam.GetGroupInput{GroupName: &name})
							}
							want := row.LookupCode
							if want == "" {
								want = "NoSuchEntity"
							}
							requireCode(t, err, want)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if row.Path != nil && path != row.StoredPath {
						t.Fatalf("created path = %q; AWS = %q", path, row.StoredPath)
					}
				})
			}
			name := aws.String("updated")
			if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: name, Path: aws.String("/initial/")}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: name, Path: aws.String("/initial/")}); err != nil {
				t.Fatal(err)
			}
			for i, row := range fixture.Updates {
				t.Run(fmt.Sprintf("update_%s_%d", row.Kind, i), func(t *testing.T) {
					var path string
					var updateErr, getErr error
					if row.Kind == "User" {
						_, updateErr = client.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: name, NewPath: row.Path})
						out, err := client.GetUser(ctx, &sdkiam.GetUserInput{UserName: name})
						getErr = err
						if err == nil {
							path = aws.ToString(out.User.Path)
						}
					} else {
						_, updateErr = client.UpdateGroup(ctx, &sdkiam.UpdateGroupInput{GroupName: name, NewPath: row.Path})
						out, err := client.GetGroup(ctx, &sdkiam.GetGroupInput{GroupName: name})
						getErr = err
						if err == nil {
							path = aws.ToString(out.Group.Path)
						}
					}
					if row.Code == "Success" {
						if updateErr != nil {
							t.Fatal(updateErr)
						}
					} else {
						requireCode(t, updateErr, row.Code)
					}
					if getErr != nil || path != row.StoredPath {
						t.Fatalf("stored path = %q, %v; AWS = %q", path, getErr, row.StoredPath)
					}
				})
			}
		})
	}
}

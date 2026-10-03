package iam_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"stackd/internal/services/iam"
)

type queryResponseCapture struct{ body []byte }

func (c *queryResponseCapture) Do(request *http.Request) (*http.Response, error) {
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	c.body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(c.body))
	return response, err
}

type queryElement struct {
	XMLName  xml.Name
	Children []queryElement `xml:",any"`
}

func queryFields(t *testing.T, data []byte, path ...string) []string {
	t.Helper()
	var element struct {
		Children []queryElement `xml:",any"`
	}
	if err := xml.Unmarshal(data, &element); err != nil {
		t.Fatal(err)
	}
	children := element.Children
	for _, name := range path {
		found := false
		for _, child := range children {
			if child.XMLName.Local == name {
				children, found = child.Children, true
				break
			}
		}
		if !found {
			t.Fatalf("missing Query response element %s in %s", name, data)
		}
	}
	fields := make([]string, 0, len(children))
	for _, child := range children {
		fields = append(fields, child.XMLName.Local)
	}
	slices.Sort(fields)
	return fields
}

func TestUserGroupResponseShapesReplayAWS(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/aws/iam/user_group_shapes.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations map[string]json.RawMessage `json:"observations"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	capture := &queryResponseCapture{}
	opts := clientFor(t, iam.New(), "123456789012", "us-east-1").Options()
	opts.HTTPClient = capture
	client := sdkiam.New(opts)
	ctx := context.Background()
	boundary := mustCreatePolicy(t, client, "read-boundary")
	assertFields := func(key string, path ...string) {
		t.Helper()
		var want []string
		if err := json.Unmarshal(fixture.Observations[key], &want); err != nil {
			t.Fatal(err)
		}
		if got := queryFields(t, capture.body, path...); !slices.Equal(got, want) {
			t.Fatalf("%s fields = %v; AWS = %v", key, got, want)
		}
	}
	user, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("observed-user"), PermissionsBoundary: aws.String(boundary), Tags: []types.Tag{{Key: aws.String("probe"), Value: aws.String("stackd")}}})
	if err != nil {
		t.Fatal(err)
	}
	assertFields("create_user_fields", "CreateUserResult", "User")
	if _, err := client.GetUser(ctx, &sdkiam.GetUserInput{UserName: user.User.UserName}); err != nil {
		t.Fatal(err)
	}
	assertFields("get_user_fields", "GetUserResult", "User")
	if _, err := client.ListUsers(ctx, &sdkiam.ListUsersInput{}); err != nil {
		t.Fatal(err)
	}
	assertFields("list_users_fields", "ListUsersResult", "Users", "member")
	group, err := client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: aws.String("observed-group")})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.AddUserToGroup(ctx, &sdkiam.AddUserToGroupInput{UserName: user.User.UserName, GroupName: group.Group.GroupName}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.GetGroup(ctx, &sdkiam.GetGroupInput{GroupName: group.Group.GroupName}); err != nil {
		t.Fatal(err)
	}
	assertFields("get_group_fields", "GetGroupResult", "Group")
	assertFields("get_group_user_fields", "GetGroupResult", "Users", "member")
	for range 2 {
		if _, err := client.RemoveUserFromGroup(ctx, &sdkiam.RemoveUserFromGroupInput{UserName: user.User.UserName, GroupName: group.Group.GroupName}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = client.RemoveUserFromGroup(ctx, &sdkiam.RemoveUserFromGroupInput{UserName: aws.String("missing"), GroupName: group.Group.GroupName})
	requireCode(t, err, "NoSuchEntity")
}

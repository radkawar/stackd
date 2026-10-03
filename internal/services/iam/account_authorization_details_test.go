package iam_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/services/iam"
)

// These SDK tests exercise the account graph contract described by
// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html.
// They compare sets rather than imposing an undocumented AWS entity sort order.
var authorizationDetailLocalFilters = []types.EntityType{
	types.EntityTypeUser, types.EntityTypeGroup, types.EntityTypeRole, types.EntityTypeLocalManagedPolicy,
}

type authorizationDetailGraph struct {
	user      *types.User
	group     *types.Group
	role      *types.Role
	profiles  []*types.InstanceProfile
	policy    *types.Policy
	boundary  *types.Policy
	versions  map[string]*types.PolicyVersion
	documents map[string]string
}

func createAuthorizationDetailGraph(t *testing.T, client *sdkiam.Client, source *clock.Manual) authorizationDetailGraph {
	t.Helper()
	ctx := t.Context()
	graph := authorizationDetailGraph{versions: make(map[string]*types.PolicyVersion), documents: map[string]string{"v1": allowRead}}
	policy, err := client.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{
		PolicyName: aws.String("GraphRead"), Path: aws.String("/policies/"), Description: aws.String("Graph policy with retained versions"), PolicyDocument: aws.String(allowRead),
	})
	if err != nil {
		t.Fatal(err)
	}
	graph.policy = policy.Policy
	version, err := client.GetPolicyVersion(ctx, &sdkiam.GetPolicyVersionInput{PolicyArn: policy.Policy.Arn, VersionId: aws.String("v1")})
	if err != nil {
		t.Fatal(err)
	}
	graph.versions["v1"] = version.PolicyVersion
	for index, document := range []string{denyRead, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"StringLike":{"s3:prefix":"reports + raw/%2B/*"}}}}`} {
		if err := source.Advance(time.Minute); err != nil {
			t.Fatal(err)
		}
		version, err := client.CreatePolicyVersion(ctx, &sdkiam.CreatePolicyVersionInput{PolicyArn: policy.Policy.Arn, PolicyDocument: aws.String(document), SetAsDefault: index == 0})
		if err != nil {
			t.Fatal(err)
		}
		graph.versions[aws.ToString(version.PolicyVersion.VersionId)] = version.PolicyVersion
		graph.documents[aws.ToString(version.PolicyVersion.VersionId)] = document
	}
	boundary, err := client.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("GraphBoundary"), PolicyDocument: aws.String(allowRead)})
	if err != nil {
		t.Fatal(err)
	}
	graph.boundary = boundary.Policy
	tags := []types.Tag{{Key: aws.String("team"), Value: aws.String("platform + audit")}, {Key: aws.String("stage"), Value: aws.String("test")}}
	user, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("GraphUser"), Path: aws.String("/people/"), Tags: tags, PermissionsBoundary: boundary.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	graph.user = user.User
	group, err := client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: aws.String("GraphGroup"), Path: aws.String("/teams/")})
	if err != nil {
		t.Fatal(err)
	}
	graph.group = group.Group
	role, err := client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("GraphRole"), Path: aws.String("/workloads/"), AssumeRolePolicyDocument: aws.String(trustEC2), PermissionsBoundary: boundary.Policy.Arn, Tags: tags, Description: aws.String("profile role"), MaxSessionDuration: aws.Int32(7200)})
	if err != nil {
		t.Fatal(err)
	}
	graph.role = role.Role
	steps := []func() error{
		func() error {
			_, err := client.AddUserToGroup(ctx, &sdkiam.AddUserToGroupInput{UserName: user.User.UserName, GroupName: group.Group.GroupName})
			return err
		},
		func() error {
			_, err := client.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("UserInline"), PolicyDocument: aws.String(allowRead)})
			return err
		},
		func() error {
			_, err := client.PutGroupPolicy(ctx, &sdkiam.PutGroupPolicyInput{GroupName: group.Group.GroupName, PolicyName: aws.String("GroupInline"), PolicyDocument: aws.String(denyRead)})
			return err
		},
		func() error {
			_, err := client.PutRolePolicy(ctx, &sdkiam.PutRolePolicyInput{RoleName: role.Role.RoleName, PolicyName: aws.String("RoleInline"), PolicyDocument: aws.String(allowRead)})
			return err
		},
		func() error {
			_, err := client.AttachUserPolicy(ctx, &sdkiam.AttachUserPolicyInput{UserName: user.User.UserName, PolicyArn: policy.Policy.Arn})
			return err
		},
		func() error {
			_, err := client.AttachGroupPolicy(ctx, &sdkiam.AttachGroupPolicyInput{GroupName: group.Group.GroupName, PolicyArn: policy.Policy.Arn})
			return err
		},
		func() error {
			_, err := client.AttachRolePolicy(ctx, &sdkiam.AttachRolePolicyInput{RoleName: role.Role.RoleName, PolicyArn: policy.Policy.Arn})
			return err
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"GraphProfileA", "GraphProfileB", "UnattachedProfile"} {
		profile, err := client.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String(name), Path: aws.String("/compute/"), Tags: tags})
		if err != nil {
			t.Fatal(err)
		}
		if name != "UnattachedProfile" {
			if _, err := client.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: role.Role.RoleName}); err != nil {
				t.Fatal(err)
			}
			graph.profiles = append(graph.profiles, profile.InstanceProfile)
		}
	}
	return graph
}

func TestAccountAuthorizationDetailsCompleteGraph(t *testing.T) {
	source := clock.NewManual(time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC))
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
	client := clientFor(t, service, "123456789012", "us-east-1")
	graph := createAuthorizationDetailGraph(t, client, source)
	lastUsed := source.Now().Add(-time.Minute)
	if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
		scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
		role, err := tx.Role(scope, "GraphRole")
		if err != nil {
			return err
		}
		role.LastUsed = iam.RoleLastUse{Date: lastUsed, Region: "eu-west-2"}
		return tx.PutRole(scope, role)
	}); err != nil {
		t.Fatal(err)
	}
	out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters, MaxItems: aws.Int32(1000)})
	if err != nil {
		t.Fatal(err)
	}
	if out.IsTruncated || out.Marker != nil || len(out.UserDetailList) != 1 || len(out.GroupDetailList) != 1 || len(out.RoleDetailList) != 1 || len(out.Policies) != 2 {
		t.Fatalf("account graph counts: users=%d groups=%d roles=%d policies=%d truncated=%v marker=%v", len(out.UserDetailList), len(out.GroupDetailList), len(out.RoleDetailList), len(out.Policies), out.IsTruncated, out.Marker)
	}
	u, g, r := out.UserDetailList[0], out.GroupDetailList[0], out.RoleDetailList[0]
	assertDetailIdentity(t, u.UserName, u.UserId, u.Arn, u.Path, u.CreateDate, graph.user.UserName, graph.user.UserId, graph.user.Arn, graph.user.Path, graph.user.CreateDate)
	assertDetailIdentity(t, g.GroupName, g.GroupId, g.Arn, g.Path, g.CreateDate, graph.group.GroupName, graph.group.GroupId, graph.group.Arn, graph.group.Path, graph.group.CreateDate)
	assertDetailIdentity(t, r.RoleName, r.RoleId, r.Arn, r.Path, r.CreateDate, graph.role.RoleName, graph.role.RoleId, graph.role.Arn, graph.role.Path, graph.role.CreateDate)
	if !slices.Equal(u.GroupList, []string{"GraphGroup"}) {
		t.Fatalf("user group relationship=%v", u.GroupList)
	}
	assertDetailInline(t, u.UserPolicyList, "UserInline", allowRead)
	assertDetailInline(t, g.GroupPolicyList, "GroupInline", denyRead)
	assertDetailInline(t, r.RolePolicyList, "RoleInline", allowRead)
	assertDetailDocument(t, r.AssumeRolePolicyDocument, trustEC2)
	for _, attached := range [][]types.AttachedPolicy{u.AttachedManagedPolicies, g.AttachedManagedPolicies, r.AttachedManagedPolicies} {
		if len(attached) != 1 || aws.ToString(attached[0].PolicyArn) != aws.ToString(graph.policy.Arn) || aws.ToString(attached[0].PolicyName) != "GraphRead" {
			t.Fatalf("managed attachment=%+v", attached)
		}
	}
	for _, boundary := range []*types.AttachedPermissionsBoundary{u.PermissionsBoundary, r.PermissionsBoundary} {
		// AWS emits "Policy", despite the SDK's differently named enum value;
		// testdata/role_wire_aws.json records that service response.
		if boundary == nil || aws.ToString(boundary.PermissionsBoundaryArn) != aws.ToString(graph.boundary.Arn) || boundary.PermissionsBoundaryType != "Policy" {
			t.Fatalf("permissions boundary=%+v", boundary)
		}
	}
	assertDetailTags(t, u.Tags)
	assertDetailTags(t, r.Tags)
	if r.RoleLastUsed == nil || !aws.ToTime(r.RoleLastUsed.LastUsedDate).Equal(lastUsed) || aws.ToString(r.RoleLastUsed.Region) != "eu-west-2" {
		t.Fatalf("role last use=%+v", r.RoleLastUsed)
	}
	if len(r.InstanceProfileList) != 2 {
		t.Fatalf("connected profiles=%+v", r.InstanceProfileList)
	}
	for _, profile := range r.InstanceProfileList {
		index := slices.IndexFunc(graph.profiles, func(p *types.InstanceProfile) bool {
			return aws.ToString(p.InstanceProfileName) == aws.ToString(profile.InstanceProfileName)
		})
		if index < 0 {
			t.Fatalf("unexpected profile %s", aws.ToString(profile.InstanceProfileName))
		}
		want := graph.profiles[index]
		assertDetailIdentity(t, profile.InstanceProfileName, profile.InstanceProfileId, profile.Arn, profile.Path, profile.CreateDate, want.InstanceProfileName, want.InstanceProfileId, want.Arn, want.Path, want.CreateDate)
		if len(profile.Roles) != 1 || aws.ToString(profile.Roles[0].RoleId) != aws.ToString(r.RoleId) || aws.ToString(profile.Roles[0].Arn) != aws.ToString(r.Arn) {
			t.Fatalf("nested role relationship=%+v", profile.Roles)
		}
		nested := profile.Roles[0]
		if profile.Tags != nil || nested.Tags != nil || nested.PermissionsBoundary != nil || nested.RoleLastUsed != nil || nested.Description != nil || nested.MaxSessionDuration != nil {
			t.Fatalf("nested profile/role includes fields omitted by AWS: %+v %+v", profile, nested)
		}
		assertDetailDocument(t, profile.Roles[0].AssumeRolePolicyDocument, trustEC2)
	}
	for _, policy := range out.Policies {
		if aws.ToString(policy.Arn) == aws.ToString(graph.boundary.Arn) {
			if aws.ToInt32(policy.AttachmentCount) != 0 || aws.ToInt32(policy.PermissionsBoundaryUsageCount) != 2 {
				t.Fatalf("boundary use counts=%+v", policy)
			}
			continue
		}
		assertDetailIdentity(t, policy.PolicyName, policy.PolicyId, policy.Arn, policy.Path, policy.CreateDate, graph.policy.PolicyName, graph.policy.PolicyId, graph.policy.Arn, graph.policy.Path, graph.policy.CreateDate)
		if !policy.IsAttachable || aws.ToInt32(policy.AttachmentCount) != 3 || aws.ToInt32(policy.PermissionsBoundaryUsageCount) != 0 || aws.ToString(policy.DefaultVersionId) != "v2" || policy.Description != nil || !aws.ToTime(policy.UpdateDate).Equal(source.Now()) {
			t.Fatalf("managed policy details=%+v", policy)
		}
		if len(policy.PolicyVersionList) != len(graph.versions) {
			t.Fatalf("retained versions=%+v", policy.PolicyVersionList)
		}
		seen := make(map[string]bool)
		for _, version := range policy.PolicyVersionList {
			id := aws.ToString(version.VersionId)
			want, ok := graph.versions[id]
			if !ok || seen[id] {
				t.Fatalf("unexpected or duplicate version %q", id)
			}
			seen[id] = true
			if version.IsDefaultVersion != (id == "v2") || !aws.ToTime(version.CreateDate).Equal(aws.ToTime(want.CreateDate)) {
				t.Fatalf("version identity/date/default=%+v", version)
			}
			assertDetailDocument(t, version.Document, graph.documents[id])
		}
	}
	if err := source.Advance(401 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	expired, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeRole}})
	if err != nil {
		t.Fatal(err)
	}
	if used := expired.RoleDetailList[0].RoleLastUsed; used != nil && (used.LastUsedDate != nil || used.Region != nil) {
		t.Fatalf("last use older than 400 days was disclosed: %+v", used)
	}
}

func assertDetailIdentity(t *testing.T, name, id, arn, path *string, date *time.Time, wantName, wantID, wantARN, wantPath *string, wantDate *time.Time) {
	t.Helper()
	if aws.ToString(name) != aws.ToString(wantName) || aws.ToString(id) != aws.ToString(wantID) || aws.ToString(arn) != aws.ToString(wantARN) || aws.ToString(path) != aws.ToString(wantPath) || date == nil || !date.Equal(aws.ToTime(wantDate)) {
		t.Fatalf("identity %q/%q/%q/%q/%v does not match %q/%q/%q/%q/%v", aws.ToString(name), aws.ToString(id), aws.ToString(arn), aws.ToString(path), date, aws.ToString(wantName), aws.ToString(wantID), aws.ToString(wantARN), aws.ToString(wantPath), wantDate)
	}
}

func assertDetailDocument(t *testing.T, encoded *string, want string) {
	t.Helper()
	decoded, err := url.QueryUnescape(aws.ToString(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if decoded == aws.ToString(encoded) {
		t.Fatal("report policy document was not URL-encoded")
	}
	var gotJSON, wantJSON any
	if err := json.Unmarshal([]byte(decoded), &gotJSON); err != nil {
		t.Fatalf("invalid returned policy document %q: %v", aws.ToString(encoded), err)
	}
	if err := json.Unmarshal([]byte(want), &wantJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotJSON, wantJSON) {
		t.Fatalf("policy document=%s; want=%s", decoded, want)
	}
}

func assertDetailInline(t *testing.T, policies []types.PolicyDetail, name, document string) {
	t.Helper()
	if len(policies) != 1 || aws.ToString(policies[0].PolicyName) != name {
		t.Fatalf("inline policies=%+v; want %s", policies, name)
	}
	assertDetailDocument(t, policies[0].PolicyDocument, document)
}

func assertDetailTags(t *testing.T, tags []types.Tag) {
	t.Helper()
	got := make(map[string]string)
	for _, tag := range tags {
		got[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	if !reflect.DeepEqual(got, map[string]string{"team": "platform + audit", "stage": "test"}) {
		t.Fatalf("tags=%v", got)
	}
}

func TestAccountAuthorizationDetailsFiltersAndPagination(t *testing.T) {
	service := iam.New()
	client := clientFor(t, service, "123456789012", "us-east-1")
	for _, name := range []string{"Zulu", "Alpha", "middle"} {
		if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("one-group")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("one-role"), AssumeRolePolicyDocument: aws.String(trustEC2)}); err != nil {
		t.Fatal(err)
	}
	policyARN := mustCreatePolicy(t, client, "one-policy")
	for _, test := range []struct {
		name    string
		filters []types.EntityType
		counts  [4]int
	}{
		{"users", []types.EntityType{types.EntityTypeUser}, [4]int{3, 0, 0, 0}},
		{"groups", []types.EntityType{types.EntityTypeGroup}, [4]int{0, 1, 0, 0}},
		{"roles", []types.EntityType{types.EntityTypeRole}, [4]int{0, 0, 1, 0}},
		{"local policies", []types.EntityType{types.EntityTypeLocalManagedPolicy}, [4]int{0, 0, 0, 1}},
		{"default filter", nil, [4]int{3, 1, 1, 1}},
		{"empty filter", []types.EntityType{}, [4]int{3, 1, 1, 1}},
		{"union", []types.EntityType{types.EntityTypeRole, types.EntityTypeUser}, [4]int{3, 0, 1, 0}},
		{"duplicate is a set", []types.EntityType{types.EntityTypeUser, types.EntityTypeUser}, [4]int{3, 0, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: test.filters, MaxItems: aws.Int32(1000)})
			if err != nil {
				t.Fatal(err)
			}
			got := [4]int{len(out.UserDetailList), len(out.GroupDetailList), len(out.RoleDetailList), len(out.Policies)}
			if got != test.counts || out.IsTruncated || out.Marker != nil {
				t.Fatalf("filtered counts=%v truncated=%v marker=%v; want %v", got, out.IsTruncated, out.Marker, test.counts)
			}
		})
	}
	var marker *string
	seen, markers := make(map[string]bool), make(map[string]bool)
	for page := 0; ; page++ {
		if page == 20 {
			t.Fatal("pagination did not terminate")
		}
		out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters, MaxItems: aws.Int32(2), Marker: marker})
		if err != nil {
			t.Fatal(err)
		}
		arns := authorizationDetailARNs(out)
		if len(arns) > 2 {
			t.Fatalf("MaxItems applies across all report sections; got %d entities", len(arns))
		}
		if page == 0 && (len(out.UserDetailList) == 0 || len(out.UserDetailList) != len(arns)) {
			t.Fatal("AWS emits users first when more users remain than the page limit")
		}
		for _, arn := range arns {
			if seen[arn] {
				t.Fatalf("duplicate entity across pages: %s", arn)
			}
			seen[arn] = true
		}
		if !out.IsTruncated {
			if out.Marker != nil {
				t.Fatal("terminal page unexpectedly carries a marker")
			}
			break
		}
		if aws.ToString(out.Marker) == "" || markers[aws.ToString(out.Marker)] {
			t.Fatal("truncated page has a missing or repeated marker")
		}
		markers[aws.ToString(out.Marker)] = true
		marker = out.Marker
	}
	if len(seen) != 6 || !seen[policyARN] || len(markers) == 0 {
		t.Fatalf("paginated entity set=%v markers=%d", seen, len(markers))
	}
}

func TestAccountAuthorizationDetailsEmptyFieldPresence(t *testing.T) {
	client := clientFor(t, iam.New(), "123456789012", "us-east-1")
	if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("BareUser")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("BareGroup")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("BareRole"), AssumeRolePolicyDocument: aws.String(trustEC2)}); err != nil {
		t.Fatal(err)
	}
	out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.UserDetailList) != 1 || len(out.GroupDetailList) != 1 || len(out.RoleDetailList) != 1 || out.Policies == nil {
		t.Fatalf("report section presence=%+v", out)
	}
	u, g, r := out.UserDetailList[0], out.GroupDetailList[0], out.RoleDetailList[0]
	// The SDK preserves absent lists as nil and present empty XML lists as [];
	// live AWS distinguishes UserPolicyList from the other empty relationships.
	if u.UserPolicyList != nil || u.GroupList == nil || u.AttachedManagedPolicies == nil || u.Tags == nil || u.PermissionsBoundary != nil {
		t.Fatalf("bare user field presence=%+v", u)
	}
	if g.GroupPolicyList == nil || g.AttachedManagedPolicies == nil {
		t.Fatalf("bare group field presence=%+v", g)
	}
	if r.RolePolicyList == nil || r.AttachedManagedPolicies == nil || r.InstanceProfileList == nil || r.Tags == nil || r.PermissionsBoundary != nil || r.RoleLastUsed == nil || r.RoleLastUsed.LastUsedDate != nil || r.RoleLastUsed.Region != nil {
		t.Fatalf("bare role field presence=%+v", r)
	}
	usersOnly, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeUser}})
	if err != nil {
		t.Fatal(err)
	}
	if usersOnly.GroupDetailList == nil || usersOnly.RoleDetailList == nil || usersOnly.Policies == nil || len(usersOnly.GroupDetailList)+len(usersOnly.RoleDetailList)+len(usersOnly.Policies) != 0 {
		t.Fatalf("excluded sections must be present empty lists: %+v", usersOnly)
	}
}

func authorizationDetailARNs(out *sdkiam.GetAccountAuthorizationDetailsOutput) []string {
	var result []string
	for _, user := range out.UserDetailList {
		result = append(result, aws.ToString(user.Arn))
	}
	for _, group := range out.GroupDetailList {
		result = append(result, aws.ToString(group.Arn))
	}
	for _, role := range out.RoleDetailList {
		result = append(result, aws.ToString(role.Arn))
	}
	for _, policy := range out.Policies {
		result = append(result, aws.ToString(policy.Arn))
	}
	return result
}

func TestAccountAuthorizationDetailsValidationAndScope(t *testing.T) {
	service := iam.New()
	client := clientFor(t, service, "123456789012", "us-east-1")
	for _, test := range []struct {
		name  string
		input sdkiam.GetAccountAuthorizationDetailsInput
		code  string
	}{
		{"zero items", sdkiam.GetAccountAuthorizationDetailsInput{MaxItems: aws.Int32(0)}, "ValidationError"},
		{"too many items", sdkiam.GetAccountAuthorizationDetailsInput{MaxItems: aws.Int32(1001)}, "ValidationError"},
		{"unknown filter", sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{"InstanceProfile"}}, "ValidationError"},
		{"wrong filter case", sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{"user"}}, "ValidationError"},
		{"invalid marker", sdkiam.GetAccountAuthorizationDetailsInput{Marker: aws.String("not-a-pagination-token")}, "ValidationError"},
	} {
		t.Run(test.name, func(t *testing.T) {
			out, err := client.GetAccountAuthorizationDetails(t.Context(), &test.input)
			requireCode(t, err, test.code)
			if out != nil {
				t.Fatal("invalid request returned account details")
			}
		})
	}
	for _, name := range []string{"one", "two", "three"} {
		if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.CreateGroup(t.Context(), &sdkiam.CreateGroupInput{GroupName: aws.String("private-group")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("private-role"), AssumeRolePolicyDocument: aws.String(trustEC2)}); err != nil {
		t.Fatal(err)
	}
	mustCreatePolicy(t, client, "private-policy")
	otherAccount := clientFor(t, service, "999999999999", "us-east-1")
	otherPartition := clientForPartition(t, service, "123456789012", "cn-north-1", "aws-cn")
	otherRegion := clientFor(t, service, "123456789012", "eu-west-2")
	for index, scoped := range []*sdkiam.Client{otherAccount, otherPartition} {
		if _, err := scoped.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("isolated")}); err != nil {
			t.Fatal(err)
		}
		out, err := scoped.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters})
		if err != nil || len(out.UserDetailList) != 1 || aws.ToString(out.UserDetailList[0].UserName) != "isolated" || len(out.GroupDetailList) != 0 || len(out.RoleDetailList) != 0 || len(out.Policies) != 0 {
			t.Fatalf("isolated scope %d: out=%+v error=%v", index, out, err)
		}
		arn := aws.ToString(out.UserDetailList[0].Arn)
		if index == 0 && !strings.Contains(arn, "::999999999999:") || index == 1 && !strings.HasPrefix(arn, "arn:aws-cn:") {
			t.Fatalf("wrong scoped ARN %s", arn)
		}
	}
	first, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeUser}, MaxItems: aws.Int32(1)})
	if err != nil || !first.IsTruncated || aws.ToString(first.Marker) == "" {
		t.Fatalf("first page=%+v error=%v", first, err)
	}
	for _, scoped := range []*sdkiam.Client{otherAccount, otherPartition} {
		_, err := scoped.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeUser}, Marker: first.Marker})
		requireCode(t, err, "ValidationError")
	}
	_, err = client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeRole}, Marker: first.Marker})
	requireCode(t, err, "ValidationError")
	second, err := otherRegion.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeUser}, MaxItems: aws.Int32(2), Marker: first.Marker})
	if err != nil || len(second.UserDetailList) != 2 || second.IsTruncated {
		t.Fatalf("global IAM region continuation=%+v error=%v", second, err)
	}
	for _, user := range second.UserDetailList {
		if aws.ToString(user.UserId) == aws.ToString(first.UserDetailList[0].UserId) {
			t.Fatal("cross-region continuation repeated the first page")
		}
	}
	mixed, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeGroup, types.EntityTypeUser, types.EntityTypeLocalManagedPolicy}, MaxItems: aws.Int32(1)})
	if err != nil || !mixed.IsTruncated {
		t.Fatalf("mixed first page=%+v error=%v", mixed, err)
	}
	reordered, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeLocalManagedPolicy, types.EntityTypeUser, types.EntityTypeGroup}, MaxItems: aws.Int32(2), Marker: mixed.Marker})
	if err != nil || len(authorizationDetailARNs(reordered)) == 0 || len(authorizationDetailARNs(reordered)) > 2 {
		t.Fatalf("reordered filters/changed limit rejected valid continuation: %+v %v", reordered, err)
	}
	_, err = client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Marker: mixed.Marker})
	requireCode(t, err, "ValidationError")
}

type authorizationDetailControls struct{}

func (authorizationDetailControls) ServiceControlPolicies(context.Context) ([]iampolicy.PolicyLevel, error) {
	return []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:GetAccountAuthorizationDetails","Resource":"*"}]}`}}}}, nil
}

func TestAccountAuthorizationDetailsIAMAndSCPAuthorization(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	created, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("auditor"), Path: aws.String("/security/")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, service, created.User)
	input := &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeUser}}
	_, err = caller.GetAccountAuthorizationDetails(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	put := func(document string) {
		t.Helper()
		_, err := root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: created.User.UserName, PolicyName: aws.String("Audit"), PolicyDocument: aws.String(document)})
		if err != nil {
			t.Fatal(err)
		}
	}
	put(`{"Statement":{"Effect":"Allow","Action":"iam:GetAccountAuthorizationDetails","Resource":"` + aws.ToString(created.User.Arn) + `"}}`)
	_, err = caller.GetAccountAuthorizationDetails(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	put(`{"Statement":[{"Effect":"Allow","Action":"iam:GetAccountAuthorizationDetails","Resource":"*"},{"Effect":"Deny","Action":["iam:GetUser","iam:ListUsers","iam:GetUserPolicy"],"Resource":"*"}]}`)
	out, err := caller.GetAccountAuthorizationDetails(t.Context(), input)
	if err != nil || len(out.UserDetailList) != 1 || len(out.UserDetailList[0].UserPolicyList) != 1 {
		t.Fatalf("account action must authorize the entire report, not per-entity Get APIs: %+v %v", out, err)
	}
	put(`{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"},{"Effect":"Deny","Action":"iam:GetAccountAuthorizationDetails","Resource":"*"}]}`)
	_, err = caller.GetAccountAuthorizationDetails(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	put(`{"Statement":{"Effect":"Allow","Action":"iam:GetAccountAuthorizationDetails","Resource":"*"}}`)
	boundary, err := root.CreatePolicy(t.Context(), &sdkiam.CreatePolicyInput{PolicyName: aws.String("AuditBoundary"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":"*"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: created.User.UserName, PermissionsBoundary: boundary.Policy.Arn}); err != nil {
		t.Fatal(err)
	}
	_, err = caller.GetAccountAuthorizationDetails(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	if _, err := root.DeleteUserPermissionsBoundary(t.Context(), &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: created.User.UserName}); err != nil {
		t.Fatal(err)
	}
	service.SetAuthorizer(authorization.New(service, authorizationDetailControls{}))
	for _, principal := range []*sdkiam.Client{caller, root} {
		out, err := principal.GetAccountAuthorizationDetails(t.Context(), input)
		requireCode(t, err, "AccessDenied")
		if out != nil {
			t.Fatal("SCP denied report leaked account details")
		}
	}
}

type authorizationDetailRepository struct {
	iam.Repository
	blockUsers atomic.Bool
	gateOnce   sync.Once
	entered    chan struct{}
	release    chan struct{}
	readOnly   atomic.Bool
	writes     atomic.Int32
}

func (r *authorizationDetailRepository) View(ctx context.Context, fn func(iam.ReadTx) error) error {
	return r.Repository.View(ctx, func(tx iam.ReadTx) error { return fn(authorizationDetailReadTx{ReadTx: tx, owner: r}) })
}

func (r *authorizationDetailRepository) Update(ctx context.Context, fn func(iam.WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx iam.WriteTx) error { return fn(authorizationDetailWriteTx{WriteTx: tx, owner: r}) })
}

func (r *authorizationDetailRepository) users(tx iam.ReadTx, scope iam.Scope) ([]iam.User, error) {
	users, err := tx.Users(scope)
	if r.blockUsers.Load() {
		r.gateOnce.Do(func() { close(r.entered); <-r.release })
	}
	return users, err
}

type authorizationDetailReadTx struct {
	iam.ReadTx
	owner *authorizationDetailRepository
}

func (tx authorizationDetailReadTx) Users(scope iam.Scope) ([]iam.User, error) {
	return tx.owner.users(tx.ReadTx, scope)
}

type authorizationDetailWriteTx struct {
	iam.WriteTx
	owner *authorizationDetailRepository
}

func (tx authorizationDetailWriteTx) Users(scope iam.Scope) ([]iam.User, error) {
	return tx.owner.users(tx.WriteTx, scope)
}

func (tx authorizationDetailWriteTx) guardWrite() error {
	if tx.owner.readOnly.Load() {
		tx.owner.writes.Add(1)
		return errors.New("account authorization report attempted to mutate IAM")
	}
	return nil
}

func (tx authorizationDetailWriteTx) PutUser(scope iam.Scope, value iam.User) error {
	if err := tx.guardWrite(); err != nil {
		return err
	}
	return tx.WriteTx.PutUser(scope, value)
}
func (tx authorizationDetailWriteTx) PutGroup(scope iam.Scope, value iam.Group) error {
	if err := tx.guardWrite(); err != nil {
		return err
	}
	return tx.WriteTx.PutGroup(scope, value)
}
func (tx authorizationDetailWriteTx) PutRole(scope iam.Scope, value iam.Role) error {
	if err := tx.guardWrite(); err != nil {
		return err
	}
	return tx.WriteTx.PutRole(scope, value)
}
func (tx authorizationDetailWriteTx) PutManagedPolicy(scope iam.Scope, value iam.ManagedPolicy) error {
	if err := tx.guardWrite(); err != nil {
		return err
	}
	return tx.WriteTx.PutManagedPolicy(scope, value)
}
func (tx authorizationDetailWriteTx) PutInstanceProfile(scope iam.Scope, value iam.InstanceProfile) error {
	if err := tx.guardWrite(); err != nil {
		return err
	}
	return tx.WriteTx.PutInstanceProfile(scope, value)
}
func (tx authorizationDetailWriteTx) PutAccountSettings(scope iam.Scope, value iam.AccountSettingsRecord) error {
	if err := tx.guardWrite(); err != nil {
		return err
	}
	return tx.WriteTx.PutAccountSettings(scope, value)
}

func TestAccountAuthorizationDetailsReadOnlyCoherentSnapshot(t *testing.T) {
	source := clock.NewManual(time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC))
	repository := &authorizationDetailRepository{Repository: iam.NewMemoryRepository(nil), entered: make(chan struct{}), release: make(chan struct{})}
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: source})
	client := clientFor(t, service, "123456789012", "us-east-1")
	createAuthorizationDetailGraph(t, client, source)
	repository.readOnly.Store(true)
	repository.blockUsers.Store(true)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(repository.release) }) }
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		output *sdkiam.GetAccountAuthorizationDetailsOutput
		err    error
	}
	queried := make(chan result, 1)
	go func() {
		output, err := client.GetAccountAuthorizationDetails(ctx, &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters})
		queried <- result{output, err}
	}()
	select {
	case <-repository.entered:
	case result := <-queried:
		t.Fatalf("query did not read graph transaction: %v", result.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	started, changed := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		changed <- repository.Repository.Update(ctx, func(tx iam.WriteTx) error {
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			user, err := tx.User(scope, "GraphUser")
			if err != nil {
				return err
			}
			group, err := tx.Group(scope, "GraphGroup")
			if err != nil {
				return err
			}
			user.Inline["UserInline"], group.Inline["GroupInline"] = denyRead, allowRead
			if err := tx.PutUser(scope, user); err != nil {
				return err
			}
			return tx.PutGroup(scope, group)
		})
	}()
	<-started
	release()
	first := <-queried
	if first.err != nil {
		t.Fatal(first.err)
	}
	assertDetailInline(t, first.output.UserDetailList[0].UserPolicyList, "UserInline", allowRead)
	assertDetailInline(t, first.output.GroupDetailList[0].GroupPolicyList, "GroupInline", denyRead)
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
	second, err := client.GetAccountAuthorizationDetails(ctx, &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters})
	if err != nil {
		t.Fatal(err)
	}
	assertDetailInline(t, second.UserDetailList[0].UserPolicyList, "UserInline", denyRead)
	assertDetailInline(t, second.GroupDetailList[0].GroupPolicyList, "GroupInline", allowRead)
	if writes := repository.writes.Load(); writes != 0 {
		t.Fatalf("report attempted %d resource/quota writes", writes)
	}
	// Mutating decoded output must not mutate a later report or stored policy.
	second.UserDetailList[0].Tags[0].Value = aws.String("changed by client")
	second.Policies[0].PolicyVersionList[0].Document = aws.String("invalid")
	third, err := client.GetAccountAuthorizationDetails(ctx, &sdkiam.GetAccountAuthorizationDetailsInput{Filter: authorizationDetailLocalFilters})
	if err != nil {
		t.Fatal(err)
	}
	assertDetailTags(t, third.UserDetailList[0].Tags)
	for _, policy := range third.Policies {
		for _, version := range policy.PolicyVersionList {
			if aws.ToString(version.Document) == "invalid" {
				t.Fatal("mutated SDK response escaped into stored policy")
			}
		}
	}
}

func TestAccountAuthorizationDetailsBoundTrustUsesCurrentPrincipal(t *testing.T) {
	service := iam.New()
	client := clientFor(t, service, "123456789012", "us-east-1")
	principal, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("Original"), Path: aws.String("/before/")})
	if err != nil {
		t.Fatal(err)
	}
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + aws.ToString(principal.User.Arn) + `"},"Action":"sts:AssumeRole"}]}`
	if _, err := client.CreateRole(t.Context(), &sdkiam.CreateRoleInput{RoleName: aws.String("BoundTrust"), AssumeRolePolicyDocument: aws.String(trust)}); err != nil {
		t.Fatal(err)
	}
	assertPrincipal := func(want string) {
		t.Helper()
		out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeRole}})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.RoleDetailList) != 1 {
			t.Fatalf("roles=%+v", out.RoleDetailList)
		}
		document, err := url.QueryUnescape(aws.ToString(out.RoleDetailList[0].AssumeRolePolicyDocument))
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Statement []struct {
				Principal struct{ AWS string }
			}
		}
		if err := json.Unmarshal([]byte(document), &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Statement) != 1 || decoded.Statement[0].Principal.AWS != want {
			t.Fatalf("current bound principal=%s; want %s", document, want)
		}
	}
	assertPrincipal(aws.ToString(principal.User.Arn))
	if _, err := client.UpdateUser(t.Context(), &sdkiam.UpdateUserInput{UserName: principal.User.UserName, NewUserName: aws.String("Renamed"), NewPath: aws.String("/after/")}); err != nil {
		t.Fatal(err)
	}
	assertPrincipal("arn:aws:iam::123456789012:user/after/Renamed")
	if _, err := client.DeleteUser(t.Context(), &sdkiam.DeleteUserInput{UserName: aws.String("Renamed")}); err != nil {
		t.Fatal(err)
	}
	assertPrincipal(aws.ToString(principal.User.UserId))
	recreated, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("Renamed"), Path: aws.String("/after/")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(recreated.User.UserId) == aws.ToString(principal.User.UserId) {
		t.Fatal("recreated user unexpectedly retained its old identity")
	}
	assertPrincipal(aws.ToString(principal.User.UserId))
}

func TestAccountAuthorizationDetailsDanglingAttachmentHasNoPartialResponse(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	service := iam.NewWithRepository(nil, repository)
	client := clientFor(t, service, "123456789012", "us-east-1")
	for _, name := range []string{"AValid", "ZBroken"} {
		if _, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
		scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
		user, err := tx.User(scope, "ZBroken")
		if err != nil {
			return err
		}
		user.Attached["arn:aws:iam::123456789012:policy/Unavailable"] = struct{}{}
		return tx.PutUser(scope, user)
	}); err != nil {
		t.Fatal(err)
	}
	out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeUser}})
	requireCode(t, err, "ServiceFailure")
	var typed *types.ServiceFailureException
	if !errors.As(err, &typed) || out != nil {
		t.Fatalf("missing modeled failure or partial SDK result: %+v %v", out, err)
	}
	// Inspect the actual error body as well: an SDK decoder can discard fields
	// from an invalid partial response, so a nil SDK output alone is insufficient.
	response, err := http.PostForm(aws.ToString(client.Options().BaseEndpoint), url.Values{"Action": {"GetAccountAuthorizationDetails"}, "Version": {"2010-05-08"}, "Filter.member.1": {"User"}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusInternalServerError || !strings.Contains(string(body), "<Code>ServiceFailure</Code>") || strings.Contains(string(body), "AValid") || strings.Contains(string(body), "UserDetailList") {
		t.Fatalf("partial account report escaped before failure: %s", body)
	}
}

func TestAccountAuthorizationDetailsNumericVersionOrder(t *testing.T) {
	repository := iam.NewMemoryRepository(nil)
	client := clientFor(t, iam.NewWithRepository(nil, repository), "123456789012", "us-east-1")
	arn := mustCreatePolicy(t, client, "ManyRevisions")
	if err := repository.Update(t.Context(), func(tx iam.WriteTx) error {
		scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
		policy, err := tx.ManagedPolicy(scope, arn)
		if err != nil {
			return err
		}
		policy.DefaultVersionId, policy.NextVersion = "v8", 101
		policy.Versions = make(map[string]*iam.PolicyVersion)
		for _, id := range []string{"v8", "v9", "v10", "v99", "v100"} {
			policy.Versions[id] = &iam.PolicyVersion{VersionId: id, Document: allowRead, CreateDate: policy.CreateDate, IsDefaultVersion: id == "v8"}
		}
		return tx.PutManagedPolicy(scope, policy)
	}); err != nil {
		t.Fatal(err)
	}
	out, err := client.GetAccountAuthorizationDetails(t.Context(), &sdkiam.GetAccountAuthorizationDetailsInput{Filter: []types.EntityType{types.EntityTypeLocalManagedPolicy}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Policies) != 1 {
		t.Fatalf("policies=%+v", out.Policies)
	}
	var ids []string
	for _, version := range out.Policies[0].PolicyVersionList {
		ids = append(ids, aws.ToString(version.VersionId))
		if version.IsDefaultVersion != (aws.ToString(version.VersionId) == "v8") {
			t.Fatalf("ordering changed default version: %+v", version)
		}
	}
	if !slices.Equal(ids, []string{"v100", "v99", "v10", "v9", "v8"}) {
		t.Fatalf("retained versions are not in numeric descending order: %v", ids)
	}
}

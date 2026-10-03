package iam_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

const allowRead = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/*"}]}`
const denyRead = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`
const trustEC2 = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

func clientFor(t *testing.T, s *iam.Service, account, region string) *sdkiam.Client {
	t.Helper()
	return clientForPartition(t, s, account, region, "aws")
}

func clientForPartition(t *testing.T, s *iam.Service, account, region, partition string) *sdkiam.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := awsctx.Metadata{AccountID: account, Region: region, Partition: partition, AccessKeyID: "test", RequestID: "iam-sdk-test", PrincipalARN: "arn:" + partition + ":iam::" + account + ":root", PrincipalID: account}
		s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), m)))
	}))
	t.Cleanup(server.Close)
	return sdkiam.New(sdkiam.Options{Region: region, BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
}

func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	if want == "Success" {
		if err != nil {
			t.Fatalf("error = %v; want success", err)
		}
		return
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != want {
		t.Fatalf("error = %v; want AWS %s", err, want)
	}
}

func mustCreatePolicy(t *testing.T, c *sdkiam.Client, name string) string {
	t.Helper()
	out, err := c.CreatePolicy(context.Background(), &sdkiam.CreatePolicyInput{PolicyName: aws.String(name), PolicyDocument: aws.String(allowRead), Path: aws.String("/app/")})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(out.Policy.Arn)
}

func TestUserGroupPolicyLifecycle(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	u, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("Alice"), Path: aws.String("/engineers/"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("platform")}}})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(u.User.Arn) != "arn:aws:iam::123456789012:user/engineers/Alice" || u.User.CreateDate == nil || len(aws.ToString(u.User.UserId)) != 21 {
		t.Fatalf("bad user: %+v", u.User)
	}
	_, err = c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("alice")})
	requireCode(t, err, "EntityAlreadyExists")
	var duplicate *types.EntityAlreadyExistsException
	if !errors.As(err, &duplicate) {
		t.Fatalf("SDK did not decode typed IAM error: %v", err)
	}
	_, err = c.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: aws.String("Developers")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AddUserToGroup(ctx, &sdkiam.AddUserToGroupInput{UserName: aws.String("alice"), GroupName: aws.String("developers")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("Alice")})
	requireCode(t, err, "DeleteConflict")
	_, err = c.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: aws.String("Alice"), NewUserName: aws.String("Alicia"), NewPath: aws.String("/staff/")})
	if err != nil {
		t.Fatal(err)
	}
	g, err := c.GetGroup(ctx, &sdkiam.GetGroupInput{GroupName: aws.String("Developers")})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Users) != 1 || aws.ToString(g.Users[0].UserName) != "Alicia" || aws.ToString(g.Users[0].Arn) != "arn:aws:iam::123456789012:user/staff/Alicia" {
		t.Fatalf("membership was not preserved: %+v", g)
	}
	_, err = c.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: aws.String("Alicia"), PolicyName: aws.String("Read"), PolicyDocument: aws.String(allowRead)})
	if err != nil {
		t.Fatal(err)
	}
	inline, err := c.GetUserPolicy(ctx, &sdkiam.GetUserPolicyInput{UserName: aws.String("Alicia"), PolicyName: aws.String("Read")})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := url.QueryUnescape(aws.ToString(inline.PolicyDocument))
	if err != nil || decoded != allowRead {
		t.Fatalf("policy document = %q, %v", decoded, err)
	}
	arn := mustCreatePolicy(t, c, "ReadObjects")
	for range 2 {
		_, err = c.AttachGroupPolicy(ctx, &sdkiam.AttachGroupPolicyInput{GroupName: aws.String("Developers"), PolicyArn: aws.String(arn)})
		if err != nil {
			t.Fatal(err)
		}
	}
	p, err := c.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil || aws.ToInt32(p.Policy.AttachmentCount) != 1 {
		t.Fatalf("idempotent attachment count: %+v, %v", p, err)
	}
	entities, err := c.ListEntitiesForPolicy(ctx, &sdkiam.ListEntitiesForPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil || len(entities.PolicyGroups) != 1 || aws.ToString(entities.PolicyGroups[0].GroupName) != "Developers" {
		t.Fatalf("entities: %+v, %v", entities, err)
	}
	_, err = c.DeletePolicy(ctx, &sdkiam.DeletePolicyInput{PolicyArn: aws.String(arn)})
	requireCode(t, err, "DeleteConflict")
	_, err = c.DetachGroupPolicy(ctx, &sdkiam.DetachGroupPolicyInput{GroupName: aws.String("Developers"), PolicyArn: aws.String(arn)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DeletePolicy(ctx, &sdkiam.DeletePolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.RemoveUserFromGroup(ctx, &sdkiam.RemoveUserFromGroupInput{UserName: aws.String("Alicia"), GroupName: aws.String("Developers")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("Alicia")})
	requireCode(t, err, "DeleteConflict")
	_, err = c.DeleteUserPolicy(ctx, &sdkiam.DeleteUserPolicyInput{UserName: aws.String("Alicia"), PolicyName: aws.String("Read")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("Alicia")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DeleteGroup(ctx, &sdkiam.DeleteGroupInput{GroupName: aws.String("Developers")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetUser(ctx, &sdkiam.GetUserInput{UserName: aws.String("Alicia")})
	requireCode(t, err, "NoSuchEntity")
}

func TestPolicyVersionLifecycle(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	arn := mustCreatePolicy(t, c, "Versioned")
	for i := 2; i <= 5; i++ {
		out, err := c.CreatePolicyVersion(ctx, &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(arn), PolicyDocument: aws.String(denyRead), SetAsDefault: i == 5})
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToString(out.PolicyVersion.VersionId) != fmt.Sprintf("v%d", i) || out.PolicyVersion.Document != nil {
			t.Fatalf("version metadata: %+v", out.PolicyVersion)
		}
	}
	_, err := c.CreatePolicyVersion(ctx, &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(arn), PolicyDocument: aws.String(allowRead)})
	requireCode(t, err, "LimitExceeded")
	_, err = c.DeletePolicyVersion(ctx, &sdkiam.DeletePolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String("v5")})
	requireCode(t, err, "DeleteConflict")
	_, err = c.DeletePolicyVersion(ctx, &sdkiam.DeletePolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String("v2")})
	if err != nil {
		t.Fatal(err)
	}
	v6, err := c.CreatePolicyVersion(ctx, &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(arn), PolicyDocument: aws.String(allowRead)})
	if err != nil || aws.ToString(v6.PolicyVersion.VersionId) != "v6" {
		t.Fatalf("version IDs reused: %+v, %v", v6, err)
	}
	version, err := c.GetPolicyVersion(ctx, &sdkiam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String("v5")})
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := url.QueryUnescape(aws.ToString(version.PolicyVersion.Document))
	if !version.PolicyVersion.IsDefaultVersion || decoded != denyRead {
		t.Fatalf("default document: %+v", version)
	}
	_, err = c.SetDefaultPolicyVersion(ctx, &sdkiam.SetDefaultPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String("v1")})
	if err != nil {
		t.Fatal(err)
	}
	pager := sdkiam.NewListPolicyVersionsPaginator(c, &sdkiam.ListPolicyVersionsInput{PolicyArn: aws.String(arn), MaxItems: aws.Int32(2)})
	var versions []string
	for pager.HasMorePages() {
		out, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range out.Versions {
			if v.Document != nil {
				t.Fatal("ListPolicyVersions exposed a document")
			}
			versions = append(versions, aws.ToString(v.VersionId))
		}
	}
	if !slices.Equal(versions, []string{"v1", "v3", "v4", "v5", "v6"}) {
		t.Fatalf("versions = %v", versions)
	}
	_, err = c.DeletePolicy(ctx, &sdkiam.DeletePolicyInput{PolicyArn: aws.String(arn)})
	requireCode(t, err, "DeleteConflict")
	for _, id := range versions[1:] {
		_, err = c.DeletePolicyVersion(ctx, &sdkiam.DeletePolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String(id)})
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = c.DeletePolicy(ctx, &sdkiam.DeletePolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRolesTagsBoundariesAndAtomicValidation(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	arn := mustCreatePolicy(t, c, "Boundary")
	_, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("Compute"), AssumeRolePolicyDocument: aws.String(trustEC2), PermissionsBoundary: aws.String(arn), MaxSessionDuration: aws.Int32(7200), Tags: []types.Tag{{Key: aws.String("owner"), Value: aws.String("one")}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.UpdateRole(ctx, &sdkiam.UpdateRoleInput{RoleName: aws.String("Compute"), Description: aws.String("must not persist"), MaxSessionDuration: aws.Int32(100)})
	requireCode(t, err, "ParamValidation")
	r, err := c.GetRole(ctx, &sdkiam.GetRoleInput{RoleName: aws.String("Compute")})
	if err != nil || aws.ToString(r.Role.Description) != "" || aws.ToInt32(r.Role.MaxSessionDuration) != 7200 || r.Role.PermissionsBoundary == nil {
		t.Fatalf("role after invalid update: %+v, %v", r, err)
	}
	decoded, _ := url.QueryUnescape(aws.ToString(r.Role.AssumeRolePolicyDocument))
	if decoded != trustEC2 {
		t.Fatalf("trust document = %s", decoded)
	}
	_, err = c.TagRole(ctx, &sdkiam.TagRoleInput{RoleName: aws.String("Compute"), Tags: []types.Tag{{Key: aws.String("owner"), Value: aws.String("two")}, {Key: aws.String("environment"), Value: aws.String("dev")}}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := c.ListRoleTags(ctx, &sdkiam.ListRoleTagsInput{RoleName: aws.String("Compute"), MaxItems: aws.Int32(1)})
	if err != nil || !tags.IsTruncated || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Key) != "environment" {
		t.Fatalf("tag page: %+v, %v", tags, err)
	}
	_, err = c.TagRole(ctx, &sdkiam.TagRoleInput{RoleName: aws.String("Compute"), Tags: []types.Tag{{Key: aws.String("owner"), Value: aws.String("bad")}, {Key: aws.String("owner"), Value: aws.String("duplicate")}}})
	requireCode(t, err, "InvalidInput")
	_, err = c.UntagRole(ctx, &sdkiam.UntagRoleInput{RoleName: aws.String("Compute"), TagKeys: []string{"environment"}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err = c.ListRoleTags(ctx, &sdkiam.ListRoleTagsInput{RoleName: aws.String("Compute")})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Value) != "two" {
		t.Fatalf("invalid tags changed resource: %+v, %v", tags, err)
	}
	p, err := c.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil || aws.ToInt32(p.Policy.PermissionsBoundaryUsageCount) != 1 {
		t.Fatalf("boundary count: %+v, %v", p, err)
	}
	_, err = c.DeletePolicy(ctx, &sdkiam.DeletePolicyInput{PolicyArn: aws.String(arn)})
	requireCode(t, err, "DeleteConflict")
	_, err = c.DeleteRole(ctx, &sdkiam.DeleteRoleInput{RoleName: aws.String("Compute")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DeletePolicy(ctx, &sdkiam.DeletePolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPaginationScopeAndConcurrentGlobalState(t *testing.T) {
	s := iam.New()
	c := clientFor(t, s, "123456789012", "us-east-1")
	otherRegion := clientFor(t, s, "123456789012", "eu-west-1")
	otherAccount := clientFor(t, s, "999999999999", "us-east-1")
	otherPartition := clientForPartition(t, s, "123456789012", "cn-north-1", "aws-cn")
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := range 12 {
		wg.Go(func() {
			_, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String(fmt.Sprintf("user%02d", i)), Path: aws.String("/app/")})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	pager := sdkiam.NewListUsersPaginator(otherRegion, &sdkiam.ListUsersInput{PathPrefix: aws.String("/app/"), MaxItems: aws.Int32(5)})
	var names []string
	for pager.HasMorePages() {
		out, err := pager.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range out.Users {
			names = append(names, aws.ToString(u.UserName))
		}
	}
	if len(names) != 12 || !slices.IsSorted(names) {
		t.Fatalf("cross-region pages: %v", names)
	}
	empty, err := otherAccount.ListUsers(ctx, &sdkiam.ListUsersInput{})
	if err != nil || len(empty.Users) != 0 {
		t.Fatalf("account state leaked: %+v, %v", empty, err)
	}
	first, err := c.ListUsers(ctx, &sdkiam.ListUsersInput{MaxItems: aws.Int32(1)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = otherAccount.ListUsers(ctx, &sdkiam.ListUsersInput{Marker: first.Marker})
	requireCode(t, err, "InvalidInput")
	_, err = otherPartition.ListUsers(ctx, &sdkiam.ListUsersInput{Marker: first.Marker})
	requireCode(t, err, "InvalidInput")
	continued, err := otherRegion.ListUsers(ctx, &sdkiam.ListUsersInput{Marker: first.Marker})
	if err != nil || len(continued.Users) != 11 {
		t.Fatalf("cross-region marker continuation: %+v, %v", continued, err)
	}
	_, err = c.ListUsers(ctx, &sdkiam.ListUsersInput{Marker: first.Marker, PathPrefix: aws.String("/different/")})
	requireCode(t, err, "InvalidInput")
	_, err = c.ListUsers(ctx, &sdkiam.ListUsersInput{Marker: aws.String("invalid")})
	requireCode(t, err, "InvalidInput")
}

func TestPolicyStorageValidation(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	for _, doc := range []string{
		`{}`, `null`, `{"Statement":{"Effect":"Allow","Action":"s3:*"}}`, trustEC2,
		`{"Statement":{"Effect":"Allow","Action":"*","NotAction":"s3:*","Resource":"*"}}`,
		`{"statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Effect":"Deny","Action":"*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Invalid":true}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Unknown":{"aws:username":"Alice"}}}}`,
		`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:username":{}}}}}`,
	} {
		_, err := c.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("Invalid"), PolicyDocument: aws.String(doc)})
		requireCode(t, err, "MalformedPolicyDocument")
	}
	_, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("InvalidRole"), AssumeRolePolicyDocument: aws.String(allowRead)})
	requireCode(t, err, "MalformedPolicyDocument")
	variable := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/${aws:username}/*"}}`
	_, err = c.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("PolicyVariables"), PolicyDocument: aws.String(variable)})
	if err != nil {
		t.Fatalf("storage rejected valid policy variables: %v", err)
	}
}

func TestIAMTagKeyCaseRules(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	_, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("Tagged"), Tags: []types.Tag{{Key: aws.String("Department"), Value: aws.String("finance")}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.TagUser(ctx, &sdkiam.TagUserInput{UserName: aws.String("Tagged"), Tags: []types.Tag{{Key: aws.String("department"), Value: aws.String("hr")}}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := c.ListUserTags(ctx, &sdkiam.ListUserTagsInput{UserName: aws.String("Tagged")})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Key) != "department" || aws.ToString(tags.Tags[0].Value) != "hr" {
		t.Fatalf("user tag case replacement: %+v, %v", tags, err)
	}
	_, err = c.UntagUser(ctx, &sdkiam.UntagUserInput{UserName: aws.String("Tagged"), TagKeys: []string{"DEPARTMENT"}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err = c.ListUserTags(ctx, &sdkiam.ListUserTagsInput{UserName: aws.String("Tagged")})
	if err != nil || len(tags.Tags) != 0 {
		t.Fatalf("case-insensitive untag: %+v, %v", tags, err)
	}
	_, err = c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("InvalidTags"), Tags: []types.Tag{{Key: aws.String("Department"), Value: aws.String("finance")}, {Key: aws.String("department"), Value: aws.String("hr")}}})
	requireCode(t, err, "InvalidInput")
	arn := mustCreatePolicy(t, c, "CaseSensitiveTags")
	_, err = c.TagPolicy(ctx, &sdkiam.TagPolicyInput{PolicyArn: aws.String(arn), Tags: []types.Tag{{Key: aws.String("Department"), Value: aws.String("finance")}, {Key: aws.String("department"), Value: aws.String("hr")}}})
	if err != nil {
		t.Fatal(err)
	}
	policyTags, err := c.ListPolicyTags(ctx, &sdkiam.ListPolicyTagsInput{PolicyArn: aws.String(arn)})
	if err != nil || len(policyTags.Tags) != 2 {
		t.Fatalf("case-sensitive policy tags: %+v, %v", policyTags, err)
	}
}

func TestPolicyCharacterQuotas(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	_, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("Quota")})
	if err != nil {
		t.Fatal(err)
	}
	large := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/` + strings.Repeat("a", 1200) + `"}}`
	_, err = c.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: aws.String("Quota"), PolicyName: aws.String("First"), PolicyDocument: aws.String(large)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: aws.String("Quota"), PolicyName: aws.String("Second"), PolicyDocument: aws.String(large)})
	requireCode(t, err, "LimitExceeded")
	_, err = c.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: aws.String("Quota"), PolicyName: aws.String("First"), PolicyDocument: aws.String(large)})
	if err != nil {
		t.Fatalf("replacement counted existing document twice: %v", err)
	}
	_, err = c.GetUserPolicy(ctx, &sdkiam.GetUserPolicyInput{UserName: aws.String("Quota"), PolicyName: aws.String("Second")})
	requireCode(t, err, "NoSuchEntity")
	oversize := strings.Replace(large, strings.Repeat("a", 1200), strings.Repeat("a", 6200), 1)
	_, err = c.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("TooLarge"), PolicyDocument: aws.String(oversize)})
	requireCode(t, err, "LimitExceeded")
	whitespace := strings.Replace(allowRead, "\"Statement\"", strings.Repeat(" ", 7000)+"\"Statement\"", 1)
	_, err = c.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("Whitespace"), PolicyDocument: aws.String(whitespace)})
	if err != nil {
		t.Fatalf("insignificant whitespace counted toward policy quota: %v", err)
	}
}

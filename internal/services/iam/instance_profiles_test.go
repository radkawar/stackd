package iam_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

func TestInstanceProfileLifecycle(t *testing.T) {
	service := iam.New()
	c := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	created, err := c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("Web"), Path: aws.String("/apps/"), Tags: []types.Tag{{Key: aws.String("Team"), Value: aws.String("one")}, {Key: aws.String("team"), Value: aws.String("two")}}})
	if err != nil {
		t.Fatal(err)
	}
	p := created.InstanceProfile
	if aws.ToString(p.Arn) != "arn:aws:iam::123456789012:instance-profile/apps/Web" || !strings.HasPrefix(aws.ToString(p.InstanceProfileId), "AIPA") || len(aws.ToString(p.InstanceProfileId)) != 21 || p.CreateDate == nil || len(p.Roles) != 0 || len(p.Tags) != 2 {
		t.Fatalf("CreateInstanceProfile = %+v", p)
	}
	_, err = c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("web"), Path: aws.String("/different/")})
	var exists *types.EntityAlreadyExistsException
	if !errors.As(err, &exists) {
		t.Fatalf("duplicate case error = %v", err)
	}
	role, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("Compute"), Path: aws.String("/roles/"), AssumeRolePolicyDocument: aws.String(trustEC2)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String("WEB"), RoleName: aws.String("compute")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String("Web"), RoleName: aws.String("Compute")})
	requireCode(t, err, "LimitExceeded")
	if _, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("Other"), AssumeRolePolicyDocument: aws.String(trustEC2)}); err != nil {
		t.Fatal(err)
	}
	_, err = c.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String("Web"), RoleName: aws.String("Other")})
	var quota *types.LimitExceededException
	if !errors.As(err, &quota) {
		t.Fatalf("second role error = %v", err)
	}
	_, err = c.RemoveRoleFromInstanceProfile(ctx, &sdkiam.RemoveRoleFromInstanceProfileInput{InstanceProfileName: aws.String("Web"), RoleName: aws.String("Other")})
	requireCode(t, err, "NoSuchEntity")
	_, err = c.DeleteInstanceProfile(ctx, &sdkiam.DeleteInstanceProfileInput{InstanceProfileName: aws.String("Web")})
	var conflict *types.DeleteConflictException
	if !errors.As(err, &conflict) {
		t.Fatalf("delete populated profile = %v", err)
	}
	_, err = c.DeleteRole(ctx, &sdkiam.DeleteRoleInput{RoleName: aws.String("Compute")})
	requireCode(t, err, "DeleteConflict")
	updatedTrust := `{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"updated"}}}}`
	if _, err := c.UpdateAssumeRolePolicy(ctx, &sdkiam.UpdateAssumeRolePolicyInput{RoleName: aws.String("Compute"), PolicyDocument: aws.String(updatedTrust)}); err != nil {
		t.Fatal(err)
	}
	got, err := clientFor(t, service, "123456789012", "eu-west-2").GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String("web")})
	if err != nil || len(got.InstanceProfile.Roles) != 1 {
		t.Fatalf("GetInstanceProfile = %+v, %v", got, err)
	}
	wireRole := got.InstanceProfile.Roles[0]
	document, err := url.QueryUnescape(aws.ToString(wireRole.AssumeRolePolicyDocument))
	if err != nil || document != updatedTrust || aws.ToString(wireRole.RoleId) != aws.ToString(role.Role.RoleId) || aws.ToString(wireRole.Arn) != aws.ToString(role.Role.Arn) {
		t.Fatalf("profile did not read current role: %+v, %v", wireRole, err)
	}
	snapshot, err := service.InstanceProfileForUse(authRootContext("aws"), aws.ToString(p.Arn))
	if err != nil || snapshot.RoleARN != aws.ToString(role.Role.Arn) || snapshot.RoleID != aws.ToString(role.Role.RoleId) || snapshot.ID != aws.ToString(p.InstanceProfileId) {
		t.Fatalf("compute provider snapshot = %+v, %v", snapshot, err)
	}
	if _, err := service.InstanceProfileForUse(authRootContext("aws-cn"), aws.ToString(p.Arn)); err == nil {
		t.Fatal("snapshot accepted profile ARN in another partition")
	}
	if _, err := service.InstanceProfileForUse(authRootContext("aws"), strings.Replace(aws.ToString(p.Arn), "/apps/", "/wrong/", 1)); err == nil {
		t.Fatal("snapshot accepted incorrect profile path")
	}
	_, err = clientFor(t, service, "999999999999", "us-east-1").GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String("Web")})
	requireCode(t, err, "NoSuchEntity")
	for _, name := range []string{"A", "Z"} {
		if _, err := c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String(name), Path: aws.String("/apps/")}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: aws.String("Compute")}); err != nil {
			t.Fatal(err)
		}
	}
	byRole, err := c.ListInstanceProfilesForRole(ctx, &sdkiam.ListInstanceProfilesForRoleInput{RoleName: aws.String("compute"), MaxItems: aws.Int32(1)})
	if err != nil || !byRole.IsTruncated || len(byRole.InstanceProfiles) != 1 || aws.ToString(byRole.InstanceProfiles[0].InstanceProfileName) != "A" {
		t.Fatalf("ListInstanceProfilesForRole = %+v, %v", byRole, err)
	}
	more, err := c.ListInstanceProfilesForRole(ctx, &sdkiam.ListInstanceProfilesForRoleInput{RoleName: aws.String("Compute"), Marker: byRole.Marker})
	if err != nil || more.IsTruncated || len(more.InstanceProfiles) != 2 {
		t.Fatalf("continued profiles for role = %+v, %v", more, err)
	}
	list, err := c.ListInstanceProfiles(ctx, &sdkiam.ListInstanceProfilesInput{PathPrefix: aws.String("/app"), MaxItems: aws.Int32(2)})
	if err != nil || len(list.InstanceProfiles) != 2 || !list.IsTruncated || len(list.InstanceProfiles[1].Tags) != 0 {
		t.Fatalf("ListInstanceProfiles = %+v, %v", list, err)
	}
	_, err = c.ListInstanceProfiles(ctx, &sdkiam.ListInstanceProfilesInput{PathPrefix: aws.String("/different"), Marker: list.Marker})
	requireCode(t, err, "InvalidInput")
	for _, name := range []string{"A", "Web", "Z"} {
		if _, err := c.RemoveRoleFromInstanceProfile(ctx, &sdkiam.RemoveRoleFromInstanceProfileInput{InstanceProfileName: aws.String(name), RoleName: aws.String("Compute")}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.DeleteInstanceProfile(ctx, &sdkiam.DeleteInstanceProfileInput{InstanceProfileName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.DeleteRole(ctx, &sdkiam.DeleteRoleInput{RoleName: aws.String("Compute")}); err != nil {
		t.Fatal(err)
	}
	_, err = c.GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String("Web")})
	var missing *types.NoSuchEntityException
	if !errors.As(err, &missing) {
		t.Fatalf("missing profile = %v", err)
	}
}

func TestInstanceProfileTagsAndValidation(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	for _, input := range []sdkiam.CreateInstanceProfileInput{
		{InstanceProfileName: aws.String("bad/name")},
		{InstanceProfileName: aws.String(strings.Repeat("a", 129))},
		{InstanceProfileName: aws.String("BadPath"), Path: aws.String("/missing-end")},
	} {
		_, err := c.CreateInstanceProfile(ctx, &input)
		requireCode(t, err, "ValidationError")
	}
	tags := make([]types.Tag, 50)
	for i := range tags {
		tags[i] = types.Tag{Key: aws.String(fmt.Sprintf("tag%02d", i)), Value: aws.String("value")}
	}
	if _, err := c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), Tags: tags}); err != nil {
		t.Fatal(err)
	}
	_, err := c.TagInstanceProfile(ctx, &sdkiam.TagInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), Tags: []types.Tag{{Key: aws.String("extra"), Value: aws.String("value")}, {Key: aws.String("tag00"), Value: aws.String("changed")}}})
	requireCode(t, err, "LimitExceeded")
	page, err := c.ListInstanceProfileTags(ctx, &sdkiam.ListInstanceProfileTagsInput{InstanceProfileName: aws.String("TAGGED"), MaxItems: aws.Int32(1)})
	if err != nil || len(page.Tags) != 1 || aws.ToString(page.Tags[0].Value) != "value" || !page.IsTruncated {
		t.Fatalf("failed tag mutation was not atomic: %+v, %v", page, err)
	}
	more, err := c.ListInstanceProfileTags(ctx, &sdkiam.ListInstanceProfileTagsInput{InstanceProfileName: aws.String("Tagged"), Marker: page.Marker})
	if err != nil || len(more.Tags) != 49 || more.IsTruncated {
		t.Fatalf("tag pagination = %+v, %v", more, err)
	}
	if _, err := c.UntagInstanceProfile(ctx, &sdkiam.UntagInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), TagKeys: []string{"tag00", "absent"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.TagInstanceProfile(ctx, &sdkiam.TagInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), Tags: []types.Tag{{Key: aws.String("tag00"), Value: aws.String("")}}}); err != nil {
		t.Fatal(err)
	}
	_, err = c.TagInstanceProfile(ctx, &sdkiam.TagInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), Tags: []types.Tag{{Key: aws.String("tag00"), Value: aws.String("first")}, {Key: aws.String("tag00"), Value: aws.String("second")}}})
	requireCode(t, err, "InvalidInput")
	_, err = c.TagInstanceProfile(ctx, &sdkiam.TagInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), Tags: []types.Tag{{Key: aws.String("aws:reserved"), Value: aws.String("value")}}})
	requireCode(t, err, "InvalidInput")
	_, err = c.TagInstanceProfile(ctx, &sdkiam.TagInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), Tags: []types.Tag{}})
	requireCode(t, err, "InvalidInput")
	if _, err := c.UntagInstanceProfile(ctx, &sdkiam.UntagInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), TagKeys: []string{}}); err != nil {
		t.Fatalf("empty untag should succeed: %v", err)
	}
	if _, err := c.TagInstanceProfile(ctx, &sdkiam.TagInstanceProfileInput{InstanceProfileName: aws.String("Tagged"), Tags: []types.Tag{{Key: aws.String("tag00"), Value: aws.String("aws:value")}}}); err != nil {
		t.Fatalf("reserved prefix in tag value should succeed: %v", err)
	}
}

func TestInstanceProfileConcurrentMembership(t *testing.T) {
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	if _, err := c.CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String("Race")}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"One", "Two"} {
		if _, err := c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String(name), AssumeRolePolicyDocument: aws.String(trustEC2)}); err != nil {
			t.Fatal(err)
		}
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"One", "Two"} {
		wg.Go(func() {
			_, err := c.AddRoleToInstanceProfile(ctx, &sdkiam.AddRoleToInstanceProfileInput{InstanceProfileName: aws.String("Race"), RoleName: aws.String(name)})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	allowed := 0
	for err := range results {
		if err == nil {
			allowed++
		} else {
			requireCode(t, err, "LimitExceeded")
		}
	}
	if allowed != 1 {
		t.Fatalf("concurrent assignments succeeded %d times", allowed)
	}
}

func TestInstanceProfilePartitionAndMarkers(t *testing.T) {
	s := iam.New()
	clients := make(map[string]*sdkiam.Client)
	for _, partition := range []string{"aws", "aws-cn"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := awsctx.Metadata{AccountID: "123456789012", Partition: partition, Region: "us-east-1", PrincipalARN: "arn:" + partition + ":iam::123456789012:root", PrincipalID: "123456789012"}
			s.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), m)))
		}))
		t.Cleanup(server.Close)
		clients[partition] = sdkiam.New(sdkiam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
	}
	ctx := context.Background()
	for _, name := range []string{"First", "Second"} {
		if _, err := clients["aws"].CreateInstanceProfile(ctx, &sdkiam.CreateInstanceProfileInput{InstanceProfileName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := clients["aws-cn"].GetInstanceProfile(ctx, &sdkiam.GetInstanceProfileInput{InstanceProfileName: aws.String("First")})
	requireCode(t, err, "NoSuchEntity")
	list, err := clients["aws"].ListInstanceProfiles(ctx, &sdkiam.ListInstanceProfilesInput{MaxItems: aws.Int32(1)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = clients["aws-cn"].ListInstanceProfiles(ctx, &sdkiam.ListInstanceProfilesInput{Marker: list.Marker})
	requireCode(t, err, "InvalidInput")
}

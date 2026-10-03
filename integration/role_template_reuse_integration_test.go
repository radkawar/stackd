package stackd_test

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestRoleTemplateReuseMutationsAWSReplay(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("111111111111", "test", "")
	fixture := templateFixture(t, "role_acquisition.json")
	name := "OWNED_ROLE-edited"
	power := map[string][]string{"AWSServiceName": {"lambda.amazonaws.com"}}
	check := func(label string) {
		t.Helper()
		out, err := acquireTemplate(t, root, powerRoleTemplate, name, power)
		assertTemplateAcquisition(t, fixture, label, out, err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check("created")
	_, err := root.UpdateRole(t.Context(), &iam.UpdateRoleInput{RoleName: aws.String(name), MaxSessionDuration: aws.Int32(7200)})
	must(err)
	check("duration_changed")
	_, err = root.UpdateRole(t.Context(), &iam.UpdateRoleInput{RoleName: aws.String(name), MaxSessionDuration: aws.Int32(3600)})
	must(err)
	check("duration_restored")
	_, err = root.TagRole(t.Context(), &iam.TagRoleInput{RoleName: aws.String(name), Tags: []types.Tag{{Key: aws.String("Owner"), Value: aws.String("probe")}}})
	must(err)
	check("tags_changed")
	_, err = root.UntagRole(t.Context(), &iam.UntagRoleInput{RoleName: aws.String(name), TagKeys: []string{"Owner"}})
	must(err)
	check("tags_restored")
	out, err := acquireTemplate(t, root, powerRoleTemplate, name, map[string][]string{"AWSServiceName": {"ec2.amazonaws.com"}})
	assertTemplateAcquisition(t, fixture, "different_parameter", out, err)
	check("original_parameter_again")
	_, err = root.AttachRolePolicy(t.Context(), &iam.AttachRolePolicyInput{RoleName: aws.String(name), PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")})
	must(err)
	check("attachment_changed")
	_, err = root.DetachRolePolicy(t.Context(), &iam.DetachRolePolicyInput{RoleName: aws.String(name), PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")})
	must(err)
	check("attachment_restored")
	_, err = root.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: aws.String(name), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
	must(err)
	check("trust_changed")
	_, err = root.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: aws.String(name), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
	must(err)
	check("trust_restored")
	_, err = root.UpdateAssumeRolePolicy(t.Context(), &iam.UpdateAssumeRolePolicyInput{RoleName: aws.String(name), PolicyDocument: aws.String(`{"Statement":{"Action":["sts:AssumeRole"],"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com"]}},"Version":"2012-10-17"}`)})
	must(err)
	check("equivalent_trust_shape")
	out, err = acquireTemplate(t, root, powerRoleTemplate, "OWNED_ROLE-EDITED", power)
	assertTemplateAcquisition(t, fixture, "role_name_case", out, err)
	_, err = root.PutRolePermissionsBoundary(t.Context(), &iam.PutRolePermissionsBoundaryInput{RoleName: aws.String(name), PermissionsBoundary: aws.String("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")})
	must(err)
	check("boundary_added")
	_, err = root.DeleteRolePermissionsBoundary(t.Context(), &iam.DeleteRolePermissionsBoundaryInput{RoleName: aws.String(name)})
	must(err)
	check("boundary_removed")
	state, err := root.GetRole(t.Context(), &iam.GetRoleInput{RoleName: aws.String(name)})
	must(err)
	var expected struct{ Role json.RawMessage }
	must(json.Unmarshal(fixture["source_after_restore"]["result"], &expected))
	assertTemplateJSON(t, state.Role, expected.Role)
	listed, err := root.ListRoles(t.Context(), &iam.ListRolesInput{})
	must(err)
	if state.Role.SourceRoleTemplate == nil || listed.Roles[0].SourceRoleTemplate != nil {
		t.Fatal("template association has incorrect read/list field presence")
	}
	// The list fixture is a role object, rather than an API result wrapper.
	listFixture, err := json.Marshal(fixture["listed_template_role"])
	must(err)
	assertTemplateJSON(t, listed.Roles[0], listFixture)
}

func TestRoleTemplateConcurrentAcquisition(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("111111111111", "test", "")
	var wait sync.WaitGroup
	results := make(chan *iam.AcquireRoleOutput, 8)
	errors := make(chan error, 8)
	for range 8 {
		wait.Go(func() {
			out, err := root.AcquireRole(t.Context(), &iam.AcquireRoleInput{TemplateArn: aws.String(powerRoleTemplate), ReplacementValues: map[string]types.ReplacementValueEntry{"RoleName": {Values: []string{"shared"}}, "AWSServiceName": {Values: []string{"lambda.amazonaws.com"}}}})
			results <- out
			errors <- err
		})
	}
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	id := ""
	for out := range results {
		if id != "" && id != *out.Role.RoleId {
			t.Fatal("concurrent acquisition created different identities")
		}
		id = *out.Role.RoleId
	}
	attached, err := root.ListEntitiesForPolicy(t.Context(), &iam.ListEntitiesForPolicyInput{PolicyArn: aws.String("arn:aws:iam::aws:policy/PowerUserAccess")})
	if err != nil || len(attached.PolicyRoles) != 1 {
		t.Fatalf("attachment count: %+v, %v", attached, err)
	}
}

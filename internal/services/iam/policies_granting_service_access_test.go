package iam_test

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

func grantingServicePolicies(t *testing.T, client *sdkiam.Client, arn string, services ...string) map[string][]types.PolicyGrantingServiceAccess {
	t.Helper()
	output, err := client.ListPoliciesGrantingServiceAccess(t.Context(), &sdkiam.ListPoliciesGrantingServiceAccessInput{Arn: aws.String(arn), ServiceNamespaces: services})
	if err != nil {
		t.Fatal(err)
	}
	if output.IsTruncated || output.Marker != nil {
		t.Fatalf("small policy graph unexpectedly paginated: %+v", output)
	}
	result := make(map[string][]types.PolicyGrantingServiceAccess)
	for _, entry := range output.PoliciesGrantingServiceAccess {
		name := aws.ToString(entry.ServiceNamespace)
		if _, exists := result[name]; exists {
			t.Fatalf("duplicate service %s", name)
		}
		result[name] = entry.Policies
	}
	return result
}

func TestListPoliciesGrantingServiceAccessAuthorization(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	root := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, root)
	auditor, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("ServiceAccessAuditor")})
	if err != nil {
		t.Fatal(err)
	}
	client := clientForIAMPrincipal(t, service, auditor.User)
	input := &sdkiam.ListPoliciesGrantingServiceAccessInput{Arn: graph.user.Arn, ServiceNamespaces: []string{"s3"}}
	output, err := client.ListPoliciesGrantingServiceAccess(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	if output != nil {
		t.Fatal("unauthorized caller received policy sources")
	}
	grant := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"iam:ListPoliciesGrantingServiceAccess","Resource":%q}}`, aws.ToString(graph.user.Arn))
	if _, err := root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: auditor.User.UserName, PolicyName: aws.String("InspectUser"), PolicyDocument: aws.String(grant)}); err != nil {
		t.Fatal(err)
	}
	assertGrantingPolicyNames(t, grantingServicePolicies(t, client, aws.ToString(graph.user.Arn), "s3")["s3"], "UserInline", "UserManaged", "GroupInline", "GroupManaged")
	input.Arn = graph.role.Arn
	_, err = client.ListPoliciesGrantingServiceAccess(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	input.Arn = graph.user.Arn
	boundary := simulationManagedPolicy(t, root, "ServiceAccessAuditorBoundary", simulationPolicy("Allow", "iam:GetUser"))
	if _, err := root.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: auditor.User.UserName, PermissionsBoundary: aws.String(boundary)}); err != nil {
		t.Fatal(err)
	}
	_, err = client.ListPoliciesGrantingServiceAccess(t.Context(), input)
	requireCode(t, err, "AccessDenied")
}

func TestStoredPolicyRejectsWildcardServicePrefixes(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("ServicePatternUser")})
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"Action", "NotAction"} {
		for _, action := range []string{"s3*:Get*", "s?:GetObject"} {
			document := fmt.Sprintf(`{"Statement":{"Effect":"Allow",%q:%q,"Resource":"*"}}`, selector, action)
			_, err := client.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("WildcardService"), PolicyDocument: aws.String(document)})
			requireCode(t, err, "MalformedPolicyDocument")
		}
	}
	for _, action := range []string{"*", "s3:Get*", "s3:StackdUnmodeledAction", "stackdunmodeled:Read"} {
		_, err := client.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("AcceptedAction"), PolicyDocument: aws.String(simulationPolicy("Allow", action))})
		if err != nil {
			t.Fatalf("accepted action %q rejected: %v", action, err)
		}
	}
}

func assertGrantingPolicyNames(t *testing.T, policies []types.PolicyGrantingServiceAccess, expected ...string) {
	t.Helper()
	actual := make([]string, 0, len(policies))
	for _, policy := range policies {
		actual = append(actual, aws.ToString(policy.PolicyName))
	}
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		t.Fatalf("granting policy names=%v; want %v", actual, expected)
	}
}

func TestListPoliciesGrantingServiceAccessCurrentGraph(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, client)
	// The same managed policy reached directly and through a group is one
	// source. A boundary's permissions never contribute to this listing.
	if _, err := client.AttachUserPolicy(t.Context(), &sdkiam.AttachUserPolicyInput{UserName: graph.user.UserName, PolicyArn: aws.String(graph.groupPolicy)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: graph.user.UserName, PermissionsBoundary: aws.String(graph.rolePolicy)}); err != nil {
		t.Fatal(err)
	}
	user := grantingServicePolicies(t, client, aws.ToString(graph.user.Arn), "s3", "ec2")
	assertGrantingPolicyNames(t, user["s3"], "UserInline", "UserManaged", "GroupInline", "GroupManaged")
	assertGrantingPolicyNames(t, user["ec2"])
	for _, entry := range user["s3"] {
		if entry.PolicyType == types.PolicyTypeManaged {
			if entry.PolicyArn == nil || entry.EntityName != nil || entry.EntityType != "" {
				t.Fatalf("managed source attribution=%+v", entry)
			}
			continue
		}
		kind, name := types.PolicyOwnerEntityTypeUser, aws.ToString(graph.user.UserName)
		if aws.ToString(entry.PolicyName) == "GroupInline" {
			kind, name = types.PolicyOwnerEntityTypeGroup, aws.ToString(graph.group.GroupName)
		}
		if entry.PolicyType != types.PolicyTypeInline || entry.PolicyArn != nil || entry.EntityType != kind || aws.ToString(entry.EntityName) != name {
			t.Fatalf("inline source attribution=%+v", entry)
		}
	}
	group := grantingServicePolicies(t, client, aws.ToString(graph.group.Arn), "s3", "ec2")
	assertGrantingPolicyNames(t, group["s3"], "GroupInline", "GroupManaged")
	assertGrantingPolicyNames(t, group["ec2"])
	role := grantingServicePolicies(t, client, aws.ToString(graph.role.Arn), "s3", "ec2")
	assertGrantingPolicyNames(t, role["s3"])
	assertGrantingPolicyNames(t, role["ec2"], "RoleInline", "RoleManaged")

	if _, err := client.CreatePolicyVersion(t.Context(), &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(graph.userPolicy), PolicyDocument: aws.String(simulationPolicy("Allow", "sqs:SendMessage")), SetAsDefault: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RemoveUserFromGroup(t.Context(), &sdkiam.RemoveUserFromGroupInput{UserName: graph.user.UserName, GroupName: graph.group.GroupName}); err != nil {
		t.Fatal(err)
	}
	updated := grantingServicePolicies(t, client, aws.ToString(graph.user.Arn), "s3", "sqs")
	assertGrantingPolicyNames(t, updated["s3"], "UserInline", "GroupManaged")
	assertGrantingPolicyNames(t, updated["sqs"], "UserManaged")

	if _, err := client.UpdateUser(t.Context(), &sdkiam.UpdateUserInput{UserName: graph.user.UserName, NewUserName: aws.String("RenamedUser"), NewPath: aws.String("/renamed/")}); err != nil {
		t.Fatal(err)
	}
	renamed, err := client.GetUser(t.Context(), &sdkiam.GetUserInput{UserName: aws.String("RenamedUser")})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range grantingServicePolicies(t, client, aws.ToString(renamed.User.Arn), "s3")["s3"] {
		if entry.PolicyType == types.PolicyTypeInline && aws.ToString(entry.EntityName) != "RenamedUser" {
			t.Fatalf("inline policy retained a stale identity name: %+v", entry)
		}
	}
}

func TestListPoliciesGrantingServiceAccessInputBoundary(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("InputSubject")})
	if err != nil {
		t.Fatal(err)
	}
	for _, namespaces := range [][]string{nil, {""}} {
		query := url.Values{"Action": {"ListPoliciesGrantingServiceAccess"}, "Version": {"2010-05-08"}, "Arn": {aws.ToString(user.User.Arn)}}
		for i, namespace := range namespaces {
			query.Set(fmt.Sprintf("ServiceNamespaces.member.%d", i+1), namespace)
		}
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(query.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		metadata := awsctx.Metadata{AccountID: "123456789012", Partition: "aws", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}
		response := httptest.NewRecorder()
		service.ServeHTTP(response, request.WithContext(awsctx.WithMetadata(request.Context(), metadata)))
		var envelope struct{ Error struct{ Code string } }
		if err := xml.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusBadRequest || envelope.Error.Code != "ValidationError" {
			t.Fatalf("empty namespace accepted: %s", response.Body.String())
		}
	}
	for _, namespaces := range [][]string{{"S3"}, {"s3", "stackdunmodeled"}} {
		_, err := client.ListPoliciesGrantingServiceAccess(t.Context(), &sdkiam.ListPoliciesGrantingServiceAccessInput{Arn: user.User.Arn, ServiceNamespaces: namespaces})
		requireCode(t, err, "InvalidInput")
	}
	_, err = client.ListPoliciesGrantingServiceAccess(t.Context(), &sdkiam.ListPoliciesGrantingServiceAccessInput{Arn: user.User.Arn, ServiceNamespaces: []string{"s3"}, Marker: aws.String("invalid")})
	requireCode(t, err, "ValidationError")
	out, err := client.ListPoliciesGrantingServiceAccess(t.Context(), &sdkiam.ListPoliciesGrantingServiceAccessInput{Arn: user.User.Arn, ServiceNamespaces: []string{"sqs", "s3", "sqs"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.PoliciesGrantingServiceAccess) != 2 || aws.ToString(out.PoliciesGrantingServiceAccess[0].ServiceNamespace) != "sqs" || aws.ToString(out.PoliciesGrantingServiceAccess[1].ServiceNamespace) != "s3" {
		t.Fatalf("namespace order/dedup: %+v", out)
	}
	foreign := strings.Replace(aws.ToString(user.User.Arn), "123456789012", "999999999999", 1)
	_, err = client.ListPoliciesGrantingServiceAccess(t.Context(), &sdkiam.ListPoliciesGrantingServiceAccessInput{Arn: aws.String(foreign), ServiceNamespaces: []string{"s3"}})
	requireCode(t, err, "AccessDenied")
	partition := strings.Replace(aws.ToString(user.User.Arn), "arn:aws:", "arn:aws-cn:", 1)
	_, err = client.ListPoliciesGrantingServiceAccess(t.Context(), &sdkiam.ListPoliciesGrantingServiceAccessInput{Arn: aws.String(partition), ServiceNamespaces: []string{"s3"}})
	requireCode(t, err, "ValidationError")
}

package stackd_test

import (
	"errors"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"stackd"
)

func identityHTTPError(t *testing.T, err error, code string, status int) {
	t.Helper()
	assertAPIError(t, err, code)
	var response *smithyhttp.ResponseError
	if !errors.As(err, &response) || response.HTTPStatusCode() != status {
		t.Fatalf("%s HTTP status: %v; want %d", code, err, status)
	}
}

// AWS's JSON API references specify 400 for these modeled client errors,
// including conflicts and missing resources, unlike the catalog's status hints.
func TestIdentityConsistencyErrorStatuses(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			admin := identityAdminClient(c, eventDeliveryAccount, "test")
			instance, err := admin.CreateInstance(ctx, &ssoadmin.CreateInstanceInput{Name: aws.String("consistency")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = admin.CreateInstance(ctx, &ssoadmin.CreateInstanceInput{Name: aws.String("second")})
			identityHTTPError(t, err, "ConflictException", 400)
			permission, err := admin.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{InstanceArn: instance.InstanceArn, Name: aws.String("Permission")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = admin.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{InstanceArn: instance.InstanceArn, Name: aws.String("Permission")})
			identityHTTPError(t, err, "ConflictException", 400)
			_, err = admin.DeleteInstance(ctx, &ssoadmin.DeleteInstanceInput{InstanceArn: instance.InstanceArn})
			identityHTTPError(t, err, "ConflictException", 400)
			_, err = admin.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission.PermissionSet.PermissionSetArn, AccountId: aws.String("999999999999")})
			identityHTTPError(t, err, "AccessDeniedException", 400)
			if _, err = admin.DeletePermissionSet(ctx, &ssoadmin.DeletePermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission.PermissionSet.PermissionSetArn}); err != nil {
				t.Fatal(err)
			}
			_, err = admin.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission.PermissionSet.PermissionSetArn})
			identityHTTPError(t, err, "ResourceNotFoundException", 400)
			details, err := admin.DescribeInstance(ctx, &ssoadmin.DescribeInstanceInput{InstanceArn: instance.InstanceArn})
			if err != nil {
				t.Fatal(err)
			}
			directory := identitystore.New(identitystore.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			_, err = directory.CreateUser(ctx, &identitystore.CreateUserInput{IdentityStoreId: details.IdentityStoreId, UserName: aws.String("alice")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = directory.CreateUser(ctx, &identitystore.CreateUserInput{IdentityStoreId: details.IdentityStoreId, UserName: aws.String("alice")})
			identityHTTPError(t, err, "ConflictException", 400)
			_, err = directory.DescribeUser(ctx, &identitystore.DescribeUserInput{IdentityStoreId: details.IdentityStoreId, UserId: aws.String("00000000-0000-4000-8000-000000000000")})
			identityHTTPError(t, err, "ResourceNotFoundException", 400)
			root := c.iam(eventDeliveryAccount, "test", "")
			if _, err = root.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("denied")}); err != nil {
				t.Fatal(err)
			}
			key, err := root.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String("denied")})
			if err != nil {
				t.Fatal(err)
			}
			denied := credentials.NewStaticCredentialsProvider(aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), "")
			deniedDirectory := identitystore.New(identitystore.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: denied, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			_, err = deniedDirectory.ListUsers(ctx, &identitystore.ListUsersInput{IdentityStoreId: details.IdentityStoreId})
			identityHTTPError(t, err, "AccessDeniedException", 400)
			deniedAdmin := identityAdminClient(c, aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey))
			_, err = deniedAdmin.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{InstanceArn: instance.InstanceArn})
			identityHTTPError(t, err, "AccessDeniedException", 400)
		})
	}
}

func TestIdentityConsistencyPagination(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			c, reopen := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount}, func(config stackd.Config) (*stackd.Stack, *httptest.Server) { return startPublicCloud(t, config) })
			admin := identityAdminClient(c, eventDeliveryAccount, "test")
			instance, err := admin.CreateInstance(ctx, &ssoadmin.CreateInstanceInput{Name: aws.String("pages")})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"One", "Two", "Three"} {
				if _, err = admin.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{InstanceArn: instance.InstanceArn, Name: &name}); err != nil {
					t.Fatal(err)
				}
			}
			all, err := admin.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{InstanceArn: instance.InstanceArn})
			if err != nil {
				t.Fatal(err)
			}
			first, err := admin.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{InstanceArn: instance.InstanceArn, MaxResults: aws.Int32(1)})
			if err != nil || first.NextToken == nil || !slices.Equal(first.PermissionSets, all.PermissionSets[:1]) {
				t.Fatalf("first permission page: %+v %v", first, err)
			}
			if _, err = admin.DeletePermissionSet(ctx, &ssoadmin.DeletePermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: &first.PermissionSets[0]}); err != nil {
				t.Fatal(err)
			}
			// Continuations survive service reconstruction and deletion of their key.
			c = reopen()
			admin = identityAdminClient(c, eventDeliveryAccount, "test")
			rest, err := admin.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{InstanceArn: instance.InstanceArn, MaxResults: aws.Int32(100), NextToken: first.NextToken})
			if err != nil || !slices.Equal(rest.PermissionSets, all.PermissionSets[1:]) || rest.NextToken != nil {
				t.Fatalf("permission continuation: %+v %v; want %v", rest, err, all.PermissionSets[1:])
			}
			permission, other := &all.PermissionSets[1], &all.PermissionSets[2]
			ref := func(path, name string) *ssotypes.CustomerManagedPolicyReference {
				return &ssotypes.CustomerManagedPolicyReference{Path: &path, Name: &name}
			}
			attach := func(path, name string) {
				t.Helper()
				if _, e := admin.AttachCustomerManagedPolicyReferenceToPermissionSet(ctx, &ssoadmin.AttachCustomerManagedPolicyReferenceToPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission, CustomerManagedPolicyReference: ref(path, name)}); e != nil {
					t.Fatal(e)
				}
			}
			list := func(token *string, limit int32) *ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput {
				t.Helper()
				out, e := admin.ListCustomerManagedPolicyReferencesInPermissionSet(ctx, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission, MaxResults: &limit, NextToken: token})
				if e != nil {
					t.Fatal(e)
				}
				return out
			}
			attach("/b/", "Same")
			attach("/d/", "Same")
			attach("/f/", "Same")
			page := list(nil, 1)
			if page.NextToken == nil || len(page.CustomerManagedPolicyReferences) != 1 || aws.ToString(page.CustomerManagedPolicyReferences[0].Path) != "/b/" {
				t.Fatalf("first customer policy page: %+v", page)
			}
			attach("/a/", "Same")
			next := list(page.NextToken, 1)
			if len(next.CustomerManagedPolicyReferences) != 1 || aws.ToString(next.CustomerManagedPolicyReferences[0].Path) != "/d/" {
				t.Fatalf("insertion before cursor repeated a row: %+v", next)
			}
			for _, path := range []string{"/a/", "/b/"} {
				if _, err = admin.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx, &ssoadmin.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission, CustomerManagedPolicyReference: ref(path, "Same")}); err != nil {
					t.Fatal(err)
				}
			}
			next = list(page.NextToken, 100)
			paths := []string{}
			for _, policy := range next.CustomerManagedPolicyReferences {
				paths = append(paths, aws.ToString(policy.Path))
			}
			if !slices.Equal(paths, []string{"/d/", "/f/"}) || next.NextToken != nil {
				t.Fatalf("deletion skipped a row: %+v", next)
			}
			_, err = admin.ListCustomerManagedPolicyReferencesInPermissionSet(ctx, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: other, NextToken: page.NextToken})
			identityHTTPError(t, err, "ValidationException", 400)
			_, err = admin.ListManagedPoliciesInPermissionSet(ctx, &ssoadmin.ListManagedPoliciesInPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission, NextToken: page.NextToken})
			identityHTTPError(t, err, "ValidationException", 400)
			_, err = admin.ListCustomerManagedPolicyReferencesInPermissionSet(ctx, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission, NextToken: aws.String("not-a-token")})
			identityHTTPError(t, err, "ValidationException", 400)
			// An empty suffix remains a valid terminal page, not an invalid offset.
			for _, path := range []string{"/d/", "/f/"} {
				if _, err = admin.DetachCustomerManagedPolicyReferenceFromPermissionSet(ctx, &ssoadmin.DetachCustomerManagedPolicyReferenceFromPermissionSetInput{InstanceArn: instance.InstanceArn, PermissionSetArn: permission, CustomerManagedPolicyReference: ref(path, "Same")}); err != nil {
					t.Fatal(err)
				}
			}
			last := list(page.NextToken, 100)
			if len(last.CustomerManagedPolicyReferences) != 0 || last.NextToken != nil {
				t.Fatalf("empty continuation: %+v", last)
			}
		})
	}
}

func TestIdentityConsistencyFilteredPagination(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := t.Context()
			c, _ := retainedCloud(t, backend, stackd.Config{AccountID: eventDeliveryAccount})
			admin := identityAdminClient(c, eventDeliveryAccount, "test")
			instance, err := admin.CreateInstance(ctx, &ssoadmin.CreateInstanceInput{Name: aws.String("filtered-pages")})
			if err != nil {
				t.Fatal(err)
			}
			details, err := admin.DescribeInstance(ctx, &ssoadmin.DescribeInstanceInput{InstanceArn: instance.InstanceArn})
			if err != nil {
				t.Fatal(err)
			}
			directory := identitystore.New(identitystore.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(eventDeliveryAccount, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
			user, err := directory.CreateUser(ctx, &identitystore.CreateUserInput{IdentityStoreId: details.IdentityStoreId, UserName: aws.String("assigned")})
			if err != nil {
				t.Fatal(err)
			}
			permissions := []string{}
			operations := []string{}
			for _, name := range []string{"One", "Two", "Three"} {
				p, e := admin.CreatePermissionSet(ctx, &ssoadmin.CreatePermissionSetInput{InstanceArn: instance.InstanceArn, Name: &name})
				if e != nil {
					t.Fatal(e)
				}
				permissions = append(permissions, aws.ToString(p.PermissionSet.PermissionSetArn))
				created, e := admin.CreateAccountAssignment(ctx, &ssoadmin.CreateAccountAssignmentInput{InstanceArn: instance.InstanceArn, PermissionSetArn: p.PermissionSet.PermissionSetArn, TargetId: aws.String(eventDeliveryAccount), TargetType: "AWS_ACCOUNT", PrincipalId: user.UserId, PrincipalType: "USER"})
				if e != nil {
					t.Fatal(e)
				}
				operations = append(operations, aws.ToString(created.AccountAssignmentCreationStatus.RequestId))
			}
			slices.Sort(permissions)
			slices.Sort(operations)
			first, err := admin.ListAccountAssignmentsForPrincipal(ctx, &ssoadmin.ListAccountAssignmentsForPrincipalInput{InstanceArn: instance.InstanceArn, PrincipalId: user.UserId, PrincipalType: "USER", MaxResults: aws.Int32(1)})
			if err != nil || first.NextToken == nil || len(first.AccountAssignments) != 1 || aws.ToString(first.AccountAssignments[0].PermissionSetArn) != permissions[0] {
				t.Fatalf("first assignment page: %+v %v", first, err)
			}
			provisioned, err := admin.ListPermissionSetsProvisionedToAccount(ctx, &ssoadmin.ListPermissionSetsProvisionedToAccountInput{InstanceArn: instance.InstanceArn, AccountId: aws.String(eventDeliveryAccount), MaxResults: aws.Int32(1)})
			if err != nil || provisioned.NextToken == nil || !slices.Equal(provisioned.PermissionSets, permissions[:1]) {
				t.Fatalf("first provisioning page: %+v %v", provisioned, err)
			}
			if _, err = admin.DeleteAccountAssignment(ctx, &ssoadmin.DeleteAccountAssignmentInput{InstanceArn: instance.InstanceArn, PermissionSetArn: &permissions[0], TargetId: aws.String(eventDeliveryAccount), TargetType: "AWS_ACCOUNT", PrincipalId: user.UserId, PrincipalType: "USER"}); err != nil {
				t.Fatal(err)
			}
			rest, err := admin.ListAccountAssignmentsForPrincipal(ctx, &ssoadmin.ListAccountAssignmentsForPrincipalInput{InstanceArn: instance.InstanceArn, PrincipalId: user.UserId, PrincipalType: "USER", NextToken: first.NextToken})
			if err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, assignment := range rest.AccountAssignments {
				if aws.ToString(assignment.AccountId) != eventDeliveryAccount || aws.ToString(assignment.PrincipalId) != aws.ToString(user.UserId) {
					t.Fatalf("assignment escaped its filter: %+v", assignment)
				}
				got = append(got, aws.ToString(assignment.PermissionSetArn))
			}
			if !slices.Equal(got, permissions[1:]) || rest.NextToken != nil {
				t.Fatalf("assignment continuation: %v; want %v", got, permissions[1:])
			}
			provisionRest, err := admin.ListPermissionSetsProvisionedToAccount(ctx, &ssoadmin.ListPermissionSetsProvisionedToAccountInput{InstanceArn: instance.InstanceArn, AccountId: aws.String(eventDeliveryAccount), NextToken: provisioned.NextToken})
			if err != nil || !slices.Equal(provisionRest.PermissionSets, permissions[1:]) || provisionRest.NextToken != nil {
				t.Fatalf("provisioning continuation: %+v %v", provisionRest, err)
			}
			_, err = admin.ListAccountAssignmentsForPrincipal(ctx, &ssoadmin.ListAccountAssignmentsForPrincipalInput{InstanceArn: instance.InstanceArn, PrincipalId: user.UserId, PrincipalType: "USER", Filter: &ssotypes.ListAccountAssignmentsFilter{AccountId: aws.String(eventDeliveryAccount)}, NextToken: first.NextToken})
			identityHTTPError(t, err, "ValidationException", 400)
			statuses, err := admin.ListAccountAssignmentCreationStatus(ctx, &ssoadmin.ListAccountAssignmentCreationStatusInput{InstanceArn: instance.InstanceArn, MaxResults: aws.Int32(1), Filter: &ssotypes.OperationStatusFilter{Status: "SUCCEEDED"}})
			if err != nil || statuses.NextToken == nil || len(statuses.AccountAssignmentsCreationStatus) != 1 || aws.ToString(statuses.AccountAssignmentsCreationStatus[0].RequestId) != operations[0] {
				t.Fatalf("first operation page: %+v %v", statuses, err)
			}
			statusRest, err := admin.ListAccountAssignmentCreationStatus(ctx, &ssoadmin.ListAccountAssignmentCreationStatusInput{InstanceArn: instance.InstanceArn, NextToken: statuses.NextToken, Filter: &ssotypes.OperationStatusFilter{Status: "SUCCEEDED"}})
			if err != nil {
				t.Fatal(err)
			}
			got = got[:0]
			for _, status := range statusRest.AccountAssignmentsCreationStatus {
				got = append(got, aws.ToString(status.RequestId))
			}
			if !slices.Equal(got, operations[1:]) || statusRest.NextToken != nil {
				t.Fatalf("operation continuation: %v; want %v", got, operations[1:])
			}
			_, err = admin.ListAccountAssignmentCreationStatus(ctx, &ssoadmin.ListAccountAssignmentCreationStatusInput{InstanceArn: instance.InstanceArn, NextToken: statuses.NextToken, Filter: &ssotypes.OperationStatusFilter{Status: "FAILED"}})
			identityHTTPError(t, err, "ValidationException", 400)
			_, err = admin.ListAccountAssignmentDeletionStatus(ctx, &ssoadmin.ListAccountAssignmentDeletionStatusInput{InstanceArn: instance.InstanceArn, NextToken: statuses.NextToken, Filter: &ssotypes.OperationStatusFilter{Status: "SUCCEEDED"}})
			identityHTTPError(t, err, "ValidationException", 400)
		})
	}
}

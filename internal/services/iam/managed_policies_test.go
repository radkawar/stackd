package iam_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"stackd/internal/authorization"
	"stackd/internal/iam/managed"
	"stackd/internal/services/iam"
)

const awsAdministrator = "arn:aws:iam::aws:policy/AdministratorAccess"
const awsSQSFull = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
const awsSQSRead = "arn:aws:iam::aws:policy/AmazonSQSReadOnlyAccess"

func TestAWSManagedResourceAccountSDKAuthorization(t *testing.T) {
	service := iam.New()
	root := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	created, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("managed-resource-account-reader")})
	if err != nil {
		t.Fatal(err)
	}
	user := clientForIAMPrincipal(t, service, created.User)
	local := mustCreatePolicy(t, root, "AdministratorAccess")
	owner, ok := managed.ResourceAccount("aws")
	if !ok {
		t.Fatal("commercial service-managed account evidence is missing")
	}
	for _, tc := range []struct {
		name, expectedAccount        string
		managedAllowed, localAllowed bool
	}{
		{"observed service account", owner, true, false},
		{"different account", "000000000000", false, false},
		{"caller account", "123456789012", false, true},
		{"ARN alias", "aws", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": map[string]any{"Effect": "Allow", "Action": "iam:GetPolicy", "Resource": "arn:aws:iam::*:policy/*", "Condition": map[string]any{"StringEquals": map[string]string{"aws:ResourceAccount": tc.expectedAccount}}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: created.User.UserName, PolicyName: aws.String("OwnerCondition"), PolicyDocument: aws.String(string(document))}); err != nil {
				t.Fatal(err)
			}
			for _, target := range []struct {
				arn     string
				allowed bool
			}{{awsAdministrator, tc.managedAllowed}, {local, tc.localAllowed}} {
				_, err := user.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: aws.String(target.arn)})
				if target.allowed {
					if err != nil {
						t.Fatalf("%s: %v", target.arn, err)
					}
				} else {
					requireCode(t, err, "AccessDenied")
				}
			}
		})
	}
}

func TestAWSManagedPolicySDKCatalogue(t *testing.T) {
	s := iam.New()
	c := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	local := mustCreatePolicy(t, c, "AdministratorAccess")
	if local == awsAdministrator {
		t.Fatal("customer policy created in AWS namespace")
	}
	for _, scope := range []types.PolicyScopeType{types.PolicyScopeTypeAws, types.PolicyScopeTypeLocal, types.PolicyScopeTypeAll} {
		pager := sdkiam.NewListPoliciesPaginator(c, &sdkiam.ListPoliciesInput{Scope: scope, MaxItems: aws.Int32(137)})
		seen := make(map[string]bool)
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range page.Policies {
				arn := aws.ToString(p.Arn)
				if seen[arn] {
					t.Fatalf("duplicate pagination entry %s", arn)
				}
				seen[arn] = true
				if p.Description != nil || len(p.Tags) != 0 {
					t.Fatal("ListPolicies included fields AWS omits")
				}
				if strings.Contains(arn, ":aws:policy/") && (aws.ToInt32(p.AttachmentCount) != 0 || aws.ToInt32(p.PermissionsBoundaryUsageCount) != 0) {
					t.Fatal("catalogue leaked source-account usage")
				}
			}
		}
		want := len(managed.List("aws"))
		if scope == types.PolicyScopeTypeLocal {
			want = 1
		}
		if scope == types.PolicyScopeTypeAll {
			want++
		}
		if len(seen) != want {
			t.Fatalf("scope %s count %d want%d", scope, len(seen), want)
		}
	}
	for _, arn := range []string{awsAdministrator, "arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"} {
		p, ok := managed.Lookup("aws", arn)
		if !ok {
			t.Fatal("fixture policy absent", arn)
		}
		got, err := c.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: aws.String(arn)})
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToString(got.Policy.PolicyId) != p.ID || aws.ToString(got.Policy.Description) != p.Description || aws.ToString(got.Policy.DefaultVersionId) != p.DefaultVersion || got.Policy.CreateDate == nil || !got.Policy.CreateDate.Equal(p.Created) {
			t.Fatalf("metadata mismatch %s", arn)
		}
		pager := sdkiam.NewListPolicyVersionsPaginator(c, &sdkiam.ListPolicyVersionsInput{PolicyArn: aws.String(arn), MaxItems: aws.Int32(17)})
		versions := make(map[string]bool)
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range page.Versions {
				versions[aws.ToString(v.VersionId)] = true
				if v.Document != nil {
					t.Fatal("ListPolicyVersions included document")
				}
			}
		}
		if len(versions) != len(p.Versions) {
			t.Fatalf("history missing %s: %d/%d", arn, len(versions), len(p.Versions))
		}
		for _, v := range p.Versions {
			if !v.Default && v.ID != "v1" {
				continue
			}
			out, err := c.GetPolicyVersion(ctx, &sdkiam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String(v.ID)})
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := url.QueryUnescape(aws.ToString(out.PolicyVersion.Document))
			if err != nil || decoded != v.Document {
				t.Fatalf("document mismatch %s %s", arn, v.ID)
			}
		}
	}
	_, err := c.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: aws.String("arn:aws:iam::aws:policy/NoSuchStackdPolicy")})
	requireCode(t, err, "NoSuchEntity")
	_, err = c.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: aws.String("arn:aws-cn:iam::aws:policy/AdministratorAccess")})
	requireCode(t, err, "ValidationError")
}

func TestAWSManagedPoliciesAccountUsageAndAuthorization(t *testing.T) {
	repo := iam.NewMemoryRepository(nil)
	s := iam.NewWithRepository(nil, repo)
	c := clientFor(t, s, "123456789012", "us-east-1")
	other := clientFor(t, s, "210987654321", "eu-west-1")
	ctx := context.Background()
	u, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("aws-policy-user"), PermissionsBoundary: aws.String(awsSQSRead)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: aws.String("aws-policy-group")}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("aws-policy-role"), AssumeRolePolicyDocument: aws.String(trustEC2), PermissionsBoundary: aws.String(awsSQSRead)}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = c.AttachUserPolicy(ctx, &sdkiam.AttachUserPolicyInput{UserName: u.User.UserName, PolicyArn: aws.String(awsSQSFull)}); err != nil {
			t.Fatal(err)
		}
		if _, err = c.AttachGroupPolicy(ctx, &sdkiam.AttachGroupPolicyInput{GroupName: aws.String("aws-policy-group"), PolicyArn: aws.String(awsSQSFull)}); err != nil {
			t.Fatal(err)
		}
		if _, err = c.AttachRolePolicy(ctx, &sdkiam.AttachRolePolicyInput{RoleName: aws.String("aws-policy-role"), PolicyArn: aws.String(awsSQSFull)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		arn              string
		attach, boundary int32
	}{{awsSQSFull, 3, 0}, {awsSQSRead, 0, 2}} {
		got, err := c.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: aws.String(tc.arn)})
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToInt32(got.Policy.AttachmentCount) != tc.attach || aws.ToInt32(got.Policy.PermissionsBoundaryUsageCount) != tc.boundary {
			t.Fatalf("local usage %+v", got.Policy)
		}
		isolated, err := other.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: aws.String(tc.arn)})
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToInt32(isolated.Policy.AttachmentCount) != 0 || aws.ToInt32(isolated.Policy.PermissionsBoundaryUsageCount) != 0 {
			t.Fatal("cross-account usage leak")
		}
	}
	for _, usage := range []types.PolicyUsageType{types.PolicyUsageTypePermissionsPolicy, types.PolicyUsageTypePermissionsBoundary} {
		got, err := c.ListPolicies(ctx, &sdkiam.ListPoliciesInput{Scope: types.PolicyScopeTypeAws, OnlyAttached: true, PolicyUsageFilter: usage})
		if err != nil || len(got.Policies) != 1 {
			t.Fatalf("usage filter %s: %+v %v", usage, got, err)
		}
	}
	entities, err := c.ListEntitiesForPolicy(ctx, &sdkiam.ListEntitiesForPolicyInput{PolicyArn: aws.String(awsSQSFull)})
	if err != nil || len(entities.PolicyUsers) != 1 || len(entities.PolicyGroups) != 1 || len(entities.PolicyRoles) != 1 {
		t.Fatalf("attachment entities %+v %v", entities, err)
	}
	evaluator := authorization.New(s, nil)
	caller := userContext(u.User, "aws")
	if authErr := evaluator.Authorize(caller, authorization.Request{Action: "sqs:GetQueueAttributes", ResourceARN: queueResource}); authErr != nil {
		t.Fatalf("real AWS full+read policies did not grant read: %v", authErr)
	}
	if authErr := evaluator.Authorize(caller, authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueResource}); authErr == nil {
		t.Fatal("AWS read-only boundary did not restrict send")
	}
	docs, err := s.ResolveManagedPolicyDocuments(authRootContext("aws"), []string{awsSQSRead, awsAdministrator})
	if err != nil || len(docs) != 2 {
		t.Fatalf("STS managed policy resolution: %v %v", docs, err)
	}
	if _, err = c.DeleteUserPermissionsBoundary(ctx, &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: u.User.UserName}); err != nil {
		t.Fatal(err)
	}
	if authErr := evaluator.Authorize(caller, authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueResource}); authErr != nil {
		t.Fatalf("full policy send: %v", authErr)
	}
	restarted := iam.NewWithRepository(nil, repo)
	if _, err = restarted.ResolveManagedPolicyDocuments(authRootContext("aws"), []string{awsAdministrator}); err != nil {
		t.Fatal("restart lost catalogue", err)
	}
	if err = repo.View(ctx, func(tx iam.ReadTx) error {
		policies, err := tx.ManagedPolicies(iam.Scope{Partition: "aws", AccountID: "123456789012"})
		if len(policies) != 0 {
			t.Error("AWS policies were persisted in customer repository")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAWSManagedReservedAttachmentDomainsReplay(t *testing.T) {
	raw, err := os.ReadFile("../../iam/managed/testdata/attachment_domains.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Scenarios []struct {
			Operation string `json:"operation"`
			PolicyARN string `json:"policy_arn"`
			ExitCode  int    `json:"exit_code"`
			Stderr    string `json:"stderr"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	u, err := c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("reserved-policy-probe")})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range fixture.Scenarios {
		t.Run(scenario.Operation+"/"+scenario.PolicyARN, func(t *testing.T) {
			var err error
			if scenario.Operation == "attach-user-policy" {
				_, err = c.AttachUserPolicy(ctx, &sdkiam.AttachUserPolicyInput{UserName: u.User.UserName, PolicyArn: aws.String(scenario.PolicyARN)})
			} else {
				_, err = c.PutUserPermissionsBoundary(ctx, &sdkiam.PutUserPermissionsBoundaryInput{UserName: u.User.UserName, PermissionsBoundary: aws.String(scenario.PolicyARN)})
			}
			if scenario.ExitCode == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) || !strings.Contains(scenario.Stderr, "("+apiErr.ErrorCode()+")") || !strings.Contains(scenario.Stderr, apiErr.ErrorMessage()) {
				t.Fatalf("local %v; AWS %s", err, scenario.Stderr)
			}
		})
	}
	const reserved = "arn:aws:iam::aws:policy/aws-service-role/AmazonTimestreamInfluxDBServiceRolePolicy"
	_, err = c.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("reserved-boundary-role"), AssumeRolePolicyDocument: aws.String(trustEC2), PermissionsBoundary: aws.String(reserved)})
	requireCode(t, err, "PolicyNotAttachable")
	_, err = c.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("reserved-boundary-user"), PermissionsBoundary: aws.String(reserved)})
	requireCode(t, err, "PolicyNotAttachable")
}

func TestAWSManagedPolicyImmutabilityReplay(t *testing.T) {
	raw, err := os.ReadFile("../../iam/managed/testdata/immutability.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Scenarios []struct {
			Operation string `json:"operation"`
			PolicyARN string `json:"policy_arn"`
			Stderr    string `json:"stderr"`
			ExitCode  int    `json:"exit_code"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	c := clientFor(t, iam.New(), "123456789012", "us-east-1")
	ctx := context.Background()
	for _, scenario := range fixture.Scenarios {
		t.Run(scenario.Operation, func(t *testing.T) {
			arn := aws.String(scenario.PolicyARN)
			var err error
			switch scenario.Operation {
			case "get-policy":
				_, err = c.GetPolicy(ctx, &sdkiam.GetPolicyInput{PolicyArn: arn})
			case "delete-policy":
				_, err = c.DeletePolicy(ctx, &sdkiam.DeletePolicyInput{PolicyArn: arn})
			case "create-policy-version":
				_, err = c.CreatePolicyVersion(ctx, &sdkiam.CreatePolicyVersionInput{PolicyArn: arn, PolicyDocument: aws.String(denyRead)})
			case "set-default-policy-version":
				_, err = c.SetDefaultPolicyVersion(ctx, &sdkiam.SetDefaultPolicyVersionInput{PolicyArn: arn, VersionId: aws.String("v1")})
			case "delete-policy-version":
				_, err = c.DeletePolicyVersion(ctx, &sdkiam.DeletePolicyVersionInput{PolicyArn: arn, VersionId: aws.String("v1")})
			case "tag-policy":
				_, err = c.TagPolicy(ctx, &sdkiam.TagPolicyInput{PolicyArn: arn, Tags: []types.Tag{{Key: aws.String("stackd-probe"), Value: aws.String("immutable-policy-rejection")}}})
			case "untag-policy":
				_, err = c.UntagPolicy(ctx, &sdkiam.UntagPolicyInput{PolicyArn: arn, TagKeys: []string{"stackd-probe"}})
			case "list-policy-tags":
				out, listErr := c.ListPolicyTags(ctx, &sdkiam.ListPolicyTagsInput{PolicyArn: arn})
				err = listErr
				if err == nil && len(out.Tags) != 0 {
					t.Fatal("AWS policy has tags")
				}
			default:
				t.Fatal("unknown fixture operation", scenario.Operation)
			}
			if scenario.ExitCode == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) || !strings.Contains(scenario.Stderr, "("+apiErr.ErrorCode()+")") || !strings.Contains(scenario.Stderr, apiErr.ErrorMessage()) {
				t.Fatalf("local %v differs from observed %s", err, scenario.Stderr)
			}
		})
	}
}

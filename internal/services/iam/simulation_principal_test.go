package iam_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

type simulationPrincipalGraph struct {
	user        *types.User
	group       *types.Group
	role        *types.Role
	userPolicy  string
	groupPolicy string
	rolePolicy  string
}

func simulationPolicy(effect, action string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":%q,"Action":%q,"Resource":"*"}}`, effect, action)
}

func simulationManagedPolicy(t *testing.T, client *sdkiam.Client, name, document string) string {
	t.Helper()
	created, err := client.CreatePolicy(t.Context(), &sdkiam.CreatePolicyInput{PolicyName: aws.String(name), Path: aws.String("/simulation/"), PolicyDocument: aws.String(document)})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(created.Policy.Arn)
}

func createSimulationPrincipalGraph(t *testing.T, client *sdkiam.Client) simulationPrincipalGraph {
	t.Helper()
	ctx := t.Context()
	user, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("SimulatedUser"), Path: aws.String("/engineering/")})
	if err != nil {
		t.Fatal(err)
	}
	group, err := client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: aws.String("SimulatedGroup"), Path: aws.String("/teams/")})
	if err != nil {
		t.Fatal(err)
	}
	role, err := client.CreateRole(ctx, &sdkiam.CreateRoleInput{RoleName: aws.String("SimulatedRole"), Path: aws.String("/applications/"), AssumeRolePolicyDocument: aws.String(trustEC2)})
	if err != nil {
		t.Fatal(err)
	}
	graph := simulationPrincipalGraph{user: user.User, group: group.Group, role: role.Role}
	graph.userPolicy = simulationManagedPolicy(t, client, "UserManaged", simulationPolicy("Allow", "s3:PutObject"))
	graph.groupPolicy = simulationManagedPolicy(t, client, "GroupManaged", simulationPolicy("Allow", "s3:DeleteObject"))
	graph.rolePolicy = simulationManagedPolicy(t, client, "RoleManaged", simulationPolicy("Allow", "ec2:DescribeVolumes"))
	if _, err := client.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: graph.user.UserName, PolicyName: aws.String("UserInline"), PolicyDocument: aws.String(simulationPolicy("Allow", "s3:GetObject"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutGroupPolicy(ctx, &sdkiam.PutGroupPolicyInput{GroupName: graph.group.GroupName, PolicyName: aws.String("GroupInline"), PolicyDocument: aws.String(simulationPolicy("Allow", "s3:ListBucket"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutRolePolicy(ctx, &sdkiam.PutRolePolicyInput{RoleName: graph.role.RoleName, PolicyName: aws.String("RoleInline"), PolicyDocument: aws.String(simulationPolicy("Allow", "ec2:DescribeInstances"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachUserPolicy(ctx, &sdkiam.AttachUserPolicyInput{UserName: graph.user.UserName, PolicyArn: aws.String(graph.userPolicy)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachGroupPolicy(ctx, &sdkiam.AttachGroupPolicyInput{GroupName: graph.group.GroupName, PolicyArn: aws.String(graph.groupPolicy)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachRolePolicy(ctx, &sdkiam.AttachRolePolicyInput{RoleName: graph.role.RoleName, PolicyArn: aws.String(graph.rolePolicy)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AddUserToGroup(ctx, &sdkiam.AddUserToGroupInput{UserName: graph.user.UserName, GroupName: graph.group.GroupName}); err != nil {
		t.Fatal(err)
	}
	return graph
}

func simulationDecisions(t *testing.T, client *sdkiam.Client, input *sdkiam.SimulatePrincipalPolicyInput) map[string]types.EvaluationResult {
	t.Helper()
	output, err := client.SimulatePrincipalPolicy(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if output.IsTruncated || output.Marker != nil || len(output.EvaluationResults) != len(input.ActionNames) {
		t.Fatalf("unexpected unpaginated simulation response: %+v", output)
	}
	results := make(map[string]types.EvaluationResult)
	for _, result := range output.EvaluationResults {
		action := aws.ToString(result.EvalActionName)
		if _, duplicate := results[action]; duplicate {
			t.Fatalf("duplicate simulated action %q", action)
		}
		results[action] = result
	}
	return results
}

func assertSimulationDecisions(t *testing.T, results map[string]types.EvaluationResult, expected map[string]types.PolicyEvaluationDecisionType) {
	t.Helper()
	if len(results) != len(expected) {
		t.Fatalf("simulation result count=%d; want %d", len(results), len(expected))
	}
	for action, decision := range expected {
		result, ok := results[action]
		if !ok || result.EvalDecision != decision {
			t.Errorf("%s decision=%q (present=%t); want %q", action, result.EvalDecision, ok, decision)
		}
	}
}

// Principal simulation collects current identity policies and a user's groups;
// role trust policies are not permissions policies. Additional input policies
// affect only the requested simulation.
// https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html
func TestSimulatePrincipalPolicyCollectsCurrentGraph(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, client)
	actions := []string{"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "ec2:DescribeInstances", "ec2:DescribeVolumes", "sts:AssumeRole"}
	for _, source := range []struct {
		name    string
		arn     *string
		allowed []string
	}{
		{"user", graph.user.Arn, actions[:4]},
		{"group", graph.group.Arn, actions[2:4]},
		{"role", graph.role.Arn, actions[4:6]},
	} {
		t.Run(source.name, func(t *testing.T) {
			expected := make(map[string]types.PolicyEvaluationDecisionType)
			for _, action := range actions {
				expected[action] = types.PolicyEvaluationDecisionTypeImplicitDeny
			}
			for _, action := range source.allowed {
				expected[action] = types.PolicyEvaluationDecisionTypeAllowed
			}
			assertSimulationDecisions(t, simulationDecisions(t, client, &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: source.arn, ActionNames: actions}), expected)
		})
	}
	input := &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: graph.user.Arn, ActionNames: []string{"s3:GetObject", "s3:DeleteBucket"}, PolicyInputList: []string{simulationPolicy("Deny", "s3:GetObject"), simulationPolicy("Allow", "s3:DeleteBucket")}}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeExplicitDeny, "s3:DeleteBucket": types.PolicyEvaluationDecisionTypeAllowed})
	input.PolicyInputList = nil
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeAllowed, "s3:DeleteBucket": types.PolicyEvaluationDecisionTypeImplicitDeny})
	if _, err := client.CreatePolicyVersion(t.Context(), &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(graph.userPolicy), PolicyDocument: aws.String(simulationPolicy("Deny", "s3:PutObject")), SetAsDefault: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DetachGroupPolicy(t.Context(), &sdkiam.DetachGroupPolicyInput{GroupName: graph.group.GroupName, PolicyArn: aws.String(graph.groupPolicy)}); err != nil {
		t.Fatal(err)
	}
	input.ActionNames = []string{"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeAllowed, "s3:PutObject": types.PolicyEvaluationDecisionTypeExplicitDeny, "s3:ListBucket": types.PolicyEvaluationDecisionTypeAllowed, "s3:DeleteObject": types.PolicyEvaluationDecisionTypeImplicitDeny})
	if _, err := client.RemoveUserFromGroup(t.Context(), &sdkiam.RemoveUserFromGroupInput{GroupName: graph.group.GroupName, UserName: graph.user.UserName}); err != nil {
		t.Fatal(err)
	}
	input.ActionNames = []string{"s3:ListBucket"}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:ListBucket": types.PolicyEvaluationDecisionTypeImplicitDeny})
	if _, err := client.DetachUserPolicy(t.Context(), &sdkiam.DetachUserPolicyInput{UserName: graph.user.UserName, PolicyArn: aws.String(graph.userPolicy)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteUserPolicy(t.Context(), &sdkiam.DeleteUserPolicyInput{UserName: graph.user.UserName, PolicyName: aws.String("UserInline")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteUser(t.Context(), &sdkiam.DeleteUserInput{UserName: graph.user.UserName}); err != nil {
		t.Fatal(err)
	}
	output, err := client.SimulatePrincipalPolicy(t.Context(), input)
	requireCode(t, err, "NoSuchEntity")
	var missing *types.NoSuchEntityException
	if !errors.As(err, &missing) || output != nil {
		t.Fatalf("deleted source result=%+v error=%v", output, err)
	}
	recreated, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: graph.user.UserName, Path: graph.user.Path})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(recreated.User.UserId) == aws.ToString(graph.user.UserId) {
		t.Fatal("recreated principal retained its immutable ID")
	}
	input.ActionNames = []string{"s3:GetObject", "s3:PutObject"}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeImplicitDeny, "s3:PutObject": types.PolicyEvaluationDecisionTypeImplicitDeny})
}

func TestSimulatePrincipalPolicyAttachedBoundaryAndOverride(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, client)
	boundary := simulationManagedPolicy(t, client, "SimulationBoundary", simulationPolicy("Allow", "s3:GetObject"))
	if _, err := client.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: graph.user.UserName, PermissionsBoundary: aws.String(boundary)}); err != nil {
		t.Fatal(err)
	}
	input := &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: graph.user.Arn, ActionNames: []string{"s3:GetObject", "s3:PutObject"}}
	results := simulationDecisions(t, client, input)
	assertSimulationDecisions(t, results, map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeAllowed, "s3:PutObject": types.PolicyEvaluationDecisionTypeImplicitDeny})
	for action, result := range results {
		if result.PermissionsBoundaryDecisionDetail == nil || result.PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary != (action == "s3:GetObject") {
			t.Fatalf("attached boundary detail for %s=%+v", action, result.PermissionsBoundaryDecisionDetail)
		}
	}
	// The request boundary replaces the attached boundary for this simulation.
	input.PermissionsBoundaryPolicyInputList = []string{simulationPolicy("Allow", "s3:PutObject")}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeImplicitDeny, "s3:PutObject": types.PolicyEvaluationDecisionTypeAllowed})
	input.PermissionsBoundaryPolicyInputList = nil
	if _, err := client.CreatePolicyVersion(t.Context(), &sdkiam.CreatePolicyVersionInput{PolicyArn: aws.String(boundary), PolicyDocument: aws.String(simulationPolicy("Allow", "s3:PutObject")), SetAsDefault: true}); err != nil {
		t.Fatal(err)
	}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeImplicitDeny, "s3:PutObject": types.PolicyEvaluationDecisionTypeAllowed})
	if _, err := client.DeleteUserPermissionsBoundary(t.Context(), &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: graph.user.UserName}); err != nil {
		t.Fatal(err)
	}
	results = simulationDecisions(t, client, input)
	assertSimulationDecisions(t, results, map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeAllowed, "s3:PutObject": types.PolicyEvaluationDecisionTypeAllowed})
	for _, result := range results {
		if result.PermissionsBoundaryDecisionDetail != nil {
			t.Fatalf("deleted boundary remained in response: %+v", result)
		}
	}
	input.PolicySourceArn = graph.role.Arn
	input.ActionNames = []string{"ec2:DescribeInstances", "ec2:DescribeVolumes"}
	if _, err := client.PutRolePermissionsBoundary(t.Context(), &sdkiam.PutRolePermissionsBoundaryInput{RoleName: graph.role.RoleName, PermissionsBoundary: aws.String(boundary)}); err != nil {
		t.Fatal(err)
	}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"ec2:DescribeInstances": types.PolicyEvaluationDecisionTypeImplicitDeny, "ec2:DescribeVolumes": types.PolicyEvaluationDecisionTypeImplicitDeny})
	input.PermissionsBoundaryPolicyInputList = []string{simulationPolicy("Allow", "ec2:*")}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"ec2:DescribeInstances": types.PolicyEvaluationDecisionTypeAllowed, "ec2:DescribeVolumes": types.PolicyEvaluationDecisionTypeAllowed})
}

func TestSimulatePrincipalPolicyExcludesAttachedPoliciesWithoutMutation(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, client)
	actions := []string{"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:DeleteBucket"}
	for _, scenario := range []struct {
		name     string
		excluded []types.PolicyIdentifier
		denied   []string
	}{
		{"pathful managed ARN is unmatched", []types.PolicyIdentifier{&types.PolicyIdentifierMemberPolicyArn{Value: graph.userPolicy}}, nil},
		{"pathless managed ARN", []types.PolicyIdentifier{&types.PolicyIdentifierMemberPolicyArn{Value: strings.Replace(graph.userPolicy, "policy/simulation/", "policy/", 1)}}, []string{"s3:PutObject"}},
		{"all customer managed", []types.PolicyIdentifier{&types.PolicyIdentifierMemberPolicyType{Value: types.PolicyIdentifierPolicyTypeUserManaged}}, []string{"s3:PutObject", "s3:DeleteObject"}},
		{"all attached inline", []types.PolicyIdentifier{&types.PolicyIdentifierMemberPolicyType{Value: types.PolicyIdentifierPolicyTypeInline}}, []string{"s3:GetObject", "s3:ListBucket"}},
		{"group inline", []types.PolicyIdentifier{&types.PolicyIdentifierMemberInlinePolicyIdentifier{Value: types.InlinePolicyIdentifierType{AttachmentType: types.AttachmentTypeGroup, AttachmentName: graph.group.GroupName, PolicyName: aws.String("GroupInline")}}}, []string{"s3:ListBucket"}},
		{"group inline wildcard", []types.PolicyIdentifier{&types.PolicyIdentifierMemberInlinePolicyIdentifier{Value: types.InlinePolicyIdentifierType{AttachmentType: types.AttachmentTypeGroup, AttachmentName: aws.String("Simulated*"), PolicyName: aws.String("GroupInline")}}}, []string{"s3:ListBucket"}},
		{"nonmatching valid ARN", []types.PolicyIdentifier{&types.PolicyIdentifierMemberPolicyArn{Value: "arn:aws:iam::123456789012:policy/not-attached"}}, nil},
		{"RCP ignored", []types.PolicyIdentifier{&types.PolicyIdentifierMemberPolicyType{Value: types.PolicyIdentifierPolicyTypeRcp}}, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			expected := make(map[string]types.PolicyEvaluationDecisionType)
			for _, action := range actions {
				expected[action] = types.PolicyEvaluationDecisionTypeAllowed
			}
			for _, action := range scenario.denied {
				expected[action] = types.PolicyEvaluationDecisionTypeImplicitDeny
			}
			input := &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: graph.user.Arn, ActionNames: actions, PolicyExclusionList: scenario.excluded, PolicyInputList: []string{simulationPolicy("Allow", "s3:DeleteBucket")}}
			assertSimulationDecisions(t, simulationDecisions(t, client, input), expected)
		})
	}
	boundary := simulationManagedPolicy(t, client, "ExcludedBoundary", simulationPolicy("Allow", "s3:GetObject"))
	if _, err := client.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: graph.user.UserName, PermissionsBoundary: aws.String(boundary)}); err != nil {
		t.Fatal(err)
	}
	input := &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: graph.user.Arn, ActionNames: []string{"s3:PutObject"}, PolicyExclusionList: []types.PolicyIdentifier{&types.PolicyIdentifierMemberPolicyType{Value: types.PolicyIdentifierPolicyTypePermissionBoundary}}}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:PutObject": types.PolicyEvaluationDecisionTypeAllowed})
	input.PolicyExclusionList = nil
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:PutObject": types.PolicyEvaluationDecisionTypeImplicitDeny})
	if _, err := client.DeleteUserPermissionsBoundary(t.Context(), &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: graph.user.UserName}); err != nil {
		t.Fatal(err)
	}
	input.ActionNames = actions[:4]
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeAllowed, "s3:PutObject": types.PolicyEvaluationDecisionTypeAllowed, "s3:ListBucket": types.PolicyEvaluationDecisionTypeAllowed, "s3:DeleteObject": types.PolicyEvaluationDecisionTypeAllowed})
}

func TestSimulatePrincipalPolicyRequestAuthorizationIsSeparate(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	root := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, root)
	auditor, err := root.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("auditor"), Path: aws.String("/security/")})
	if err != nil {
		t.Fatal(err)
	}
	caller := clientForIAMPrincipal(t, service, auditor.User)
	input := &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: graph.user.Arn, ActionNames: []string{"s3:GetObject"}}
	output, err := caller.SimulatePrincipalPolicy(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	if output != nil {
		t.Fatal("unauthorized caller saw principal policies")
	}
	grant := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":"iam:SimulatePrincipalPolicy","Resource":%q,"Condition":{"StringEquals":{"aws:username":"auditor"}}},{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`, aws.ToString(graph.user.Arn))
	if _, err := root.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: auditor.User.UserName, PolicyName: aws.String("Simulation"), PolicyDocument: aws.String(grant)}); err != nil {
		t.Fatal(err)
	}
	input.ContextEntries = []types.ContextEntry{{ContextKeyName: aws.String("aws:username"), ContextKeyType: types.ContextKeyTypeEnumString, ContextKeyValues: []string{"SimulatedUser"}}}
	assertSimulationDecisions(t, simulationDecisions(t, caller, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeAllowed})
	input.PolicySourceArn = graph.role.Arn
	_, err = caller.SimulatePrincipalPolicy(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	_, err = caller.SimulateCustomPolicy(t.Context(), &sdkiam.SimulateCustomPolicyInput{ActionNames: []string{"s3:GetObject"}, PolicyInputList: []string{simulationPolicy("Allow", "s3:GetObject")}})
	requireCode(t, err, "AccessDenied")
	input.PolicySourceArn = graph.user.Arn
	boundary := simulationManagedPolicy(t, root, "AuditorBoundary", simulationPolicy("Allow", "iam:GetUser"))
	if _, err := root.PutUserPermissionsBoundary(t.Context(), &sdkiam.PutUserPermissionsBoundaryInput{UserName: auditor.User.UserName, PermissionsBoundary: aws.String(boundary)}); err != nil {
		t.Fatal(err)
	}
	// A permissive simulated boundary cannot bypass the real caller's boundary.
	input.PermissionsBoundaryPolicyInputList = []string{simulationPolicy("Allow", "*")}
	_, err = caller.SimulatePrincipalPolicy(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	if _, err := root.DeleteUserPermissionsBoundary(t.Context(), &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: auditor.User.UserName}); err != nil {
		t.Fatal(err)
	}
	service.SetAuthorizer(authorization.New(service, simulationDenyRequestControls{}))
	for _, client := range []*sdkiam.Client{caller, root} {
		output, err := client.SimulatePrincipalPolicy(t.Context(), input)
		requireCode(t, err, "AccessDenied")
		if output != nil {
			t.Fatal("SCP-denied simulation exposed results")
		}
	}
}

type simulationDenyRequestControls struct{}

func (simulationDenyRequestControls) ServiceControlPolicies(context.Context) ([]iampolicy.PolicyLevel, error) {
	return []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":["iam:SimulatePrincipalPolicy","iam:SimulateCustomPolicy"],"Resource":"*"}]}`}}}}, nil
}

type simulationMutableControls struct {
	mu     sync.Mutex
	levels []iampolicy.PolicyLevel
	err    error
}

func (source *simulationMutableControls) ServiceControlPolicies(ctx context.Context) ([]iampolicy.PolicyLevel, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	m := awsctx.FromContext(ctx)
	if m.AccountID != "123456789012" || m.Partition != "aws" {
		return nil, fmt.Errorf("simulation control source received another scope: %+v", m)
	}
	return source.levels, source.err
}

func TestSimulatePrincipalPolicyCurrentSCPsAndExplicitExclusion(t *testing.T) {
	controls := &simulationMutableControls{levels: []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: simulationPolicy("Allow", "*")}}}, {Documents: []iampolicy.Policy{{Document: simulationPolicy("Allow", "s3:GetObject")}}}}}
	service := iam.NewWithConfig(iam.Config{SimulationControls: controls})
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, client)
	input := &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: graph.user.Arn, ActionNames: []string{"s3:GetObject", "s3:PutObject"}}
	results := simulationDecisions(t, client, input)
	assertSimulationDecisions(t, results, map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeAllowed, "s3:PutObject": types.PolicyEvaluationDecisionTypeImplicitDeny})
	for action, result := range results {
		if result.OrganizationsDecisionDetail == nil || result.OrganizationsDecisionDetail.AllowedByOrganizations != (action == "s3:GetObject") {
			t.Fatalf("SCP decision detail for %s=%+v", action, result.OrganizationsDecisionDetail)
		}
	}
	controls.mu.Lock()
	controls.levels = []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: simulationPolicy("Allow", "*")}, {Document: simulationPolicy("Deny", "s3:GetObject")}}}}
	controls.mu.Unlock()
	results = simulationDecisions(t, client, input)
	assertSimulationDecisions(t, results, map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeExplicitDeny, "s3:PutObject": types.PolicyEvaluationDecisionTypeAllowed})
	if len(results["s3:GetObject"].MatchedStatements) != 0 {
		t.Fatal("simulation exposed SCP statement source positions")
	}
	input.PolicyExclusionList = []types.PolicyIdentifier{&types.PolicyIdentifierMemberPolicyType{Value: types.PolicyIdentifierPolicyTypeScp}}
	results = simulationDecisions(t, client, input)
	assertSimulationDecisions(t, results, map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeAllowed, "s3:PutObject": types.PolicyEvaluationDecisionTypeAllowed})
	for _, result := range results {
		if result.OrganizationsDecisionDetail != nil {
			t.Fatalf("excluded SCPs remained in result detail: %+v", result)
		}
	}
	input.PolicyExclusionList = nil
	controls.mu.Lock()
	controls.err = errors.New("current Organizations policies are unavailable")
	controls.mu.Unlock()
	output, err := client.SimulatePrincipalPolicy(t.Context(), input)
	requireCode(t, err, "PolicyEvaluation")
	if output != nil {
		t.Fatal("unavailable current SCPs produced a partial simulation")
	}
}

func TestSimulatePrincipalPolicyCallerSessionPolicyOnlyGatesRequest(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	root := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, root)
	grant := simulationPolicy("Allow", "iam:SimulatePrincipalPolicy")
	if _, err := root.PutRolePolicy(t.Context(), &sdkiam.PutRolePolicyInput{RoleName: graph.role.RoleName, PolicyName: aws.String("Simulate"), PolicyDocument: aws.String(grant)}); err != nil {
		t.Fatal(err)
	}
	newCaller := func(sessionPolicy string) *sdkiam.Client {
		t.Helper()
		m := awsctx.Metadata{AccountID: "123456789012", Partition: "aws", Region: "us-east-1", PrincipalARN: "arn:aws:sts::123456789012:assumed-role/SimulatedRole/session", PrincipalID: aws.ToString(graph.role.RoleId) + ":session", IssuerARN: aws.ToString(graph.role.Arn), IssuerID: aws.ToString(graph.role.RoleId), SessionType: "AssumeRole", HasSessionPolicy: true, SessionPolicies: []string{sessionPolicy}}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			service.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), m)))
		}))
		t.Cleanup(server.Close)
		return sdkiam.New(sdkiam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
	}
	caller := newCaller(grant)
	input := &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: graph.role.Arn, ActionNames: []string{"ec2:DescribeInstances", "ec2:DescribeVolumes"}}
	// This role session cannot call EC2, but can inspect the role's full policy
	// set. Its session limit is not one of the role's attached policies.
	assertSimulationDecisions(t, simulationDecisions(t, caller, input), map[string]types.PolicyEvaluationDecisionType{"ec2:DescribeInstances": types.PolicyEvaluationDecisionTypeAllowed, "ec2:DescribeVolumes": types.PolicyEvaluationDecisionTypeAllowed})
	caller = newCaller(simulationPolicy("Allow", "ec2:*"))
	output, err := caller.SimulatePrincipalPolicy(t.Context(), input)
	requireCode(t, err, "AccessDenied")
	if output != nil {
		t.Fatal("session-denied request exposed role policies")
	}
}

func TestSimulatePrincipalPolicyAccountPartitionAndSourceValidation(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	root := clientFor(t, service, "123456789012", "us-east-1")
	for _, scope := range []struct{ account, partition, region string }{{"123456789012", "aws", "us-east-1"}, {"234567890123", "aws", "us-east-1"}, {"123456789012", "aws-cn", "cn-north-1"}} {
		client := clientForPartition(t, service, scope.account, scope.region, scope.partition)
		user, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("SameName"), Path: aws.String("/scoped/")})
		if err != nil {
			t.Fatal(err)
		}
		effect := "Deny"
		if scope.account == "123456789012" && scope.partition == "aws" {
			effect = "Allow"
		}
		if _, err := client.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("Scope"), PolicyDocument: aws.String(simulationPolicy(effect, "s3:GetObject"))}); err != nil {
			t.Fatal(err)
		}
		decision := types.PolicyEvaluationDecisionTypeExplicitDeny
		if effect == "Allow" {
			decision = types.PolicyEvaluationDecisionTypeAllowed
		}
		assertSimulationDecisions(t, simulationDecisions(t, client, &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: user.User.Arn, ActionNames: []string{"s3:GetObject"}}), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": decision})
		// AWS's simulation source lookup uses the entity name, even when the
		// supplied ARN path differs from the stored IAM resource path.
		wrongPath := strings.Replace(aws.ToString(user.User.Arn), "/scoped/", "/not-the-stored-path/", 1)
		assertSimulationDecisions(t, simulationDecisions(t, client, &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: aws.String(wrongPath), ActionNames: []string{"s3:GetObject"}}), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": decision})
	}
	for _, arn := range []string{"arn:aws:iam::234567890123:user/scoped/SameName", "arn:aws-cn:iam::123456789012:user/scoped/SameName", "arn:aws:iam::123456789012:root", "arn:aws:sts::123456789012:assumed-role/Role/session", "arn:aws:iam::123456789012:policy/Policy", "not-an-arn-but-long-enough"} {
		t.Run(arn, func(t *testing.T) {
			output, err := root.SimulatePrincipalPolicy(t.Context(), &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: aws.String(arn), ActionNames: []string{"s3:GetObject"}})
			requireCode(t, err, "InvalidInput")
			if output != nil {
				t.Fatal("invalid or foreign source returned policies")
			}
		})
	}
	for _, kind := range []string{"user", "group", "role"} {
		_, err := root.SimulatePrincipalPolicy(t.Context(), &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: aws.String("arn:aws:iam::123456789012:" + kind + "/missing"), ActionNames: []string{"s3:GetObject"}})
		requireCode(t, err, "NoSuchEntity")
	}
}

func TestSimulatePrincipalPolicyReadOnlyCoherentGraph(t *testing.T) {
	repository := &authorizationDetailRepository{Repository: iam.NewMemoryRepository(nil), entered: make(chan struct{}), release: make(chan struct{})}
	service := iam.NewWithConfig(iam.Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	graph := createSimulationPrincipalGraph(t, client)
	if _, err := client.PutGroupPolicy(t.Context(), &sdkiam.PutGroupPolicyInput{GroupName: graph.group.GroupName, PolicyName: aws.String("GroupInline"), PolicyDocument: aws.String(simulationPolicy("Deny", "s3:GetObject"))}); err != nil {
		t.Fatal(err)
	}
	repository.readOnly.Store(true)
	repository.blockUsers.Store(true)
	var once sync.Once
	release := func() { once.Do(func() { close(repository.release) }) }
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		output *sdkiam.SimulatePrincipalPolicyOutput
		err    error
	}
	input := &sdkiam.SimulatePrincipalPolicyInput{PolicySourceArn: graph.user.Arn, ActionNames: []string{"s3:GetObject"}}
	queried := make(chan result, 1)
	go func() { out, err := client.SimulatePrincipalPolicy(ctx, input); queried <- result{out, err} }()
	select {
	case <-repository.entered:
	case result := <-queried:
		t.Fatalf("simulation did not read current principal graph: %v", result.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	started, changed := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		changed <- repository.Repository.Update(ctx, func(tx iam.WriteTx) error {
			scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
			user, err := tx.User(scope, aws.ToString(graph.user.UserName))
			if err != nil {
				return err
			}
			group, err := tx.Group(scope, aws.ToString(graph.group.GroupName))
			if err != nil {
				return err
			}
			user.Inline["UserInline"] = simulationPolicy("Deny", "s3:GetObject")
			group.Inline["GroupInline"] = simulationPolicy("Allow", "s3:GetObject")
			if err := tx.PutUser(scope, user); err != nil {
				return err
			}
			return tx.PutGroup(scope, group)
		})
	}()
	<-started
	release()
	first := <-queried
	if first.err != nil || len(first.output.EvaluationResults) != 1 || first.output.EvaluationResults[0].EvalDecision != types.PolicyEvaluationDecisionTypeExplicitDeny {
		t.Fatalf("simulation mixed user/group snapshots: %+v %v", first.output, first.err)
	}
	if err := <-changed; err != nil {
		t.Fatal(err)
	}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"s3:GetObject": types.PolicyEvaluationDecisionTypeExplicitDeny})
	if writes := repository.writes.Load(); writes != 0 {
		t.Fatalf("simulation attempted %d principal/policy writes", writes)
	}
	// No fake simulated action is dispatched into the underlying IAM service.
	input.ActionNames = []string{"iam:DeleteUser"}
	input.PolicyInputList = []string{simulationPolicy("Allow", "iam:DeleteUser")}
	assertSimulationDecisions(t, simulationDecisions(t, client, input), map[string]types.PolicyEvaluationDecisionType{"iam:DeleteUser": types.PolicyEvaluationDecisionTypeAllowed})
	user, err := client.GetUser(t.Context(), &sdkiam.GetUserInput{UserName: graph.user.UserName})
	if err != nil || !strings.EqualFold(aws.ToString(user.User.UserId), aws.ToString(graph.user.UserId)) {
		t.Fatalf("simulation changed the source principal: %+v %v", user, err)
	}
}

func TestSimulationModelCorrectionsRemainScoped(t *testing.T) {
	service := iam.New()
	t.Cleanup(func() { _ = service.Close() })
	client := clientFor(t, service, "123456789012", "us-east-1")
	created, err := client.CreateUser(t.Context(), &sdkiam.CreateUserInput{UserName: aws.String("SelectorOwner")})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name, policyName, code string
	}{
		{"prefix wildcard reaches semantic validation", "Extra*", "InvalidInput"},
		{"question wildcard reaches semantic validation", "ExtraInlin?", "InvalidInput"},
		{"bare wildcard fails modeled pattern", "*", "ValidationError"},
		{"member still inherits maximum length", strings.Repeat("P", 129), "ValidationError"},
		{"member still inherits minimum length", "", "ValidationError"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input := &sdkiam.SimulatePrincipalPolicyInput{
				PolicySourceArn: created.User.Arn,
				ActionNames:     []string{"s3:GetObject"},
				PolicyExclusionList: []types.PolicyIdentifier{&types.PolicyIdentifierMemberInlinePolicyIdentifier{Value: types.InlinePolicyIdentifierType{
					AttachmentName: created.User.UserName,
					AttachmentType: types.AttachmentTypeUser,
					PolicyName:     aws.String(scenario.policyName),
				}}},
			}
			output, err := client.SimulatePrincipalPolicy(t.Context(), input)
			requireCode(t, err, scenario.code)
			if output != nil {
				t.Fatal("invalid selector returned simulation results")
			}
			// policyNameType is shared by IAM mutations. The simulator's
			// member override must not weaken any of those API contracts.
			_, err = client.PutUserPolicy(t.Context(), &sdkiam.PutUserPolicyInput{UserName: created.User.UserName, PolicyName: aws.String(scenario.policyName), PolicyDocument: aws.String(simulationPolicy("Allow", "s3:GetObject"))})
			requireCode(t, err, "ValidationError")
		})
	}
	listed, err := client.ListUserPolicies(t.Context(), &sdkiam.ListUserPoliciesInput{UserName: created.User.UserName})
	if err != nil || len(listed.PolicyNames) != 0 {
		t.Fatalf("rejected policy names changed stored policies: %+v %v", listed, err)
	}
}

package iam_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

const queueResource = "arn:aws:sqs:us-east-1:123456789012:work"

func userContext(user *types.User, partition string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{AccountID: "123456789012", Partition: partition, Region: "us-east-1", PrincipalARN: aws.ToString(user.Arn), PrincipalID: aws.ToString(user.UserId), UserName: aws.ToString(user.UserName)})
}

func authRootContext(partition string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{AccountID: "123456789012", Partition: partition, Region: "us-east-1", PrincipalARN: "arn:" + partition + ":iam::123456789012:root", PrincipalID: "123456789012"})
}

func TestIAMAuthorizationAttachmentsAndBoundary(t *testing.T) {
	service := iam.New()
	client := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	user, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("worker"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("payments")}}})
	if err != nil {
		t.Fatal(err)
	}
	caller := userContext(user.User, "aws")
	evaluator := authorization.New(service, nil)
	req := authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueResource}
	if err := evaluator.Authorize(caller, req); err == nil {
		t.Fatal("user with no policies was allowed")
	}
	_, err = client.CreateGroup(ctx, &sdkiam.CreateGroupInput{GroupName: aws.String("workers")})
	if err != nil {
		t.Fatal(err)
	}
	groupDocument := `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"` + queueResource + `","Condition":{"StringEquals":{"aws:PrincipalTag/team":"payments","aws:username":"worker"}}}}`
	_, err = client.PutGroupPolicy(ctx, &sdkiam.PutGroupPolicyInput{GroupName: aws.String("workers"), PolicyName: aws.String("Send"), PolicyDocument: aws.String(groupDocument)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AddUserToGroup(ctx, &sdkiam.AddUserToGroupInput{GroupName: aws.String("workers"), UserName: aws.String("worker")})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluator.Authorize(caller, req); err != nil {
		t.Fatalf("group policy grant: %v", err)
	}
	snapshot, err := service.IdentityPolicies(caller)
	if err != nil || !slices.ContainsFunc(snapshot.Identity, func(p iampolicy.Policy) bool { return p.Document == groupDocument }) {
		t.Fatalf("snapshot=%+v error=%v", snapshot, err)
	}
	if len(snapshot.Identity) != 1 || snapshot.Identity[0].Source != "arn:aws:iam::123456789012:group/workers#Send" || snapshot.Identity[0].Version != "" {
		t.Fatalf("inline source metadata = %+v", snapshot.Identity)
	}
	snapshot.Identity[0].Document = "bad document"
	snapshot.PrincipalTags["team"] = "other"
	if err := evaluator.Authorize(caller, req); err != nil {
		t.Fatalf("snapshot mutation affected policies: %v", err)
	}
	denySend := `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`
	managed, err := client.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("QueueAccess"), PolicyDocument: aws.String(denySend)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AttachUserPolicy(ctx, &sdkiam.AttachUserPolicyInput{UserName: aws.String("worker"), PolicyArn: managed.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluator.Authorize(caller, req); err == nil {
		t.Fatal("group allow bypassed managed explicit deny")
	}
	previous, err := service.IdentityPolicies(caller)
	if err != nil {
		t.Fatal(err)
	}
	allowReceive := `{"Statement":{"Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"*"}}`
	_, err = client.CreatePolicyVersion(ctx, &sdkiam.CreatePolicyVersionInput{PolicyArn: managed.Policy.Arn, PolicyDocument: aws.String(allowReceive), SetAsDefault: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluator.Authorize(caller, req); err != nil {
		t.Fatalf("new default policy did not remove deny: %v", err)
	}
	current, err := service.IdentityPolicies(caller)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, version string
		snapshot      authorization.PolicySet
		decision      iampolicy.Decision
	}{
		{"retained snapshot", "v1", previous, iampolicy.ExplicitDeny},
		{"current snapshot", "v2", current, iampolicy.Allow},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := iampolicy.Authorize(iampolicy.Request{Action: req.Action, Resource: req.ResourceARN, Context: map[string][]string{"aws:PrincipalTag/team": {"payments"}, "aws:username": {"worker"}}}, iampolicy.Authorization{
				Principal: iampolicy.Principal{ARN: aws.ToString(user.User.Arn), AccountID: "123456789012", Partition: "aws", ID: aws.ToString(user.User.UserId)}, Identity: test.snapshot.Identity,
			})
			if err != nil || result.Decision != test.decision {
				t.Fatalf("snapshot decision = %+v, %v", result, err)
			}
			index := slices.IndexFunc(result.Layers[0].Policies, func(p iampolicy.PolicyEvaluation) bool { return p.Source == aws.ToString(managed.Policy.Arn) })
			if index < 0 || result.Layers[0].Policies[index].Version != test.version {
				t.Fatalf("managed source version = %+v", result.Layers[0].Policies)
			}
		})
	}
	boundary, err := client.CreatePolicy(ctx, &sdkiam.CreatePolicyInput{PolicyName: aws.String("Boundary"), PolicyDocument: aws.String(allowReceive)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PutUserPermissionsBoundary(ctx, &sdkiam.PutUserPermissionsBoundaryInput{UserName: aws.String("worker"), PermissionsBoundary: boundary.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluator.Authorize(caller, req); err == nil {
		t.Fatal("boundary did not restrict group allow")
	}
	bounded, err := service.IdentityPolicies(caller)
	if err != nil || len(bounded.Boundary) != 1 || bounded.Boundary[0].Source != aws.ToString(boundary.Policy.Arn) || bounded.Boundary[0].Version != "v1" {
		t.Fatalf("boundary source = %+v, %v", bounded.Boundary, err)
	}
	req.Action = "sqs:ReceiveMessage"
	if err := evaluator.Authorize(caller, req); err != nil {
		t.Fatalf("matching managed policy and boundary: %v", err)
	}
	_, err = client.DetachUserPolicy(ctx, &sdkiam.DetachUserPolicyInput{UserName: aws.String("worker"), PolicyArn: managed.Policy.Arn})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluator.Authorize(caller, req); err == nil {
		t.Fatal("boundary granted permission without identity allow")
	}
	_, err = client.DeleteUserPermissionsBoundary(ctx, &sdkiam.DeleteUserPermissionsBoundaryInput{UserName: aws.String("worker")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RemoveUserFromGroup(ctx, &sdkiam.RemoveUserFromGroupInput{GroupName: aws.String("workers"), UserName: aws.String("worker")})
	if err != nil {
		t.Fatal(err)
	}
	req.Action = "sqs:SendMessage"
	if err := evaluator.Authorize(caller, req); err == nil {
		t.Fatal("removed group still granted permission")
	}
}

func TestResourcePolicyPrincipalBindingLifecycle(t *testing.T) {
	service := iam.New()
	client := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	user, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("worker")})
	if err != nil {
		t.Fatal(err)
	}
	evaluator := authorization.New(service, nil)
	document := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"` + aws.ToString(user.User.Arn) + `"},"Action":"sqs:SendMessage","Resource":"*"}}`
	bound, err := evaluator.BindResourcePolicy(authRootContext("aws"), document, authorization.ResourcePolicyOptions{})
	if err != nil || bound.PrincipalIDs[aws.ToString(user.User.Arn)] != aws.ToString(user.User.UserId) {
		t.Fatalf("bound=%+v error=%v", bound, err)
	}
	req := authorization.Request{Action: "sqs:SendMessage", ResourceARN: queueResource, ResourcePolicies: []authorization.BoundPolicy{bound}}
	if err := evaluator.Authorize(userContext(user.User, "aws"), req); err != nil {
		t.Fatal(err)
	}
	_, err = client.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: aws.String("worker"), NewUserName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := client.GetUser(ctx, &sdkiam.GetUserInput{UserName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluator.Authorize(userContext(renamed.User, "aws"), req); err != nil {
		t.Fatalf("rename broke stable grant: %v", err)
	}
	rendered, err := evaluator.RenderResourcePolicy(authRootContext("aws"), bound)
	if err != nil || !strings.Contains(rendered, aws.ToString(renamed.User.Arn)) {
		t.Fatalf("renamed policy=%s error=%v", rendered, err)
	}
	_, err = client.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	newUser, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("renamed")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(newUser.User.UserId) == aws.ToString(user.User.UserId) {
		t.Fatal("new user reused immutable ID")
	}
	if err := evaluator.Authorize(userContext(newUser.User, "aws"), req); err == nil {
		t.Fatal("recreated principal inherited deleted principal's grant")
	}
	rendered, err = evaluator.RenderResourcePolicy(authRootContext("aws"), bound)
	if err != nil || !strings.Contains(rendered, aws.ToString(user.User.UserId)) {
		t.Fatalf("deleted principal not rendered as unique ID: %s error=%v", rendered, err)
	}
	if _, err = evaluator.BindResourcePolicy(authRootContext("aws"), rendered, authorization.ResourcePolicyOptions{}); !errors.Is(err, authorization.ErrInvalidPrincipal) {
		t.Fatalf("orphaned principal accepted: %v", err)
	}
	if _, err = evaluator.BindResourcePolicy(authRootContext("aws"), document, authorization.ResourcePolicyOptions{}); !errors.Is(err, authorization.ErrInvalidPrincipal) {
		t.Fatalf("unknown ARN principal accepted: %v", err)
	}
}

func TestIAMPartitionIsolationAndPrincipalResolver(t *testing.T) {
	service := iam.New()
	commercial := clientFor(t, service, "123456789012", "us-east-1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		service.ServeHTTP(w, r.WithContext(awsctx.WithMetadata(r.Context(), awsctx.Metadata{AccountID: "123456789012", Region: "cn-north-1", Partition: "aws-cn", PrincipalARN: "arn:aws-cn:iam::123456789012:root", PrincipalID: "123456789012"})))
	}))
	t.Cleanup(server.Close)
	china := sdkiam.New(sdkiam.Options{Region: "cn-north-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
	ctx := context.Background()
	a, err := commercial.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("same-name")})
	if err != nil {
		t.Fatal(err)
	}
	b, err := china.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("same-name")})
	if err != nil {
		t.Fatalf("partition scopes collided: %v", err)
	}
	if aws.ToString(a.User.UserId) == aws.ToString(b.User.UserId) || !strings.HasPrefix(aws.ToString(b.User.Arn), "arn:aws-cn:") {
		t.Fatal("partition identities were not independent")
	}
	if _, err := service.ResolvePrincipal(authRootContext("aws"), aws.ToString(b.User.Arn)); !errors.Is(err, authorization.ErrInvalidPrincipal) {
		t.Fatalf("cross-partition ARN resolved: %v", err)
	}
	if _, err := service.ResolvePrincipal(authRootContext("aws"), aws.ToString(b.User.UserId)); !errors.Is(err, authorization.ErrInvalidPrincipal) {
		t.Fatalf("cross-partition ID resolved: %v", err)
	}
	if _, err := service.IdentityPolicies(userContext(a.User, "aws-cn")); err == nil {
		t.Fatal("cross-partition IAM snapshot resolved")
	}
	other := clientFor(t, service, "999999999999", "us-east-1")
	external, err := other.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("external")})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := service.ResolvePrincipal(authRootContext("aws"), aws.ToString(external.User.Arn))
	if err != nil || resolved.ID != aws.ToString(external.User.UserId) {
		t.Fatalf("cross-account principal resolution: %+v %v", resolved, err)
	}
}

package iam_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/services/iam"
)

func TestServiceLinkedRoleAuthorizationUsesServiceAndRetainedRoleARN(t *testing.T) {
	s := iam.New()
	t.Cleanup(func() { _ = s.Close() })
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	user, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("LinkedRoleProvisioner")})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.ServeHTTP(w, r.WithContext(userContext(user.User, "aws")))
	}))
	t.Cleanup(server.Close)
	c := sdkiam.New(sdkiam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
	arn := "arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling_scoped"
	policy := `{"Statement":[{"Effect":"Allow","Action":"iam:CreateServiceLinkedRole","Resource":"` + arn + `","Condition":{"StringEquals":{"iam:AWSServiceName":"autoscaling.amazonaws.com"}}},{"Effect":"Allow","Action":["iam:DeleteServiceLinkedRole","iam:GetServiceLinkedRoleDeletionStatus"],"Resource":"` + arn + `"}]}`
	if _, err := root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("Provision"), PolicyDocument: aws.String(policy)}); err != nil {
		t.Fatal(err)
	}
	_, err = c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("ecs.amazonaws.com")})
	requireCode(t, err, "AccessDenied")
	_, err = c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("autoscaling.amazonaws.com"), CustomSuffix: aws.String("other")})
	requireCode(t, err, "AccessDenied")
	out, err := c.CreateServiceLinkedRole(ctx, &sdkiam.CreateServiceLinkedRoleInput{AWSServiceName: aws.String("autoscaling.amazonaws.com"), CustomSuffix: aws.String("scoped")})
	if err != nil {
		t.Fatalf("exact resource and service condition denied: %v", err)
	}
	if aws.ToString(out.Role.Arn) != arn {
		t.Fatalf("authorized ARN differs from created ARN: %+v", out.Role)
	}
	del, err := c.DeleteServiceLinkedRole(ctx, &sdkiam.DeleteServiceLinkedRoleInput{RoleName: out.Role.RoleName})
	if err != nil {
		t.Fatal(err)
	}
	waitLinkedStatus(t, c, aws.ToString(del.DeletionTaskId), types.DeletionTaskStatusTypeSucceeded)
	// GetStatus remains scoped to its original role after role deletion;
	// falling back to '*' would deny this otherwise valid permission.
	status, err := c.GetServiceLinkedRoleDeletionStatus(ctx, &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: del.DeletionTaskId})
	if err != nil || status.Status != types.DeletionTaskStatusTypeSucceeded {
		t.Fatalf("completed task lost role authorization: %+v, %v", status, err)
	}
	if _, err := root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: user.User.UserName, PolicyName: aws.String("Deny"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Action":"iam:GetServiceLinkedRoleDeletionStatus","Resource":"` + arn + `"}}`)}); err != nil {
		t.Fatal(err)
	}
	_, err = c.GetServiceLinkedRoleDeletionStatus(ctx, &sdkiam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: del.DeletionTaskId})
	requireCode(t, err, "AccessDenied")
}

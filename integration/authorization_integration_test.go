package stackd_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"stackd"
)

type cloudClients struct{ server *httptest.Server }

func newCloudClients(t *testing.T) cloudClients {
	t.Helper()
	cloud, err := stackd.New(stackd.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(cloud)
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		if err := cloud.Close(); err != nil {
			t.Error(err)
		}
	})
	return cloudClients{server}
}
func (c cloudClients) iam(key, secret, token string) *iam.Client {
	return iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func (c cloudClients) sts(key, secret, token string) *sts.Client {
	return sts.New(sts.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func (c cloudClients) sqs(key, secret, token string) *sqs.Client {
	return sqs.New(sqs.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func (c cloudClients) snsRegion(region, key, secret, token string) *sns.Client {
	return sns.New(sns.Options{Region: region, BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, token), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}
func (c cloudClients) sessionSTS(v *ststypes.Credentials) *sts.Client {
	return c.sts(aws.ToString(v.AccessKeyId), aws.ToString(v.SecretAccessKey), aws.ToString(v.SessionToken))
}
func (c cloudClients) sessionSQS(v *ststypes.Credentials) *sqs.Client {
	return c.sqs(aws.ToString(v.AccessKeyId), aws.ToString(v.SecretAccessKey), aws.ToString(v.SessionToken))
}
func (c cloudClients) user(t *testing.T, owner, name string) (string, string, string) {
	t.Helper()
	ctx := context.Background()
	root := c.iam(owner, "test", "")
	user, err := root.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	key, err := root.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	return aws.ToString(user.User.Arn), aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey)
}
func putUserPolicy(t *testing.T, client *iam.Client, user, document string) {
	t.Helper()
	_, err := client.PutUserPolicy(context.Background(), &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String("access"), PolicyDocument: aws.String(document)})
	if err != nil {
		t.Fatal(err)
	}
}
func putRolePolicy(t *testing.T, client *iam.Client, role, document string) {
	t.Helper()
	_, err := client.PutRolePolicy(context.Background(), &iam.PutRolePolicyInput{RoleName: aws.String(role), PolicyName: aws.String("access"), PolicyDocument: aws.String(document)})
	if err != nil {
		t.Fatal(err)
	}
}
func allow(actions, resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":%s,"Resource":%q}}`, actions, resource)
}

func TestAssumedRoleEnforcesTrustSessionAndCurrentPolicies(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	userARN, key, secret := c.user(t, "test", "caller")
	queue, err := c.sqs("test", "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("work")})
	if err != nil {
		t.Fatal(err)
	}
	queueARN := "arn:aws:sqs:us-east-1:000000000000:work"
	_, err = c.sqs(key, secret, "").SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("denied")})
	assertAPIError(t, err, "AccessDenied")
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"tenant"}}}}`, userARN)
	role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("worker"), Path: aws.String("/application/"), AssumeRolePolicyDocument: aws.String(trust), MaxSessionDuration: aws.Int32(7200)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "worker", allow(`["sqs:SendMessage","sqs:ReceiveMessage"]`, queueARN))
	assume := &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("job"), DurationSeconds: aws.Int32(900)}
	_, err = c.sts(key, secret, "").AssumeRole(ctx, assume)
	assertAPIError(t, err, "AccessDenied")
	assume.ExternalId = aws.String("tenant")
	assume.Policy = aws.String(allow(`"sqs:SendMessage"`, queueARN))
	session, err := c.sts(key, secret, "").AssumeRole(ctx, assume)
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(session.AssumedRoleUser.Arn) != "arn:aws:sts::000000000000:assumed-role/worker/job" {
		t.Fatalf("role ARN includes wrong path: %v", session.AssumedRoleUser)
	}
	who, err := c.sessionSTS(session.Credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(who.UserId) != aws.ToString(session.AssumedRoleUser.AssumedRoleId) {
		t.Fatalf("session identity: %#v, %v", who, err)
	}
	sender := c.sessionSQS(session.Credentials)
	if _, err := sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("allowed")}); err != nil {
		t.Fatal(err)
	}
	_, err = sender.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	assertAPIError(t, err, "AccessDenied")
	putRolePolicy(t, root, "worker", `{"Statement":{"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}}`)
	_, err = sender.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("denied after policy update")})
	assertAPIError(t, err, "AccessDenied")
	// Authentication and GetCallerIdentity remain valid while a permission policy denies access.
	if _, err := c.sessionSTS(session.Credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatal(err)
	}
	_, err = c.sessionSTS(session.Credentials).GetSessionToken(ctx, &sts.GetSessionTokenInput{})
	assertAPIError(t, err, "AccessDenied")
	_, err = c.sessionSTS(session.Credentials).GetFederationToken(ctx, &sts.GetFederationTokenInput{Name: aws.String("forbidden")})
	assertAPIError(t, err, "AccessDenied")
	received, err := c.sqs("test", "test", "").ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(received.Messages) != 1 {
		t.Fatalf("denied requests mutated queue: %#v %v", received, err)
	}
}

func TestCrossAccountRoleNeedsCallerPermissionAndTrust(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	_, key, secret := c.user(t, "test", "caller")
	owner := c.iam("123456789012", "test", "")
	trust := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`
	role, err := owner.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("external"), AssumeRolePolicyDocument: aws.String(trust)})
	if err != nil {
		t.Fatal(err)
	}
	in := &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("external")}
	_, err = c.sts(key, secret, "").AssumeRole(ctx, in)
	assertAPIError(t, err, "AccessDenied")
	putUserPolicy(t, c.iam("test", "test", ""), "caller", allow(`"sts:AssumeRole"`, aws.ToString(role.Role.Arn)))
	session, err := c.sts(key, secret, "").AssumeRole(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	who, err := c.sessionSTS(session.Credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(who.Account) != "123456789012" {
		t.Fatalf("cross-account session: %#v %v", who, err)
	}
	_, err = owner.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{RoleName: aws.String("external"), PolicyDocument: aws.String(`{"Statement":{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.sts(key, secret, "").AssumeRole(ctx, in)
	assertAPIError(t, err, "AccessDenied")
	// Trust changes stop new assumptions, but do not revoke an existing session.
	if _, err := c.sessionSTS(session.Credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatal(err)
	}
}

func TestRoleChainPreservesSourceAndTransitiveTags(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	userARN, key, secret := c.user(t, "test", "chaincaller")
	queue, err := c.sqs("test", "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("tagged")})
	if err != nil {
		t.Fatal(err)
	}
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]}}`, userARN)
	first, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("first"), AssumeRolePolicyDocument: aws.String(trust), MaxSessionDuration: aws.Int32(7200)})
	if err != nil {
		t.Fatal(err)
	}
	trust = fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]}}`, aws.ToString(first.Role.Arn))
	second, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("second"), AssumeRolePolicyDocument: aws.String(trust), MaxSessionDuration: aws.Int32(7200)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "first", allow(`["sts:AssumeRole","sts:TagSession","sts:SetSourceIdentity"]`, aws.ToString(second.Role.Arn)))
	putRolePolicy(t, root, "second", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"blue","aws:SourceIdentity":"origin"}}}}`)
	parent, err := c.sts(key, secret, "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: first.Role.Arn, RoleSessionName: aws.String("parent"), SourceIdentity: aws.String("origin"), Tags: []ststypes.Tag{{Key: aws.String("team"), Value: aws.String("blue")}}, TransitiveTagKeys: []string{"team"}})
	if err != nil {
		t.Fatal(err)
	}
	client := c.sessionSTS(parent.Credentials)
	in := &sts.AssumeRoleInput{RoleArn: second.Role.Arn, RoleSessionName: aws.String("child"), DurationSeconds: aws.Int32(7200)}
	_, err = client.AssumeRole(ctx, in)
	assertAPIError(t, err, "ValidationError")
	in.DurationSeconds = aws.Int32(3600)
	in.SourceIdentity = aws.String("changed")
	_, err = client.AssumeRole(ctx, in)
	assertAPIError(t, err, "AccessDenied")
	in.SourceIdentity = nil
	in.Tags = []ststypes.Tag{{Key: aws.String("TEAM"), Value: aws.String("red")}}
	_, err = client.AssumeRole(ctx, in)
	assertAPIError(t, err, "ValidationError")
	in.Tags = nil
	child, err := client.AssumeRole(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(child.SourceIdentity) != "origin" {
		t.Fatalf("source identity not inherited: %v", child.SourceIdentity)
	}
	if _, err := c.sessionSQS(child.Credentials).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("tagged")}); err != nil {
		t.Fatal(err)
	}
}

func TestFederationRequiresSessionPolicyAndRemainsRestricted(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "broker")
	putUserPolicy(t, root, "broker", allow(`["sts:GetFederationToken","sqs:SendMessage"]`, "*"))
	queue, err := c.sqs("test", "test", "").CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("federation")})
	if err != nil {
		t.Fatal(err)
	}
	caller := c.sts(key, secret, "")
	in := &sts.GetFederationTokenInput{Name: aws.String("client")}
	empty, err := caller.GetFederationToken(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.sessionSQS(empty.Credentials).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("denied")})
	assertAPIError(t, err, "AccessDenied")
	in.Policy = aws.String(allow(`"sqs:SendMessage"`, "*"))
	allowed, err := caller.GetFederationToken(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.sessionSQS(allowed.Credentials).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("allowed")}); err != nil {
		t.Fatal(err)
	}
	_, err = c.iam(aws.ToString(allowed.Credentials.AccessKeyId), aws.ToString(allowed.Credentials.SecretAccessKey), aws.ToString(allowed.Credentials.SessionToken)).ListUsers(ctx, &iam.ListUsersInput{})
	assertAPIError(t, err, "AccessDenied")
	who, err := c.sessionSTS(allowed.Credentials).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(who.Arn) != "arn:aws:sts::000000000000:federated-user/client" {
		t.Fatalf("federated identity: %#v %v", who, err)
	}
	putUserPolicy(t, root, "broker", allow(`"sts:GetFederationToken"`, "*"))
	_, err = c.sessionSQS(allowed.Credentials).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("denied after broker update")})
	assertAPIError(t, err, "AccessDenied")
	rootSession, err := c.sts("test", "test", "").GetFederationToken(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.sessionSQS(rootSession.Credentials).SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("root federation")}); err != nil {
		t.Fatal(err)
	}
}

func TestFederationEnforcesScopedResourceAndTagPermissions(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "scoped-broker")
	scoped := allow(`"sts:GetFederationToken"`, "arn:aws:sts::000000000000:federated-user/permitted")
	putUserPolicy(t, root, "scoped-broker", scoped)
	caller := c.sts(key, secret, "")
	if _, err := caller.GetFederationToken(ctx, &sts.GetFederationTokenInput{Name: aws.String("permitted")}); err != nil {
		t.Fatal(err)
	}
	_, err := caller.GetFederationToken(ctx, &sts.GetFederationTokenInput{Name: aws.String("other")})
	assertAPIError(t, err, "AccessDenied")
	input := &sts.GetFederationTokenInput{Name: aws.String("permitted"), Tags: []ststypes.Tag{{Key: aws.String("team"), Value: aws.String("blue")}}}
	_, err = caller.GetFederationToken(ctx, input)
	assertAPIError(t, err, "AccessDenied")
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetFederationToken","Resource":"arn:aws:sts::000000000000:federated-user/permitted"},{"Effect":"Allow","Action":"sts:TagSession","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/team":"blue"}}}]}`
	putUserPolicy(t, root, "scoped-broker", policy)
	if _, err := caller.GetFederationToken(ctx, input); err != nil {
		t.Fatal(err)
	}
	input.Tags[0].Value = aws.String("red")
	_, err = caller.GetFederationToken(ctx, input)
	assertAPIError(t, err, "AccessDenied")
	putUserPolicy(t, root, "scoped-broker", `{"Statement":[{"Effect":"Allow","Action":"sts:*","Resource":"*"},{"Effect":"Deny","Action":"sts:TagSession","Resource":"*"}]}`)
	input.Tags[0].Value = aws.String("blue")
	_, err = caller.GetFederationToken(ctx, input)
	assertAPIError(t, err, "AccessDenied")
}

func TestGetSessionTokenCannotCallOtherSTSOperations(t *testing.T) {
	ctx := context.Background()
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "session-caller")
	putUserPolicy(t, root, "session-caller", allow(`"sts:*"`, "*"))
	session, err := c.sts(key, secret, "").GetSessionToken(ctx, &sts.GetSessionTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.sessionSTS(session.Credentials).GetAccessKeyInfo(ctx, &sts.GetAccessKeyInfoInput{AccessKeyId: aws.String(key)})
	assertAPIError(t, err, "AccessDenied")
	if _, err := c.sts(key, secret, "").GetAccessKeyInfo(ctx, &sts.GetAccessKeyInfoInput{AccessKeyId: aws.String(key)}); err != nil {
		t.Fatal(err)
	}
}

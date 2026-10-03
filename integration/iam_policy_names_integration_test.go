package stackd_test

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/storage"
)

func TestSQLiteInlinePolicyCaseChangesControlSQSPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-names.sqlite")
	backends := &storage.Backends{}
	c, closeFirst := openSQLiteCloud(t, path, backends, nil)
	root := c.iam("test", "test", "")
	_, userKey, userSecret := c.user(t, "test", "user-sender")
	_, groupKey, groupSecret := c.user(t, "test", "group-sender")
	_, err := root.CreateGroup(t.Context(), &iam.CreateGroupInput{GroupName: aws.String("policy-group")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.AddUserToGroup(t.Context(), &iam.AddUserToGroupInput{GroupName: aws.String("policy-group"), UserName: aws.String("group-sender")})
	if err != nil {
		t.Fatal(err)
	}
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("role-sender"), AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::000000000000:root"}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("policy-name-session")})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := c.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("policy-names")})
	if err != nil {
		t.Fatal(err)
	}
	queueURL := queue.QueueUrl
	actors := []struct{ kind, key, secret, token string }{
		{"User", userKey, userSecret, ""},
		{"Group", groupKey, groupSecret, ""},
		{"Role", aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), aws.ToString(session.Credentials.SessionToken)},
	}
	put := func(kind, name, document string) {
		t.Helper()
		var err error
		switch kind {
		case "User":
			_, err = root.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: aws.String("user-sender"), PolicyName: &name, PolicyDocument: &document})
		case "Group":
			_, err = root.PutGroupPolicy(t.Context(), &iam.PutGroupPolicyInput{GroupName: aws.String("policy-group"), PolicyName: &name, PolicyDocument: &document})
		case "Role":
			_, err = root.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{RoleName: aws.String("role-sender"), PolicyName: &name, PolicyDocument: &document})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	remove := func(kind string) {
		t.Helper()
		var err error
		name := aws.String("mIxEdNaMe")
		switch kind {
		case "User":
			_, err = root.DeleteUserPolicy(t.Context(), &iam.DeleteUserPolicyInput{UserName: aws.String("user-sender"), PolicyName: name})
		case "Group":
			_, err = root.DeleteGroupPolicy(t.Context(), &iam.DeleteGroupPolicyInput{GroupName: aws.String("policy-group"), PolicyName: name})
		case "Role":
			_, err = root.DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: aws.String("role-sender"), PolicyName: name})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	allowSend := allow(`"sqs:SendMessage"`, "*")
	denySend := strings.Replace(allowSend, `"Effect":"Allow"`, `"Effect":"Deny"`, 1)
	var expected []string
	for _, actor := range actors {
		put(actor.kind, "MixedName", denySend)
		client := c.sqs(actor.key, actor.secret, actor.token)
		_, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queueURL, MessageBody: aws.String("denied")})
		assertAPIError(t, err, "AccessDenied")
		put(actor.kind, "mixedname", allowSend)
		body := actor.kind + "/before-reopen"
		if _, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queueURL, MessageBody: &body}); err != nil {
			t.Fatalf("%s policy replacement did not remove the deny: %v", actor.kind, err)
		}
		expected = append(expected, body)
	}
	closeFirst()
	c, _ = openSQLiteCloud(t, path, backends, nil)
	root = c.iam("test", "test", "")
	address, err := c.sqs("test", "test", "").GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("policy-names")})
	if err != nil {
		t.Fatal(err)
	}
	queueURL = address.QueueUrl
	for _, actor := range actors {
		client := c.sqs(actor.key, actor.secret, actor.token)
		body := actor.kind + "/after-reopen"
		if _, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queueURL, MessageBody: &body}); err != nil {
			t.Fatalf("%s policy replacement did not survive reopening: %v", actor.kind, err)
		}
		expected = append(expected, body)
		remove(actor.kind)
		_, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queueURL, MessageBody: aws.String("denied")})
		assertAPIError(t, err, "AccessDenied")
	}
	messages, err := c.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queueURL, MaxNumberOfMessages: 10})
	if err != nil {
		t.Fatal(err)
	}
	var actual []string
	for _, message := range messages.Messages {
		actual = append(actual, aws.ToString(message.Body))
	}
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		t.Fatalf("delivered messages = %v; want only authorized sends %v", actual, expected)
	}
}

package stackd_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestSQSKeyCacheCannotAuthorizeReplacementIAMIdentities(t *testing.T) {
	for _, kind := range []string{"user", "role"} {
		t.Run(kind, func(t *testing.T) {
			c := newCloudClients(t)
			root, owner, queues := c.iam("test", "test", ""), c.kms("test", "test", ""), c.sqs("test", "test", "")
			key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
			if err != nil {
				t.Fatal(err)
			}
			queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("identity-cache"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn), "VisibilityTimeout": "0"}})
			if err != nil {
				t.Fatal(err)
			}
			create := func(encryption bool) (*sqs.Client, func()) {
				t.Helper()
				policy := allow(`["sqs:SendMessage","sqs:ReceiveMessage"]`, "*")
				if encryption {
					policy = allow(`["sqs:SendMessage","sqs:ReceiveMessage","kms:GenerateDataKey","kms:Decrypt"]`, "*")
				}
				if kind == "user" {
					_, access, secret := c.user(t, "test", "queue-worker")
					putUserPolicy(t, root, "queue-worker", policy)
					return c.sqs(access, secret, ""), func() {
						if _, err := root.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{UserName: aws.String("queue-worker"), AccessKeyId: &access}); err != nil {
							t.Fatal(err)
						}
						if _, err := root.DeleteUserPolicy(t.Context(), &iam.DeleteUserPolicyInput{UserName: aws.String("queue-worker"), PolicyName: aws.String("access")}); err != nil {
							t.Fatal(err)
						}
						if _, err := root.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String("queue-worker")}); err != nil {
							t.Fatal(err)
						}
					}
				}
				role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("queue-worker"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
				if err != nil {
					t.Fatal(err)
				}
				putRolePolicy(t, root, "queue-worker", policy)
				session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("same-session")})
				if err != nil {
					t.Fatal(err)
				}
				return c.sessionSQS(session.Credentials), func() {
					if _, err := root.DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{RoleName: aws.String("queue-worker"), PolicyName: aws.String("access")}); err != nil {
						t.Fatal(err)
					}
					if _, err := root.DeleteRole(t.Context(), &iam.DeleteRoleInput{RoleName: aws.String("queue-worker")}); err != nil {
						t.Fatal(err)
					}
				}
			}
			first, remove := create(true)
			if _, err := first.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("retained")}); err != nil {
				t.Fatal(err)
			}
			if output, err := first.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl}); err != nil || len(output.Messages) != 1 {
				t.Fatal("could not prime the consumer cache", output, err)
			}
			remove()
			replacement, _ := create(false)
			_, err = replacement.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("unauthorized")})
			assertAPIError(t, err, "KMS.AccessDeniedException")
			_, err = replacement.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
			assertAPIError(t, err, "KMS.AccessDeniedException")
		})
	}
}

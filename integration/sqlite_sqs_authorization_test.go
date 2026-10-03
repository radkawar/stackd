package stackd_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd/clock"
	"stackd/storage"
)

func TestSQLiteSQSRedriveReusesTheAcceptedCallersDataKey(t *testing.T) {
	manual := clock.NewManual(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	c, _ := openSQLiteCloud(t, filepath.Join(t.TempDir(), "state.sqlite"), storage.NewMemory(), manual)
	root, owner, queues := c.iam("test", "test", ""), c.kms("test", "test", ""), c.sqs("test", "test", "")
	key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	dead, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("dead")})
	if err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:sqs:us-east-1:000000000000:dead"
	if _, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("source"), Attributes: map[string]string{"RedrivePolicy": fmt.Sprintf(`{"deadLetterTargetArn":%q,"maxReceiveCount":1}`, arn)}}); err != nil {
		t.Fatal(err)
	}
	destination, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("encrypted"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(key.KeyMetadata.Arn)}})
	if err != nil {
		t.Fatal(err)
	}
	role, err := root.CreateRole(t.Context(), &iam.CreateRoleInput{RoleName: aws.String("worker"), AssumeRolePolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "worker", allow(`["sqs:*","kms:GenerateDataKey","kms:Decrypt"]`, "*"))
	session, err := c.sts("test", "test", "").AssumeRole(t.Context(), &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("accepted")})
	if err != nil {
		t.Fatal(err)
	}
	client := c.sessionSQS(session.Credentials)
	if _, err := client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: destination.QueueUrl, MessageBody: aws.String("warm")}); err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "worker", `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"},{"Effect":"Deny","Action":"kms:*","Resource":"*"}]}`)
	if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: dead.QueueUrl, MessageBody: aws.String("redriven")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartMessageMoveTask(t.Context(), &sqs.StartMessageMoveTaskInput{SourceArn: &arn, DestinationArn: aws.String("arn:aws:sqs:us-east-1:000000000000:encrypted"), MaxNumberOfMessagesPerSecond: aws.Int32(1)}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, manual, time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		result, err := client.ListMessageMoveTasks(t.Context(), &sqs.ListMessageMoveTasksInput{SourceArn: &arn})
		if err != nil || len(result.Results) != 1 {
			t.Fatal(result, err)
		}
		task := result.Results[0]
		if aws.ToString(task.Status) == "COMPLETED" {
			if task.ApproximateNumberOfMessagesMoved != 1 {
				t.Fatal("redrive did not deliver the source message", task)
			}
			break
		}
		if aws.ToString(task.Status) != "RUNNING" || time.Now().After(deadline) {
			t.Fatal("persisting the accepted caller changed KMS cache scope", task)
		}
		time.Sleep(time.Millisecond)
	}
}

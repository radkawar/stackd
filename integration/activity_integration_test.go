package stackd_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"stackd"
	"stackd/clock"
	"stackd/storage"
	iamstorage "stackd/storage/iam"
)

type kmsActivityFailureRepository struct {
	iamstorage.Repository
	fail atomic.Bool
}

func (r *kmsActivityFailureRepository) Update(ctx context.Context, fn func(iamstorage.WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx iamstorage.WriteTx) error {
		return fn(kmsActivityFailureTx{WriteTx: tx, fail: r.fail.Load()})
	})
}

type kmsActivityFailureTx struct {
	iamstorage.WriteTx
	fail bool
}

func (tx kmsActivityFailureTx) PutPrincipalActivity(scope iamstorage.Scope, row iamstorage.PrincipalActivity) error {
	if err := tx.WriteTx.PutPrincipalActivity(scope, row); err != nil {
		return err
	}
	if tx.fail && row.ServiceNamespace == "kms" {
		return errors.New("injected KMS activity failure")
	}
	return nil
}

func TestActivityRecordsActualSQSAndKMSAttempts(t *testing.T) {
	start := time.Unix(0, 0).UTC()
	source := clock.NewManual(start)
	backends := storage.NewMemory()
	repository := &kmsActivityFailureRepository{Repository: backends.IAM}
	backends.IAM = repository
	c := clockCloud(t, stackd.Config{Clock: source, Storage: backends})
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "activity-producer")
	user, err := root.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("activity-producer")})
	if err != nil {
		t.Fatal(err)
	}
	kmsClient := func(key, secret string) *kms.Client {
		return kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	}
	k, err := kmsClient("test", "test").CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := c.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("activity-encrypted"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(k.KeyMetadata.Arn)}})
	if err != nil {
		t.Fatal(err)
	}
	sender := c.sqs(key, secret, "")
	send := func() error {
		_, err := sender.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("activity")})
		return err
	}
	read := func() map[string]iamstorage.PrincipalActivity {
		t.Helper()
		result := make(map[string]iamstorage.PrincipalActivity)
		if err := repository.View(t.Context(), func(tx iamstorage.ReadTx) error {
			rows, err := tx.PrincipalActivities(iamstorage.Scope{Partition: "aws", AccountID: "000000000000"})
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.PrincipalID == aws.ToString(user.User.UserId) {
					result[row.ServiceNamespace+":"+row.ActionName] = row
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	assertAPIError(t, send(), "AccessDenied")
	if rows := read(); len(rows) != 1 || rows["sqs:SendMessage"].ActionName != "SendMessage" {
		t.Fatalf("denied SQS request invented KMS activity: %+v", rows)
	}
	putUserPolicy(t, root, "activity-producer", allow(`"sqs:SendMessage"`, "*"))
	assertAPIError(t, send(), "KMS.AccessDeniedException")
	if rows := read(); len(rows) != 2 || rows["kms:GenerateDataKey"].ActionName != "GenerateDataKey" {
		t.Fatalf("denied nested KMS attempt missing or invented decrypt: %+v", rows)
	}
	advanceClock(t, source, time.Second)
	putUserPolicy(t, root, "activity-producer", allow(`["sqs:SendMessage","kms:GenerateDataKey","kms:Decrypt"]`, "*"))
	if err := send(); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, time.Second)
	if err := send(); err != nil {
		t.Fatal(err)
	}
	rows := read()
	if len(rows) != 3 || !rows["sqs:SendMessage"].LastAuthenticated.Equal(start.Add(2*time.Second)) || !rows["kms:GenerateDataKey"].LastAuthenticated.Equal(start.Add(time.Second)) || !rows["kms:Decrypt"].LastAuthenticated.Equal(start.Add(time.Second)) {
		t.Fatalf("SQS key-cache reuse recorded nonexistent KMS calls: %+v", rows)
	}
	_, err = kmsClient(key, secret).Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyMetadata.Arn, Plaintext: []byte("denied")})
	assertAPIError(t, err, "AccessDeniedException")
	if rows := read(); len(rows) != 4 || rows["kms:Encrypt"].PrincipalARN != aws.ToString(user.User.Arn) {
		t.Fatalf("direct JSON KMS attempt missing: %+v", rows)
	}
	usage, err := root.GetAccessKeyLastUsed(t.Context(), &iam.GetAccessKeyLastUsedInput{AccessKeyId: &key})
	if err != nil || aws.ToString(usage.AccessKeyLastUsed.ServiceName) != "sqs" || !aws.ToTime(usage.AccessKeyLastUsed.LastUsedDate).Equal(start) {
		t.Fatalf("nested calls rewrote coalesced credential use: %+v %v", usage, err)
	}
	// Expire the SQS key cache, then fail the nested activity transaction. The
	// outer SQS attempt survives; neither a key-cache entry nor a message does.
	advanceClock(t, source, 5*time.Minute)
	repository.fail.Store(true)
	err = send()
	assertAPIError(t, err, "ServiceFailure")
	repository.fail.Store(false)
	rows = read()
	if !rows["sqs:SendMessage"].LastAuthenticated.Equal(source.Now()) || !rows["kms:GenerateDataKey"].LastAuthenticated.Equal(start.Add(time.Second)) {
		t.Fatalf("nested failure crossed activity transaction boundary: %+v", rows)
	}
	messages, err := c.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(messages.Messages) != 2 {
		t.Fatalf("failed operations changed message delivery: %+v %v", messages, err)
	}
}

func TestActivityCrossAccountResourceUsesCallerScope(t *testing.T) {
	backends := storage.NewMemory()
	c := clockCloud(t, stackd.Config{Storage: backends})
	owner := c.sqs("test", "test", "")
	queue, err := owner.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("cross-account-activity")})
	if err != nil {
		t.Fatal(err)
	}
	const account = "123456789012"
	arn, key, secret := c.user(t, account, "activity-caller")
	policy := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sqs:SendMessage","Resource":"*"}}`, arn)
	if _, err := owner.SetQueueAttributes(t.Context(), &sqs.SetQueueAttributesInput{QueueUrl: queue.QueueUrl, Attributes: map[string]string{"Policy": policy}}); err != nil {
		t.Fatal(err)
	}
	putUserPolicy(t, c.iam(account, "test", ""), "activity-caller", allow(`"sqs:SendMessage"`, "*"))
	if _, err := c.sqs(key, secret, "").SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("cross-account")}); err != nil {
		t.Fatal(err)
	}
	if err := backends.IAM.View(t.Context(), func(tx iamstorage.ReadTx) error {
		user, err := tx.User(iamstorage.Scope{Partition: "aws", AccountID: account}, "activity-caller")
		if err != nil {
			return err
		}
		for _, scopeAccount := range []string{account, "000000000000"} {
			rows, err := tx.PrincipalActivities(iamstorage.Scope{Partition: "aws", AccountID: scopeAccount})
			if err != nil {
				return err
			}
			found := 0
			for _, row := range rows {
				if row.PrincipalID == user.UserId {
					found++
					if row.PrincipalARN != arn || row.ServiceNamespace != "sqs" || row.ActionName != "SendMessage" {
						return fmt.Errorf("wrong cross-account activity: %+v", row)
					}
				}
			}
			if (scopeAccount == account && found != 1) || (scopeAccount != account && found != 0) {
				return fmt.Errorf("activity in account %s: %d; resource owner must not replace caller scope", scopeAccount, found)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

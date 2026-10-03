package stackd_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/storage"
	iamstore "stackd/storage/iam"
)

// retainedCloud reconstructs services over the same memory domain or SQLite file.
// Each reopen closes the previous HTTP server and workers before opening storage.
func retainedCloud(t *testing.T, backend string, config stackd.Config, start ...func(stackd.Config) (*stackd.Stack, *httptest.Server)) (cloudClients, func() cloudClients) {
	t.Helper()
	config.Storage = storage.NewMemory()
	path := filepath.Join(t.TempDir(), "state.sqlite")
	var closeCurrent func()
	open := func() cloudClients {
		t.Helper()
		if closeCurrent != nil {
			closeCurrent()
			closeCurrent = nil
		}
		var closeDatabase func()
		if backend == "sqlite" {
			config.Storage, closeDatabase = openSQLiteBackends(t, path)
		}
		var cloud *stackd.Stack
		var server *httptest.Server
		if len(start) != 0 {
			cloud, server = start[0](config)
		} else {
			var err error
			cloud, err = stackd.New(config)
			if err != nil {
				t.Fatal(err)
			}
			server = httptest.NewServer(cloud)
		}
		closeCurrent = func() {
			if err := cloud.Close(); err != nil {
				t.Error(err)
			}
			server.Close()
			if closeDatabase != nil {
				closeDatabase()
			}
		}
		t.Cleanup(closeCurrent)
		return cloudClients{server}
	}
	return open(), open
}

// startPublicCloud binds the actual origin before services issue signed URLs or
// SNS signing-certificate links. The caller owns server and stack shutdown.
func startPublicCloud(t *testing.T, config stackd.Config) (*stackd.Stack, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	config.PublicEndpoint = "http://" + server.Listener.Addr().String()
	cloud, err := stackd.New(config)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	server.Config.Handler = cloud
	server.Start()
	return cloud, server
}

// This wrapper uses only public storage contracts, as an external backend would.
// Rejecting the completed rename must roll back both IAM and credential rows.
type rejectRenameRepository struct{ iamstore.Repository }

func (r *rejectRenameRepository) Update(ctx context.Context, fn func(iamstore.WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx iamstore.WriteTx) error {
		if err := fn(tx); err != nil {
			return err
		}
		_, err := tx.User(iamstore.Scope{Partition: "aws", AccountID: "000000000000"}, "renamed")
		if err == nil {
			return errors.New("injected commit failure")
		}
		if !errors.Is(err, iamstore.ErrRecordNotFound) {
			return err
		}
		return nil
	})
}

func TestInjectedStoragePreservesCrossServiceState(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) { testInjectedStoragePreservesCrossServiceState(t, backend) })
	}
}

func testInjectedStoragePreservesCrossServiceState(t *testing.T, backend string) {
	backends := storage.NewMemory()
	backends.IAM = &rejectRenameRepository{backends.IAM}
	path := filepath.Join(t.TempDir(), "state.sqlite")
	start := func() (cloudClients, func()) {
		closeDatabase := func() {}
		if backend == "sqlite" {
			backends, closeDatabase = openSQLiteBackends(t, path)
			backends.IAM = &rejectRenameRepository{backends.IAM}
		}
		cloud, err := stackd.New(stackd.Config{Storage: backends})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(cloud)
		closeStack := func() {
			server.Close()
			if err := cloud.Close(); err != nil {
				t.Error(err)
			}
			closeDatabase()
		}
		t.Cleanup(closeStack)
		return cloudClients{server}, closeStack
	}
	orgClient := func(c cloudClients) *organizations.Client {
		return organizations.New(organizations.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	}
	c, closeFirst := start()
	root := c.iam("test", "test", "")
	arn, key, secret := c.user(t, "test", "stored")
	putUserPolicy(t, root, "stored", allow(`["sqs:SendMessage","kms:GenerateDataKey","kms:Decrypt"]`, "*"))
	_, err := root.UpdateUser(t.Context(), &iam.UpdateUserInput{UserName: aws.String("stored"), NewUserName: aws.String("renamed")})
	assertAPIError(t, err, "ServiceFailure")
	if _, err := root.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String("stored")}); err != nil {
		t.Fatal("failed rename changed IAM state:", err)
	}
	org, err := orgClient(c).CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{})
	if err != nil {
		t.Fatal(err)
	}
	keys := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
	encryptionKey, err := keys.CreateKey(t.Context(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := c.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("stored"), Attributes: map[string]string{"KmsMasterKeyId": aws.ToString(encryptionKey.KeyMetadata.Arn)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.sqs(key, secret, "").SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("stored encrypted message")}); err != nil {
		t.Fatal(err)
	}
	closeFirst()

	// Reconstruct services, reopening the file for SQLite. The failed rename
	// must preserve both the IAM principal and its signing credentials.
	c, _ = start()
	who, err := c.sts(key, secret, "").GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	if err != nil || aws.ToString(who.Arn) != arn {
		t.Fatalf("credential state after failed rename/reconstruction: %v, %v", who, err)
	}
	gotOrg, err := orgClient(c).DescribeOrganization(t.Context(), &organizations.DescribeOrganizationInput{})
	if err != nil || aws.ToString(gotOrg.Organization.Id) != aws.ToString(org.Organization.Id) {
		t.Fatalf("injected Organizations state lost: %v, %v", gotOrg, err)
	}
	queues := c.sqs("test", "test", "")
	url, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("stored")})
	if err != nil {
		t.Fatal(err)
	}
	received, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url.QueueUrl})
	if err != nil || len(received.Messages) != 1 || aws.ToString(received.Messages[0].Body) != "stored encrypted message" {
		t.Fatalf("injected SQS/KMS state lost: %v, %v", received, err)
	}
}

func TestStorageConfigurationRejectsIncompleteBackends(t *testing.T) {
	for _, name := range []string{"Journal", "IAM", "KMS", "Organizations", "SQS", "typed nil"} {
		t.Run(name, func(t *testing.T) {
			backends := storage.NewMemory()
			switch name {
			case "Journal":
				backends.Journal = nil
			case "IAM":
				backends.IAM = nil
			case "KMS":
				backends.KMS = nil
			case "Organizations":
				backends.Organizations = nil
			case "SQS":
				backends.SQS = nil
			case "typed nil":
				backends.IAM = (*rejectRenameRepository)(nil)
			}
			cloud, err := stackd.New(stackd.Config{Storage: backends})
			if err == nil {
				_ = cloud.Close()
				t.Fatal("incomplete backend bundle accepted")
			}
		})
	}
}

package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/storage"
	iamstore "stackd/storage/iam"
	orgstore "stackd/storage/organizations"
	sqsstore "stackd/storage/sqs"
)

func TestServiceJobsSDKDrainAndRecovery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, reopen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reopen=%t", backend, reopen), func(t *testing.T) {
				ctx := t.Context()
				epoch := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
				manual := clock.NewManual(epoch)
				path := filepath.Join(t.TempDir(), "jobs.sqlite")
				retained := storage.NewMemory()
				order := &observedJobOrder{}
				start := func() (*stackd.Stack, cloudClients, func()) {
					backends := *retained
					closeDB := func() {}
					if backend == "sqlite" {
						opened, close := openSQLiteBackends(t, path)
						backends, closeDB = *opened, close
					}
					backends.IAM = &observedJobIAM{Repository: backends.IAM, order: order}
					backends.Organizations = &observedJobOrganizations{Storage: backends.Organizations, order: order}
					backends.SQS = &observedJobSQS{Repository: backends.SQS, order: order}
					cloud, err := stackd.New(stackd.Config{Storage: &backends, Clock: manual})
					if err != nil {
						t.Fatal(err)
					}
					server := httptest.NewServer(cloud)
					close := func() { server.Close(); _ = cloud.Close(); closeDB() }
					t.Cleanup(close)
					return cloud, cloudClients{server}, close
				}
				cloud, c, closeFirst := start()
				org := c.organizations("test", "test")
				if _, err := org.CreateOrganization(ctx, &organizations.CreateOrganizationInput{}); err != nil {
					t.Fatal(err)
				}
				// Admit in the opposite order to the source tie-break: SQS, then
				// Organizations, then IAM. Every job is due at epoch + 1s.
				queues := c.sqs("test", "test", "")
				createQueue := func(name string, attributes map[string]string) *string {
					out, err := queues.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: &name, Attributes: attributes})
					if err != nil {
						t.Fatal(err)
					}
					return out.QueueUrl
				}
				dead := createQueue("dead", nil)
				deadARN := "arn:aws:sqs:us-east-1:000000000000:dead"
				createQueue("source", map[string]string{"RedrivePolicy": fmt.Sprintf(`{"deadLetterTargetArn":%q,"maxReceiveCount":1}`, deadARN)})
				createQueue("destination", nil)
				if _, err := queues.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: dead, MessageBody: aws.String("recover this message")}); err != nil {
					t.Fatal(err)
				}
				if _, err := queues.StartMessageMoveTask(ctx, &sqs.StartMessageMoveTaskInput{SourceArn: &deadARN, DestinationArn: aws.String("arn:aws:sqs:us-east-1:000000000000:destination"), MaxNumberOfMessagesPerSecond: aws.Int32(1)}); err != nil {
					t.Fatal(err)
				}
				created, err := org.CreateAccount(ctx, &organizations.CreateAccountInput{AccountName: aws.String("joined"), Email: aws.String("joined@example.test")})
				if err != nil {
					t.Fatal(err)
				}
				root := c.iam("test", "test", "")
				user, err := root.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String("report-owner")})
				if err != nil {
					t.Fatal(err)
				}
				report, err := root.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{Arn: user.User.Arn})
				if err != nil {
					t.Fatal(err)
				}
				before, err := cloud.RunDueJobs(ctx, 10)
				if err != nil || before.Processed != 0 || before.More || before.Next == nil || !before.Next.Equal(epoch.Add(time.Second)) {
					t.Fatal("future jobs ran early or lost their deadline", before, err)
				}
				if reopen {
					closeFirst()
				}
				advanceClock(t, manual, time.Second)
				if reopen {
					cloud, c, _ = start()
				}
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server.URL+"/_stackd/jobs/drain?limit=10", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := c.server.Client().Do(request)
				if err != nil {
					t.Fatal(err)
				}
				var result stackd.JobDrainResult
				err = json.NewDecoder(response.Body).Decode(&result)
				response.Body.Close()
				// The automatic worker may win the drain gate. The explicit drain
				// must then observe its completed work, without another advance.
				if err != nil || response.StatusCode != http.StatusOK || result.More || !cloud.ServiceTime().Equal(epoch.Add(time.Second)) {
					t.Fatal("drain did not reach the current horizon", result, response.Status, err)
				}
				if got := order.snapshot(); !slices.Equal(got, []string{"iam", "organizations", "sqs"}) {
					t.Fatal("equal-deadline jobs completed out of source order", got)
				}
				details, err := c.iam("test", "test", "").GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{JobId: report.JobId})
				if err != nil || details.JobStatus != iamtypes.JobStatusTypeCompleted || !aws.ToTime(details.JobCompletionDate).Equal(manual.Now()) {
					t.Fatal("IAM report was not completed", details, err)
				}
				account, err := c.organizations("test", "test").DescribeCreateAccountStatus(ctx, &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: created.CreateAccountStatus.Id})
				if err != nil || account.CreateAccountStatus.State != orgtypes.CreateAccountStateSucceeded || !aws.ToTime(account.CreateAccountStatus.CompletedTimestamp).Equal(manual.Now()) {
					t.Fatal("account was not provisioned", account, err)
				}
				roleARN := fmt.Sprintf("arn:aws:iam::%s:role/OrganizationAccountAccessRole", aws.ToString(account.CreateAccountStatus.AccountId))
				if _, err := c.sts("test", "test", "").AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &roleARN, RoleSessionName: aws.String("joined-jobs")}); err != nil {
					t.Fatal("account completion did not publish its access role", err)
				}
				queues = c.sqs("test", "test", "")
				tasks, err := queues.ListMessageMoveTasks(ctx, &sqs.ListMessageMoveTasksInput{SourceArn: &deadARN})
				if err != nil || len(tasks.Results) != 1 || aws.ToString(tasks.Results[0].Status) != "COMPLETED" || tasks.Results[0].ApproximateNumberOfMessagesMoved != 1 {
					t.Fatal("redrive was not completed", tasks, err)
				}
				destination, err := queues.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: aws.String("destination")})
				if err != nil {
					t.Fatal(err)
				}
				messages, err := queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: destination.QueueUrl})
				if err != nil || len(messages.Messages) != 1 || aws.ToString(messages.Messages[0].Body) != "recover this message" {
					t.Fatal("redrive lost the delivered payload", messages, err)
				}
			})
		}
	}
}

// Observe terminal writes through the injected production storage contracts.
// Later API calls can save those records again, so record each source once.
type observedJobOrder struct {
	mu    sync.Mutex
	order []string
}

func (o *observedJobOrder) record(source string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !slices.Contains(o.order, source) {
		o.order = append(o.order, source)
	}
}

func (o *observedJobOrder) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.order)
}

type observedJobIAM struct {
	iamstore.Repository
	order *observedJobOrder
}

func (r *observedJobIAM) Update(ctx context.Context, fn func(iamstore.WriteTx) error) error {
	return r.Repository.Update(ctx, func(tx iamstore.WriteTx) error { return fn(observedJobIAMTx{tx, r.order}) })
}

type observedJobIAMTx struct {
	iamstore.WriteTx
	order *observedJobOrder
}

func (tx observedJobIAMTx) PutAccessReport(scope iamstore.Scope, report iamstore.AccessReport) error {
	err := tx.WriteTx.PutAccessReport(scope, report)
	if err == nil && report.CompletedAt != nil {
		tx.order.record("iam")
	}
	return err
}

type observedJobOrganizations struct {
	orgstore.Storage
	order *observedJobOrder
}

func (s *observedJobOrganizations) CompareAndSwap(ctx context.Context, partition string, revision uint64, record orgstore.PartitionRecord, commit func(context.Context) error) (bool, error) {
	ok, err := s.Storage.CompareAndSwap(ctx, partition, revision, record, commit)
	if ok && err == nil {
		for _, org := range record.Organizations {
			for _, job := range org.Creations {
				if job.State == "SUCCEEDED" {
					s.order.record("organizations")
				}
			}
		}
	}
	return ok, err
}

type observedJobSQS struct {
	sqsstore.Repository
	order *observedJobOrder
}

func (r *observedJobSQS) Update(ctx context.Context, fn func(sqsstore.Transaction) error) error {
	return r.Repository.Update(ctx, func(tx sqsstore.Transaction) error { return fn(observedJobSQSTx{tx, r.order}) })
}

type observedJobSQSTx struct {
	sqsstore.Transaction
	order *observedJobOrder
}

func (tx observedJobSQSTx) PutMoveTask(task sqsstore.MoveTaskRecord) error {
	err := tx.Transaction.PutMoveTask(task)
	if err == nil && task.Status == "COMPLETED" {
		tx.order.record("sqs")
	}
	return err
}

func TestJobDrainHTTPRejectsInvalidRequestsAndClosedStack(t *testing.T) {
	c := clockCloud(t, stackd.Config{})
	cloud := c.server.Config.Handler.(*stackd.Stack)
	for _, test := range []struct {
		method, query string
		status        int
	}{
		{http.MethodGet, "", http.StatusMethodNotAllowed},
		{http.MethodPost, "?limit=bad", http.StatusBadRequest},
		{http.MethodPost, "?limit=0", http.StatusBadRequest},
		{http.MethodPost, "?limit=-1", http.StatusBadRequest},
		{http.MethodPost, "", http.StatusOK},
	} {
		request := httptest.NewRequest(test.method, "/_stackd/jobs/drain"+test.query, nil)
		response := httptest.NewRecorder()
		cloud.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatal(test, response.Code, response.Body.String())
		}
	}
	if err := cloud.Close(); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	cloud.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/_stackd/jobs/drain", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("closed stack accepted work", response.Code, response.Body.String())
	}
}

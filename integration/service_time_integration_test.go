package stackd_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
	sqlclock "stackd/storage/sqlite/clock"
)

func clockRequest(t *testing.T, c cloudClients, method, body string, status int) time.Time {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, c.server.URL+"/_stackd/clock", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := c.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		b, _ := io.ReadAll(response.Body)
		t.Fatalf("clock status %d: %s", response.StatusCode, b)
	}
	if status != http.StatusOK {
		return time.Time{}
	}
	var out struct {
		Time time.Time `json:"time"`
	}
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Time
}

func TestPersistentServiceTimeRecoversJobsVisibilityAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "time.sqlite")
	start := time.Date(2031, 2, 3, 4, 5, 0, 123456789, time.UTC)
	open := func(initial *time.Time) (cloudClients, func()) {
		db, err := sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		source, err := clock.OpenManual(t.Context(), sqlclock.New(db), initial)
		if err != nil || source == nil {
			t.Fatal("missing persistent clock", err)
		}
		backends, err := sqlbackends.New(t.Context(), db)
		if err != nil {
			t.Fatal(err)
		}
		handler, err := stackd.New(stackd.Config{Storage: backends, Clock: source})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(handler)
		close := func() {
			if err := handler.Close(); err != nil {
				t.Error(err)
			}
			server.Close()
			if err := db.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Cleanup(close)
		return cloudClients{server}, close
	}
	c, close := open(&start)
	if got := clockRequest(t, c, http.MethodGet, "", http.StatusOK); !got.Equal(start) {
		t.Fatal("initial service time differs", got)
	}
	session, err := c.sts("test", "test", "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{DurationSeconds: aws.Int32(900)})
	if err != nil {
		t.Fatal(err)
	}
	queues := c.sqs("test", "test", "")
	queue, err := queues.CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("timed"), Attributes: map[string]string{"VisibilityTimeout": "120"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queues.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String("recover visibility")}); err != nil {
		t.Fatal(err)
	}
	held, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl})
	if err != nil || len(held.Messages) != 1 {
		t.Fatal("initial delivery", err)
	}
	org := c.organizations("test", "test")
	if _, err := org.CreateOrganization(t.Context(), &organizations.CreateOrganizationInput{}); err != nil {
		t.Fatal(err)
	}
	job, err := org.CreateAccount(t.Context(), &organizations.CreateAccountInput{AccountName: aws.String("clock-member"), Email: aws.String("clock-member@example.test")})
	if err != nil || job.CreateAccountStatus.State != orgtypes.CreateAccountStateInProgress {
		t.Fatal("creation was not pending", err)
	}
	close()
	c, close = open(nil)
	if got := clockRequest(t, c, http.MethodGet, "", http.StatusOK); !got.Equal(start) {
		t.Fatal("restart advanced or reset manual time", got)
	}
	pending, err := c.organizations("test", "test").DescribeCreateAccountStatus(t.Context(), &organizations.DescribeCreateAccountStatusInput{CreateAccountRequestId: job.CreateAccountStatus.Id})
	if err != nil || pending.CreateAccountStatus.State != orgtypes.CreateAccountStateInProgress {
		t.Fatal("recovery skipped the stored deadline", err)
	}
	if got := clockRequest(t, c, http.MethodPost, `{"advance":"2m"}`, http.StatusOK); !got.Equal(start.Add(2 * time.Minute)) {
		t.Fatal("advance result differs", got)
	}
	// Stop immediately; recovery must not depend on waiting for the timer's
	// goroutine to finish after the acknowledged clock commit.
	close()
	c, close = open(nil)
	status := waitAccountCreation(t, c.organizations("test", "test"), job.CreateAccountStatus, nil)
	// Organizations uses floating-point epoch timestamps; the SDK cannot
	// preserve every nanosecond. Clock-control responses retain RFC3339 nanos.
	if status.State != orgtypes.CreateAccountStateSucceeded || status.CompletedTimestamp == nil || status.CompletedTimestamp.UnixMilli() != start.Add(2*time.Minute).UnixMilli() {
		t.Fatalf("recovered account work: state=%s completed=%v", status.State, status.CompletedTimestamp)
	}
	queues = c.sqs("test", "test", "")
	url, err := queues.GetQueueUrl(t.Context(), &sqs.GetQueueUrlInput{QueueName: aws.String("timed")})
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := queues.ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: url.QueueUrl, MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{sqstypes.MessageSystemAttributeNameAll}})
	if err != nil || len(delivered.Messages) != 1 || delivered.Messages[0].Attributes["ApproximateReceiveCount"] != "2" {
		t.Fatal("visibility deadline did not survive clock recovery", err)
	}
	if _, err := c.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{}); err != nil {
		t.Fatal("unexpired session was lost", err)
	}
	clockRequest(t, c, http.MethodPost, `{"advance":"13m"}`, http.StatusOK)
	close()
	c, _ = open(nil)
	if got := clockRequest(t, c, http.MethodGet, "", http.StatusOK); !got.Equal(start.Add(15 * time.Minute)) {
		t.Fatal("expiry instant was not retained", got)
	}
	_, err = c.sessionSTS(session.Credentials).GetCallerIdentity(t.Context(), &sts.GetCallerIdentityInput{})
	assertAPIError(t, err, "ExpiredToken")
}

func TestClockControlRejectsInvalidAdvances(t *testing.T) {
	source := clock.NewManual(time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	original := source.Now()
	for _, body := range []string{`{"advance":"-1s"}`, `{"advance":"invalid"}`, `{"advance":42}`, `{"advance":"1s","ignored":true}`, `{"advance":"1s"} {"advance":"2s"}`} {
		clockRequest(t, c, http.MethodPost, body, http.StatusBadRequest)
		if !source.Now().Equal(original) {
			t.Fatal("invalid control changed service time")
		}
	}
	clockRequest(t, c, http.MethodDelete, "", http.StatusMethodNotAllowed)
	wall := newCloudClients(t)
	clockRequest(t, wall, http.MethodPost, `{"advance":"1s"}`, http.StatusConflict)
	handler := c.server.Config.Handler.(*stackd.Stack)
	if got, err := handler.AdvanceTime(t.Context(), time.Second); err != nil || !got.Equal(original.Add(time.Second)) {
		t.Fatal("embedding advance failed", got, err)
	}
}

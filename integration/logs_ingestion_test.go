package stackd_test

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"stackd"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

func logsClient(c cloudClients, key string) *cloudwatchlogs.Client {
	return cloudwatchlogs.New(cloudwatchlogs.Options{Region: "us-east-1", BaseEndpoint: aws.String(c.server.URL), Credentials: credentials.NewStaticCredentialsProvider(key, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestLogsNativeIngestionSDK(t *testing.T) {
	var fixture struct {
		Anchor       int64 `json:"clock_anchor_ms"`
		Observations []struct {
			Label, Operation string
			Input            json.RawMessage
			Started          int64 `json:"request_started_ms"`
			Result           struct {
				Code   string
				Output json.RawMessage
			}
		}
		Pagination struct {
			Forward, Backward struct {
				Messages [][]string `json:"messages_in_page_order"`
			}
		}
	}
	data, err := os.ReadFile("../testdata/aws/logs/ingestion.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "logs.sqlite")
			backends := storage.NewMemory()
			closeDB := func() {}
			if backend == "sqlite" {
				backends, closeDB = openSQLiteBackends(t, path)
			}
			source := clock.NewManual(time.UnixMilli(fixture.Anchor).UTC())
			cloud, err := stackd.New(stackd.Config{AccountID: "123456789012", Storage: backends, Clock: source})
			if err != nil {
				t.Fatal(err)
			}
			c := cloudClients{httptest.NewServer(cloud)}
			close := c.server.Close
			defer func() { close(); _ = cloud.Close(); closeDB() }()
			client := logsClient(c, "test")
			const group, stream = "/stackd/native-logs-ingestion-owned", "owned-sequence"
			pagination := func() {
				t.Helper()
				for _, direction := range []string{"forward", "backward"} {
					var token *string
					var messages []string
					terminal := false
					for range 20 {
						out, err := client.GetLogEvents(t.Context(), &cloudwatchlogs.GetLogEventsInput{LogGroupName: aws.String(group), LogStreamName: aws.String(stream), StartFromHead: aws.Bool(direction == "forward"), Limit: aws.Int32(3), NextToken: token})
						if err != nil {
							t.Fatal(err)
						}
						for i, event := range out.Events {
							if i > 0 && aws.ToInt64(event.Timestamp) < aws.ToInt64(out.Events[i-1].Timestamp) {
								t.Fatal("page is not chronological", out.Events)
							}
							messages = append(messages, aws.ToString(event.Message))
						}
						next := out.NextForwardToken
						if direction == "backward" {
							next = out.NextBackwardToken
						}
						if next == nil {
							t.Fatal("missing directional token")
						}
						if token != nil && *token == *next {
							terminal = true
							break
						}
						token = next
					}
					var expected []string
					pages := fixture.Pagination.Forward.Messages
					if direction == "backward" {
						pages = fixture.Pagination.Backward.Messages
					}
					for _, page := range pages {
						expected = append(expected, page...)
					}
					if !terminal || !reflect.DeepEqual(messages, expected) {
						t.Fatalf("%s pagination: %v, native %v, terminal %v", direction, messages, expected, terminal)
					}
				}
			}
			for _, row := range fixture.Observations {
				if row.Label == "delete-group" {
					pagination()
					_, err := logsClient(c, "444444444444").GetLogEvents(t.Context(), &cloudwatchlogs.GetLogEventsInput{LogGroupName: aws.String(group), LogStreamName: aws.String(stream)})
					assertAPIError(t, err, "ResourceNotFoundException")
					close()
					if err := cloud.Close(); err != nil {
						t.Fatal(err)
					}
					closeDB()
					if backend == "sqlite" {
						backends, closeDB = openSQLiteBackends(t, path)
					}
					cloud, err = stackd.New(stackd.Config{AccountID: "123456789012", Storage: backends, Clock: source})
					if err != nil {
						t.Fatal(err)
					}
					c = cloudClients{httptest.NewServer(cloud)}
					close = c.server.Close
					client = logsClient(c, "test")
					pagination()
				}
				// Native success reads include eventual visibility samples and native
				// opaque tokens. Replay stable time-bound queries, not transient loss.
				if row.Operation == "get-log-events" && row.Result.Code == "Success" && !strings.HasPrefix(row.Label, "boundaries-") {
					continue
				}
				if row.Operation == "describe-log-streams" && row.Result.Code == "Success" {
					continue
				}
				if at := time.UnixMilli(row.Started); at.After(source.Now()) {
					advanceClock(t, source, at.Sub(source.Now()))
				}
				operation := ""
				for _, word := range strings.Split(row.Operation, "-") {
					operation += strings.ToUpper(word[:1]) + word[1:]
				}
				out, err := awstest.CallSDK(t.Context(), client, operation, row.Input, func(value any) {
					input, ok := value.(*cloudwatchlogs.PutLogEventsInput)
					if !ok {
						return
					}
					var construction struct {
						LogEvents []struct {
							MessageConstruction struct {
								Repeat string
								Count  int
							}
						}
					}
					if err := json.Unmarshal(row.Input, &construction); err != nil {
						t.Fatal(err)
					}
					for i, event := range construction.LogEvents {
						if event.MessageConstruction.Count != 0 {
							input.LogEvents[i].Message = aws.String(strings.Repeat(event.MessageConstruction.Repeat, event.MessageConstruction.Count))
						}
					}
				})
				if row.Result.Code != "Success" {
					assertAPIError(t, err, row.Result.Code)
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", row.Label, err)
				}
				switch out := out.(type) {
				case *cloudwatchlogs.PutLogEventsOutput:
					var expected struct {
						RejectedLogEventsInfo *logtypes.RejectedLogEventsInfo
					}
					if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(out.RejectedLogEventsInfo, expected.RejectedLogEventsInfo) {
						t.Fatalf("%s rejection indices: %+v, native %+v", row.Label, out.RejectedLogEventsInfo, expected.RejectedLogEventsInfo)
					}
				case *cloudwatchlogs.ListTagsForResourceOutput:
					var expected struct{ Tags map[string]string }
					if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(out.Tags, expected.Tags) {
						t.Fatalf("%s tags: %v, native %v", row.Label, out.Tags, expected.Tags)
					}
				case *cloudwatchlogs.DescribeLogGroupsOutput:
					var expected struct{ LogGroups []logtypes.LogGroup }
					if err := json.Unmarshal(row.Result.Output, &expected); err != nil {
						t.Fatal(err)
					}
					if len(out.LogGroups) != len(expected.LogGroups) {
						t.Fatalf("%s group selection: %v", row.Label, out.LogGroups)
					}
					for i, group := range out.LogGroups {
						if !reflect.DeepEqual(group.RetentionInDays, expected.LogGroups[i].RetentionInDays) {
							t.Fatalf("%s retention: %v, native %v", row.Label, group.RetentionInDays, expected.LogGroups[i].RetentionInDays)
						}
					}
				case *cloudwatchlogs.GetLogEventsOutput:
					// A native boundary capture can be a partial page even when
					// its limit is omitted. Compare the complete selected range
					// against the native forward corpus, not one page's size.
					var input cloudwatchlogs.GetLogEventsInput
					if err := json.Unmarshal(row.Input, &input); err != nil {
						t.Fatal(err)
					}
					var expected, actual []logtypes.OutputLogEvent
					for _, page := range fixture.Observations {
						if !strings.HasPrefix(page.Label, "get-forward-page-") {
							continue
						}
						var native struct{ Events []logtypes.OutputLogEvent }
						if err := json.Unmarshal(page.Result.Output, &native); err != nil {
							t.Fatal(err)
						}
						for _, event := range native.Events {
							if *event.Timestamp >= *input.StartTime && *event.Timestamp < *input.EndTime {
								event.IngestionTime = nil
								expected = append(expected, event)
							}
						}
					}
					terminal := false
					for range 20 {
						for _, event := range out.Events {
							event.IngestionTime = nil
							actual = append(actual, event)
						}
						if input.NextToken != nil && aws.ToString(out.NextForwardToken) == *input.NextToken {
							terminal = true
							break
						}
						input.NextToken = out.NextForwardToken
						out, err = client.GetLogEvents(t.Context(), &input)
						if err != nil {
							t.Fatal(err)
						}
					}
					if !terminal || !reflect.DeepEqual(actual, expected) {
						t.Fatalf("%s complete boundary range: %v, native %v, terminal %v", row.Label, actual, expected, terminal)
					}
				}
			}
		})
	}
}

func TestLogsNativeAuthorizationSDK(t *testing.T) {
	var fixture struct {
		Observations []struct {
			Label, Operation string
			Input            json.RawMessage
			SessionPolicy    json.RawMessage `json:"session_policy"`
			Result           struct {
				Code       string
				HTTPStatus int `json:"http_status"`
			}
		}
	}
	data, err := os.ReadFile("../testdata/aws/logs/authentication.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	c := clockCloud(t, stackd.Config{})
	for _, row := range fixture.Observations {
		t.Run(row.Label, func(t *testing.T) {
			client := logsClient(c, "AKIAEXAMPLE0000000000")
			if row.SessionPolicy != nil {
				session, err := c.sts("test", "test", "").GetFederationToken(t.Context(), &sts.GetFederationTokenInput{
					Name: aws.String("stackd-logs-denial"), DurationSeconds: aws.Int32(900), Policy: aws.String(string(row.SessionPolicy)),
				})
				if err != nil {
					t.Fatal(err)
				}
				options := client.Options()
				options.Credentials = credentials.NewStaticCredentialsProvider(*session.Credentials.AccessKeyId, *session.Credentials.SecretAccessKey, *session.Credentials.SessionToken)
				client = cloudwatchlogs.New(options)
			}
			_, err := awstest.CallSDK(t.Context(), client, row.Operation, row.Input)
			assertAPIError(t, err, row.Result.Code)
			var response interface{ HTTPStatusCode() int }
			if !errors.As(err, &response) || response.HTTPStatusCode() != row.Result.HTTPStatus {
				t.Fatalf("HTTP error differs from native %d: %v", row.Result.HTTPStatus, err)
			}
		})
	}
}

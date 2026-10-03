package stackd_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/smithy-go"
	"stackd/clock"
	"stackd/internal/awstest"
	"stackd/storage"
)

// The native fixture creates only a free configuration; native broker behavior
// is proven separately against the executable and the pinned Apache Kafka image.
func TestMSKNativeConfigurationRevisionsSDK(t *testing.T) {
	data, err := os.ReadFile("../testdata/aws/kafka/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		RetrievedAt time.Time                `json:"retrieved_at"`
		Identity    struct{ Account string } `json:"identity"`
		Calls       []struct {
			Label     string          `json:"label"`
			Operation string          `json:"operation"`
			Input     json.RawMessage `json:"input"`
			Output    json.RawMessage `json:"output"`
			Code      string          `json:"code"`
		} `json:"calls"`
		ManagementHistory struct {
			Events []struct {
				Label string          `json:"call_label"`
				Event json.RawMessage `json:"event"`
			} `json:"events"`
		} `json:"management_history"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	audits := make(map[string]json.RawMessage)
	for _, row := range fixture.ManagementHistory.Events {
		audits[row.Label] = row.Event
	}
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			backends := storage.NewMemory()
			if kind == "sqlite" {
				backends, _ = openSQLiteBackends(t, filepath.Join(t.TempDir(), "msk.sqlite"))
			}
			source := clock.NewManual(fixture.RetrievedAt)
			_, clients, _ := startEventDeliveryCloud(t, backends, source)
			client := kafka.New(kafka.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL),
				Credentials: credentials.NewStaticCredentialsProvider(fixture.Identity.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			trails := cloudtrail.New(cloudtrail.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL),
				Credentials: credentials.NewStaticCredentialsProvider(fixture.Identity.Account, "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
			var nativeARN, localARN string
			for _, row := range fixture.Calls {
				if row.Label == "versions" || strings.HasPrefix(row.Label, "absence-") {
					continue
				}
				t.Run(row.Label, func(t *testing.T) {
					input := row.Input
					if nativeARN != "" {
						input = json.RawMessage(strings.ReplaceAll(string(input), nativeARN, localARN))
					}
					out, err := awstest.CallSDK(t.Context(), client, row.Operation, input)
					code := "Success"
					if err != nil {
						var rejected smithy.APIError
						if !errors.As(err, &rejected) {
							t.Fatal(err)
						}
						code = rejected.ErrorCode()
					}
					if code != row.Code {
						t.Fatalf("native code %s, local %s: %v", row.Code, code, err)
					}
					if row.Label == "create" {
						var native kafka.CreateConfigurationOutput
						if err := awstest.DecodeSDK(row.Output, &native); err != nil {
							t.Fatal(err)
						}
						nativeARN, localARN = aws.ToString(native.Arn), aws.ToString(out.(*kafka.CreateConfigurationOutput).Arn)
					}
					nativeAudit := string(audits[row.Label])
					if nativeARN != "" {
						nativeAudit = strings.NewReplacer(nativeARN, localARN, url.QueryEscape(nativeARN), url.QueryEscape(localARN)).Replace(nativeAudit)
					}
					var wantAudit map[string]any
					if e := json.Unmarshal([]byte(nativeAudit), &wantAudit); e != nil {
						t.Fatal(e)
					}
					wantAudit["eventTime"] = source.Now().UTC().Format(time.RFC3339)
					actualAudit := auditLookupRecord(t, trails, nativeAuditRequestID(t, out, err), row.Operation)
					normalizeMSKAuditTimes(wantAudit)
					normalizeMSKAuditTimes(actualAudit)
					assertNativeAuditEvent(t, actualAudit, wantAudit, "")
					if err != nil {
						return
					}
					var want map[string]any
					if err := json.Unmarshal(row.Output, &want); err != nil {
						t.Fatal(err)
					}
					gotBytes, err := json.Marshal(out)
					if err != nil {
						t.Fatal(err)
					}
					var got map[string]any
					if err := json.Unmarshal(gotBytes, &got); err != nil {
						t.Fatal(err)
					}
					normalizeMSKFixture(want, nativeARN, localARN)
					normalizeMSKFixture(got, nativeARN, localARN)
					// The assertion covers raw property bytes, independent retained
					// revisions, revision descriptions and pagination boundaries.
					if !reflect.DeepEqual(want, got) {
						t.Fatalf("configuration result mismatch\nnative: %#v\nlocal: %#v", want, got)
					}
					if row.Label == "revision-one-after-update" {
						foreign := kafka.New(kafka.Options{Region: "us-east-1", BaseEndpoint: aws.String(clients.server.URL),
							Credentials: credentials.NewStaticCredentialsProvider("222222222222", "test", ""), HTTPClient: clients.server.Client(), RetryMaxAttempts: 1})
						_, err := foreign.DescribeConfiguration(t.Context(), &kafka.DescribeConfigurationInput{Arn: aws.String(localARN)})
						var rejected smithy.APIError
						if !errors.As(err, &rejected) || rejected.ErrorCode() != "BadRequestException" {
							t.Fatalf("foreign configuration disclosure: %v", err)
						}
					}
				})
			}
			_, err := client.DescribeConfiguration(t.Context(), &kafka.DescribeConfigurationInput{Arn: aws.String(localARN)})
			var rejected smithy.APIError
			if !errors.As(err, &rejected) || rejected.ErrorCode() != "BadRequestException" {
				t.Fatalf("deleted configuration remained reachable: %v", err)
			}
		})
	}
}

func normalizeMSKFixture(value any, nativeARN, localARN string) {
	switch v := value.(type) {
	case map[string]any:
		delete(v, "ResultMetadata")
		delete(v, "CreationTime")
		for k, item := range v {
			if item == nil {
				delete(v, k)
				continue
			}
			if k == "Arn" && item == nativeARN {
				v[k] = localARN
				continue
			}
			if k == "NextToken" {
				v[k] = "<continuation>"
				continue
			}
			normalizeMSKFixture(item, nativeARN, localARN)
		}
	case []any:
		for _, item := range v {
			normalizeMSKFixture(item, nativeARN, localARN)
		}
	}
}

func normalizeMSKAuditTimes(value any) {
	switch v := value.(type) {
	case map[string]any:
		delete(v, "creationTime")
		// Diagnostic wording is not an API contract. Retain its native presence
		// and type while asserting the modeled invalidParameter separately.
		if _, ok := v["message"].(string); ok {
			v["message"] = "<diagnostic>"
		}
		for _, item := range v {
			normalizeMSKAuditTimes(item)
		}
	case []any:
		for _, item := range v {
			normalizeMSKAuditTimes(item)
		}
	}
}

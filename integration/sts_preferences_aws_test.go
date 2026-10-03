package stackd_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type preferenceObservation struct {
	Case, Operation, Code, Service, Region string
	Input                                  struct{ GlobalEndpointTokenVersion string }
	Status                                 int  `json:"http_status"`
	InvalidToken                           bool `json:"invalid_token"`
}

func preferenceObservations(t *testing.T) map[string]preferenceObservation {
	t.Helper()
	data, err := os.ReadFile("../testdata/aws/iam/sts_preferences.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []preferenceObservation
	}
	if err := json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]preferenceObservation)
	for _, row := range capture.Observations {
		rows[row.Case] = row
	}
	return rows
}

func TestSTSTokenPreferenceAWSValidation(t *testing.T) {
	rows := preferenceObservations(t)
	c := newCloudClients(t)
	for _, name := range []string{"invalid_v3Token", "invalid_V1Token", "invalid_1", "invalid_empty", "invalid_v2token"} {
		row, ok := rows[name]
		if !ok {
			t.Fatalf("missing AWS observation %s", name)
		}
		t.Run(row.Case, func(t *testing.T) {
			params := url.Values{"Action": {row.Operation}, "Version": {"2010-05-08"}}
			params.Set("GlobalEndpointTokenVersion", row.Input.GlobalEndpointTokenVersion)
			body := params.Encode()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.server.URL, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			digest := sha256.Sum256([]byte(body))
			if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, request, hex.EncodeToString(digest[:]), "iam", "us-east-1", time.Now()); err != nil {
				t.Fatal(err)
			}
			response, err := c.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var output struct{ Error struct{ Code string } }
			if err := xml.NewDecoder(response.Body).Decode(&output); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != row.Status || output.Error.Code != row.Code {
				t.Fatalf("local %d %s; AWS %d %s", response.StatusCode, output.Error.Code, row.Status, row.Code)
			}
		})
	}
}

func TestSTSTokenPreferenceAWSAuthenticationErrors(t *testing.T) {
	rows := preferenceObservations(t)
	c := newCloudClients(t)
	session, err := globalSTSClient(t, c, "test", "test", "").GetSessionToken(t.Context(), &sts.GetSessionTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"legacy_kms", "legacy_sqs", "invalid_credential_kms", "invalid_credential_sqs"} {
		row, ok := rows[name]
		if !ok {
			t.Fatalf("missing AWS observation %s", name)
		}
		t.Run(name, func(t *testing.T) {
			token := aws.ToString(session.Credentials.SessionToken)
			if row.InvalidToken {
				token = "invalid"
			}
			provider := credentials.NewStaticCredentialsProvider(aws.ToString(session.Credentials.AccessKeyId), aws.ToString(session.Credentials.SecretAccessKey), token)
			var err error
			switch row.Service {
			case "kms":
				client := kms.New(kms.Options{Region: row.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: provider, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				_, err = client.ListKeys(t.Context(), &kms.ListKeysInput{})
			case "sqs":
				client := sqs.New(sqs.Options{Region: row.Region, BaseEndpoint: aws.String(c.server.URL), Credentials: provider, HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
				_, err = client.ListQueues(t.Context(), &sqs.ListQueuesInput{})
			default:
				t.Fatalf("unexpected fixture service %s", row.Service)
			}
			assertAPIError(t, err, row.Code)
			var response interface{ HTTPStatusCode() int }
			if !errors.As(err, &response) || response.HTTPStatusCode() != row.Status {
				t.Fatalf("HTTP status differs from AWS %d: %v", row.Status, err)
			}
		})
	}
}

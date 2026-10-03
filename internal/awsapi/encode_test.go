package awsapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	kmsclient "github.com/aws/aws-sdk-go-v2/service/kms"
	sqsclient "github.com/aws/aws-sdk-go-v2/service/sqs"

	kmsapi "stackd/internal/awsapi/kms"
	sqsapi "stackd/internal/awsapi/sqs"
	"stackd/internal/awswire"
)

func ptr[T any](value T) *T { return &value }

func TestGeneratedJSONOutputThroughSDK(t *testing.T) {
	stamp := time.Unix(1234567890, 123456789).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		var err error
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.DescribeKey":
			body, err = kmsapi.EncodeResponse("DescribeKey", &kmsapi.DescribeKeyOutput{KeyMetadata: &kmsapi.KeyMetadata{KeyId: ptr(kmsapi.KeyIdType("key")), CreationDate: &stamp}})
		case "TrentService.Encrypt":
			body, err = kmsapi.EncodeResponse("Encrypt", &kmsapi.EncryptOutput{CiphertextBlob: kmsapi.CiphertextType{0, 1, 2, 0xff}})
		case "AmazonSQS.ReceiveMessage":
			if r.URL.Path != "/" {
				t.Errorf("SDK JSON protocol path=%s, want /", r.URL.Path)
			}
			body, err = sqsapi.EncodeResponse("ReceiveMessage", &sqsapi.ReceiveMessageOutput{Messages: sqsapi.MessageList{}})
		default:
			t.Errorf("unexpected operation %s", r.Header.Get("X-Amz-Target"))
		}
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		awswire.WriteJSONBytes(w, r, body)
	}))
	t.Cleanup(server.Close)
	kms := kmsclient.New(kmsclient.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	key, err := kms.DescribeKey(context.Background(), &kmsclient.DescribeKeyInput{KeyId: aws.String("key")})
	if err != nil {
		t.Fatal(err)
	}
	// The AWS SDK's epoch decoder retains millisecond precision.
	if !key.KeyMetadata.CreationDate.Equal(stamp.Truncate(time.Millisecond)) {
		t.Fatalf("timestamp decoded incorrectly: %v", key.KeyMetadata.CreationDate)
	}
	encrypted, err := kms.Encrypt(context.Background(), &kmsclient.EncryptInput{KeyId: aws.String("key"), Plaintext: []byte("hello")})
	if err != nil || !bytes.Equal(encrypted.CiphertextBlob, []byte{0, 1, 2, 0xff}) {
		t.Fatalf("binary output=%v error=%v", encrypted, err)
	}
	sqs := sqsclient.New(sqsclient.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: server.Client(), RetryMaxAttempts: 1})
	output, err := sqs.ReceiveMessage(context.Background(), &sqsclient.ReceiveMessageInput{QueueUrl: aws.String(server.URL + "/000000000000/example")})
	if err != nil || len(output.Messages) != 0 {
		t.Fatalf("empty collection output=%v error=%v", output, err)
	}
}

func TestGeneratedEncoderPresenceTypesAndEpoch(t *testing.T) {
	for _, test := range []struct {
		stamp time.Time
		want  string
	}{{time.Unix(0, 1), "0.000000001"}, {time.Unix(-1, 500000000), "-0.5"}, {time.Unix(-2, 123456789), "-1.876543211"}, {time.Unix(1234567890, 123456789), "1234567890.123456789"}} {
		stamp := test.stamp
		body, err := kmsapi.EncodeResponse("DescribeKey", &kmsapi.DescribeKeyOutput{KeyMetadata: &kmsapi.KeyMetadata{KeyId: ptr(kmsapi.KeyIdType("id")), CreationDate: &stamp}})
		if err != nil {
			t.Fatal(err)
		}
		var value struct {
			KeyMetadata struct{ CreationDate json.Number }
		}
		if err := json.Unmarshal(body, &value); err != nil {
			t.Fatal(err)
		}
		if string(value.KeyMetadata.CreationDate) != test.want {
			t.Fatalf("bad epoch %s, want %s", value.KeyMetadata.CreationDate, test.want)
		}
	}
	if _, err := kmsapi.EncodeResponse("DescribeKey", &kmsapi.EncryptOutput{}); err == nil {
		t.Fatal("accepted unrelated output type")
	}
	body, err := sqsapi.EncodeResponse("ReceiveMessage", &sqsapi.ReceiveMessageOutput{Messages: sqsapi.MessageList{}})
	if err != nil || string(body) != `{"Messages":[]}` {
		t.Fatalf("present empty collection: %s %v", body, err)
	}
	body, err = sqsapi.EncodeResponse("ReceiveMessage", &sqsapi.ReceiveMessageOutput{})
	if err != nil || string(body) != `{}` {
		t.Fatalf("absent collection: %s %v", body, err)
	}
}

func TestJSONVersionResponseAndError(t *testing.T) {
	for _, version := range []string{"1.0", "1.1"} {
		for _, fail := range []bool{false, true} {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.Header.Set("Content-Type", "application/x-amz-json-"+version+"; charset=utf-8")
			w := httptest.NewRecorder()
			if fail {
				awswire.JSONError(w, r, &awswire.Error{Code: "InvalidParameterValue", Message: "invalid", StatusCode: 400})
			} else {
				awswire.WriteJSONBytes(w, r, []byte(`{}`))
			}
			response := w.Result()
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if got := response.Header.Get("Content-Type"); got != "application/x-amz-json-"+version {
				t.Fatalf("content-type=%s", got)
			}
		}
	}
}

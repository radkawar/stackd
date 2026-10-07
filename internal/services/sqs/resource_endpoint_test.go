package sqs

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/sqs"
	api "stackd/internal/awsapi/sqs"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
)

func TestResourceQueueURLThroughSignedNativeGateway(t *testing.T) {
	s := NewWithConfig(Config{EndpointDomain: "dev.example"})
	registry := &gateway.Registry{}
	model, _ := awscatalog.LookupService("sqs")
	if err := registry.Register(gateway.Service{Name: "sqs", SigningName: "sqs", Protocol: gateway.JSON10, TargetPrefix: "AmazonSQS", Provider: s, Model: &model, Decode: api.DecodeRequest}); err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(registry, gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(g)
	t.Cleanup(func() { server.Close(); _ = s.Close() })
	s.publicEndpoint = server.URL
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := func(region, account, endpoint string) *sdk.Client {
		return sdk.New(sdk.Options{Region: region, BaseEndpoint: &endpoint, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), HTTPClient: &http.Client{Transport: transport}, RetryMaxAttempts: 1})
	}
	owner := client("us-east-1", "111111111111", server.URL)
	queueURL := create(t, owner, "jobs.fifo", map[string]string{"FifoQueue": "true"})
	u, err := url.Parse(queueURL)
	if err != nil || u.Hostname() != "sqs.us-east-1.dev.example" || u.Path != "/111111111111/jobs.fifo" || u.Port() == "" {
		t.Fatalf("generated queue URL %q: %v", queueURL, err)
	}
	unsigned := httptest.NewRequest("POST", u.Scheme+"://"+u.Host+"/", strings.NewReader(`{"QueueUrl":"`+queueURL+`"}`))
	unsigned.Header.Set("X-Amz-Target", "AmazonSQS.GetQueueAttributes")
	unsigned.Header.Set("Content-Type", "application/x-amz-json-1.0")
	unsignedResponse := httptest.NewRecorder()
	g.ServeHTTP(unsignedResponse, unsigned)
	if unsignedResponse.Code != http.StatusForbidden {
		t.Fatalf("regional service host admitted an unsigned request: %d", unsignedResponse.Code)
	}
	regional := client("us-east-1", "111111111111", u.Scheme+"://"+u.Host)
	fifoSend(t, regional, queueURL, "hostname transport", "group", "dedup")
	got := receive(t, regional, queueURL, 1)
	if len(got) != 1 || aws.ToString(got[0].Body) != "hostname transport" {
		t.Fatalf("resource hostname did not reach the native queue: %v", got)
	}
	foreign := client("us-east-1", "222222222222", u.Scheme+"://"+u.Host)
	_, err = foreign.GetQueueAttributes(t.Context(), &sdk.GetQueueAttributesInput{QueueUrl: &queueURL})
	requireCode(t, err, "AccessDenied")
	wrongRegion := client("eu-west-2", "111111111111", u.Scheme+"://"+u.Host)
	_, err = wrongRegion.GetQueueAttributes(t.Context(), &sdk.GetQueueAttributesInput{QueueUrl: &queueURL})
	requireCode(t, err, "SignatureDoesNotMatch")
	_, err = regional.DeleteQueue(t.Context(), &sdk.DeleteQueueInput{QueueUrl: &queueURL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = regional.GetQueueAttributes(t.Context(), &sdk.GetQueueAttributesInput{QueueUrl: &queueURL})
	requireCode(t, err, "AWS.SimpleQueueService.NonExistentQueue")
	if strings.Contains(queueURL, server.Listener.Addr().String()+"/") {
		t.Fatal("public origin leaked as the resource hostname")
	}
}

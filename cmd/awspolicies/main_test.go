package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"stackd/internal/iam/managed"
)

func TestVersionCapturePreservesDocumentAndResumesOffline(t *testing.T) {
	const arn = "arn:aws:iam::aws:policy/Example"
	const document = "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::space+plus/*\"}\n}"
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("Action") != "GetPolicyVersion" || r.Form.Get("PolicyArn") != arn || r.Form.Get("VersionId") != "v4" {
			t.Errorf("unexpected acquisition: %v", r.Form)
		}
		w.Header().Set("Content-Type", "text/xml")
		w.Header().Set("X-Amzn-Requestid", "source-request-id")
		fmt.Fprintf(w, `<GetPolicyVersionResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetPolicyVersionResult><PolicyVersion><Document>%s</Document><VersionId>v4</VersionId><IsDefaultVersion>true</IsDefaultVersion><CreateDate>2025-01-02T03:04:05Z</CreateDate></PolicyVersion></GetPolicyVersionResult><ResponseMetadata><RequestId>source-request-id</RequestId></ResponseMetadata></GetPolicyVersionResponse>`, url.QueryEscape(document))
	}))
	defer server.Close()
	client := iam.New(iam.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), Retryer: aws.NopRetryer{}})
	ticks := make(chan time.Time, 3)
	for range 3 {
		ticks <- time.Now()
	}
	c := capture{client: client, cache: t.TempDir(), ticks: ticks}
	v, err := c.version(context.Background(), arn, "v4")
	if err != nil {
		t.Fatal(err)
	}
	if v.Document != document || v.RequestID != "source-request-id" || v.SHA256 != managed.Digest([]byte(document)) {
		t.Fatalf("capture altered source: %+v", v)
	}
	cached, err := c.version(context.Background(), arn, "v4")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || cached != v {
		t.Fatal("immutable cached document was fetched again or altered")
	}
	cacheFile := filepath.Join(c.cache, managed.Digest([]byte(arn)), "v4.json")
	if err = os.WriteFile(cacheFile, []byte(`{"id":"v4","document":"{}","sha256":"corrupt","request_id":"old"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = c.version(context.Background(), arn, "v4"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("corrupt cache was trusted")
	}
}

func TestCancelledCaptureMakesNoRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := capture{cache: t.TempDir(), ticks: make(chan time.Time)}
	if _, err := c.version(ctx, "arn:aws:iam::aws:policy/Example", "v1"); err != context.Canceled {
		t.Fatalf("cancelled capture: %v", err)
	}
}

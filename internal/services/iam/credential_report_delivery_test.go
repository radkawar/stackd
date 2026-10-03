package iam_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/services/iam"
)

type blockedReportResponse struct {
	http.ResponseWriter
	entered chan struct{}
	release chan struct{}
}

func (w blockedReportResponse) WriteHeader(status int) {
	close(w.entered)
	<-w.release
	w.ResponseWriter.WriteHeader(status)
}

func TestCredentialReportProgressBeforeResponseDelivery(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	repository := newCredentialReportTestRepository(nil, false)
	service := iam.NewWithConfig(iam.Config{Repository: repository, Clock: clock.NewManual(time.Time{})})
	response := httptest.NewRecorder()
	w := blockedReportResponse{ResponseWriter: response, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(w.release) })
		<-done
		_ = service.Close()
	})
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("Action=GenerateCredentialReport&Version=2010-05-08"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: scope.Partition, AccountID: scope.AccountID, PrincipalID: scope.AccountID, PrincipalARN: "arn:aws:iam::" + scope.AccountID + ":root"}))
	go func() {
		defer close(done)
		service.ServeHTTP(w, request)
	}()
	select {
	case <-w.entered:
	case <-ctx.Done():
		t.Fatal("response did not reach delivery", ctx.Err())
	}
	completed := waitCredentialReportCommit(t, ctx, repository, scope, 1)
	if len(completed.Content) == 0 {
		t.Fatal("committed work did not produce the credential snapshot")
	}
	select {
	case <-done:
		t.Fatal("response was not blocked while the worker completed")
	default:
	}
	release.Do(func() { close(w.release) })
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<State>STARTED</State>") {
		t.Fatal("accepted generation response changed during delivery", response.Code, response.Body.String())
	}
}

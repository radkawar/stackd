package eks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stackd/clock"
	native "stackd/compute/eks"
)

type authenticationCapture struct {
	native.Runtime
	records []native.LogRecord
}

func (c *authenticationCapture) RecordAuthentication(_ context.Context, _ string, record native.LogRecord) error {
	c.records = append(c.records, record)
	return nil
}

func TestAuthenticationDecisionUsesServiceTime(t *testing.T) {
	at := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	repository := NewMemoryRepository(nil)
	key := Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "clock"}
	cluster := Cluster{Key: key, ID: "incarnation", Status: "ACTIVE", EnabledLogTypes: []string{"authenticator"}}
	if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutCluster(cluster) }); err != nil {
		t.Fatal(err)
	}
	capture := &authenticationCapture{}
	service := New(Config{Repository: repository, Clock: clock.NewManual(at), Runtime: capture})
	t.Cleanup(func() { _ = service.Close() })
	handler := service.kubernetesHandler(key, cluster.ID)
	request := httptest.NewRequest(http.MethodGet, "/version", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(capture.records) != 1 {
		t.Fatalf("authentication result = %d, decisions = %d", response.Code, len(capture.records))
	}
	record := capture.records[0]
	var decision struct {
		Time    time.Time `json:"time"`
		Message string    `json:"msg"`
	}
	if err := json.Unmarshal([]byte(record.Message), &decision); err != nil {
		t.Fatal(err)
	}
	if !record.Timestamp.Equal(at) || !decision.Time.Equal(at) || decision.Message != "access denied" {
		t.Fatalf("decision escaped service timeline: %+v, %+v", record, decision)
	}
	cluster.EnabledLogTypes = nil
	if err := repository.Update(t.Context(), func(tx Transaction) error { return tx.PutCluster(cluster) }); err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if len(capture.records) != 1 {
		t.Fatal("disabled authenticator logging admitted another decision")
	}
}

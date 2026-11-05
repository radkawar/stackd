package integrations

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fixtureTableData struct {
	calls int
	body  string
	payer string
}

func (owner *fixtureTableData) ClaimsData(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/fixture--table-s3/")
}
func (owner *fixtureTableData) HandleData(w http.ResponseWriter, r *http.Request) bool {
	owner.calls++
	data, _ := io.ReadAll(r.Body)
	owner.body = string(data)
	owner.payer = r.Header.Get("X-Amz-Request-Payer")
	w.WriteHeader(http.StatusForbidden)
	// A claimed namespace cannot fall through even if an adapter misreports.
	return false
}

func TestAthenaTableDataNeverFallsThroughToOrdinaryS3(t *testing.T) {
	owner := &fixtureTableData{}
	ordinary := 0
	bridge := &athenaDataPlane{execution: context.Background(), tables: owner, s3: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ordinary++ }), requesterPays: true}
	response := httptest.NewRecorder()
	bridge.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "http://callback/fixture--table-s3/data/part.parquet", strings.NewReader("actual-data-bytes")))
	if response.Code != http.StatusForbidden || ordinary != 0 || owner.calls != 1 || owner.body != "actual-data-bytes" || owner.payer != "requester" {
		t.Fatalf("table data owner bypass: status=%d ordinary=%d owner=%+v", response.Code, ordinary, owner)
	}
}

func TestAthenaKMSWorkgroupRejectsTableWritesBeforeEffects(t *testing.T) {
	owner := &fixtureTableData{}
	bridge := &athenaDataPlane{execution: context.Background(), tables: owner, tablesReadOnly: true, s3: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("claimed table path reached ordinary S3") })}
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
		response := httptest.NewRecorder()
		bridge.ServeHTTP(response, httptest.NewRequest(method, "http://callback/fixture--table-s3/data/part.parquet", strings.NewReader("not-written")))
		if response.Code != http.StatusForbidden || owner.calls != 0 {
			t.Fatalf("KMS table write reached owner: %s status=%d calls=%d", method, response.Code, owner.calls)
		}
	}
	response := httptest.NewRecorder()
	bridge.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://callback/fixture--table-s3/data/part.parquet", nil))
	if owner.calls != 1 {
		t.Fatal("KMS workgroup incorrectly suppressed table read authority")
	}
}

package glue

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"stackd/compute/docker"
)

const observationRunKey = "owned-observation-run"

// The prefix has real Spark listener event shapes and observed nonzero counters.
// A damaged suffix must not turn those partial counters into published totals.
const observationEvents = `{"Event":"SparkListenerApplicationStart","App Name":"observation-regression"}
{"Event":"SparkListenerTaskEnd","Task End Reason":{"Reason":"Success"},"Task Metrics":{"Input Metrics":{"Bytes Read":17,"Records Read":3}}}
{"Event":"SparkListenerStageCompleted"}
`

func TestDockerObservationFailureDoesNotBlockLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, suffix, logSuffix, diagnostic string
		metrics                             SparkMetrics
	}{
		{name: "malformed-record", suffix: "{not-json}\n", diagnostic: "event log"},
		{name: "truncated-record", suffix: `{"Event":"SparkListenerTaskEnd","Task Metrics":`, diagnostic: "event log"},
		{name: "oversized-record", suffix: `{"Event":"org.apache.spark.sql.execution.ui.SparkListenerSQLExecutionStart","details":"` + strings.Repeat("x", 4<<20) + "\"}\n", diagnostic: "event log"},
		{name: "truncated-docker-frame", logSuffix: "\x01\x00\x00", diagnostic: "container logs", metrics: SparkMetrics{Observed: true, CompletedTasks: 1, CompletedStages: 1, BytesRead: 17, RecordsRead: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := observationRuntime(t, observationEvents+tc.suffix, tc.logSuffix, observationRunKey)
			if err := runtime.Stop(t.Context(), observationRunKey); err != nil {
				t.Fatal(err)
			}
			status, err := runtime.Inspect(t.Context(), observationRunKey)
			if err != nil {
				t.Fatalf("optional observation blocked process state: %v", err)
			}
			if !status.Found || status.Running || status.ExitCode != 137 || status.ExecutionSeconds != 2 {
				t.Fatalf("lost authoritative stopped state: %+v", status)
			}
			if !strings.Contains(status.ObservationError, tc.diagnostic) || status.Error != "" {
				t.Fatalf("observation diagnostic lost or became a process error: %+v", status)
			}
			if status.SparkMetrics != tc.metrics {
				t.Fatalf("published incomplete or lost valid native counters: %+v", status.SparkMetrics)
			}
			if status.Output != "done\n" {
				t.Fatalf("lost captured output: %q", status.Output)
			}
			// Repeated stop after termination and removal must not depend on the
			// same permanently unreadable optional data being repaired.
			if err := runtime.Stop(t.Context(), observationRunKey); err != nil {
				t.Fatalf("stopped execution cannot be stopped again: %v", err)
			}
			if err := runtime.Remove(t.Context(), observationRunKey); err != nil {
				t.Fatalf("observation failure blocked removal: %v", err)
			}
			status, err = runtime.Inspect(t.Context(), observationRunKey)
			if err != nil || status.Found {
				t.Fatalf("owned execution remains after removal: %+v, %v", status, err)
			}
		})
	}
}

func TestDockerLifecycleRejectsUnownedContainer(t *testing.T) {
	runtime := observationRuntime(t, observationEvents, "", "another-run")
	if _, err := runtime.Inspect(t.Context(), observationRunKey); err == nil {
		t.Fatal("inspection accepted a foreign execution")
	}
	if err := runtime.Stop(t.Context(), observationRunKey); err == nil {
		t.Fatal("stop accepted a foreign execution")
	}
	if err := runtime.Remove(t.Context(), observationRunKey); err == nil {
		t.Fatal("remove accepted a foreign execution")
	}
}

// Exercise the real Engine transport, multiplexed logs and tar/event parser at
// their wire boundaries, without requiring Docker in the ordinary test suite.
func observationRuntime(t *testing.T, events, logSuffix, owner string) *DockerRuntime {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "stackd-spark-events/local-1.inprogress", Mode: 0644, Size: int64(len(events))}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, events); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	found, running := true, true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path := strings.TrimPrefix(request.URL.Path, "/v1.41")
		switch path {
		case "/version":
			_, _ = io.WriteString(w, `{"ApiVersion":"1.41","Os":"linux"}`)
		case "/info":
			_, _ = io.WriteString(w, `{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`)
		case containerPath(observationRunKey) + "/json":
			if !found {
				http.NotFound(w, request)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Config": map[string]any{"Labels": map[string]string{"stackd.glue.run": owner, "stackd.glue.command": "glueetl"}},
				"State":  map[string]any{"Running": running, "ExitCode": 137, "Status": "exited", "StartedAt": "2026-09-26T00:00:00Z", "FinishedAt": "2026-09-26T00:00:02Z"},
			})
		case containerPath(observationRunKey) + "/kill":
			running = false
			w.WriteHeader(http.StatusNoContent)
		case containerPath(observationRunKey):
			if request.Method != http.MethodDelete {
				http.NotFound(w, request)
				return
			}
			found = false
			w.WriteHeader(http.StatusNoContent)
		case containerPath(observationRunKey) + "/logs":
			_, _ = io.WriteString(w, "\x01\x00\x00\x00\x00\x00\x00\x05done\n"+logSuffix)
		case containerPath(observationRunKey) + "/archive":
			switch request.URL.Query().Get("path") {
			case "/tmp/stackd-glue-context.observed":
				w.WriteHeader(http.StatusOK)
			case "/tmp/stackd-spark-events":
				_, _ = w.Write(archive.Bytes())
			default:
				http.NotFound(w, request)
			}
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	engine, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return &DockerRuntime{config: Config{Client: engine}}
}

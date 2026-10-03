package glue

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// SparkMetrics contains observed native event-log counters, never inferred DPU
// allocation, billing, utilization or synthetic Python-shell profile metrics.
type SparkMetrics struct {
	Observed                                                                          bool
	CompletedTasks, FailedTasks, KilledTasks, CompletedStages, BytesRead, RecordsRead int64
}

func (r *DockerRuntime) sparkMetrics(ctx context.Context, key string) (SparkMetrics, error) {
	var out SparkMetrics
	marker, err := r.config.Client.Request(ctx, http.MethodGet, containerPath(key)+"/archive?path=/tmp/stackd-glue-context.observed", nil, "")
	if missing(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	marker.Body.Close()
	response, err := r.config.Client.Request(ctx, http.MethodGet, containerPath(key)+"/archive?path=/tmp/stackd-spark-events", nil, "")
	if missing(err) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	defer response.Body.Close()
	archive := tar.NewReader(response.Body)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		scanner := bufio.NewScanner(archive)
		scanner.Buffer(make([]byte, 64<<10), 4<<20)
		record := 0
		for scanner.Scan() {
			record++
			var event struct {
				Event   string
				Reason  struct{ Reason string } `json:"Task End Reason"`
				Metrics struct {
					Input struct {
						BytesRead   int64 `json:"Bytes Read"`
						RecordsRead int64 `json:"Records Read"`
					} `json:"Input Metrics"`
				} `json:"Task Metrics"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				return out, fmt.Errorf("event log %q record %d: %w", header.Name, record, err)
			}
			switch event.Event {
			case "SparkListenerApplicationStart":
				out.Observed = true
			case "SparkListenerStageCompleted":
				out.CompletedStages++
			case "SparkListenerTaskEnd":
				switch event.Reason.Reason {
				case "Success":
					out.CompletedTasks++
					out.BytesRead += event.Metrics.Input.BytesRead
					out.RecordsRead += event.Metrics.Input.RecordsRead
				case "TaskKilled":
					out.KilledTasks++
				default:
					out.FailedTasks++
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return out, fmt.Errorf("event log %q record %d: %w", header.Name, record+1, err)
		}
	}
}

// Observe the real constructor only when profiling was explicitly enabled.
// The original GlueContext still owns all initialization and customer behavior.
// TODO: Comeback stream native counters at Glue's reporting cadence; retained
// counters currently publish only after the actual process reaches a terminal state.
const profilingScript = `import os
if os.environ.get('STACKD_GLUE_PROFILE') == '1':
    from awsglue.context import GlueContext
    _initialize = GlueContext.__init__
    def _observe_context(self, *args, **kwargs):
        _initialize(self, *args, **kwargs)
        with open('/tmp/stackd-glue-context.observed', 'a'):
            pass
    GlueContext.__init__ = _observe_context
`

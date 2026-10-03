package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	runtime "stackd/compute/lambda"
)

const runtimePrefix = "/2018-06-01/runtime/"

type attempt struct {
	invocation Invocation
	id         string
	deadline   time.Time
	result     chan runtime.Result
	delivered  bool
}
type environment struct {
	deployment           Deployment
	owner                *Server
	listener             net.Listener
	server               *http.Server
	ready                chan struct{}
	readyOnce            sync.Once
	done                 chan struct{}
	stopOnce             sync.Once
	mu                   sync.Mutex
	pending              map[string]*attempt
	queue                chan *attempt
	initError            error
	container            string
	directory            string
	logs                 *logSpool
	renderer             *runtime.ManagedLogRenderer
	logCancel            context.CancelFunc
	logDone              chan struct{}
	containerIP          string
	credentials          runtime.Credentials
	credentialsToken     string
	startupDeadline      time.Time
	draining, terminated bool
}

func (e *environment) runtimeAPI(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host != e.containerIP {
		http.Error(w, "Execution environment source rejected", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/credentials" {
		e.credentialsAPI(w, r)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == runtimePrefix+"invocation/next":
		e.readyOnce.Do(func() { close(e.ready) })
		for {
			select {
			case <-r.Context().Done():
				return
			case <-e.done:
				http.Error(w, "Environment terminated", http.StatusGone)
				return
			case a := <-e.queue:
				e.mu.Lock()
				current := e.pending[a.invocation.RequestID]
				if current != a {
					e.mu.Unlock()
					continue
				}
				a.delivered = true
				e.mu.Unlock()
				w.Header().Set("Lambda-Runtime-Aws-Request-Id", a.invocation.RequestID)
				w.Header().Set("Lambda-Runtime-Invocation-Id", a.id)
				w.Header().Set("Lambda-Runtime-Deadline-Ms", strconv.FormatInt(a.deadline.UnixMilli(), 10))
				w.Header().Set("Lambda-Runtime-Invoked-Function-Arn", a.invocation.FunctionARN)
				if a.invocation.TraceID != "" {
					w.Header().Set("Lambda-Runtime-Trace-Id", a.invocation.TraceID)
				}
				if a.invocation.ClientContext != "" {
					w.Header().Set("Lambda-Runtime-Client-Context", a.invocation.ClientContext)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(a.invocation.Payload)
				return
			}
		}
	case r.Method == http.MethodPost && r.URL.Path == runtimePrefix+"init/error":
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 6<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		e.mu.Lock()
		e.initError = fmt.Errorf("lambda runtime initialization failed: %s", data)
		e.mu.Unlock()
		e.readyOnce.Do(func() { close(e.ready) })
		w.WriteHeader(http.StatusAccepted)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, runtimePrefix+"invocation/"):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, runtimePrefix+"invocation/"), "/")
		if len(parts) != 2 || (parts[1] != "response" && parts[1] != "error") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Lambda-Runtime-Function-Response-Mode") == "streaming" {
			http.Error(w, "Managed response streaming is not implemented", http.StatusNotImplemented)
			return
		}
		payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 6<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		e.mu.Lock()
		a := e.pending[parts[0]]
		if a == nil || !a.delivered {
			e.mu.Unlock()
			http.Error(w, "Unknown invocation", http.StatusBadRequest)
			return
		}
		if id := r.Header.Get("Lambda-Runtime-Invocation-Id"); id != "" && id != a.id {
			e.mu.Unlock()
			http.Error(w, "InvalidInvocationId", http.StatusBadRequest)
			return
		}
		delete(e.pending, parts[0])
		e.mu.Unlock()
		result := runtime.Result{Payload: payload, ContentType: r.Header.Get("Content-Type")}
		if parts[1] == "error" {
			result.FunctionError = "Unhandled"
		}
		// A timed-out invocation keeps its worker occupied until the runtime actually
		// responds. Sending into this buffered channel does not revive its caller.
		a.result <- result
		w.WriteHeader(http.StatusAccepted)
	default:
		http.NotFound(w, r)
	}
}

func (e *environment) invoke(in Invocation) (Outcome, error) {
	started := time.Now()
	timeout := min(e.deployment.Specification.Timeout, 900*time.Second)
	if in.Timeout > 0 {
		timeout = min(e.deployment.Specification.Timeout, in.Timeout)
	}
	a := &attempt{invocation: in, id: uuid.NewString(), deadline: started.Add(timeout), result: make(chan runtime.Result, 1)}
	e.mu.Lock()
	if e.initError != nil {
		err := e.initError
		e.mu.Unlock()
		return Outcome{}, err
	}
	select {
	case <-e.done:
		e.mu.Unlock()
		return Outcome{}, errors.New("execution environment is terminated")
	default:
	}
	if len(e.pending) >= e.deployment.MaxConcurrency {
		e.mu.Unlock()
		return Outcome{}, &RemoteError{429, "Execution environment concurrency limit reached"}
	}
	if _, exists := e.pending[in.RequestID]; exists {
		e.mu.Unlock()
		return Outcome{}, &RemoteError{409, "Request ID is already executing"}
	}
	if e.draining {
		e.mu.Unlock()
		return Outcome{}, &RemoteError{429, "Execution environment is draining"}
	}
	e.pending[in.RequestID] = a
	logStart := e.logs.position()
	select {
	case e.queue <- a:
	default:
		delete(e.pending, in.RequestID)
		e.mu.Unlock()
		return Outcome{}, &RemoteError{429, "Runtime workers are not polling"}
	}
	version := e.deployment.Specification.FunctionARN[strings.LastIndex(e.deployment.Specification.FunctionARN, ":")+1:]
	e.renderer.Start(in.RequestID, version)
	e.mu.Unlock()
	timer := time.NewTimer(time.Until(a.deadline))
	defer timer.Stop()
	out := Outcome{}
	select {
	case out.Result = <-a.result:
		out.Report.Status = runtime.InvocationSuccess
		if out.Result.FunctionError != "" {
			out.Report.Status = runtime.InvocationFailure
			out.Report.FunctionFailed = true
		}
	case <-timer.C:
		e.mu.Lock()
		if !a.delivered {
			delete(e.pending, in.RequestID)
		}
		e.mu.Unlock()
		payload, _ := json.Marshal(map[string]string{"errorType": "Sandbox.Timedout", "errorMessage": fmt.Sprintf("Task timed out after %.2f seconds", timeout.Seconds())})
		out.Result = runtime.Result{Payload: payload, FunctionError: "Unhandled", ContentType: "application/json"}
		out.Report.Status = runtime.InvocationTimeout
		out.Report.FunctionFailed = true
	case <-e.done:
		return Outcome{}, errors.New("execution environment terminated during invocation")
	}
	out.Report.Duration = time.Since(started)
	e.renderer.Finish(in.RequestID, out.Report, e.deployment.Specification.MemoryMB)
	out.Report.Logs = e.logs.capture(logStart)
	return out, nil
}

func (e *environment) waitReady(ctx context.Context) error {
	timer := time.NewTimer(time.Until(e.startupDeadline))
	defer timer.Stop()
	select {
	case <-e.ready:
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.initError
	case <-e.done:
		return errors.New("execution environment terminated during initialization")
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		err := errors.New("managed runtime initialization timed out")
		e.mu.Lock()
		e.initError = err
		e.mu.Unlock()
		e.readyOnce.Do(func() { close(e.ready) })
		return err
	}
}
func (e *environment) observation(ctx context.Context) (Observation, error) {
	out := Observation{ID: e.deployment.ID, Revision: e.deployment.Revision, MaxConcurrency: e.deployment.MaxConcurrency, ObservedAt: time.Now().UTC(), LogGroup: e.deployment.Specification.LogGroup, LogStream: e.deployment.Specification.LogStream}
	e.mu.Lock()
	out.CredentialsExpire = e.credentials.Expiration
	out.InFlight = len(e.pending)
	out.Ready = e.initError == nil
	terminated := e.terminated
	e.mu.Unlock()
	if terminated {
		out.Ready = false
		return out, nil
	}
	select {
	case <-e.ready:
	default:
		out.Ready = false
	}
	select {
	case <-e.done:
		out.Ready = false
	default:
	}
	var current struct{ State struct{ Running bool } }
	if err := e.owner.engine.JSON(ctx, "GET", "/containers/"+e.container+"/json", nil, &current); err != nil {
		return Observation{}, err
	}
	if !current.State.Running {
		out.Ready = false
		return out, nil
	}
	var stats struct {
		CPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
		} `json:"cpu_stats"`
		MemoryStats struct {
			Usage uint64 `json:"usage"`
		} `json:"memory_stats"`
	}
	if err := e.owner.engine.JSON(ctx, "GET", "/containers/"+e.container+"/stats?stream=false", nil, &stats); err != nil {
		return Observation{}, err
	}
	out.CPUTimeNS = stats.CPUStats.CPUUsage.TotalUsage
	out.MemoryBytes = stats.MemoryStats.Usage
	return out, nil
}

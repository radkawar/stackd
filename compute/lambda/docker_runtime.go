package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	"stackd/compute/lambda/internal/extensionapi"
	"stackd/compute/lambda/internal/telemetryapi"
)

const runtimePrefix = "/2018-06-01/runtime/"
const maxRuntimeResponse = 6 << 20

type runtimeInvocation struct {
	invocation                        Invocation
	deadline                          time.Time
	result                            chan Result
	responseContext                   context.Context
	cancelResponse                    context.CancelFunc
	responseDone                      chan struct{}
	streamedResponse                  *Result
	responded                         bool
	functionFailed                    bool
	started, runtimeDoneAt            time.Time
	responseStartedAt, responseDoneAt time.Time
	producedBytes                     uint64
}

func runtimeSpan(name string, start time.Time, duration time.Duration) telemetryapi.Span {
	return telemetryapi.Span{Name: name, Start: start.UTC().Format(time.RFC3339Nano), DurationMs: float64(duration) / float64(time.Millisecond)}
}

type customerFailure struct {
	errorType, message string
	payload            []byte
	timeout            bool
}

func (f *customerFailure) Error() string { return f.errorType + ": " + f.message }

// All protocol state is generation-local. Changed is a broadcast condition, not
// a work queue: no readiness notification can be consumed by the wrong barrier.
type dockerRuntime struct {
	ctx                                context.Context
	cancel                             context.CancelFunc
	done                               chan struct{}
	queue                              chan *runtimeInvocation
	mu                                 sync.Mutex
	changed                            chan struct{}
	failureOnce                        sync.Once
	err                                error
	reportedError                      *customerFailure
	phase, initPhase, container        string
	initialized, polling, runtimeReady bool
	active                             *runtimeInvocation
	expected                           map[string]bool
	extensions                         map[string]*runtimeExtension
	byName                             map[string]*runtimeExtension
	processes                          []*dockerProcess
	runtimeProcess                     *dockerProcess
}

func (r *dockerRuntime) changedLocked() { close(r.changed); r.changed = make(chan struct{}) }
func (r *dockerRuntime) fail(err error) {
	r.failureOnce.Do(func() { r.mu.Lock(); r.err = err; r.changedLocked(); r.mu.Unlock(); close(r.done) })
}
func (r *dockerRuntime) failure() error { r.mu.Lock(); defer r.mu.Unlock(); return r.err }

func (r *dockerRuntime) readyLocked() bool {
	return r.polling && r.runtimeReady && r.extensionsReadyLocked()
}

func (r *dockerRuntime) extensionsReadyLocked() bool {
	if r.phase == "Init" {
		for name := range r.expected {
			if r.byName[name] == nil {
				return false
			}
		}
	}
	for _, extension := range r.extensions {
		if (r.phase == "Init" || extension.invoke) && (extension.state != "Ready" || !extension.polling) {
			return false
		}
	}
	return true
}

func (r *dockerRuntime) waitReady(ctx context.Context) error {
	for {
		r.mu.Lock()
		ready := r.readyLocked()
		changed := r.changed
		err := r.err
		r.mu.Unlock()
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			r.mu.Lock()
			reported := r.reportedError
			r.mu.Unlock()
			if reported != nil {
				return reported
			}
			return ctx.Err()
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-changed:
		}
	}
}

type dockerEnvironment struct {
	engine                                                                                *docker.Client
	spec                                                                                  Specification
	platform                                                                              string
	identity, host                                                                        string
	container, staging, volume, tmpVolume, layerVolume                                    string
	containerRemoved, stagingRemoved, volumeRemoved, tmpVolumeRemoved, layerVolumeRemoved bool
	helperVolume                                                                          string
	helperVolumeRemoved                                                                   bool
	diskVolume                                                                            string
	diskOwner                                                                             *DockerExecutor
	diskRemoved                                                                           bool
	runtimeConfig                                                                         docker.ContainerConfig
	startupTimeout                                                                        time.Duration
	listener                                                                              net.Listener
	server                                                                                *http.Server
	lifetime                                                                              context.Context
	stop                                                                                  context.CancelFunc
	done                                                                                  chan struct{}
	gate                                                                                  chan struct{}
	mu                                                                                    sync.Mutex
	runtime                                                                               *dockerRuntime
	failureOnce                                                                           sync.Once
	closeMu                                                                               sync.Mutex
	err                                                                                   error
	telemetry                                                                             *telemetryManager
	runMu                                                                                 sync.Mutex
	frozen                                                                                bool
	initAttempted                                                                         bool
	hotReload                                                                             *hotReloadWatcher
	sourceRevision                                                                        uint64
}

func (e *dockerEnvironment) fail(err error) {
	e.failureOnce.Do(func() {
		e.mu.Lock()
		e.err = err
		runtime := e.runtime
		e.mu.Unlock()
		if runtime != nil {
			runtime.fail(err)
		}
		if e.telemetry != nil && e.telemetry.remote != nil {
			e.telemetry.remote.cancel()
		}
		close(e.done)
	})
}
func (e *dockerEnvironment) failure() error { e.mu.Lock(); defer e.mu.Unlock(); return e.err }
func (e *dockerEnvironment) currentRuntime() *dockerRuntime {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.runtime
}

func (e *dockerEnvironment) watchKeeper(id string) {
	var exit struct{ StatusCode int64 }
	err := e.engine.JSON(e.lifetime, "POST", "/containers/"+url.PathEscape(id)+"/wait?condition=not-running", nil, &exit)
	if e.lifetime.Err() != nil {
		return
	}
	if err != nil {
		e.fail(fmt.Errorf("waiting for Lambda temporary-storage keeper: %w", err))
		return
	}
	e.fail(fmt.Errorf("lambda temporary-storage keeper exited with status %d", exit.StatusCode))
}

func (e *dockerEnvironment) watchTelemetryContainer(id string) {
	var exit struct{ StatusCode int64 }
	err := e.engine.JSON(e.lifetime, "POST", "/containers/"+url.PathEscape(id)+"/wait?condition=not-running", nil, &exit)
	if e.lifetime.Err() != nil || e.telemetry.remote.ctx.Err() != nil {
		return
	}
	if err != nil {
		e.fail(fmt.Errorf("watching Lambda telemetry owner: %w", err))
		return
	}
	e.fail(&customerFailure{errorType: "Runtime.ExitError", message: fmt.Sprintf("Lambda execution environment exited with status %d", exit.StatusCode)})
}

// Preparation starts only the telemetry owner as PID 1. Customer entrypoints are
// exclusively launched by Invoke, so bad imports/extensions never fail deploy.
func (e *dockerEnvironment) startContainer(ctx context.Context) error {
	var created struct {
		ID string `json:"Id"`
	}
	e.container = e.identity
	e.containerRemoved = false
	if err := e.engine.JSON(ctx, "POST", "/containers/create?name="+e.identity+"&platform="+url.QueryEscape(e.platform), e.runtimeConfig, &created); err != nil {
		return fmt.Errorf("creating Lambda runtime container: %w", err)
	}
	e.container = created.ID
	if err := e.engine.JSON(ctx, "POST", "/containers/"+url.PathEscape(e.container)+"/start", nil, nil); err != nil {
		return fmt.Errorf("starting Lambda runtime container: %w", err)
	}
	go e.watchTelemetryContainer(e.container)
	select {
	case <-e.telemetry.remote.ready:
	case <-ctx.Done():
		return fmt.Errorf("starting Lambda telemetry owner: %w", ctx.Err())
	case <-e.telemetry.remote.ctx.Done():
		return errors.New("lambda telemetry owner exited before readiness")
	}
	e.runMu.Lock()
	e.frozen = false
	e.runMu.Unlock()
	return nil
}

// Recreate the inert backend before starting customer initialization's deadline.
// Docker provisioning is platform work, not a runtime or extension Init step.
func (e *dockerEnvironment) prepareRuntimeContainer(ctx context.Context) error {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	select {
	case <-e.done:
		return e.failure()
	default:
	}
	if e.container != "" && !e.containerRemoved {
		return nil
	}
	startup, cancel := context.WithTimeout(ctx, e.startupTimeout)
	defer cancel()
	if err := e.startContainer(startup); err != nil {
		return fmt.Errorf("preparing Lambda runtime container: %w", err)
	}
	return nil
}

func (e *dockerEnvironment) startRuntime(ctx context.Context, phase string) (*dockerRuntime, error) {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	select {
	case <-e.done:
		return nil, e.failure()
	default:
	}
	runtimeCtx, cancel := context.WithCancel(e.lifetime)
	runtime := &dockerRuntime{ctx: runtimeCtx, cancel: cancel, container: e.container, done: make(chan struct{}), changed: make(chan struct{}), queue: make(chan *runtimeInvocation, 1), phase: "Init", initPhase: phase, expected: make(map[string]bool), extensions: make(map[string]*runtimeExtension), byName: make(map[string]*runtimeExtension)}
	e.mu.Lock()
	e.runtime = runtime
	e.mu.Unlock()
	output, err := execOutput(e.engine, ctx, e.container, []string{"/bin/bash", "-c", `for file in /opt/extensions/*; do if test -f "$file" && test -x "$file"; then printf '%s\0' "${file##*/}"; fi; done`})
	if err != nil {
		cancel()
		return runtime, fmt.Errorf("discovering Lambda extensions: %w", err)
	}
	for _, name := range strings.Split(string(output), "\x00") {
		if name != "" {
			runtime.expected[name] = true
		}
	}
	if _, err := e.telemetry.remote.call(ctx, telemetryCommand{Operation: "resume"}); err != nil {
		return runtime, err
	}
	for _, name := range strings.Split(string(output), "\x00") {
		if name == "" {
			continue
		}
		if err := e.startExtension(ctx, runtime, name); err != nil {
			return runtime, fmt.Errorf("starting extension %s: %w", name, err)
		}
	}
	// AWS starts the runtime after external extensions have registered, but does
	// not wait for their first Next; their remaining initialization runs in parallel.
	for {
		runtime.mu.Lock()
		registered := true
		for name := range runtime.expected {
			if runtime.byName[name] == nil {
				registered = false
				break
			}
		}
		changed := runtime.changed
		failure := runtime.err
		runtime.mu.Unlock()
		if failure != nil {
			return runtime, failure
		}
		if registered {
			break
		}
		select {
		case <-ctx.Done():
			return runtime, ctx.Err()
		case <-runtime.ctx.Done():
			return runtime, runtime.ctx.Err()
		case <-changed:
		}
	}
	process, err := e.startCustomer(ctx, runtime, "runtime", "function", []string{"/lambda-entrypoint.sh", e.spec.Handler})
	if err != nil {
		return runtime, fmt.Errorf("starting Lambda runtime: %w", err)
	}
	runtime.mu.Lock()
	runtime.runtimeProcess = process
	runtime.mu.Unlock()
	return runtime, nil
}

func (e *dockerEnvironment) shutdownRuntime(ctx context.Context, reason string) {
	runtime := e.currentRuntime()
	if runtime == nil {
		return
	}
	if err := e.setFrozen(ctx, false); err != nil {
		return
	}
	runtime.mu.Lock()
	runtime.phase = "Shutdown"
	process := runtime.runtimeProcess
	budget := time.Duration(0)
	for _, extension := range runtime.extensions {
		if extension.external {
			budget = 2 * time.Second
			break
		}
		budget = 500 * time.Millisecond
	}
	runtime.changedLocked()
	runtime.mu.Unlock()
	if budget == 0 {
		return
	}
	deadline := time.Now().Add(budget)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	// The runtime/internal-extension step and external callbacks share the one
	// documented shutdown budget; an uncooperative runtime cannot extend it.
	runtimeDeadline := time.Now().Add(500 * time.Millisecond)
	if deadline.Before(runtimeDeadline) {
		runtimeDeadline = deadline
	}
	runtimeCtx, runtimeCancel := context.WithDeadline(ctx, runtimeDeadline)
	_ = e.signalProcess(runtimeCtx, process, "TERM")
	if process != nil {
		select {
		case <-process.done:
		case <-runtimeCtx.Done():
		}
	}
	runtimeCancel()
	event := extensionapi.EventShutdown{EventType: new("SHUTDOWN"), DeadlineMs: new(deadline.UnixMilli()), ShutdownReason: &reason}
	runtime.mu.Lock()
	for _, extension := range runtime.extensions {
		if extension.external && extension.shutdown && !extension.exited && extension.state != "InitError" && extension.state != "ExitError" {
			// An extension still processing INVOKE receives SHUTDOWN on its next poll.
			select {
			case extension.events <- event:
			default:
			}
		}
	}
	runtime.changedLocked()
	runtime.mu.Unlock()
	shutdownCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for {
		runtime.mu.Lock()
		complete := true
		for _, extension := range runtime.extensions {
			if extension.external && extension.shutdown && !extension.exited && extension.state != "ExitError" && extension.state != "InitError" {
				// Channel receipt can precede the receiver acquiring this mutex.
				// Only a poll after delivered SHUTDOWN acknowledges completion.
				if extension.state != "Ready" || !extension.shutdownDelivered {
					complete = false
					break
				}
			}
		}
		changed := runtime.changed
		runtime.mu.Unlock()
		if complete {
			return
		}
		select {
		case <-shutdownCtx.Done():
			return
		case <-changed:
		}
	}
}

// PID 1 kills/reaps every customer process in its private namespace, including
// detached descendants. Subscription data and the memory cgroup survive reset.
func (e *dockerEnvironment) resetRuntime(ctx context.Context, reason string) error {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	runtime := e.currentRuntime()
	if e.container == "" || e.containerRemoved {
		return nil
	}
	e.shutdownRuntime(ctx, reason)
	if _, err := e.telemetry.remote.call(ctx, telemetryCommand{Operation: "reset"}); err != nil {
		killErr := e.killRuntime(ctx)
		if removeErr := e.engine.RemoveContainer(ctx, e.container); removeErr != nil {
			return errors.Join(err, killErr, removeErr)
		}
		e.containerRemoved = true
		e.telemetry.remote.cancel()
		e.fail(fmt.Errorf("lambda telemetry reset failed: %w", err))
		return err
	}
	if runtime != nil {
		runtime.finishProcesses(ctx)
	}
	e.runMu.Lock()
	e.frozen = false
	e.runMu.Unlock()
	e.mu.Lock()
	e.runtime = nil
	e.mu.Unlock()
	return nil
}

func (e *dockerEnvironment) Invoke(ctx context.Context, invocation Invocation, respond func(Result)) (report Report, returned error) {
	if invocation.RequestID == "" || strings.ContainsAny(invocation.RequestID, "/\\\x00\r\n") {
		return report, fmt.Errorf("invalid Lambda invocation request ID")
	}
	if len(invocation.Payload) > maxRuntimeResponse {
		return report, fmt.Errorf("lambda invocation payload exceeds %d bytes", maxRuntimeResponse)
	}
	if strings.ContainsAny(invocation.ClientContext, "\r\n\x00") || strings.ContainsAny(invocation.TraceID, "\r\n\x00") {
		return report, fmt.Errorf("invalid Lambda invocation context headers")
	}
	if respond == nil {
		return report, fmt.Errorf("lambda response callback is required")
	}
	select {
	case <-ctx.Done():
		return report, ctx.Err()
	case <-e.done:
		return report, e.failure()
	case <-e.gate:
	}
	defer func() { e.gate <- struct{}{} }()
	if err := e.reloadSource(ctx); err != nil {
		return report, err
	}
	if e.currentRuntime() != nil {
		if err := e.setFrozen(ctx, false); err != nil {
			return report, err
		}
		if err := e.drainOutput(ctx); err != nil {
			return report, err
		}
	}
	e.telemetry.BeginInvocation()
	defer func() {
		if report.Logs == nil {
			report.Logs = e.telemetry.EndInvocation()
		}
	}()
	started := time.Now()
	report.Status = InvocationSuccess
	responseSent := false
	var initDuration *float64
	var pending *runtimeInvocation
	send := func(result Result) {
		if !responseSent {
			responseSent = true
			respond(result)
		}
	}
	finishFailure := func(cause error) (Report, error) {
		var runtimeDoneAt time.Time
		if current := e.currentRuntime(); current != nil {
			// Close response admission before inspecting the winning result. A late
			// runtime poll cannot publish a second completion after the phase failed.
			current.fail(cause)
			var responseDone <-chan struct{}
			current.mu.Lock()
			report.HasExtensions = len(current.expected) != 0 || len(current.extensions) != 0
			if pending != nil {
				runtimeDoneAt = pending.runtimeDoneAt
				pending.cancelResponse()
				responseDone = pending.responseDone
			}
			current.mu.Unlock()
			// A response reader may be blocked on customer input or downstream
			// backpressure. Cancel and join it before publishing terminal failure.
			if responseDone != nil {
				<-responseDone
			}
		}
		var customer *customerFailure
		var platformReport telemetryapi.PlatformReport
		if cause == context.DeadlineExceeded && ctx.Err() == nil {
			customer = &customerFailure{errorType: "Sandbox.Timedout", message: fmt.Sprintf("Task timed out after %.2f seconds", e.spec.Timeout.Seconds()), timeout: true}
		} else {
			errors.As(cause, &customer)
		}
		finishedAt := time.Now()
		// A timeout ends the phase at its deadline, not when the host goroutine
		// happens to run. Shutdown and telemetry delivery are outside that duration.
		if customer != nil && customer.timeout {
			finishedAt = started.Add(e.spec.Timeout)
			if pending != nil {
				finishedAt = pending.deadline
			}
		}
		report.Duration = finishedAt.Sub(started)
		if pending != nil {
			if !runtimeDoneAt.IsZero() && finishedAt.After(runtimeDoneAt) {
				report.PostRuntimeExtensionsDuration = finishedAt.Sub(runtimeDoneAt)
			}
			// A posted response wins even when an exit notification races the waiter.
			select {
			case result := <-pending.result:
				send(result)
			default:
			}
			// Streaming response headers commit the response independently of
			// phase success. The joined reader retains the prefix on timeout.
			if !responseSent && pending.streamedResponse != nil {
				send(*pending.streamedResponse)
			}
		}
		reason := "failure"
		if customer != nil {
			report.Status = InvocationFailure
			if customer.timeout {
				report.Status = InvocationTimeout
				reason = "timeout"
			}
			if pending != nil && runtimeDoneAt.IsZero() {
				failedAt := time.Now()
				record := telemetryapi.PlatformRuntimeDone{RequestId: invocation.RequestID, Status: string(report.Status), Metrics: &telemetryapi.RuntimeDoneMetrics{DurationMs: float64(failedAt.Sub(pending.started)) / float64(time.Millisecond), ProducedBytes: &pending.producedBytes}}
				if !customer.timeout {
					record.ErrorType = &customer.errorType
				}
				e.telemetry.Emit(failedAt, "platform.runtimeDone", record)
			}
			if !responseSent {
				payload := customer.payload
				if len(payload) == 0 {
					message := "RequestId: " + invocation.RequestID + " Error: " + customer.message
					payload, _ = json.Marshal(extensionapi.ErrorResponse{ErrorType: &customer.errorType, ErrorMessage: &message})
				}
				send(Result{Payload: payload, FunctionError: "Unhandled"})
				if customer.timeout {
					report.Status = InvocationTimeout
				}
			}
			platformReport = e.prepareReport(invocation.RequestID, report, initDuration, customer.errorType, runtimeDoneAt)
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		resetErr := e.resetRuntime(cleanupCtx, reason)
		if customer != nil {
			// AWS emits the terminal fault/end/report after shutdown. Retaining these
			// records outside the dead generation lets its replacement receive them.
			reportedAt := time.Now()
			if customer.timeout {
				e.telemetry.Emit(reportedAt, "platform.fault", "RequestId: "+invocation.RequestID+"\tStatus: timeout\n")
			}
			if pending != nil && runtimeDoneAt.IsZero() {
				e.telemetry.Emit(reportedAt, "platform.end", telemetryapi.LogsPlatformEnd{RequestId: invocation.RequestID})
			}
			e.telemetry.Emit(reportedAt, "platform.report", platformReport)
		}
		if resetErr != nil {
			e.fail(resetErr)
			return report, errors.Join(cause, resetErr)
		}
		if customer != nil {
			return report, nil
		}
		return report, cause
	}
	runtime := e.currentRuntime()
	if runtime != nil {
		if err := e.setFrozen(ctx, false); err != nil {
			return finishFailure(err)
		}
		select {
		case <-runtime.done:
			var customer *customerFailure
			if !errors.As(runtime.failure(), &customer) {
				return finishFailure(runtime.failure())
			}
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			err := e.resetRuntime(cleanupCtx, "failure")
			cancel()
			if err != nil {
				return report, err
			}
			runtime = nil
		default:
		}
	}
	if runtime == nil {
		attempts := 1
		phase := "invoke"
		if !e.initAttempted {
			attempts = 2
			phase = "init"
			e.initAttempted = true
		}
		for attempt := range attempts {
			if err := e.prepareRuntimeContainer(ctx); err != nil {
				return finishFailure(err)
			}
			initStart := time.Now()
			timeout := e.spec.Timeout
			if phase == "init" {
				timeout = 10 * time.Second
			} else {
				started = initStart
			}
			initCtx, cancel := context.WithDeadline(ctx, initStart.Add(timeout))
			e.telemetry.Emit(initStart, "platform.initStart", telemetryapi.PlatformInitStart{InitializationType: e.initializationType(), Phase: telemetryapi.InitPhase(phase), FunctionName: &e.spec.FunctionName, FunctionVersion: new(e.functionVersion())})
			var err error
			runtime, err = e.startRuntime(initCtx, phase)
			if err == nil {
				err = runtime.waitReady(initCtx)
			}
			cancel()
			duration := float64(time.Since(initStart)) / float64(time.Millisecond)
			status, errorType := "success", ""
			if err != nil {
				status = "error"
				var customer *customerFailure
				if errors.As(err, &customer) {
					errorType = customer.errorType
				} else if err == context.DeadlineExceeded && ctx.Err() == nil {
					status = "timeout"
				} else {
					return finishFailure(err)
				}
			}
			initReport := telemetryapi.PlatformInitReport{InitializationType: e.initializationType(), Phase: telemetryapi.InitPhase(phase), Status: &status, Metrics: telemetryapi.InitReportMetrics{DurationMs: duration}}
			if errorType != "" {
				initReport.ErrorType = &errorType
			}
			e.telemetry.Emit(time.Now(), "platform.initReport", initReport)
			if err == nil {
				if phase == "init" {
					initDuration = &duration
					started = time.Now()
				}
				break
			}
			if attempt+1 == attempts {
				return finishFailure(err)
			}
			cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			reason := "failure"
			if errors.Is(err, context.DeadlineExceeded) {
				reason = "timeout"
			}
			resetErr := e.resetRuntime(cleanupCtx, reason)
			cleanupCancel()
			if resetErr != nil {
				return report, errors.Join(err, resetErr)
			}
			phase = "invoke"
		}
	} else {
		started = time.Now()
	}
	// A suppressed Init contributes to reported duration, but the native INVOKE
	// event starts a fresh function-timeout budget after initialization is ready.
	invokeStarted := time.Now()
	invocationCtx, cancelInvocation := context.WithDeadline(ctx, invokeStarted.Add(e.spec.Timeout))
	defer cancelInvocation()
	deadline, _ := invocationCtx.Deadline()
	pending = &runtimeInvocation{invocation: invocation, deadline: deadline, started: invokeStarted, result: make(chan Result, 1), responseContext: invocationCtx, cancelResponse: cancelInvocation}
	arn := invocation.FunctionARN
	if arn == "" {
		arn = e.spec.FunctionARN
	}
	e.telemetry.Emit(time.Now(), "platform.start", telemetryapi.PlatformStart{RequestId: invocation.RequestID, Version: new(e.functionVersion()), FunctionArn: &arn})
	runtime.mu.Lock()
	runtime.phase = "Invoke"
	runtime.active = pending
	report.HasExtensions = len(runtime.expected) != 0 || len(runtime.extensions) != 0
	for _, extension := range runtime.extensions {
		if !extension.invoke {
			continue
		}
		extension.state = "Running"
		arn := invocation.FunctionARN
		if arn == "" {
			arn = e.spec.FunctionARN
		}
		extension.events <- extensionapi.EventInvoke{EventType: new("INVOKE"), DeadlineMs: new(deadline.UnixMilli()), RequestId: &invocation.RequestID, InvokedFunctionArn: &arn, Tracing: &extensionapi.XRayTracingInfo{Type: new("X-Amzn-Trace-Id"), Value: &invocation.TraceID}}
	}
	runtime.changedLocked()
	runtime.mu.Unlock()
	runtime.queue <- pending
	for {
		runtime.mu.Lock()
		complete := pending.responded && runtime.readyLocked()
		report.FunctionFailed = pending.functionFailed
		changed := runtime.changed
		completedAt := pending.runtimeDoneAt
		for _, extension := range runtime.extensions {
			if extension.invoke && extension.readyAt.After(completedAt) {
				completedAt = extension.readyAt
			}
		}
		runtimeDoneAt := pending.runtimeDoneAt
		failure := runtime.err
		runtime.mu.Unlock()
		if failure != nil {
			return finishFailure(failure)
		}
		if complete && responseSent {
			report.Duration = completedAt.Sub(started)
			if completedAt.After(runtimeDoneAt) {
				report.PostRuntimeExtensionsDuration = completedAt.Sub(runtimeDoneAt)
			}
			if err := e.drainOutput(invocationCtx); err != nil {
				return finishFailure(err)
			}
			e.telemetry.Emit(time.Now(), "platform.report", e.prepareReport(invocation.RequestID, report, initDuration, "", runtimeDoneAt))
			report.Logs = e.telemetry.EndInvocation()
			runtime.mu.Lock()
			runtime.phase = "Idle"
			runtime.active = nil
			runtime.mu.Unlock()
			if err := e.setFrozen(ctx, true); err != nil {
				return finishFailure(err)
			}
			return report, nil
		}
		select {
		case result := <-pending.result:
			send(result)
		case <-changed:
		case <-runtime.done:
			return finishFailure(runtime.failure())
		case <-e.done:
			return finishFailure(e.failure())
		case <-invocationCtx.Done():
			runtime.mu.Lock()
			reported := runtime.reportedError
			runtime.mu.Unlock()
			if reported != nil {
				return finishFailure(reported)
			}
			return finishFailure(invocationCtx.Err())
		}
	}
}

func (e *dockerEnvironment) prepareReport(requestID string, report Report, initDuration *float64, errorType string, runtimeDoneAt time.Time) telemetryapi.PlatformReport {
	duration := float64(report.Duration) / float64(time.Millisecond)
	billed := uint64((report.Duration + time.Millisecond - 1) / time.Millisecond)
	if initDuration != nil {
		billed = uint64(math.Ceil(duration + *initDuration))
	}
	status := string(report.Status)
	record := telemetryapi.PlatformReport{RequestId: requestID, Status: &status, Metrics: telemetryapi.ReportMetrics{DurationMs: duration, BilledDurationMs: &billed, InitDurationMs: initDuration, MemorySizeMB: new(uint64(e.spec.MemoryMB))}}
	memoryCtx, cancel := context.WithTimeout(e.lifetime, time.Second)
	defer cancel()
	record.Metrics.MaxMemoryUsedMB = e.memoryPeak(memoryCtx)
	if report.Status != InvocationTimeout && errorType != "" {
		record.ErrorType = &errorType
	}
	if report.HasExtensions && !runtimeDoneAt.IsZero() {
		record.Spans = []telemetryapi.Span{runtimeSpan("extensionOverhead", runtimeDoneAt, report.PostRuntimeExtensionsDuration)}
	}
	return record
}

// Close is retryable, and destroys only exact-owned resources. The keeper and
// volumes remain until removal has proved no customer process can survive.
func (e *dockerEnvironment) Close(ctx context.Context) error {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	var failures []error
	runtime := e.currentRuntime()
	if e.container != "" && !e.containerRemoved {
		e.shutdownRuntime(ctx, "spindown")
		select {
		case <-e.telemetry.remote.ready:
			if _, err := e.telemetry.remote.call(ctx, telemetryCommand{Operation: "reset"}); err != nil {
				failures = append(failures, fmt.Errorf("draining Lambda output: %w", err))
			}
		default:
		}
		e.telemetry.remote.cancel()
		_ = e.killRuntime(ctx)
	}
	// A canceled Engine create can finish after an earlier DELETE returned 404.
	// Retry removal of the exact-owned resource before releasing its volumes.
	if e.container != "" {
		if err := e.engine.RemoveContainer(ctx, e.container); err != nil {
			e.containerRemoved = false
			failures = append(failures, fmt.Errorf("removing Lambda runtime %s: %w", e.container, err))
		} else {
			e.containerRemoved = true
		}
	}
	if runtime != nil {
		if !e.containerRemoved {
			runtime.cancel()
		}
		runtime.finishProcesses(ctx)
	}
	e.fail(fmt.Errorf("lambda execution environment is closed"))
	e.stop()
	if e.telemetry != nil {
		if err := e.telemetry.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	if e.server != nil {
		_ = e.server.Close()
	}
	if (e.container == "" || e.containerRemoved) && e.staging != "" {
		if err := e.engine.RemoveContainer(ctx, e.staging); err != nil {
			e.stagingRemoved = false
			failures = append(failures, fmt.Errorf("removing Lambda storage keeper %s: %w", e.staging, err))
		} else {
			e.stagingRemoved = true
		}
	}
	if (e.container == "" || e.containerRemoved) && (e.staging == "" || e.stagingRemoved) {
		for _, volume := range []struct {
			name    string
			removed *bool
		}{{e.volume, &e.volumeRemoved}, {e.tmpVolume, &e.tmpVolumeRemoved}, {e.layerVolume, &e.layerVolumeRemoved}, {e.helperVolume, &e.helperVolumeRemoved}} {
			if volume.name == "" || *volume.removed {
				continue
			}
			err := e.engine.JSON(ctx, "DELETE", "/volumes/"+url.PathEscape(volume.name), nil, nil)
			var remote *docker.Error
			if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
				err = nil
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("removing Lambda volume %s: %w", volume.name, err))
			} else {
				*volume.removed = true
			}
		}
		if e.tmpVolumeRemoved && e.diskOwner != nil && !e.diskRemoved {
			if err := e.diskOwner.removeDisk(ctx, e.diskVolume, e.diskOwner.labels(e.identity, e.spec.FunctionARN)); err != nil {
				failures = append(failures, err)
			} else {
				e.diskRemoved = true
			}
		}
	}
	return errors.Join(failures...)
}

func (e *dockerEnvironment) killRuntime(ctx context.Context) error {
	_ = e.setFrozen(ctx, false)
	err := e.engine.JSON(ctx, "POST", "/containers/"+url.PathEscape(e.container)+"/kill?signal=KILL", nil, nil)
	var remote *docker.Error
	if errors.As(err, &remote) && (remote.StatusCode == http.StatusConflict || remote.StatusCode == http.StatusNotFound) {
		return nil
	}
	return err
}

func (e *dockerEnvironment) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Host != e.host {
		http.Error(w, "unknown execution environment", http.StatusForbidden)
		return
	}
	select {
	case <-e.done:
		http.Error(w, "execution environment is closed", http.StatusGone)
		return
	default:
	}
	if strings.HasPrefix(r.URL.Path, e.telemetry.remote.path) {
		e.telemetry.remote.serve(w, r)
		return
	}
	runtime := e.currentRuntime()
	if runtime == nil || runtime.ctx.Err() != nil {
		http.Error(w, "runtime is resetting", http.StatusGone)
		return
	}
	if strings.HasPrefix(r.URL.Path, extensionPrefix) {
		e.extensionAPI(runtime, w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/2022-07-01/telemetry") || strings.HasPrefix(r.URL.Path, "/2020-08-15/logs") {
		e.telemetry.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == runtimePrefix+"invocation/next" && r.Method == http.MethodGet {
		e.next(runtime, w, r)
		return
	}
	if r.URL.Path == runtimePrefix+"init/error" && r.Method == http.MethodPost {
		e.initError(runtime, w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, runtimePrefix+"invocation/") && r.Method == http.MethodPost {
		e.respond(runtime, w, r)
		return
	}
	http.NotFound(w, r)
}

func (e *dockerEnvironment) next(runtime *dockerRuntime, w http.ResponseWriter, r *http.Request) {
	runtime.mu.Lock()
	if runtime.err != nil || runtime.polling || (runtime.active != nil && !runtime.active.responded) {
		runtime.mu.Unlock()
		writeRuntimeError(w, &runtimeAPIError{409, "Runtime.InvalidState", "Runtime cannot accept another invocation poll"})
		return
	}
	initial := !runtime.initialized
	runtime.initialized = true
	runtime.polling = true
	runtime.runtimeReady = false
	pending := runtime.active
	if pending != nil && pending.runtimeDoneAt.IsZero() {
		pending.runtimeDoneAt = time.Now()
	}
	phase := runtime.initPhase
	runtime.mu.Unlock()
	if err := e.drainOutput(r.Context()); err != nil {
		runtime.fail(err)
		http.Error(w, "runtime output unavailable", http.StatusServiceUnavailable)
		return
	}
	if initial {
		e.telemetry.Emit(time.Now(), "platform.initRuntimeDone", telemetryapi.PlatformInitRuntimeDone{InitializationType: e.initializationType(), Phase: telemetryapi.InitPhase(phase), Status: "success"})
	} else if pending != nil {
		record := telemetryapi.PlatformRuntimeDone{RequestId: pending.invocation.RequestID, Status: "success", Metrics: &telemetryapi.RuntimeDoneMetrics{DurationMs: float64(pending.runtimeDoneAt.Sub(pending.started)) / float64(time.Millisecond), ProducedBytes: &pending.producedBytes}}
		if !pending.responseStartedAt.IsZero() {
			record.Spans = []telemetryapi.Span{
				runtimeSpan("responseLatency", pending.started, pending.responseStartedAt.Sub(pending.started)),
				runtimeSpan("responseDuration", pending.responseStartedAt, pending.responseDoneAt.Sub(pending.responseStartedAt)),
				runtimeSpan("runtimeOverhead", pending.responseDoneAt, pending.runtimeDoneAt.Sub(pending.responseDoneAt)),
			}
		}
		e.telemetry.Emit(pending.runtimeDoneAt, "platform.runtimeDone", record)
		e.telemetry.Emit(time.Now(), "platform.end", telemetryapi.LogsPlatformEnd{RequestId: pending.invocation.RequestID})
	}
	runtime.mu.Lock()
	runtime.runtimeReady = true
	runtime.changedLocked()
	runtime.mu.Unlock()
	release := func() {
		runtime.mu.Lock()
		runtime.polling = false
		runtime.runtimeReady = false
		runtime.changedLocked()
		runtime.mu.Unlock()
	}
	select {
	case <-runtime.ctx.Done():
		release()
		http.Error(w, "runtime is closed", http.StatusGone)
		return
	case <-r.Context().Done():
		release()
		return
	case pending = <-runtime.queue:
	}
	runtime.mu.Lock()
	runtime.polling = false
	runtime.runtimeReady = false
	runtime.changedLocked()
	runtime.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Lambda-Runtime-Aws-Request-Id", pending.invocation.RequestID)
	w.Header().Set("Lambda-Runtime-Invocation-Id", pending.invocation.RequestID)
	w.Header().Set("Lambda-Runtime-Deadline-Ms", strconv.FormatInt(pending.deadline.UnixMilli(), 10))
	arn := pending.invocation.FunctionARN
	if arn == "" {
		arn = e.spec.FunctionARN
	}
	w.Header().Set("Lambda-Runtime-Invoked-Function-Arn", arn)
	if pending.invocation.ClientContext != "" {
		w.Header().Set("Lambda-Runtime-Client-Context", pending.invocation.ClientContext)
	}
	if pending.invocation.TraceID != "" {
		w.Header().Set("Lambda-Runtime-Trace-Id", pending.invocation.TraceID)
	}
	if _, err := w.Write(pending.invocation.Payload); err != nil {
		runtime.fail(fmt.Errorf("delivering Lambda invocation: %w", err))
	}
}

func (e *dockerEnvironment) initError(runtime *dockerRuntime, w http.ResponseWriter, r *http.Request) {
	runtime.mu.Lock()
	initialized := runtime.initialized
	phase := runtime.initPhase
	runtime.mu.Unlock()
	if initialized {
		writeRuntimeError(w, &runtimeAPIError{403, "Runtime.InvalidState", "Runtime has already initialized"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRuntimeResponse))
	if err != nil {
		http.Error(w, "invalid initialization error body", http.StatusRequestEntityTooLarge)
		return
	}
	writeRuntimeJSON(w, http.StatusAccepted, extensionapi.StatusResponse{Status: new("OK")})
	_ = http.NewResponseController(w).Flush()
	errorType := r.Header.Get("Lambda-Runtime-Function-Error-Type")
	if errorType == "" {
		errorType = "Runtime.Unknown"
	}
	var native extensionapi.ErrorRequest
	if json.Unmarshal(body, &native) == nil && native.ErrorType != nil {
		errorType = *native.ErrorType
	}
	e.telemetry.Emit(time.Now(), "platform.initRuntimeDone", telemetryapi.PlatformInitRuntimeDone{InitializationType: e.initializationType(), Phase: telemetryapi.InitPhase(phase), Status: "error", ErrorType: &errorType})
	runtime.fail(&customerFailure{errorType: errorType, message: "Runtime failed to initialize", payload: body})
}

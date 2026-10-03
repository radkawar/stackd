package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"stackd/compute/lambda/internal/extensionapi"
)

const maxRuntimeStreamingResponse = 200 << 20

func (e *dockerEnvironment) respond(runtime *dockerRuntime, w http.ResponseWriter, r *http.Request) {
	receivedAt := time.Now()
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, runtimePrefix+"invocation/"), "/")
	if len(parts) != 2 || (parts[1] != "response" && parts[1] != "error") {
		http.NotFound(w, r)
		return
	}
	runtime.mu.Lock()
	pending := runtime.active
	if pending == nil || pending.invocation.RequestID != parts[0] {
		runtime.mu.Unlock()
		http.Error(w, "unknown invocation request ID", http.StatusBadRequest)
		return
	}
	if id := r.Header.Get("Lambda-Runtime-Invocation-Id"); id != "" && id != pending.invocation.RequestID {
		runtime.mu.Unlock()
		http.Error(w, "invalid invocation ID", http.StatusBadRequest)
		return
	}
	if pending.responseDone != nil || pending.responded || runtime.err != nil || runtime.ctx.Err() != nil {
		runtime.mu.Unlock()
		http.Error(w, "invocation already completed", http.StatusConflict)
		return
	}
	pending.responseDone = make(chan struct{})
	runtime.mu.Unlock()
	defer close(pending.responseDone)
	controller := http.NewResponseController(w)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(pending.responseContext, func() {
		defer close(interrupted)
		// Abort writes before waking the blocked Read: returning from an
		// unwritten handler must not turn timeout into an implicit HTTP 200.
		// Body.Close alone can wait behind that Read instead of interrupting it.
		now := time.Now()
		_ = controller.SetWriteDeadline(now)
		_ = controller.SetReadDeadline(now)
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()

	mode := r.Header.Get("Lambda-Runtime-Function-Response-Mode")
	if mode != "" && mode != "buffered" && mode != "streaming" {
		http.Error(w, "invalid response mode", http.StatusBadRequest)
		runtime.fail(&customerFailure{errorType: "Runtime.InvalidResponse", message: "Invalid response mode: " + mode})
		return
	}
	if mode == "streaming" && !slices.Contains(r.TransferEncoding, "chunked") {
		http.Error(w, "streaming responses require chunked transfer encoding", http.StatusBadRequest)
		runtime.fail(&customerFailure{errorType: "Runtime.InvalidResponse", message: "Streaming responses require chunked transfer encoding"})
		return
	}

	result := Result{ContentType: r.Header.Get("Content-Type"), Streaming: mode == "streaming"}
	if result.Streaming && parts[1] == "response" {
		runtime.mu.Lock()
		pending.streamedResponse = &result
		runtime.mu.Unlock()
	}
	var produced uint64
	var err error
	if mode == "streaming" && parts[1] == "response" && pending.invocation.Stream != nil {
		produced, err = streamRuntimeResponse(pending.responseContext, r.Body, func(ctx context.Context, payload []byte) error {
			return pending.invocation.Stream(ctx, result.ContentType, payload)
		})
	} else {
		// The captured buffered size error names a 6 MiB + 100 byte limit.
		// Do not retain the oversized remainder or interrupt customer execution.
		const maximum = maxRuntimeResponse + 100
		result.Payload, err = io.ReadAll(io.LimitReader(r.Body, maximum+1))
		produced = uint64(len(result.Payload))
		if err == nil && len(result.Payload) > maximum {
			var discarded int64
			discarded, err = io.Copy(io.Discard, r.Body)
			produced += uint64(discarded)
			result.Payload, _ = json.Marshal(extensionapi.ErrorResponse{
				ErrorType:    new("Function.ResponseSizeTooLarge"),
				ErrorMessage: new(fmt.Sprintf("Response payload size exceeded maximum allowed payload size (%d bytes).", maximum)),
			})
			result.FunctionError = "Unhandled"
		}
	}
	if parts[1] == "error" {
		result.FunctionError = "Unhandled"
		produced = 0
	}
	runtime.mu.Lock()
	pending.producedBytes = produced
	runtime.mu.Unlock()
	if err != nil {
		if pending.responseContext.Err() != nil {
			return
		}
		http.Error(w, "invalid runtime response", http.StatusRequestEntityTooLarge)
		runtime.fail(&customerFailure{errorType: "Runtime.InvalidResponse", message: err.Error()})
		return
	}
	// Native streaming trailers affect Errors metrics, not public FunctionError
	// or asynchronous destination routing. /error remains an error payload.

	runtime.mu.Lock()
	if runtime.err != nil || pending.responseContext.Err() != nil {
		runtime.mu.Unlock()
		return
	}
	pending.responded = true
	pending.functionFailed = result.FunctionError != "" || r.Trailer.Get("Lambda-Runtime-Function-Error-Type") != ""
	if parts[1] == "response" {
		pending.responseStartedAt = receivedAt
		pending.responseDoneAt = time.Now()
	}
	result.ExtensionsPending = !runtime.extensionsReadyLocked()
	// The generation lock arbitrates response acceptance against process failure.
	pending.result <- result
	runtime.changedLocked()
	runtime.mu.Unlock()
	writeRuntimeJSON(w, http.StatusAccepted, extensionapi.StatusResponse{Status: new("OK")})
}

// Streaming is customer execution: pacing and deadlines use wall time, not the
// service scheduler. One borrowed chunk bounds runtime-to-consumer memory use.
func streamRuntimeResponse(ctx context.Context, body io.Reader, write func(context.Context, []byte) error) (uint64, error) {
	const rate = 2 << 20
	buffer := make([]byte, 32<<10)
	var produced uint64
	var pacedAt time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	if err := write(ctx, nil); err != nil {
		return 0, err
	}
	for {
		// The native fixture forwards the first byte beyond 200 MiB, then
		// completes without a terminal error. Drain the runtime remainder
		// rather than cancelling accepted customer execution at this boundary.
		remaining := maxRuntimeStreamingResponse + 1 - int(produced)
		if remaining == 0 {
			discarded, err := io.Copy(io.Discard, body)
			return produced + uint64(discarded), err
		}
		n, err := body.Read(buffer[:min(len(buffer), remaining)])
		accepted := n
		if accepted != 0 {
			produced += uint64(accepted)
			if produced > maxRuntimeResponse {
				if pacedAt.IsZero() {
					pacedAt = time.Now()
				}
				due := pacedAt.Add(time.Duration(produced-maxRuntimeResponse) * time.Second / rate)
				if delay := time.Until(due); delay > 0 {
					if timer == nil {
						timer = time.NewTimer(delay)
					} else {
						timer.Reset(delay)
					}
					select {
					case <-ctx.Done():
						return produced, ctx.Err()
					case <-timer.C:
					}
				}
			}
			if err := write(ctx, buffer[:accepted]); err != nil {
				return produced, err
			}
		}
		if errors.Is(err, io.EOF) {
			return produced, nil
		}
		if err != nil {
			return produced, err
		}
	}
}

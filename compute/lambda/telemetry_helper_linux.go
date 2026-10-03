package lambda

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// RunTelemetryBuffer is the runtime container's PID 1, not a customer runtime.
// The official image entrypoint and all extensions are still Docker execs driven
// by the existing Runtime/Extension API lifecycle. Ordinary resets kill every
// other process in this private PID namespace, retaining actual buffer memory
// and its cgroup. The container itself remains the final cleanup boundary.
func RunTelemetryBuffer(endpoint string) error {
	if os.Getpid() != 1 {
		return fmt.Errorf("telemetry buffer must be container PID 1")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &containerTelemetryOwner{ctx: ctx, wake: make(chan struct{}), client: &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	defer owner.client.CloseIdleConnections()
	manager := newTelemetryManager(ctx, owner, io.Discard)
	defer manager.Close()
	go reapTelemetryChildren(ctx)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	manager.forwardOutput = func(body []byte, deliver, capture bool) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/output", bytes.NewReader(body))
		if err == nil {
			request.Header.Set("X-Stackd-Log-Deliver", strconv.FormatBool(deliver))
			request.Header.Set("X-Stackd-Log-Capture", strconv.FormatBool(capture))
			var response *http.Response
			response, err = client.Do(request)
			if err == nil {
				response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					err = fmt.Errorf("output consumer returned %s", response.Status)
				}
			}
		}
		if err != nil {
			// A broken private stream is a runtime transport failure, not a
			// successful invocation with silently missing logs.
			cancel()
		}
	}
	pipes := &telemetryPipes{manager: manager}
	defer pipes.close()
	manager.deliver = owner.deliverTelemetry
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		var command telemetryCommand
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return fmt.Errorf("telemetry command endpoint returned %s", response.Status)
		}
		err = json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&command)
		response.Body.Close()
		if err != nil {
			return err
		}
		reply := telemetryReply{ID: command.ID}
		switch command.Operation {
		case "open-output":
			if len(pipes.streams) == 0 {
				err = json.Unmarshal(command.Body, &manager.logging)
			}
			if err == nil {
				err = pipes.open(command.Path, command.Kind, command.Name)
			}
			if err != nil {
				reply.Error = err.Error()
			}
		case "drain-output":
			if err := pipes.drain(); err != nil {
				reply.Error = err.Error()
			}
		case "emit":
			manager.emitRecord(command.At, command.Kind, command.Body)
		case "flush":
			manager.flush()
		case "subscribe":
			request, err := http.NewRequest(http.MethodPut, "http://runtime"+command.Path, bytes.NewReader(command.Body))
			if err != nil {
				return err
			}
			request.Header.Set("Lambda-Extension-Identifier", command.Name)
			output := &telemetryResponse{header: make(http.Header), Code: http.StatusOK}
			manager.ServeHTTP(output, request)
			reply.Status, reply.Body = output.Code, output.Body.Bytes()
		case "resume":
			owner.resume()
		case "reset":
			owner.pause()
			if err := errors.Join(resetTelemetryProcesses(), pipes.close()); err != nil {
				reply.Error = err.Error()
			}
		default:
			reply.Error = "unknown telemetry command"
		}
		body, err := json.Marshal(reply)
		if err != nil {
			return err
		}
		request, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/"+strconv.FormatUint(command.ID, 10), bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err = client.Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("telemetry reply endpoint returned %s", response.Status)
		}
	}
}

func reapTelemetryChildren(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		for {
			pid, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
			if pid <= 0 || err != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type telemetryResponse struct {
	header http.Header
	Code   int
	Body   bytes.Buffer
}

func (r *telemetryResponse) Header() http.Header            { return r.header }
func (r *telemetryResponse) WriteHeader(status int)         { r.Code = status }
func (r *telemetryResponse) Write(body []byte) (int, error) { return r.Body.Write(body) }

func resetTelemetryProcesses() error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		// Linux excludes namespace PID 1 and the caller from kill(-1). No host
		// namespace or elevated capability is used, and detached groups are not
		// exempt. Repeat to cover a fork concurrent with the first kill.
		if err := syscall.Kill(-1, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return err
		}
		remaining := false
		for _, entry := range entries {
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid <= 1 {
				continue
			}
			// A zombie still has an owner. Do not acknowledge reset until the
			// PID 1 reaper (or Docker's exec parent) has collected it as well.
			remaining = true
		}
		if !remaining {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("customer processes survived telemetry reset")
		}
		time.Sleep(time.Millisecond)
	}
}

type containerTelemetryOwner struct {
	ctx    context.Context
	mu     sync.Mutex
	active context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	client *http.Client
}

func (o *containerTelemetryOwner) lookupExtension(name string) (string, *runtimeAPIError) {
	return name, nil
}
func (o *containerTelemetryOwner) initializing() bool { return true }
func (o *containerTelemetryOwner) resume() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.active == nil {
		o.active, o.cancel = context.WithCancel(o.ctx)
		close(o.wake)
		o.wake = make(chan struct{})
	}
}
func (o *containerTelemetryOwner) pause() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cancel != nil {
		o.cancel()
	}
	o.active, o.cancel = nil, nil
}
func (o *containerTelemetryOwner) deliverTelemetry(ctx context.Context, destination telemetryDestination, payload []byte) error {
	for {
		o.mu.Lock()
		active, wake := o.active, o.wake
		o.mu.Unlock()
		if active != nil {
			ctx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(active, cancel)
			defer cancel()
			defer stop()
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(destination.port))
			if destination.protocol == "TCP" {
				connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
				if err != nil {
					return err
				}
				defer connection.Close()
				stop := context.AfterFunc(ctx, func() { connection.Close() })
				defer stop()
				_, err = io.Copy(connection, bytes.NewReader(payload))
				return err
			}
			request, err := http.NewRequestWithContext(ctx, destination.method, destination.uri, bytes.NewReader(payload))
			if err != nil {
				return err
			}
			request.Header.Set("Content-Type", "application/json")
			request.Host = request.URL.Host
			request.URL.Host = address
			response, err := o.client.Do(request)
			if err != nil {
				return err
			}
			response.Body.Close()
			if response.StatusCode >= 400 {
				return fmt.Errorf("telemetry listener returned %s", response.Status)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

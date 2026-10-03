package lambda

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
)

// Every customer process is an exec in the one resource-limited runtime
// container. Removing that container is the final cancellation boundary, including
// grandchildren which have deliberately detached from their parent's group.
type dockerProcess struct {
	id, pidFile, container string
	done                   chan struct{}
	mu                     sync.Mutex
	err                    error
	exit                   int
}

func startExec(d *docker.Client, startup, ctx context.Context, container string, command []string, stdout, stderr io.Writer) (*dockerProcess, error) {
	var created struct {
		ID string `json:"Id"`
	}
	input := struct {
		AttachStdout, AttachStderr bool
		Cmd                        []string
	}{true, true, command}
	if err := d.JSON(startup, "POST", "/containers/"+url.PathEscape(container)+"/exec", input, &created); err != nil {
		return nil, err
	}
	p := &dockerProcess{id: created.ID, container: container, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		if closer, ok := stdout.(io.Closer); ok {
			defer closer.Close()
		}
		if closer, ok := stderr.(io.Closer); ok {
			defer closer.Close()
		}
		response, err := d.Request(ctx, "POST", "/exec/"+url.PathEscape(p.id)+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`), "application/json")
		if err == nil {
			err = docker.CopyStream(stdout, stderr, response.Body)
			response.Body.Close()
		}
		var state struct {
			Running  bool
			ExitCode int
		}
		if err == nil {
			// Docker can close the output pipe just before recording the exit status.
			for {
				err = d.JSON(ctx, "GET", "/exec/"+url.PathEscape(p.id)+"/json", nil, &state)
				if err != nil || !state.Running {
					break
				}
				select {
				case <-ctx.Done():
					err = ctx.Err()
				case <-time.After(time.Millisecond):
				}
				if err != nil {
					break
				}
			}
		}
		p.mu.Lock()
		p.err, p.exit = err, state.ExitCode
		p.mu.Unlock()
	}()
	return p, nil
}

func (p *dockerProcess) outcome() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exit, p.err
}

func (runtime *dockerRuntime) finishProcesses(ctx context.Context) {
	runtime.mu.Lock()
	processes := append([]*dockerProcess(nil), runtime.processes...)
	runtime.mu.Unlock()
	for _, process := range processes {
		select {
		case <-process.done:
		case <-ctx.Done():
			runtime.cancel()
			<-process.done
		}
	}
	runtime.cancel()
}

func execOutput(d *docker.Client, ctx context.Context, container string, command []string) ([]byte, error) {
	var output bytes.Buffer
	p, err := startExec(d, ctx, ctx, container, command, &output, &output)
	if err != nil {
		return nil, err
	}
	<-p.done
	exit, err := p.outcome()
	if err != nil {
		return nil, err
	}
	if exit != 0 {
		return nil, fmt.Errorf("container command exited with status %d: %s", exit, output.Bytes())
	}
	return output.Bytes(), nil
}

// Bash job control gives each command a process group without requiring setsid.
// The owned pid file supports runtime-first shutdown; namespace removal remains
// responsible for children which escape that group.
const customerProcessScript = `set -m
pidfile=$1; shift
"$@" &
child=$!
if ! printf '%s\n' "$child" > "$pidfile"; then kill -KILL -- -"$child" 2>/dev/null; wait "$child" 2>/dev/null; exit 1; fi
trap 'kill -TERM -- -"$child" 2>/dev/null; wait "$child" 2>/dev/null; exit 143' TERM INT
wait "$child" 2>/dev/null
status=$?
rm -f -- "$pidfile"
exit "$status"`

func (e *dockerEnvironment) startCustomer(ctx context.Context, runtime *dockerRuntime, name, kind string, command []string) (*dockerProcess, error) {
	var err error
	command, err = e.customerLoggingCommand(ctx, name, kind, command)
	if err != nil {
		return nil, err
	}
	pidFile := "/tmp/." + e.identity + "-" + newRuntimeID() + ".pid"
	args := append([]string{"/bin/bash", "-c", customerProcessScript, "stackd-process", pidFile}, command...)
	p, err := startExec(e.engine, ctx, runtime.ctx, runtime.container, args, e.telemetry.Output(kind, name), e.telemetry.Output(kind, name))
	if err != nil {
		return nil, err
	}
	p.pidFile = pidFile
	runtime.mu.Lock()
	runtime.processes = append(runtime.processes, p)
	runtime.mu.Unlock()
	go func() {
		<-p.done
		if runtime.ctx.Err() != nil {
			return
		}
		exit, err := p.outcome()
		runtime.mu.Lock()
		shutdown := runtime.phase == "Shutdown"
		errorType := "Runtime.ExitError"
		if kind == "extension" {
			errorType = "Extension.Crash"
			if extension := runtime.byName[name]; extension != nil {
				extension.exited = true
				if extension.state == "InitError" {
					errorType = "Extension.InitError"
				}
				runtime.changedLocked()
			}
		}
		runtime.mu.Unlock()
		if shutdown {
			return
		}
		if err != nil {
			runtime.fail(fmt.Errorf("reading %s process %s: %w", kind, name, err))
			return
		}
		message := fmt.Sprintf("exit status %d", exit)
		if exit == 0 {
			message = "exit code 0"
		}
		runtime.fail(&customerFailure{errorType: errorType, message: message})
	}()
	return p, nil
}

func (e *dockerEnvironment) signalProcess(ctx context.Context, process *dockerProcess, signal string) error {
	if process == nil {
		return nil
	}
	select {
	case <-process.done:
		return nil
	default:
	}
	_, err := execOutput(e.engine, ctx, process.container, []string{"/bin/bash", "-c", `for attempt in {1..100}; do if test -s "$1"; then read -r pid < "$1"; kill -"$2" -- -"$pid" 2>/dev/null; exit; fi; sleep 0.01; done; exit 1`, "stackd-signal", process.pidFile, signal})
	select {
	case <-process.done:
		return nil
	default:
	}
	return err
}

func (e *dockerEnvironment) setFrozen(ctx context.Context, frozen bool) error {
	e.runMu.Lock()
	defer e.runMu.Unlock()
	if e.frozen == frozen {
		return nil
	}
	operation := "unpause"
	if frozen {
		operation = "pause"
	}
	if err := e.engine.JSON(ctx, "POST", "/containers/"+url.PathEscape(e.container)+"/"+operation, nil, nil); err != nil {
		return err
	}
	e.frozen = frozen
	return nil
}

func (e *dockerEnvironment) memoryPeak(ctx context.Context) *uint64 {
	output, err := execOutput(e.engine, ctx, e.container, []string{"/bin/bash", "-c", `if test -r /sys/fs/cgroup/memory.peak; then cat /sys/fs/cgroup/memory.peak; elif test -r /sys/fs/cgroup/memory/memory.max_usage_in_bytes; then cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes; else exit 1; fi`})
	if err != nil {
		return nil
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return nil
	}
	mb := (value + (1 << 20) - 1) >> 20
	return &mb
}

func writeRuntimeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

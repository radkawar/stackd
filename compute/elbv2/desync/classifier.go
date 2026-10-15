// Package desync invokes the pinned aws/http-desync-guardian C ABI in a separate
// process. It deliberately contains no Go request-safety classifier and needs no
// cgo in the controller binary. Build adapter/main.c with adapter/Makefile.
package desync

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const SourceRevision = "f0b15a772926ca47cf6216c73df8cfeaae02cd75"
const MaxHeaderBytes = 64 * 1024
const operationTimeout = 2 * time.Second
const greeting = "STACKD-HDG/1 " + SourceRevision + "\n"

// Tier values are the pinned library's RequestSafetyTier C discriminants.
type Tier uint32

const (
	Compliant Tier = iota
	Acceptable
	Ambiguous
	Severe
)

type Verdict struct {
	Tier    Tier
	Reason  uint32
	Message string
}

// Classifier owns one bounded, serialized native worker. A broken, stalled, or
// invalid worker is permanently unavailable, never replaced by an approximation.
// The assembly owns Close; services sharing this dependency must not close it.
type Classifier struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	output  io.ReadCloser
	turn    chan struct{}
	mu      sync.Mutex
	failure error
	stop    sync.Once
	wait    chan struct{}
}

// New starts the installed adapter and verifies both its pinned protocol and a
// real library classification. executable is an operator-trusted absolute path.
// ctx bounds initialization only; cancellation after New succeeds does not kill
// the worker. Each later operation uses its own context. Close owns its lifetime.
func New(ctx context.Context, executable string) (*Classifier, error) {
	if executable == "" {
		return nil, errors.New("native desync adapter executable is required")
	}
	if !filepath.IsAbs(executable) {
		return nil, errors.New("native desync adapter executable must be an absolute trusted path")
	}
	cmd := exec.Command(executable)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	c := &Classifier{cmd: cmd, input: input, output: output, turn: make(chan struct{}, 1), wait: make(chan struct{})}
	c.turn <- struct{}{}
	go func() {
		_ = cmd.Wait()
		close(c.wait)
	}()
	err = c.operation(ctx, func() error {
		var hello [len(greeting)]byte
		if _, err := io.ReadFull(c.output, hello[:]); err != nil {
			return err
		}
		if string(hello[:]) != greeting {
			return errors.New("native desync adapter protocol or source revision mismatch")
		}
		return nil
	})
	if err == nil {
		err = c.Health(ctx)
	}
	if err != nil {
		closeErr := c.Close()
		return nil, fmt.Errorf("starting genuine native desync classifier: %w", errors.Join(err, closeErr))
	}
	return c, nil
}

func (c *Classifier) operation(ctx context.Context, f func() error) error {
	if c == nil {
		return errors.New("native desync classifier is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.turn:
	}
	defer func() { c.turn <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	err := c.failure
	c.mu.Unlock()
	if err != nil {
		return err
	}
	// Closing the pipes and killing the process interrupts blocking pipe I/O;
	// merely timing out a goroutine would leave a stuck worker and unbounded work.
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		c.fail(ctx.Err())
		close(finished)
	})
	err = f()
	if !stop() {
		<-finished
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		c.fail(err)
		return fmt.Errorf("native desync classification failed: %w", err)
	}
	return nil
}

func (c *Classifier) fail(err error) {
	c.mu.Lock()
	if c.failure == nil {
		c.failure = err
	}
	c.mu.Unlock()
	c.stop.Do(func() {
		_ = c.input.Close()
		_ = c.output.Close()
		_ = c.cmd.Process.Kill()
	})
}

func (c *Classifier) Classify(ctx context.Context, rawHeader []byte) (Verdict, error) {
	var verdict Verdict
	if len(rawHeader) == 0 || len(rawHeader) > MaxHeaderBytes {
		return verdict, errors.New("native desync header must contain 1..65536 original bytes")
	}
	err := c.operation(ctx, func() error {
		var frame [12]byte
		binary.BigEndian.PutUint32(frame[:4], uint32(len(rawHeader)))
		if err := writeFull(c.input, frame[:4]); err != nil {
			return err
		}
		if err := writeFull(c.input, rawHeader); err != nil {
			return err
		}
		if _, err := io.ReadFull(c.output, frame[:]); err != nil {
			return err
		}
		verdict.Tier = Tier(binary.BigEndian.Uint32(frame[:4]))
		verdict.Reason = binary.BigEndian.Uint32(frame[4:8])
		length := binary.BigEndian.Uint32(frame[8:12])
		if verdict.Tier > Severe || verdict.Reason > 26 || length > 299 {
			return errors.New("native desync adapter returned an invalid C ABI verdict")
		}
		var message [299]byte
		if _, err := io.ReadFull(c.output, message[:length]); err != nil {
			return err
		}
		verdict.Message = string(message[:length])
		return nil
	})
	return verdict, err
}

// Health is a fresh round trip through the real C ABI, not process existence or
// cached readiness. The control-plane uses it before admitting defensive mode.
func (c *Classifier) Health(ctx context.Context) error {
	verdict, err := c.Classify(ctx, []byte("POST /guardian-health HTTP/1.1\r\nHost: guardian.invalid\r\nContent-Length: 0\r\n\r\n"))
	if err != nil {
		return err
	}
	if verdict.Tier != Compliant || verdict.Reason != 0 {
		err = errors.New("native desync classifier failed its compliant-request health probe")
		c.fail(err)
		return err
	}
	return nil
}

// Close is idempotent. It interrupts all worker I/O, kills the owned process, and
// waits for exec.Cmd.Wait to reap it. A kill-induced exit is normal cleanup, not
// an error; failure to reap within the fixed bound is returned explicitly.
func (c *Classifier) Close() error {
	if c == nil {
		return nil
	}
	c.fail(errors.New("native desync classifier is closed"))
	select {
	case <-c.wait:
		return nil
	default:
	}
	timer := time.NewTimer(operationTimeout)
	defer timer.Stop()
	select {
	case <-c.wait:
		return nil
	case <-timer.C:
		return errors.New("native desync adapter did not exit and reap within 2 seconds")
	}
}

func writeFull(w io.Writer, bytes []byte) error {
	for len(bytes) != 0 {
		n, err := w.Write(bytes)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		bytes = bytes[n:]
	}
	return nil
}

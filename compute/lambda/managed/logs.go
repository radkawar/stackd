package managed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"unicode/utf8"

	"stackd/compute/docker"
	runtime "stackd/compute/lambda"
)

// LogBatch is acknowledged only after handing actual runtime bytes to the
// controller's execution-role-authorized log sink. Lost acknowledgements replay.
type LogBatch struct {
	Offset int64
	Data   []byte
}

type logSpool struct {
	mu        sync.Mutex
	file      *os.File
	ackPath   string
	ack, size int64
	sequence  uint64
	tail      []byte
	dropped   bool
}

func openLogSpool(directory string) (*logSpool, error) {
	file, err := os.OpenFile(filepath.Join(directory, "runtime.log"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	spool := &logSpool{file: file, ackPath: filepath.Join(directory, "runtime-log-ack"), size: info.Size(), sequence: uint64(info.Size()), tail: make([]byte, 0, 4096)}
	raw, err := os.ReadFile(spool.ackPath)
	if err == nil {
		spool.ack, err = strconv.ParseInt(string(raw), 10, 64)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		file.Close()
		return nil, err
	}
	if spool.ack < 0 {
		file.Close()
		return nil, errors.New("invalid retained log acknowledgement")
	}
	// A crash after truncating a fully acknowledged file can retain its old ack.
	if spool.ack > spool.size {
		spool.ack = 0
	}
	return spool, nil
}
func (s *logSpool) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(data)
	s.sequence += uint64(n)
	if n >= 4096 {
		s.tail = append(s.tail[:0], data[n-4096:]...)
	} else {
		excess := len(s.tail) + n - 4096
		if excess > 0 {
			copy(s.tail, s.tail[excess:])
			s.tail = s.tail[:len(s.tail)-excess]
		}
		s.tail = append(s.tail, data...)
	}
	if s.size+int64(n) > 64<<20 {
		if !s.dropped {
			slog.Warn("Lambda managed log buffer full; dropping output until delivery resumes")
			s.dropped = true
		}
		return n, nil
	}
	written, err := s.file.Write(data)
	s.size += int64(written)
	return written, err
}
func (s *logSpool) position() uint64 { s.mu.Lock(); defer s.mu.Unlock(); return s.sequence }
func (s *logSpool) capture(start uint64) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := min(uint64(len(s.tail)), s.sequence-start)
	result := append([]byte(nil), s.tail[len(s.tail)-int(count):]...)
	if !utf8.Valid(result) {
		result = []byte(string([]rune(string(result))))
	}
	return result
}
func (s *logSpool) batch() (LogBatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := LogBatch{Offset: s.ack, Data: make([]byte, min(s.size-s.ack, 1<<20))}
	if len(out.Data) > 0 {
		if _, err := s.file.ReadAt(out.Data, s.ack); err != nil {
			return LogBatch{}, err
		}
	}
	return out, nil
}
func (s *logSpool) acknowledge(offset int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if offset < s.ack || offset > s.size {
		return &RemoteError{409, "Log acknowledgement is outside the pending batch"}
	}
	if offset == s.size && s.size >= 1<<20 {
		// Persisting zero first can replay an already delivered file after a crash,
		// never skip an undelivered byte. Retained offsets remain bounded.
		if err := atomicPrivateFile(s.ackPath, []byte("0")); err != nil {
			return err
		}
		if err := s.file.Truncate(0); err != nil {
			return err
		}
		s.ack = 0
		s.size = 0
		s.dropped = false
		return nil
	}
	if err := atomicPrivateFile(s.ackPath, []byte(strconv.FormatInt(offset, 10))); err != nil {
		return err
	}
	s.ack = offset
	return nil
}
func (s *logSpool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.file.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

func atomicPrivateFile(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".managed-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (e *environment) startLogs() error {
	spool, err := openLogSpool(e.directory)
	if err != nil {
		return err
	}
	e.logs = spool
	e.renderer = runtime.NewManagedLogRenderer(context.Background(), e.deployment.Specification.Logging, spool)
	stdout, stderr := e.renderer.Application(), e.renderer.Application()
	ctx, cancel := context.WithCancel(context.Background())
	e.logCancel = cancel
	e.logDone = make(chan struct{})
	go func() {
		defer close(e.logDone)
		defer e.renderer.Close()
		response, err := e.owner.engine.Request(ctx, "GET", "/containers/"+e.container+"/logs?follow=true&stdout=true&stderr=true&tail=all", nil, "")
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("Lambda managed runtime output connection failed", "environment", e.deployment.ID, "error", err)
			}
			return
		}
		defer response.Body.Close()
		if err := docker.CopyStream(stdout, stderr, response.Body); err != nil && ctx.Err() == nil {
			slog.Error("Lambda managed runtime output failed", "environment", e.deployment.ID, "error", err)
		}
	}()
	return nil
}
func (e *environment) stopLogs() error {
	if e.logCancel != nil {
		e.logCancel()
		<-e.logDone
		e.logCancel = nil
	}
	return nil
}
func (e *environment) readLogs() (LogBatch, error) {
	if e.logs == nil {
		return LogBatch{}, fmt.Errorf("managed runtime output is not initialized")
	}
	return e.logs.batch()
}

var _ io.Writer = (*logSpool)(nil)

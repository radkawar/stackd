package lambda

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// The existing container helper owns the actual process output pipes. Reading a
// finite kernel snapshot at a lifecycle boundary joins already-written output
// without a customer marker, a time window, or a second retained log spool.
// RawConn keeps descriptor lifetime and readiness polling under os.File ownership.
type telemetryPipe struct {
	file   *os.File
	raw    syscall.RawConn
	output io.WriteCloser
	mu     sync.Mutex
	err    error
	done   chan struct{}
	buffer [32 << 10]byte
}

func newTelemetryPipe(path string, output io.WriteCloser) (*telemetryPipe, error) {
	if err := syscall.Mkfifo(path, 0600); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		file.Close()
		os.Remove(path)
		return nil, err
	}
	p := &telemetryPipe{file: file, raw: raw, output: output, done: make(chan struct{})}
	go p.collect()
	return p, nil
}

func (p *telemetryPipe) collect() {
	defer close(p.done)
	for {
		err := p.raw.Read(func(fd uintptr) bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.err != nil {
				return true
			}
			n, err := syscall.Read(int(fd), p.buffer[:])
			if err == syscall.EAGAIN || err == syscall.EINTR {
				return false
			}
			if err == nil && n > 0 {
				_, err = p.output.Write(p.buffer[:n])
			}
			p.err = err
			return true
		})
		p.mu.Lock()
		failed := p.err != nil
		p.mu.Unlock()
		if err != nil || failed {
			return
		}
	}
}

func (p *telemetryPipe) drain() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	err := p.raw.Control(func(fd uintptr) {
		var available int32
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&available)))
		if errno != 0 {
			p.err = errno
			return
		}
		// Never chase an active background writer. The snapshot is bounded by
		// pipe capacity, and bytes already read by collect were joined by mu.
		for available > 0 {
			n, err := syscall.Read(int(fd), p.buffer[:min(int(available), len(p.buffer))])
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				p.err = err
				return
			}
			if n == 0 {
				p.err = io.ErrUnexpectedEOF
				return
			}
			if _, err := p.output.Write(p.buffer[:n]); err != nil {
				p.err = err
				return
			}
			available -= int32(n)
		}
	})
	return errors.Join(err, p.err)
}

func (p *telemetryPipe) close() error {
	drainErr := p.drain()
	closeErr := p.file.Close()
	<-p.done
	return errors.Join(drainErr, closeErr, p.output.Close(), os.Remove(p.file.Name()))
}

type telemetryPipes struct {
	manager *telemetryManager
	streams []*telemetryPipe
}

func (p *telemetryPipes) open(path, kind, name string) error {
	for _, suffix := range []string{"stdout", "stderr", "frames"} {
		if suffix == "frames" && kind != "function" {
			continue
		}
		var output io.WriteCloser
		if suffix == "frames" {
			output = &runtimeLogFrames{manager: p.manager}
		} else {
			output = p.manager.Output(kind, name).(io.WriteCloser)
		}
		stream, err := newTelemetryPipe(path+"."+suffix, output)
		if err != nil {
			output.Close()
			return fmt.Errorf("opening %s output: %w", suffix, err)
		}
		p.streams = append(p.streams, stream)
	}
	return nil
}

func (p *telemetryPipes) drain() error {
	var failures []error
	for _, stream := range p.streams {
		if err := stream.drain(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (p *telemetryPipes) close() error {
	var failures []error
	for _, stream := range p.streams {
		if err := stream.close(); err != nil {
			failures = append(failures, err)
		}
	}
	p.streams = nil
	return errors.Join(failures...)
}

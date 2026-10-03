package mq

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	service "stackd/internal/services/mq"
	"strconv"
	"strings"
	"sync"
)

//go:embed StackdMQ.java
var jmsSource string

type jmsConsumer struct {
	mu      sync.Mutex
	command *exec.Cmd
	cancel  context.CancelFunc
	input   io.WriteCloser
	output  *bufio.Reader
	closed  bool
}

func (r *Runtime) openJMS(ctx context.Context, broker service.Connection, credentials Credentials, queue string) (Consumer, error) {
	dir := r.jmsDirectory()
	lifetime, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(lifetime, r.config.Java, "-Xms16m", "-Xmx96m", "-cp", dir+string(filepath.ListSeparator)+filepath.Join(dir, "*"), "StackdMQ")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	c := &jmsConsumer{command: cmd, cancel: cancel, input: stdin, output: bufio.NewReaderSize(stdout, 64<<10)}
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	fields := []string{broker.Endpoint.Address, credentials.Username, credentials.Password, queue, string(broker.Endpoint.CAPEM)}
	for i, v := range fields {
		fields[i] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	if _, err = io.WriteString(stdin, strings.Join(fields, "\t")+"\n"); err == nil {
		var line string
		line, err = c.output.ReadString('\n')
		if err == nil && line != "READY\n" {
			err = errors.New("ActiveMQ OpenWire authentication failed")
		}
	}
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("ActiveMQ OpenWire connection: %w", err)
	}
	return c, nil
}
func (c *jmsConsumer) Fetch(ctx context.Context, limit int) ([]Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("MQ consumer is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, c.cancel)
	defer stop()
	if _, err := fmt.Fprintf(c.input, "FETCH\t%d\n", limit); err != nil {
		return nil, err
	}
	out := make([]Message, 0, min(limit, 100))
	for {
		line, err := c.output.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if string(line) == "END\n" {
			return out, nil
		}
		var record struct {
			MessageID string `json:"messageID"`
			Data      []byte `json:"data"`
		}
		if err = json.Unmarshal(line, &record); err != nil {
			return nil, errors.New("ActiveMQ returned an unsupported message or failed OpenWire delivery")
		}
		// Normalize JSON escaping once so Lambda can account for the exact
		// encoded record size before selecting an invocation batch.
		encoded, err := json.Marshal(json.RawMessage(line))
		if err != nil {
			return nil, err
		}
		out = append(out, Message{ID: record.MessageID, Data: record.Data, Record: encoded})
	}
}
func (c *jmsConsumer) Acknowledge(ctx context.Context, count int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("MQ consumer is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, c.cancel)
	defer stop()
	if _, err := io.WriteString(c.input, "ACK\t"+strconv.Itoa(count)+"\n"); err != nil {
		return err
	}
	line, err := c.output.ReadString('\n')
	if err != nil {
		return err
	}
	if line != "OK\n" {
		return errors.New("ActiveMQ failed to acknowledge native messages")
	}
	return nil
}
func (c *jmsConsumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	_ = c.input.Close()
	c.cancel()
	err := c.command.Wait()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil
	}
	return err
}

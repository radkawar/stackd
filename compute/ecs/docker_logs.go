package ecs

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"stackd/compute/docker"
)

func (e *dockerEnvironment) Logs(ctx context.Context, name string, since time.Time, emit func(LogRecord) error) error {
	container, ok := e.containers[name]
	if !ok {
		return fmt.Errorf("unknown ECS execution container %q", name)
	}
	ctx, cancel := context.WithCancel(ctx)
	detach := context.AfterFunc(e.lifetime, cancel)
	defer detach()
	defer cancel()
	query := url.Values{"stdout": {"true"}, "stderr": {"true"}, "timestamps": {"true"}, "follow": {"true"}}
	if !since.IsZero() {
		query.Set("since", fmt.Sprintf("%d.%09d", since.Unix(), since.Nanosecond()))
	}
	response, err := e.executor.client.Request(ctx, http.MethodGet, "/containers/"+url.PathEscape(container.id)+"/logs?"+query.Encode(), nil, "")
	if err != nil {
		return fmt.Errorf("read ECS container %s logs: %w", name, err)
	}
	defer response.Body.Close()
	reader := bufio.NewReaderSize(nil, 4096)
	var message bytes.Buffer
	return docker.VisitStream(response.Body, func(stderr bool, frame io.Reader) error {
		reader.Reset(frame)
		prefix, err := reader.ReadSlice(' ')
		if err == io.EOF && len(prefix) == 0 {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read native Docker log timestamp: %w", err)
		}
		stamp, err := time.Parse(time.RFC3339Nano, string(prefix[:len(prefix)-1]))
		if err != nil {
			return fmt.Errorf("decode native Docker log timestamp: %w", err)
		}
		message.Reset()
		if _, err := message.ReadFrom(reader); err != nil {
			return err
		}
		return emit(LogRecord{Time: stamp, Stderr: stderr, Message: message.Bytes()})
	})
}

package mq

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"stackd/compute/docker"
)

// execNative reads bounded stdout from an already inspected exact-owned
// container ID. The caller supplies a deadline and checks native ownership.
// Stderr, incomplete execution and nonzero exit status invalidate the read.
func (r *Runtime) execNative(ctx context.Context, id string, command []string, limit int) ([]byte, error) {
	var created struct {
		ID string `json:"Id"`
	}
	input := map[string]any{"Cmd": command, "AttachStdout": true, "AttachStderr": true, "Tty": false}
	if err := r.client.JSON(ctx, "POST", "/containers/"+id+"/exec", input, &created); err != nil {
		return nil, err
	}
	response, err := r.client.Request(ctx, "POST", "/exec/"+created.ID+"/start", strings.NewReader(`{"Detach":false,"Tty":false}`), "application/json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var output bytes.Buffer
	remaining := int64(limit)
	err = docker.VisitStream(response.Body, func(stderr bool, frame io.Reader) error {
		if stderr {
			return errors.New("native MQ reader reported an error")
		}
		n, err := io.Copy(&output, io.LimitReader(frame, remaining+1))
		remaining -= n
		if remaining < 0 {
			return errors.New("native MQ reader exceeded its bounded response")
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	var result struct {
		Running  bool
		ExitCode int
	}
	if err = r.client.JSON(ctx, "GET", "/exec/"+created.ID+"/json", nil, &result); err != nil {
		return nil, err
	}
	if result.Running || result.ExitCode != 0 {
		return nil, errors.New("native MQ reader did not complete successfully")
	}
	return output.Bytes(), nil
}

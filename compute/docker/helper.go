package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"
)

// ToolkitImage provides networking utilities and native host systemd calls. It
// must be installed explicitly; execution never pulls from a registry. The
// upstream index contains Linux amd64 and arm64 images.
const ToolkitImage = "nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61"

type helperExitError string

func (e helperExitError) Error() string { return string(e) }

// RunHelper bounds a trusted one-shot helper and removes it even when
// cancellation races a successful native create. Callers own its labels,
// command and explicit host capabilities; kind identifies diagnostics and names.
func RunHelper(ctx context.Context, client *Client, kind string, config ContainerConfig) (output []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	name := "stackd-" + kind + "-" + rand.Text()
	defer func() {
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancelCleanup()
		if cleanupErr := client.RemoveContainer(cleanup, name); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove native %s helper: %w", kind, cleanupErr))
		}
	}()
	if err = client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, nil); err != nil {
		return nil, fmt.Errorf("create native %s helper: %w", kind, err)
	}
	path := "/containers/" + url.PathEscape(name)
	if err = client.JSON(ctx, "POST", path+"/start", nil, nil); err != nil {
		return nil, fmt.Errorf("start native %s helper: %w", kind, err)
	}
	var exit struct {
		StatusCode int64
		Error      *struct{ Message string }
	}
	if err = client.JSON(ctx, "POST", path+"/wait?condition=not-running", nil, &exit); err != nil {
		return nil, fmt.Errorf("wait for native %s helper: %w", kind, err)
	}
	response, err := client.Request(ctx, "GET", path+"/logs?stdout=true&stderr=true", nil, "")
	if err != nil {
		return nil, fmt.Errorf("read native %s helper output (exit %d): %w", kind, exit.StatusCode, err)
	}
	defer response.Body.Close()
	stdout, stderr, err := readHelperOutput(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read native %s helper output (exit %d): %w", kind, exit.StatusCode, err)
	}
	if exit.Error != nil && exit.Error.Message != "" {
		return nil, fmt.Errorf("native %s helper wait: %s (stdout %q, stderr %q)", kind, exit.Error.Message, stdout, stderr)
	}
	if exit.StatusCode != 0 {
		return nil, helperExitError(fmt.Sprintf("native %s helper failed (exit %d): stdout %q, stderr %q", kind, exit.StatusCode, stdout, stderr))
	}
	return stdout, nil
}

func readHelperOutput(src io.Reader) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	bounded := &io.LimitedReader{R: src, N: (64 << 10) + 1}
	err := CopyStream(&stdout, &stderr, bounded)
	if bounded.N == 0 {
		return nil, nil, fmt.Errorf("native helper output exceeds 64 KiB")
	}
	if err != nil {
		return nil, nil, err
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

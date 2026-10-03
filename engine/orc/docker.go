// Package orc encodes reports through the installed Apache ORC native engine.
package orc

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"stackd/compute/docker"
)

// DockerImage is the local tag built from this package's digest-pinned Dockerfile
// and Apache ORC 2.2.2 Maven artifact. NewDocker resolves it to an immutable local
// image ID once; neither construction nor encoding pulls or builds images.
const DockerImage = "stackd/orc:2.2.2"

// DockerConfig selects the installed native ORC conversion image.
type DockerConfig struct {
	// Client is caller-owned and must outlive this encoder.
	Client *docker.Client
	// Empty selects DockerImage. Overrides must be immutable sha256 image IDs
	// or digest-qualified references with the same Java and ORC tools layout.
	Image string
}

// Docker runs each conversion in its own short-lived, network-disabled container.
// It owns no durable resources and does not own the shared Docker client.
type Docker struct {
	client  *docker.Client
	imageID string
}

// NewDocker requires an already installed Linux image. Inspection is bounded to
// 30 seconds; each Encode is independently bounded to two minutes.
func NewDocker(ctx context.Context, config DockerConfig) (*Docker, error) {
	if config.Client == nil {
		return nil, errors.New("ORC Docker client is required")
	}
	if config.Image == "" {
		config.Image = DockerImage
	} else if !regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`).MatchString(config.Image) {
		return nil, errors.New("ORC image override must be an immutable sha256 ID or digest-qualified reference")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var image struct {
		ID string `json:"Id"`
		OS string `json:"Os"`
	}
	if err := config.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(config.Image)+"/json", nil, &image); err != nil {
		return nil, fmt.Errorf("ORC image must be installed locally (%s): %w", config.Image, err)
	}
	if image.ID == "" || image.OS != "linux" {
		return nil, fmt.Errorf("ORC requires an installed Linux image, got id=%q os=%q", image.ID, image.OS)
	}
	return &Docker{client: config.Client, imageID: image.ID}, nil
}

// Encode converts newline-delimited JSON objects to ZLIB-compressed ORC using
// the explicit native struct schema. Null and absent fields remain null; an
// empty input still writes a typed ORC file. Timestamps use UTC RFC3339 with
// milliseconds. Apache ORC owns parsing, type conversion, indexes and encoding.
// Cleanup uses a separate bounded context even if the caller cancels.
func (d *Docker) Encode(ctx context.Context, schema string, jsonLines []byte) (output []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name := "stackd-orc-" + rand.Text()
	// Install cleanup before create: cancellation can race native creation.
	defer func() {
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancelCleanup()
		if cleanupErr := d.removeOwned(cleanup, name); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove ORC converter: %w", cleanupErr))
		}
	}()
	config := docker.ContainerConfig{
		Image: d.imageID,
		Cmd:   []string{schema, "/work/input.json", "/work/report.orc"},
		Env:   []string{"TZ=UTC"}, WorkingDir: "/work", User: "65534:65534",
		NetworkDisabled: true,
		Labels:          map[string]string{"stackd.orc.id": name},
		HostConfig: docker.ContainerHostConfig{
			NetworkMode: "none",
			Memory:      512 << 20, MemorySwap: 512 << 20,
			CPUPeriod: 100000, CPUQuota: 100000, PidsLimit: 128,
			CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"},
			LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "1m", "max-file": "1"}},
		},
	}
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(name), config, nil); err != nil {
		return nil, fmt.Errorf("create ORC converter: %w", err)
	}
	path := "/containers/" + url.PathEscape(name)
	if err := d.copyInput(ctx, path, jsonLines); err != nil {
		return nil, fmt.Errorf("copy ORC input: %w", err)
	}
	if err := d.client.JSON(ctx, http.MethodPost, path+"/start", nil, nil); err != nil {
		return nil, fmt.Errorf("start ORC converter: %w", err)
	}
	var exit struct {
		StatusCode int64
		Error      *struct{ Message string }
	}
	if err := d.client.JSON(ctx, http.MethodPost, path+"/wait?condition=not-running", nil, &exit); err != nil {
		return nil, d.failure(ctx, path, fmt.Errorf("wait for ORC converter: %w", err))
	}
	if exit.Error != nil && exit.Error.Message != "" {
		return nil, d.failure(ctx, path, fmt.Errorf("ORC converter wait (exit %d): %s", exit.StatusCode, exit.Error.Message))
	}
	if exit.StatusCode != 0 {
		return nil, d.failure(ctx, path, fmt.Errorf("ORC converter failed (exit %d)", exit.StatusCode))
	}
	response, err := d.client.Request(ctx, http.MethodGet, path+"/archive?path="+url.QueryEscape("/work/report.orc"), nil, "")
	if err != nil {
		return nil, fmt.Errorf("copy ORC output: %w", err)
	}
	defer response.Body.Close()
	archive := tar.NewReader(response.Body)
	header, err := archive.Next()
	if err != nil {
		return nil, fmt.Errorf("read ORC output archive: %w", err)
	}
	if header.Name != "report.orc" || header.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("unexpected ORC output archive entry %q (type %d)", header.Name, header.Typeflag)
	}
	output, err = io.ReadAll(archive)
	if err != nil {
		return nil, fmt.Errorf("read ORC output: %w", err)
	}
	return output, nil
}

// copyInput streams the caller's bytes directly into the native copy archive,
// without retaining another report-sized buffer or exposing a host filesystem.
func (d *Docker) copyInput(ctx context.Context, path string, rows []byte) error {
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		archive := tar.NewWriter(writer)
		err := archive.WriteHeader(&tar.Header{Name: "input.json", Mode: 0444, Uid: 65534, Gid: 65534, Size: int64(len(rows)), Typeflag: tar.TypeReg})
		if err == nil {
			_, err = archive.Write(rows)
		}
		if err == nil {
			err = archive.Close()
		}
		writer.CloseWithError(err)
		done <- err
	}()
	response, err := d.client.Request(ctx, http.MethodPut, path+"/archive?path=%2Fwork&noOverwriteDirNonDir=true", reader, "application/x-tar")
	if response != nil {
		response.Body.Close()
	}
	reader.Close()
	copyErr := <-done
	return errors.Join(err, copyErr)
}

func (d *Docker) failure(ctx context.Context, path string, cause error) error {
	diagnosis, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	response, err := d.client.Request(diagnosis, http.MethodGet, path+"/logs?stdout=true&stderr=true&tail=100", nil, "")
	if err != nil {
		return errors.Join(cause, fmt.Errorf("read ORC converter diagnostics: %w", err))
	}
	defer response.Body.Close()
	var stdout, stderr bytes.Buffer
	bounded := &io.LimitedReader{R: response.Body, N: (64 << 10) + 1}
	err = docker.CopyStream(&stdout, &stderr, bounded)
	if bounded.N == 0 {
		err = errors.New("ORC converter diagnostics exceed 64 KiB")
	}
	return errors.Join(fmt.Errorf("%w: stdout %q, stderr %q", cause, stdout.String(), stderr.String()), err)
}

func (d *Docker) removeOwned(ctx context.Context, name string) error {
	var container struct {
		ID     string
		Config struct{ Labels map[string]string }
	}
	if err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &container); err != nil {
		var remote *docker.Error
		if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}
	if container.Config.Labels["stackd.orc.id"] != name {
		return errors.New("ORC converter ownership conflict")
	}
	return d.client.RemoveContainer(ctx, container.ID)
}

package codebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
)

const namespaceLabel = "stackd.codebuild.namespace"
const arnLabel = "stackd.codebuild.arn"

// DockerConfig isolates native resources by a stable stack namespace. Network
// may name an isolated Docker network, never host or another container's network.
// Images are explicit: local images are used; a missing image is pulled from its
// named registry without inheriting any host Docker credentials. Networking
// selects build resolvers and the AWS SDK CA bundle for new builds (see
// docker.Networking); empty DNS keeps the daemon's resolver configuration.
type DockerConfig struct {
	Namespace, Network, FleetImage string
	Networking                     docker.Networking
}
type DockerExecutor struct {
	client  *docker.Client
	config  DockerConfig
	locks   [64]sync.Mutex
	fleetMu sync.Mutex
}

func NewDockerExecutor(client *docker.Client, config DockerConfig) (*DockerExecutor, error) {
	if client == nil {
		return nil, fmt.Errorf("CodeBuild requires an explicit Docker client")
	}
	if config.Namespace == "" {
		return nil, fmt.Errorf("CodeBuild requires a stable unique namespace")
	}
	if config.Network == "host" || strings.HasPrefix(config.Network, "container:") {
		return nil, fmt.Errorf("CodeBuild cannot share host or container networking")
	}
	if err := config.Networking.Validate(); err != nil {
		return nil, fmt.Errorf("CodeBuild runtime networking: %w", err)
	}
	config.Networking.DNS = slices.Clone(config.Networking.DNS)
	return &DockerExecutor{client: client, config: config}, nil
}
func (d *DockerExecutor) name(arn string) string {
	sum := sha256.Sum256([]byte(d.config.Namespace + "\x00" + arn))
	return fmt.Sprintf("stackd-codebuild-%x", sum[:12])
}
func (d *DockerExecutor) buildLock(arn string) *sync.Mutex {
	sum := sha256.Sum256([]byte(arn))
	return &d.locks[int(sum[0])%len(d.locks)]
}
func (d *DockerExecutor) containerConfig(spec Specification) (docker.ContainerConfig, error) {
	memory, quota := spec.MemoryBytes, spec.CPUQuota
	if memory == 0 {
		memory = 1 << 30
	}
	if quota == 0 {
		quota = 100000
	}
	if memory < 64<<20 || memory > 256<<30 || quota < 1000 || quota > 7200000 {
		return docker.ContainerConfig{}, fmt.Errorf("invalid build memory or CPU limits")
	}
	return docker.ContainerConfig{
		Image: spec.Image, User: "0", WorkingDir: "/codebuild/src", Entrypoint: []string{"/bin/sh"}, Cmd: []string{"/codebuild/control/run.sh"},
		Labels: map[string]string{namespaceLabel: d.config.Namespace, arnLabel: spec.ARN},
		HostConfig: docker.ContainerHostConfig{NetworkMode: d.config.Network, Memory: memory, MemorySwap: memory, CPUPeriod: 100000, CPUQuota: quota, PidsLimit: 256,
			CapDrop: []string{"ALL"}, CapAdd: []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}, SecurityOpt: []string{"no-new-privileges:true"}, ExtraHosts: []string{"host.docker.internal:host-gateway"}, DNS: d.config.Networking.DNS, LogConfig: docker.ContainerLogConfig{Type: "json-file"}},
	}, nil
}

type containerState struct {
	ID     string `json:"Id"`
	Config struct {
		Labels map[string]string
		Env    []string
	}
	State struct {
		Status                       string
		Running, OOMKilled           bool
		ExitCode                     int
		Error, StartedAt, FinishedAt string
	}
}

func (d *DockerExecutor) nativeInspect(ctx context.Context, id string) (containerState, error) {
	var result containerState
	err := d.client.JSON(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, &result)
	var native *docker.Error
	if errors.As(err, &native) && native.StatusCode == http.StatusNotFound {
		return result, ErrNotFound
	}
	return result, err
}
func (d *DockerExecutor) lookup(ctx context.Context, arn string) (containerState, error) {
	state, err := d.nativeInspect(ctx, d.name(arn))
	if errors.Is(err, ErrNotFound) {
		filters, _ := json.Marshal(map[string][]string{"label": {namespaceLabel + "=" + d.config.Namespace, arnLabel + "=" + arn}})
		var found []struct {
			ID     string `json:"Id"`
			Labels map[string]string
		}
		if listErr := d.client.JSON(ctx, "GET", "/containers/json?all=true&filters="+url.QueryEscape(string(filters)), nil, &found); listErr != nil {
			return state, listErr
		}
		id := ""
		for _, item := range found {
			if item.Labels["stackd.codebuild.source"] == "true" || item.Labels[metadataLabel] == "true" {
				continue
			}
			if id != "" {
				return state, fmt.Errorf("multiple native containers own build %s", arn)
			}
			id = item.ID
		}
		if id == "" {
			return state, ErrNotFound
		}
		state, err = d.nativeInspect(ctx, id)
	}
	if err != nil {
		return state, err
	}
	if state.Config.Labels[namespaceLabel] != d.config.Namespace || state.Config.Labels[arnLabel] != arn {
		return state, fmt.Errorf("native build ownership mismatch")
	}
	return state, nil
}
func (d *DockerExecutor) Open(ctx context.Context, arn string) (Execution, error) {
	state, err := d.lookup(ctx, arn)
	if err != nil {
		return nil, err
	}
	return &dockerExecution{executor: d, id: state.ID, arn: arn}, nil
}

func (d *DockerExecutor) Prepare(ctx context.Context, spec Specification) (Execution, error) {
	if spec.ARN == "" || spec.Image == "" {
		return nil, fmt.Errorf("build ARN and image are required")
	}
	lock := d.buildLock(spec.ARN)
	lock.Lock()
	defer lock.Unlock()
	if execution, err := d.Open(ctx, spec.ARN); err == nil {
		retained, readErr := execution.(*dockerExecution).archive(ctx, "/codebuild/control")
		if readErr == nil {
			for _, file := range retained {
				if file.Path == "spec.json" {
					return execution, nil
				}
			}
		}
		// A crash between container creation and source upload leaves no executable
		// preparation. Only a never-started owned container may be replaced.
		state, inspectErr := d.lookup(ctx, spec.ARN)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if state.State.Status != "created" {
			return nil, fmt.Errorf("retained build control files are unavailable: %w", readErr)
		}
		if removeErr := d.client.RemoveContainer(ctx, state.ID); removeErr != nil {
			return nil, removeErr
		}
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := d.ensureImage(ctx, spec); err != nil {
		return nil, err
	}
	var image struct{ Config struct{ Env []string } }
	if err := d.client.JSON(ctx, "GET", "/images/"+url.PathEscape(spec.Image)+"/json", nil, &image); err != nil {
		return nil, fmt.Errorf("inspecting build image: %w", err)
	}
	source, err := prepareSource(spec.SourceZIP, spec.SourceFiles)
	if err != nil {
		return nil, err
	}
	if spec.Git != nil {
		if len(spec.SourceZIP) != 0 || spec.SourceFiles != nil {
			return nil, fmt.Errorf("a build cannot have both Git and S3 source")
		}
		source, err = d.gitSource(ctx, spec)
		if err != nil {
			return nil, err
		}
	}
	secondary := make([]File, 0)
	seenSources := make(map[string]bool, len(spec.SecondarySources))
	for _, input := range spec.SecondarySources {
		if !sourceIdentifier.MatchString(input.Identifier) || seenSources[input.Identifier] {
			return nil, fmt.Errorf("invalid secondary source identifier %q", input.Identifier)
		}
		seenSources[input.Identifier] = true
		var files []File
		if input.Git != nil {
			if len(input.ZIP) != 0 || input.Files != nil {
				return nil, fmt.Errorf("secondary source %q cannot have both Git and S3 source", input.Identifier)
			}
			gitSpec := spec
			gitSpec.Git = input.Git
			files, err = d.gitSource(ctx, gitSpec)
			if err != nil {
				return nil, fmt.Errorf("retrieving secondary source %q: %w", input.Identifier, err)
			}
		} else {
			files, err = prepareSource(input.ZIP, input.Files)
			if err != nil {
				return nil, fmt.Errorf("extracting secondary source %q: %w", input.Identifier, err)
			}
		}
		secondary = append(secondary, File{Path: "codebuild/secondary/" + input.Identifier, Mode: uint32(fs.ModeDir | 0700)})
		for _, file := range files {
			file.Path = "codebuild/secondary/" + input.Identifier + "/" + file.Path
			secondary = append(secondary, file)
		}
	}
	parsed, err := parseBuildspec(spec, source)
	if err != nil {
		return nil, err
	}
	environment, err := buildEnvironment(ctx, spec, parsed)
	if err != nil {
		return nil, err
	}
	cache, err := unzipSource(spec.CacheZIP)
	if err != nil {
		return nil, fmt.Errorf("restoring build cache: %w", err)
	}
	proxyID, environment, err := d.prepareMetadata(ctx, spec.ARN, environment)
	if err != nil {
		return nil, err
	}
	prepared := false
	defer func() {
		if proxyID != "" && !prepared {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			_ = d.removeMetadata(cleanup, spec.ARN)
		}
	}()
	name, labels, release, err := d.reserveBuildSlot(ctx, &spec)
	if err != nil {
		return nil, err
	}
	config, err := d.containerConfig(spec)
	if err != nil {
		release()
		_ = d.restoreBuildSlot(ctx, labels)
		return nil, err
	}
	config.Env = environment
	if proxyID != "" {
		// The proxy owns the namespace and its resolv.conf; Docker rejects
		// per-container DNS in container network mode.
		config.HostConfig.NetworkMode = "container:" + proxyID
		config.HostConfig.ExtraHosts = nil
		config.HostConfig.DNS = nil
		config.Labels[metadataIDLabel] = proxyID
	}
	trust, err := d.config.Networking.PrepareTrust(&config, image.Config.Env, "")
	if err != nil {
		release()
		_ = d.restoreBuildSlot(ctx, labels)
		return nil, err
	}
	if parsed.Env.Shell == "bash" {
		config.Entrypoint = []string{"/bin/bash"}
	}
	for key, value := range labels {
		config.Labels[key] = value
	}
	var created struct {
		ID string `json:"Id"`
	}
	err = d.client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, &created)
	release()
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = d.restoreBuildSlot(cleanup, labels)
		return nil, err
	}
	execution := &dockerExecution{executor: d, id: created.ID, arn: spec.ARN}
	defer func() {
		if !prepared {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_ = d.client.RemoveContainer(cleanup, created.ID)
			_ = d.restoreBuildSlot(cleanup, labels)
		}
	}()
	// Install before control files: retained spec.json proves a complete build.
	if err := trust.Install(ctx, d.client, created.ID); err != nil {
		return nil, err
	}
	if err := execution.selectRuntimes(ctx, &parsed, environment); err != nil {
		return nil, err
	}
	controls, err := controlFiles(parsed, spec.SensitiveEnvironment)
	if err != nil {
		return nil, err
	}
	contents := make([]File, 0, len(source)+len(secondary)+len(cache)+len(controls))
	for _, files := range [][]File{source, cache} {
		for _, file := range files {
			file.Path = "codebuild/src/" + file.Path
			contents = append(contents, file)
		}
	}
	contents = append(contents, secondary...)
	contents = append(contents, controls...)
	archive, err := writeArchive(contents)
	if err != nil {
		return nil, err
	}
	if err := execution.upload(ctx, archive); err != nil {
		return nil, err
	}
	prepared = true
	return execution, nil
}

func (e *dockerExecution) selectRuntimes(ctx context.Context, parsed *buildspec, environment []string) error {
	install := parsed.Phases["install"]
	if len(install.RuntimeVersions) == 0 {
		return nil
	}
	files, err := e.archive(ctx, "/codebuild/image/config")
	if err != nil {
		return fmt.Errorf("selected image runtime manifest is unavailable: %w", err)
	}
	for _, file := range files {
		if file.Path != "runtimes.yml" {
			continue
		}
		commands, err := runtimeCommands(file.Body, install.RuntimeVersions, environment)
		if err != nil {
			return err
		}
		install.RuntimeCommands = commands
		parsed.Phases["install"] = install
		return nil
	}
	return fmt.Errorf("selected image does not provide /codebuild/image/config/runtimes.yml")
}

func (d *DockerExecutor) ensureImage(ctx context.Context, spec Specification) error {
	if spec.RegistryAuth == nil {
		var image struct{ ID string }
		err := d.client.JSON(ctx, "GET", "/images/"+url.PathEscape(spec.Image)+"/json", nil, &image)
		if err == nil {
			return nil
		}
		var native *docker.Error
		if !errors.As(err, &native) || native.StatusCode != http.StatusNotFound {
			return err
		}
	}
	headers := make(http.Header)
	if auth := spec.RegistryAuth; auth != nil {
		body, err := json.Marshal(struct {
			Username      string `json:"username"`
			Password      string `json:"password"`
			ServerAddress string `json:"serveraddress"`
		}{auth.Username, auth.Password, auth.ServerAddress})
		if err != nil {
			return err
		}
		headers.Set("X-Registry-Auth", base64.URLEncoding.EncodeToString(body))
	}
	response, err := d.client.RequestHeaders(ctx, "POST", "/images/create?fromImage="+url.QueryEscape(spec.Image), nil, "", headers)
	if err != nil {
		return fmt.Errorf("pulling build image: %w", err)
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<20))
	for {
		var progress struct {
			Error       string
			ErrorDetail struct{ Message string }
		}
		if err := decoder.Decode(&progress); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("reading image pull: %w", err)
		}
		if progress.ErrorDetail.Message != "" {
			return fmt.Errorf("pulling build image: %s", progress.ErrorDetail.Message)
		}
		if progress.Error != "" {
			return fmt.Errorf("pulling build image: %s", progress.Error)
		}
	}
}

func (d *DockerExecutor) Remove(ctx context.Context, arn string) error {
	lock := d.buildLock(arn)
	lock.Lock()
	defer lock.Unlock()
	state, err := d.lookup(ctx, arn)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err == nil {
		if state.State.Running {
			execution := &dockerExecution{executor: d, id: state.ID, arn: arn}
			if err := execution.Stop(ctx); err != nil {
				return err
			}
		}
		if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
			return err
		}
	}
	// DOWNLOAD_SOURCE can outlive the controller without any main execution.
	// Do not report cleanup complete until every owned staging container is gone.
	return errors.Join(d.removeStaging(ctx, arn), d.restoreBuildSlot(ctx, state.Config.Labels))
}

func (d *DockerExecutor) removeStaging(ctx context.Context, arn string) error {
	filters, _ := json.Marshal(map[string][]string{"label": {namespaceLabel + "=" + d.config.Namespace, arnLabel + "=" + arn}})
	var containers []struct {
		ID     string `json:"Id"`
		Labels map[string]string
	}
	if err := d.client.JSON(ctx, "GET", "/containers/json?all=true&filters="+url.QueryEscape(string(filters)), nil, &containers); err != nil {
		return err
	}
	var failures []error
	for _, container := range containers {
		labels := container.Labels
		if labels[namespaceLabel] != d.config.Namespace || labels[arnLabel] != arn ||
			(labels["stackd.codebuild.source"] != "true" && labels[metadataLabel] != "true") {
			continue
		}
		state, err := d.nativeInspect(ctx, container.ID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err == nil {
			labels = state.Config.Labels
			if labels[namespaceLabel] != d.config.Namespace || labels[arnLabel] != arn ||
				(labels["stackd.codebuild.source"] != "true" && labels[metadataLabel] != "true") {
				err = fmt.Errorf("native build staging ownership mismatch")
			} else {
				err = d.client.RemoveContainer(ctx, state.ID)
			}
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Dispose destroys only this namespace's native resources. The owner calls it
// after detaching all controllers for an ephemeral stack; durable stacks must
// not call it, because their containers are the retained restart boundary.
func (d *DockerExecutor) Dispose(ctx context.Context) error {
	filters, _ := json.Marshal(map[string][]string{"label": {namespaceLabel + "=" + d.config.Namespace}})
	var containers []struct {
		ID     string `json:"Id"`
		Labels map[string]string
	}
	if err := d.client.JSON(ctx, "GET", "/containers/json?all=true&filters="+url.QueryEscape(string(filters)), nil, &containers); err != nil {
		return err
	}
	sort.SliceStable(containers, func(i, j int) bool {
		return containers[i].Labels[metadataLabel] != "true" && containers[j].Labels[metadataLabel] == "true"
	})
	var failures []error
	for _, container := range containers {
		if container.Labels[namespaceLabel] != d.config.Namespace {
			continue
		}
		if err := d.client.RemoveContainer(ctx, container.ID); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

type dockerExecution struct {
	executor *DockerExecutor
	id, arn  string
}

func (e *dockerExecution) endpoint() string { return "/containers/" + url.PathEscape(e.id) }
func (e *dockerExecution) upload(ctx context.Context, archive []byte) error {
	response, err := e.executor.client.Request(ctx, "PUT", e.endpoint()+"/archive?path=/", bytes.NewReader(archive), "application/x-tar")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	return err
}
func (e *dockerExecution) archive(ctx context.Context, directory string) ([]File, error) {
	response, err := e.executor.client.Request(ctx, "GET", e.endpoint()+"/archive?path="+url.QueryEscape(directory), nil, "")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	root := directory[strings.LastIndexByte(directory, '/')+1:]
	return readArchive(response.Body, root)
}
func (e *dockerExecution) Start(ctx context.Context) error {
	state, err := e.executor.nativeInspect(ctx, e.id)
	if err != nil {
		return err
	}
	if state.State.Running || state.State.Status == "exited" || state.State.Status == "dead" {
		return nil
	}
	if state.State.Status != "created" {
		return fmt.Errorf("cannot start build in native state %q", state.State.Status)
	}
	_, err = e.archive(ctx, "/codebuild/control")
	if err != nil {
		return fmt.Errorf("build preparation is incomplete: %w", err)
	}
	if err := e.checkMetadata(ctx, state); err != nil {
		return err
	}
	return e.executor.client.JSON(ctx, "POST", e.endpoint()+"/start", nil, nil)
}
func (e *dockerExecution) Stop(ctx context.Context) error {
	state, err := e.executor.nativeInspect(ctx, e.id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !state.State.Running {
		return nil
	}
	err = e.executor.client.JSON(ctx, "POST", e.endpoint()+"/stop?t=2", nil, nil)
	if err != nil {
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if killErr := e.executor.client.JSON(stopCtx, "POST", e.endpoint()+"/kill?signal=KILL", nil, nil); killErr != nil {
			return errors.Join(err, killErr)
		}
	}
	return nil
}
func (e *dockerExecution) Close() error { return nil }
func (e *dockerExecution) Inspect(ctx context.Context) (Status, error) {
	native, err := e.executor.nativeInspect(ctx, e.id)
	if err != nil {
		return Status{}, err
	}
	result := Status{State: "exited", ExitCode: native.State.ExitCode, Error: native.State.Error}
	if native.State.Status == "created" {
		result.State = "created"
	} else if native.State.Running {
		result.State = "running"
	}
	if native.State.OOMKilled {
		result.Error = "build exceeded its memory limit"
	}
	files, err := e.archive(ctx, "/codebuild/state")
	if err != nil {
		var remote *docker.Error
		if !errors.As(err, &remote) || remote.StatusCode != http.StatusNotFound {
			return result, err
		}
	}
	byName := make(map[string]Phase)
	for _, file := range files {
		if file.Path == "exported" || file.Path == "artifact_names" {
			fields := bytes.Split(file.Body, []byte{0})
			values := make(map[string]string, len(fields)/2)
			for i := 0; i+1 < len(fields); i += 2 {
				values[string(fields[i])] = string(fields[i+1])
			}
			if file.Path == "exported" {
				result.ExportedVariables = values
			} else {
				result.ArtifactNames = values
			}
			continue
		}
		fields := strings.Split(strings.TrimSpace(string(file.Body)), "\t")
		if len(fields) != 5 || file.Path != fields[0] {
			continue
		}
		start, _ := strconv.ParseInt(fields[2], 10, 64)
		end, _ := strconv.ParseInt(fields[3], 10, 64)
		phase := Phase{Name: fields[0], Status: fields[1], Started: time.Unix(start, 0).UTC()}
		if end != 0 {
			phase.Ended = time.Unix(end, 0).UTC()
		}
		if fields[4] != "0" {
			phase.Message = "command exited with status " + fields[4]
		}
		if result.State == "exited" && phase.Status == "RUNNING" {
			phase.Status = "FAILED"
			phase.Message = "build process terminated"
			phase.Ended, _ = time.Parse(time.RFC3339Nano, native.State.FinishedAt)
		}
		byName[phase.Name] = phase
	}
	for _, name := range phaseNames {
		if phase, ok := byName[strings.ToUpper(name)]; ok {
			result.Phases = append(result.Phases, phase)
		}
	}
	return result, nil
}

type logWindow struct {
	skip, read int64
	buffer     bytes.Buffer
}

func (w *logWindow) Write(data []byte) (int, error) {
	original := len(data)
	if w.skip > 0 {
		n := min(w.skip, int64(len(data)))
		w.skip -= n
		data = data[n:]
	}
	if len(data) > 0 {
		if int64(w.buffer.Len())+int64(len(data)) > 64<<20 {
			return 0, fmt.Errorf("unread build logs exceed 64 MiB")
		}
		_, _ = w.buffer.Write(data)
		w.read += int64(len(data))
	}
	return original, nil
}
func (e *dockerExecution) Logs(ctx context.Context, offset int64) ([]byte, int64, error) {
	if offset < 0 {
		return nil, offset, fmt.Errorf("invalid negative log offset")
	}
	state, err := e.executor.nativeInspect(ctx, e.id)
	if err != nil {
		return nil, offset, err
	}
	secrets, err := e.sensitiveValues(ctx, state)
	if err != nil {
		return nil, offset, err
	}
	response, err := e.executor.client.Request(ctx, "GET", e.endpoint()+"/logs?stdout=true&stderr=true&timestamps=false", nil, "")
	if err != nil {
		return nil, offset, err
	}
	defer response.Body.Close()
	window := logWindow{skip: offset}
	if err := docker.CopyStream(&window, &window, response.Body); err != nil {
		return nil, offset, err
	}
	masked, consumed := redactLogs(window.buffer.Bytes(), secrets, state.State.Running)
	return masked, offset + int64(consumed), nil
}
func (e *dockerExecution) Files(ctx context.Context, selector string) ([]File, error) {
	control, err := e.archive(ctx, "/codebuild/control")
	if err != nil {
		return nil, err
	}
	var retained retainedSpec
	found := false
	for _, file := range control {
		if file.Path == "spec.json" {
			if err := json.Unmarshal(file.Body, &retained); err != nil {
				return nil, err
			}
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("retained buildspec is missing")
	}
	var selection artifactSpec
	switch {
	case selector == "cache":
		for _, pattern := range retained.CachePaths {
			selection.Files = append(selection.Files, strings.TrimPrefix(pattern, "/codebuild/src/"))
		}
	case selector == "artifacts":
		selection = retained.Artifacts
	case strings.HasPrefix(selector, "artifacts:"):
		var ok bool
		selection, ok = retained.Artifacts.Secondary[strings.TrimPrefix(selector, "artifacts:")]
		if !ok {
			return nil, fmt.Errorf("secondary artifact %q is not configured", selector)
		}
	default:
		return nil, fmt.Errorf("unknown build file selector %q", selector)
	}
	if len(selection.Files) == 0 {
		return nil, nil
	}
	root := "/codebuild/src"
	if strings.Contains(selection.BaseDirectory, "$") {
		state, err := e.executor.lookup(ctx, e.arn)
		if err != nil {
			return nil, err
		}
		root, selection.BaseDirectory, err = artifactWorkspace(selection.BaseDirectory, state.Config.Env)
		if err != nil {
			return nil, err
		}
	}
	response, err := e.executor.client.Request(ctx, "GET", e.endpoint()+"/archive?path="+url.QueryEscape(root), nil, "")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	selected, err := readSelectedArchive(response.Body, path.Base(root), &selection)
	if err != nil {
		return nil, err
	}
	if len(selected) == 0 && selector != "cache" {
		return nil, fmt.Errorf("no matching artifact files")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path })
	return selected, nil
}

// Artifact base directories may refer to the named input workspaces. Resolve
// from retained container environment, keeping archive reads within those roots.
func artifactWorkspace(base string, environment []string) (string, string, error) {
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		values[name] = value
	}
	base = os.Expand(base, func(name string) string { return values[name] })
	root := "/codebuild/src"
	if strings.HasPrefix(base, "/codebuild/secondary/") {
		name, rest, _ := strings.Cut(strings.TrimPrefix(base, "/codebuild/secondary/"), "/")
		if !sourceIdentifier.MatchString(name) || values["CODEBUILD_SRC_DIR_"+name] != "/codebuild/secondary/"+name {
			return "", "", fmt.Errorf("artifact base directory is not an admitted source")
		}
		root = "/codebuild/secondary/" + name
		base = rest
	} else if base == root {
		base = ""
	} else {
		base = strings.TrimPrefix(base, root+"/")
	}
	if base != "" && base != "." {
		if err := validatePattern(base); err != nil {
			return "", "", err
		}
	}
	return root, base, nil
}

package lambda

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"stackd/compute/docker"
)

func (d *DockerExecutor) Prepare(ctx context.Context, spec Specification) (Environment, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || d.lifetime.Err() != nil {
		return nil, fmt.Errorf("lambda Docker instance owner is closed")
	}
	if d.recoveryErr != nil {
		return nil, fmt.Errorf("recovering older Lambda controller resources: %w", d.recoveryErr)
	}
	ctx, cancelOwnership := context.WithCancel(ctx)
	defer cancelOwnership()
	stopOwnership := context.AfterFunc(d.lifetime, cancelOwnership)
	defer stopOwnership()
	var architecture string
	switch spec.Architecture {
	case "x86_64":
		architecture = "amd64"
	case "arm64":
		architecture = "arm64"
	default:
		return nil, fmt.Errorf("unsupported Lambda architecture %q", spec.Architecture)
	}
	image, ok := d.config.Images[RuntimePlatform{Runtime: spec.Runtime, Architecture: spec.Architecture}]
	if !ok {
		return nil, fmt.Errorf("lambda runtime %q architecture %q is not configured for Docker execution", spec.Runtime, spec.Architecture)
	}
	if spec.Timeout <= 0 || spec.Timeout > 900*time.Second || spec.MemoryMB < 128 || spec.MemoryMB > 10240 || spec.EphemeralMB < 512 || spec.EphemeralMB > 10240 {
		return nil, fmt.Errorf("invalid Lambda timeout, memory or ephemeral-storage limits")
	}
	if spec.Handler == "" || strings.ContainsAny(spec.Handler, "\x00\r\n") {
		return nil, fmt.Errorf("lambda handler is required and must not contain control characters")
	}
	if spec.Credentials.AccessKeyID == "" || spec.Credentials.SecretAccessKey == "" || spec.Credentials.SessionToken == "" {
		return nil, fmt.Errorf("lambda execution role credentials are missing")
	}
	arn := strings.Split(spec.FunctionARN, ":")
	if len(arn) < 7 || arn[0] != "arn" || arn[2] != "lambda" || arn[3] == "" {
		return nil, fmt.Errorf("invalid Lambda function ARN")
	}
	version := "$LATEST"
	if len(arn) > 7 {
		version = arn[7]
	}
	if spec.Endpoint != "" {
		endpoint, err := url.Parse(spec.Endpoint)
		if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return nil, fmt.Errorf("lambda customer SDK endpoint must be an HTTP(S) origin")
		}
	}
	var directories HotReloadDirectories
	if version == "$LATEST" {
		directories = d.config.HotReload[strings.TrimSuffix(spec.FunctionARN, ":$LATEST")]
	}
	var archive, layers *os.File
	var err error
	if directories.Code == "" {
		archive, err = codeArchive(ctx, spec.Code)
		if err != nil {
			return nil, err
		}
		defer func() { archive.Close(); os.Remove(archive.Name()) }()
	}
	if directories.Layers == "" && len(spec.Layers) != 0 {
		layers, err = codeArchive(ctx, spec.Layers...)
		if err != nil {
			return nil, err
		}
		defer func() { layers.Close(); os.Remove(layers.Name()) }()
	}
	helper, err := telemetryHelperArchive(ctx, d.config.TelemetryHelpers[spec.Architecture], spec.Architecture)
	if err != nil {
		return nil, err
	}
	defer func() { helper.Close(); os.Remove(helper.Name()) }()
	startupCtx, cancel := context.WithTimeout(ctx, d.config.StartupTimeout)
	defer cancel()
	var imageInfo struct {
		ID           string `json:"Id"`
		OS           string `json:"Os"`
		Architecture string
		Config       struct{ Entrypoint []string }
	}
	// API 1.41 inspects the locally stored image, not a requested manifest-list
	// platform. Verify its actual platform, then create by that exact image ID.
	if err := d.engine.JSON(startupCtx, "GET", "/images/"+url.PathEscape(image)+"/json", nil, &imageInfo); err != nil {
		return nil, fmt.Errorf("lambda image %s is unavailable locally (automatic pull is disabled): %w", image, err)
	}
	if imageInfo.OS != "linux" || imageInfo.Architecture != architecture {
		return nil, fmt.Errorf("lambda image platform %s/%s does not match linux/%s", imageInfo.OS, imageInfo.Architecture, architecture)
	}
	if len(imageInfo.Config.Entrypoint) != 1 || imageInfo.Config.Entrypoint[0] != "/lambda-entrypoint.sh" {
		return nil, fmt.Errorf("lambda image must provide the official /lambda-entrypoint.sh entrypoint")
	}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	identity := "stackd-lambda-" + hex.EncodeToString(random[:])
	hostname := identity + ".runtime.internal"
	gateway := "host-gateway"
	if d.config.CallbackHost != "" {
		addresses, err := net.DefaultResolver.LookupIPAddr(startupCtx, d.config.CallbackHost)
		if err != nil || len(addresses) == 0 {
			return nil, fmt.Errorf("resolving Lambda callback host %q: %w", d.config.CallbackHost, err)
		}
		gateway = addresses[0].IP.String()
		for _, address := range addresses {
			if address.IP.To4() != nil {
				gateway = address.IP.String()
				break
			}
		}
	}
	listener, err := (&net.ListenConfig{}).Listen(startupCtx, "tcp", d.config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listening for Lambda Runtime API: %w", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		return nil, err
	}
	lifetime, stop := context.WithCancel(d.lifetime)
	e := &dockerEnvironment{engine: d.engine, spec: spec, platform: "linux/" + architecture, identity: identity, host: net.JoinHostPort(hostname, port), listener: listener, lifetime: lifetime, stop: stop, done: make(chan struct{}), gate: make(chan struct{}, 1)}
	e.startupTimeout = d.config.StartupTimeout
	e.telemetry = newTelemetryManager(lifetime, e, spec.Logs)
	e.telemetry.logging = spec.Logging
	e.telemetry.remote = newTelemetryBridge(lifetime)
	e.telemetry.remote.output = e.telemetry.forward
	e.telemetry.remoteFailure = e.fail
	e.spec.Code = nil
	e.spec.Layers = nil
	e.spec.Variables = nil
	e.gate <- struct{}{}
	e.server = &http.Server{Handler: e, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() {
		if err := e.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			e.fail(fmt.Errorf("lambda Runtime API listener: %w", err))
		}
	}()
	go func() {
		<-lifetime.Done()
		e.fail(fmt.Errorf("lambda Docker instance owner is closed"))
	}()
	failed := func(cause error) (Environment, error) {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cleanupCancel()
		if cleanupErr := e.Close(cleanupCtx); cleanupErr != nil {
			return e, errors.Join(cause, cleanupErr)
		}
		return nil, cause
	}
	if directories.Code != "" || directories.Layers != "" {
		e.hotReload, err = newHotReloadWatcher(lifetime, directories)
		if err != nil {
			return failed(err)
		}
	}
	labels := d.labels(identity, spec.FunctionARN)
	if archive != nil {
		e.volume = identity
	}
	// A separately allocated ext4 filesystem bounds /tmp independently of the
	// runtime memory cgroup and retains its contents across runtime replacement.
	e.tmpVolume = identity + "-tmp"
	e.helperVolume = identity + "-helper"
	if layers != nil {
		e.layerVolume = identity + "-layers"
	}
	if err := d.prepareDisk(startupCtx, e, labels); err != nil {
		return failed(err)
	}
	for _, volume := range []docker.VolumeConfig{
		{Name: e.volume, Labels: labels},
		{Name: e.layerVolume, Labels: labels},
		{Name: e.helperVolume, Labels: labels},
	} {
		if volume.Name == "" {
			continue
		}
		if err := d.engine.JSON(startupCtx, "POST", "/volumes/create", volume, nil); err != nil {
			return failed(fmt.Errorf("creating Lambda storage volume: %w", err))
		}
	}
	var staging struct {
		ID string `json:"Id"`
	}
	// The installer keeps /tmp and the network namespace across process resets.
	// It does not own subscription data. The runtime's PID 1 owns those bytes
	// under the same memory cgroup as the real function and extension processes.
	stageConfig := docker.ContainerConfig{Image: imageInfo.ID, Entrypoint: []string{"/bin/sleep"}, Cmd: []string{"infinity"}, User: "993:993", Labels: labels, HostConfig: docker.ContainerHostConfig{
		ReadonlyRootfs: true, Memory: 256 << 20, MemorySwap: 256 << 20, CPUPeriod: 100000, CPUQuota: 100000, PidsLimit: 256,
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, LogConfig: docker.ContainerLogConfig{Type: "none"},
		ExtraHosts: []string{hostname + ":" + gateway, "host.docker.internal:" + gateway, "sandbox.localdomain:127.0.0.1"},
		Mounts: []docker.ContainerMount{
			{Type: "volume", Source: e.tmpVolume, Target: "/tmp", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true, Labels: labels}},
			{Type: "volume", Source: e.helperVolume, Target: "/stackd", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true, Labels: labels}},
		},
	}}
	if archive != nil {
		stageConfig.HostConfig.Mounts = append(stageConfig.HostConfig.Mounts, docker.ContainerMount{Type: "volume", Source: e.volume, Target: "/var/task", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true, Labels: labels}})
	}
	if layers != nil {
		stageConfig.HostConfig.Mounts = append(stageConfig.HostConfig.Mounts, docker.ContainerMount{Type: "volume", Source: e.layerVolume, Target: "/opt", VolumeOptions: docker.ContainerVolumeOptions{NoCopy: true, Labels: labels}})
	}
	e.staging = identity + "-code"
	if err := d.engine.JSON(startupCtx, "POST", "/containers/create?name="+identity+"-code&platform="+url.QueryEscape(e.platform), stageConfig, &staging); err != nil {
		return failed(fmt.Errorf("creating Lambda code installer: %w", err))
	}
	e.staging = staging.ID
	for _, item := range []struct {
		file      *os.File
		directory string
	}{{archive, "/var/task"}, {layers, "/opt"}, {helper, "/stackd"}} {
		if item.file == nil {
			continue
		}
		response, err := d.engine.Request(startupCtx, "PUT", "/containers/"+url.PathEscape(e.staging)+"/archive?path="+url.QueryEscape(item.directory)+"&noOverwriteDirNonDir=true", item.file, "application/x-tar")
		if err != nil {
			return failed(fmt.Errorf("installing Lambda deployment at %s: %w", item.directory, err))
		}
		response.Body.Close()
	}
	if err := d.engine.JSON(startupCtx, "POST", "/containers/"+url.PathEscape(e.staging)+"/start", nil, nil); err != nil {
		return failed(fmt.Errorf("starting Lambda temporary-storage keeper: %w", err))
	}
	go e.watchKeeper(e.staging)
	variables := make(map[string]string, len(spec.Variables)+16)
	for key, value := range spec.Variables {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
			return failed(fmt.Errorf("invalid Lambda environment variable %q", key))
		}
		variables[key] = value
	}
	for key, value := range map[string]string{
		"AWS_LAMBDA_RUNTIME_API": e.host, "AWS_ACCESS_KEY_ID": spec.Credentials.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY": spec.Credentials.SecretAccessKey, "AWS_SESSION_TOKEN": spec.Credentials.SessionToken,
		"AWS_REGION": arn[3], "AWS_DEFAULT_REGION": arn[3], "AWS_LAMBDA_FUNCTION_NAME": spec.FunctionName,
		"AWS_LAMBDA_FUNCTION_VERSION": version, "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": strconv.Itoa(spec.MemoryMB),
		"AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/" + spec.FunctionName, "AWS_LAMBDA_LOG_STREAM_NAME": identity,
		"AWS_EXECUTION_ENV": "AWS_Lambda_" + spec.Runtime, "AWS_LAMBDA_INITIALIZATION_TYPE": string(e.initializationType()),
	} {
		variables[key] = value
	}
	// These are runtime-owned controls, never inherited from customer variables.
	delete(variables, "_LAMBDA_TELEMETRY_LOG_FD")
	delete(variables, "AWS_LAMBDA_LOG_LEVEL")
	variables["AWS_LAMBDA_LOG_FORMAT"] = "Text"
	if spec.Logging.Format == "JSON" {
		variables["AWS_LAMBDA_LOG_FORMAT"] = "JSON"
		variables["AWS_LAMBDA_LOG_LEVEL"] = spec.Logging.ApplicationLevel
	}
	if spec.LogGroup != "" {
		variables["AWS_LAMBDA_LOG_GROUP_NAME"] = spec.LogGroup
	}
	if spec.LogStream != "" {
		variables["AWS_LAMBDA_LOG_STREAM_NAME"] = spec.LogStream
	}
	for key, value := range map[string]string{"AWS_EC2_METADATA_DISABLED": "true", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"} {
		if _, set := variables[key]; !set {
			variables[key] = value
		}
	}
	if spec.Endpoint != "" {
		if _, set := variables["AWS_ENDPOINT_URL"]; !set {
			variables["AWS_ENDPOINT_URL"] = spec.Endpoint
		}
	}
	keys := make([]string, 0, len(variables))
	for key := range variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+variables[key])
	}
	// The installer configuration has already been submitted. Reuse its mounts
	// for the customer, with only /tmp writable; host directories never need to
	// be mounted in the keeper.
	mounts := stageConfig.HostConfig.Mounts
	for index := range mounts {
		mounts[index].ReadOnly = mounts[index].Target != "/tmp"
	}
	if directories.Code != "" {
		mounts = append(mounts, docker.ContainerMount{Type: "bind", Source: directories.Code, Target: "/var/task", ReadOnly: true})
	}
	if directories.Layers != "" {
		mounts = append(mounts, docker.ContainerMount{Type: "bind", Source: directories.Layers, Target: "/opt", ReadOnly: true})
	}
	memory := int64(spec.MemoryMB) << 20
	e.runtimeConfig = docker.ContainerConfig{Image: imageInfo.ID, Entrypoint: []string{"/stackd/telemetry-buffer"}, Cmd: []string{"http://" + e.host + e.telemetry.remote.path}, Env: environment, WorkingDir: "/var/task", User: "993:993", Labels: labels, HostConfig: docker.ContainerHostConfig{
		ReadonlyRootfs: true, Memory: memory, MemorySwap: memory, CPUPeriod: 100000, CPUQuota: int64(spec.MemoryMB) * 100000 / 1769, PidsLimit: 1024,
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"}, NetworkMode: "container:" + e.staging,
		Mounts:    mounts,
		LogConfig: docker.ContainerLogConfig{Type: "none"},
	}}
	if err := e.startContainer(startupCtx); err != nil {
		return failed(err)
	}
	if spec.Provisioned {
		if err := e.preinitialize(ctx); err != nil {
			return failed(err)
		}
	}
	return e, nil
}

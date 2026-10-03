package glue

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"stackd/compute/docker"
)

// Images are installed by the operator, never downloaded at job admission.
// Glue libraries use Amazon Software License 1.0, including its AWS-use
// limitation (§3.3); this optional adapter is for AWS-targeted development.
const SparkImage = "public.ecr.aws/glue/aws-glue-libs@sha256:a54bd25fb72c55a2f28d07656a3cda943a042f345cc25f4c2c170667be864f01"
const PythonImage = "public.ecr.aws/lambda/python@sha256:6aa6ba1ae1662df3e7400a25d3293bc464c3a907da13370eec7637128c8eb0a3"

type Config struct {
	Client                                        *docker.Client
	SparkImage, PythonImage, EndpointURL, Network string
	MemoryBytes, CPUs                             int64
}

type DockerRuntime struct {
	config      Config
	credentials credentialCallbacks
}

func New(ctx context.Context, c Config) (*DockerRuntime, error) {
	if c.Client == nil {
		return nil, errors.New("glue Docker client is required")
	}
	if c.SparkImage == "" {
		c.SparkImage = SparkImage
	}
	if c.PythonImage == "" {
		c.PythonImage = PythonImage
	}
	if c.MemoryBytes == 0 {
		c.MemoryBytes = 6 << 30
	}
	if c.CPUs == 0 {
		c.CPUs = 2
	}
	if c.MemoryBytes < 512<<20 || c.MemoryBytes > 6<<30 || c.CPUs < 1 {
		return nil, errors.New("glue requires 512MiB..6GiB and positive CPU limits")
	}
	endpoint, err := url.Parse(c.EndpointURL)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return nil, errors.New("glue requires an explicit emulator HTTP endpoint reachable from containers")
	}
	for _, image := range []string{c.SparkImage, c.PythonImage} {
		if !strings.Contains(image, "@sha256:") {
			return nil, errors.New("glue runtime images must be digest-pinned")
		}
		if err := c.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(image)+"/json", nil, nil); err != nil {
			return nil, fmt.Errorf("glue image must be installed locally (%s): %w", image, err)
		}
	}
	return &DockerRuntime{config: c}, nil
}

func containerName(key string) string {
	return fmt.Sprintf("stackd-glue-%x", sha256.Sum256([]byte(key)))
}
func containerPath(key string) string { return "/containers/" + containerName(key) }
func missing(err error) bool          { var e *docker.Error; return errors.As(err, &e) && e.StatusCode == 404 }

func (r *DockerRuntime) Start(ctx context.Context, e Execution) error {
	if e.Key == "" {
		return errors.New("glue execution identity is required")
	}
	image, command := r.config.PythonImage, []string{"/var/lang/bin/python3.9", "/tmp/stackd-job.py"}
	memory := min(r.config.MemoryBytes, int64(1<<30))
	if e.Command == "glueetl" {
		image, memory = r.config.SparkImage, r.config.MemoryBytes
		command = []string{"spark-submit", "--master", "local[2]", "--driver-memory", "2g", "--conf", "spark.ui.enabled=false", "--conf", "spark.hadoop.fs.s3.impl=org.apache.hadoop.fs.s3a.S3AFileSystem", "--conf", "spark.hadoop.fs.s3a.impl=org.apache.hadoop.fs.s3a.S3AFileSystem", "--conf", "spark.hadoop.fs.s3a.endpoint=" + r.config.EndpointURL, "--conf", "spark.hadoop.fs.s3a.path.style.access=true", "--conf", "spark.hadoop.fs.s3a.aws.credentials.provider=com.amazonaws.auth.EC2ContainerCredentialsProviderWrapper", "--conf", "spark.eventLog.enabled=true", "--conf", "spark.eventLog.compress=false", "--conf", "spark.eventLog.dir=file:///tmp/stackd-spark-events"}
		if e.S3EncryptionMode == "SSE-S3" {
			command = append(command, "--conf", "spark.hadoop.fs.s3a.server-side-encryption-algorithm=AES256")
		}
		if e.S3EncryptionMode == "SSE-KMS" {
			command = append(command, "--conf", "spark.hadoop.fs.s3a.server-side-encryption-algorithm=SSE-KMS", "--conf", "spark.hadoop.fs.s3a.server-side-encryption.key="+e.S3KMSKeyARN)
		}
		if strings.HasPrefix(r.config.EndpointURL, "http://") {
			command = append(command, "--conf", "spark.hadoop.fs.s3a.connection.ssl.enabled=false")
		}
		command = append(command, "--conf", "spark.pyspark.driver.python=/tmp/stackd-driver-python")
		command = append(command, "/tmp/stackd-job.py")
	} else if e.Command != "pythonshell" {
		return errors.New("unsupported Glue command")
	}
	keys := make([]string, 0, len(e.Arguments))
	for key := range e.Arguments {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		command = append(command, key, e.Arguments[key])
	}
	env := append([]string{"AWS_REGION=" + e.Region, "AWS_DEFAULT_REGION=" + e.Region, "AWS_ENDPOINT_URL=" + r.config.EndpointURL, "AWS_ENDPOINT_URL_S3=" + r.config.EndpointURL, "AWS_EC2_METADATA_DISABLED=true", "PYTHONUNBUFFERED=1"}, e.Environment...)
	if e.Command == "pythonshell" {
		env = append(env, "PYTHONPATH=/var/runtime:/var/lang/lib/python3.9/site-packages")
	}
	if _, ok := e.Arguments["--enable-metrics"]; e.Command == "glueetl" && ok {
		env = append(env, "STACKD_GLUE_PROFILE=1")
	}
	credentialEnv, labels, err := r.credentialEnvironment(e.Key)
	if err != nil {
		return err
	}
	env = append(env, credentialEnv...)
	labels["stackd.glue.command"] = e.Command
	python := "python3"
	if e.Command == "pythonshell" {
		python = "/var/lang/bin/python3.9"
	}
	command = append([]string{"/tmp/stackd-bootstrap.py"}, command...)
	config := docker.ContainerConfig{Image: image, Entrypoint: []string{python}, Cmd: command, Env: env, WorkingDir: "/tmp", Labels: labels, HostConfig: docker.ContainerHostConfig{NetworkMode: r.config.Network, Memory: memory, MemorySwap: memory, CPUPeriod: 100000, CPUQuota: r.config.CPUs * 100000, PidsLimit: 512, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, ExtraHosts: []string{"host.docker.internal:host-gateway"}, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "8m", "max-file": "1"}}}}
	// The durable controller marks its launch attempt before entering here. A
	// name conflict is deliberately not a reason to execute the script again.
	if err := r.config.Client.JSON(ctx, http.MethodPost, "/containers/create?name="+containerName(e.Key), config, nil); err != nil {
		return err
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "stackd-job.py", Mode: 0444, Size: int64(len(e.Script))}); err != nil {
		return err
	}
	if _, err := tw.Write(e.Script); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "stackd-bootstrap.py", Mode: 0444, Size: int64(len(bootstrapScript))}); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, bootstrapScript); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "stackd-profiling", Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "stackd-profiling/sitecustomize.py", Mode: 0444, Size: int64(len(profilingScript))}); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, profilingScript); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "stackd-driver-python", Mode: 0555, Size: int64(len(driverPython))}); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, driverPython); err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "stackd-spark-events", Mode: 0777, Typeflag: tar.TypeDir}); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	response, err := r.config.Client.Request(ctx, http.MethodPut, containerPath(e.Key)+"/archive?path=/tmp", &archive, "application/x-tar")
	if err != nil {
		return err
	}
	response.Body.Close()
	return r.config.Client.JSON(ctx, http.MethodPost, containerPath(e.Key)+"/start", nil, nil)
}

func (r *DockerRuntime) Inspect(ctx context.Context, key string) (Status, error) {
	out, command, err := r.inspectContainer(ctx, key)
	if err != nil || !out.Found || out.Running {
		return out, err
	}
	// Observation is optional: a lost log stream or damaged Spark event record
	// must not obscure authoritative process state or prevent native cleanup.
	var observationErr error
	response, err := r.config.Client.Request(ctx, http.MethodGet, containerPath(key)+"/logs?stdout=true&stderr=true&tail=2000", nil, "")
	if err != nil {
		observationErr = fmt.Errorf("container logs: %w", err)
	} else {
		var output, errorOutput cappedOutput
		err = docker.CopyStream(&output, &errorOutput, response.Body)
		response.Body.Close()
		out.Output, out.ErrorOutput = output.String(), errorOutput.String()
		if err != nil {
			observationErr = fmt.Errorf("container logs: %w", err)
		}
	}
	if command == "glueetl" {
		metrics, err := r.sparkMetrics(ctx, key)
		if err != nil {
			observationErr = errors.Join(observationErr, fmt.Errorf("spark metrics: %w", err))
		} else {
			// Partial counters from an unreadable event log are not complete job
			// metrics. Publish only a successfully observed log.
			out.SparkMetrics = metrics
		}
	}
	if observationErr != nil {
		out.ObservationError = observationErr.Error()
	}
	return out, nil
}

// inspectContainer is the ownership and process-state boundary. Stop and Remove
// deliberately do not fetch or parse customer output or optional event logs.
func (r *DockerRuntime) inspectContainer(ctx context.Context, key string) (Status, string, error) {
	var native struct {
		Config struct{ Labels map[string]string }
		State  struct {
			Running               bool
			ExitCode              int
			Error, Status         string
			StartedAt, FinishedAt time.Time
		}
	}
	err := r.config.Client.JSON(ctx, http.MethodGet, containerPath(key)+"/json", nil, &native)
	if missing(err) {
		return Status{}, "", nil
	}
	if err != nil {
		return Status{}, "", err
	}
	if native.Config.Labels["stackd.glue.run"] != key {
		return Status{}, "", errors.New("glue container ownership mismatch")
	}
	out := Status{Found: true, Running: native.State.Running, ExitCode: native.State.ExitCode, Error: native.State.Error}
	if !native.State.FinishedAt.IsZero() && !native.State.StartedAt.IsZero() {
		out.ExecutionSeconds = int32(max(0, native.State.FinishedAt.Sub(native.State.StartedAt)/time.Second))
	}
	if native.State.Status == "created" {
		out.ExitCode = -1
		out.Error = "Execution was interrupted before the customer process started"
	}
	return out, native.Config.Labels["stackd.glue.command"], nil
}

type cappedOutput struct{ bytes.Buffer }

func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if room := (1 << 20) - b.Len(); room > 0 {
		_, _ = b.Buffer.Write(p[:min(room, n)])
	}
	return n, nil
}

var _ io.Writer = (*cappedOutput)(nil)

func (r *DockerRuntime) Stop(ctx context.Context, key string) error {
	state, _, err := r.inspectContainer(ctx, key)
	if err != nil || !state.Found || !state.Running {
		return err
	}
	err = r.config.Client.JSON(ctx, http.MethodPost, containerPath(key)+"/kill?signal=SIGKILL", nil, nil)
	var remote *docker.Error
	if missing(err) || (errors.As(err, &remote) && remote.StatusCode == 409) {
		return nil
	}
	return err
}
func (r *DockerRuntime) Remove(ctx context.Context, key string) error {
	state, _, err := r.inspectContainer(ctx, key)
	if err != nil {
		return err
	}
	if state.Found {
		if err := r.config.Client.RemoveContainer(ctx, containerName(key)); err != nil {
			return err
		}
	}
	return r.closeCredentials(key)
}

// Glue 5 sends user Python stderr to output while Spark/Glue daemon stderr
// remains in the error group. Python shell retains its separate error stream.
const driverPython = "#!/bin/sh\nexec python3 \"$@\" 2>&1\n"

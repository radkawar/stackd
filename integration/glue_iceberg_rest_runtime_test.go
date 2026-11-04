package stackd_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestGlueIcebergRESTPyIcebergAthenaRuntime uses a separately running controller
// with the existing Athena/Trino runtime enabled; the REST API has no new flag.
// Install the actual client in an external environment, for example:
//
//	python3 -m venv /tmp/stackd-iceberg-client
//	/tmp/stackd-iceberg-client/bin/pip install 'pyiceberg[pyarrow,glue]==0.10.0'
//	STACKD_GLUE_ICEBERG_REST_ENDPOINT=http://127.0.0.1:4566 \
//	  STACKD_GLUE_ICEBERG_REST_STATE_DIRECTORY=/tmp/stackd-smoke/catalog.sqlite.athena \
//	  STACKD_GLUE_ICEBERG_REST_PYTHON=/tmp/stackd-iceberg-client/bin/python \
//	  go test ./integration -run '^TestGlueIcebergRESTPyIcebergAthenaRuntime$' -count=1 -timeout 12m -v
//
// Launch the controller using the documented -athena-runtime, -docker-host and
// -compute-endpoint options with the pinned Trino image already installed. This
// fixture creates unique resources and removes only those resources. It does not
// replace PyIceberg's transport/FileIO or Athena's real execution boundary.
// It also requires Docker CLI access (STACKD_GLUE_ICEBERG_REST_DOCKER_HOST,
// default unix:///var/run/docker.sock), the pinned Spark parser image, and this
// isolated controller's private ownership directory. Native denial evidence is
// correlated to a fresh query on that exact-owned engine, including its nested
// S3 403 cause. Only sanitized witnesses leave the directory: no engine/query
// identities, ownership receipts or callback capabilities are logged.
func TestGlueIcebergRESTPyIcebergAthenaRuntime(t *testing.T) {
	endpoint := os.Getenv("STACKD_GLUE_ICEBERG_REST_ENDPOINT")
	if endpoint == "" {
		t.Skip("set STACKD_GLUE_ICEBERG_REST_ENDPOINT to a running local stackd with the native Athena/Trino runtime")
	}
	stateDirectory := os.Getenv("STACKD_GLUE_ICEBERG_REST_STATE_DIRECTORY")
	if stateDirectory == "" {
		t.Fatal("set STACKD_GLUE_ICEBERG_REST_STATE_DIRECTORY to this isolated controller's private Athena ownership directory")
	}
	var err error
	stateDirectory, err = filepath.Abs(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	dockerHost := os.Getenv("STACKD_GLUE_ICEBERG_REST_DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}
	python := os.Getenv("STACKD_GLUE_ICEBERG_REST_PYTHON")
	if python == "" {
		python = "python3"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 11*time.Minute)
	defer cancel()
	script, err := filepath.Abs(filepath.Join("..", "scripts", "aws", "glue_iceberg_rest_smoke.py"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, python, script, "--endpoint", strings.TrimRight(endpoint, "/"), "--state-directory", stateDirectory, "--docker-host", dockerHost)
	command.Dir = t.TempDir()
	// Never forward a host AWS identity, endpoint override, profile or ambient
	// PyIceberg catalog. All SDK calls below select the explicit local origin.
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "AWS_") && !strings.HasPrefix(value, "PYICEBERG_") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env,
		"AWS_ACCESS_KEY_ID=test", "AWS_SECRET_ACCESS_KEY=test",
		"AWS_DEFAULT_REGION=us-east-1", "AWS_REGION=us-east-1",
		"AWS_EC2_METADATA_DISABLED=true", "AWS_MAX_ATTEMPTS=1",
		"PYICEBERG_HOME="+command.Dir,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("real PyIceberg/Athena fixture failed: %v\n%s", err, output)
	}
	t.Logf("real PyIceberg/Athena fixture:\n%s", output)
}

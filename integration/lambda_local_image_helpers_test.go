package stackd_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	computelambda "stackd/compute/lambda"
)

// Build only from the already installed, digest-pinned official Python RIC.
// Inspect first: --pull=false alone would still pull a missing FROM image.
func buildLambdaLocalPython312Image(t *testing.T, source string) string {
	t.Helper()
	lambdaURLDocker(t)
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("local Lambda image fixture requires the Docker CLI: ", err)
	}
	inspect := exec.CommandContext(t.Context(), "docker", "image", "inspect", computelambda.Python312X8664Image)
	output, err := inspect.Output()
	if err != nil {
		t.Fatalf("installed official Python 3.12 RIC image is unavailable; fixture never pulls: %v", err)
	}
	var images []struct{ Os, Architecture string }
	if err := json.Unmarshal(output, &images); err != nil {
		t.Fatal(err)
	}
	if len(images) != 1 || images[0].Os != "linux" || images[0].Architecture != "amd64" {
		t.Fatalf("official local RIC image must be linux/amd64: %s", output)
	}
	tag := "stackd-lambda-guard-image:" + uuid.NewString()
	directory := t.TempDir()
	dockerfile := fmt.Sprintf("FROM %s\nCOPY index.py /var/task/index.py\nCMD [\"index.handler\"]\n", computelambda.Python312X8664Image)
	for name, body := range map[string]string{"Dockerfile": dockerfile, "index.py": source} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.CommandContext(t.Context(), "docker", "build", "--platform=linux/amd64", "--pull=false", "--network=none", "-t", tag, directory)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building local official RIC image without network: %v\n%s", err, output)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Only this fixture's unique tag is owned; never remove the public base.
		remove := exec.CommandContext(ctx, "docker", "image", "rm", tag)
		if output, err := remove.CombinedOutput(); err != nil {
			t.Errorf("removing owned local RIC image: %v %s", err, output)
		}
	})
	return tag
}

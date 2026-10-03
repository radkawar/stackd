package eks

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestNativeCommandFailurePreservesDiagnosisWithoutCredentials(t *testing.T) {
	body, err := os.ReadFile("../../testdata/integration/eks_command_failure.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Stdout, Stderr             string
		RequiredDiagnosis, Secrets []string
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKD_EKS_TEST_STDOUT", fixture.Stdout)
	t.Setenv("STACKD_EKS_TEST_STDERR", fixture.Stderr)
	t.Setenv("STACKD_EKS_TEST_PASSWORD", "environment-only-password")
	runtime := &K3d{}
	_, err = runtime.command(t.Context(), "sh", "-c", `printf '%s' "$STACKD_EKS_TEST_STDOUT"; printf '%s' "$STACKD_EKS_TEST_STDERR" >&2; exit 23`, "cluster", "--token=argument-join-value@agent:0")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatal("native process failure lost its original exit status")
	}
	for _, diagnosis := range fixture.RequiredDiagnosis {
		if !strings.Contains(err.Error(), diagnosis) {
			t.Fatal("native process diagnosis was discarded during redaction")
		}
	}
	for _, secret := range fixture.Secrets {
		if strings.Contains(err.Error(), secret) || strings.Contains(string(exit.Stderr), secret) {
			t.Fatal("native process failure exposed a credential")
		}
	}
}

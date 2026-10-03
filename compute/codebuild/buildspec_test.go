package codebuild

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Run the generated scripts in real shells. Only the container's absolute root
// is relocated into an isolated temporary directory; no command is simulated.
func runBuildShell(t *testing.T, parsed buildspec) (string, string, int) {
	t.Helper()
	root := t.TempDir()
	files, err := controlFiles(parsed, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		name := filepath.Join(root, file.Path)
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		body := strings.ReplaceAll(string(file.Body), "/codebuild/", root+"/codebuild/")
		if err := os.WriteFile(name, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	shell := "/bin/sh"
	if parsed.Env.Shell == "bash" {
		shell = "/bin/bash"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, filepath.Join(root, "codebuild/control/run.sh"))
	cmd.Env, err = buildEnvironment(ctx, Specification{Environment: []string{"PATH=/usr/bin:/bin", "REMOVE_ME=initial"}}, parsed)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range cmd.Env {
		cmd.Env[i] = strings.ReplaceAll(value, "/codebuild/", root+"/codebuild/")
	}
	output, err := cmd.CombinedOutput()
	var exited *exec.ExitError
	if err != nil && !errors.As(err, &exited) {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	return root, string(output), cmd.ProcessState.ExitCode()
}

func readBuildFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "codebuild", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertBuildPhase(t *testing.T, root, phase, status, code string) {
	t.Helper()
	fields := strings.Split(strings.TrimSpace(readBuildFile(t, root, "state/"+phase)), "\t")
	if len(fields) != 5 || fields[0] != phase || fields[1] != status || fields[4] != code {
		t.Fatalf("%s phase = %q, want %s exit %s", phase, fields, status, code)
	}
}

func TestBuildspecInlineDocumentAndSourcePath(t *testing.T) {
	document := `{"version":"0.2","phases":{"build":{"commands":["printf actual-buildspec > result.txt"]}}}`
	for _, input := range []struct {
		name, specification string
		source              []File
	}{
		{name: "inline flow mapping", specification: document},
		{name: "source path", specification: "ci/buildspec.yml", source: []File{{Path: "ci/buildspec.yml", Body: []byte(document)}}},
	} {
		t.Run(input.name, func(t *testing.T) {
			parsed, err := parseBuildspec(Specification{Buildspec: input.specification}, input.source)
			if err != nil {
				t.Fatal(err)
			}
			root, output, code := runBuildShell(t, parsed)
			if code != 0 {
				t.Fatalf("build failed with exit %d:\n%s", code, output)
			}
			if got := readBuildFile(t, root, "src/result.txt"); got != "actual-buildspec" {
				t.Fatalf("buildspec commands produced %q", got)
			}
		})
	}
}

func TestNativeBuildFailureContinuesPostBuild(t *testing.T) {
	fixture, err := os.ReadFile("../../testdata/aws/codebuild/stackd-buildowner-cb-2c8f66f66e07-resume-ae70cd.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Cases []struct {
			Case       string `json:"case"`
			Parameters struct {
				Buildspec string `json:"buildspecOverride"`
			} `json:"parameters"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(fixture, &capture); err != nil {
		t.Fatal(err)
	}
	text := ""
	for _, item := range capture.Cases {
		if item.Case == "failure_start" {
			text = item.Parameters.Buildspec
		}
	}
	if text == "" {
		t.Fatal("native failure_start buildspec is missing")
	}
	parsed, err := parseBuildspec(Specification{Buildspec: text + "\n"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, shell := range []string{"/bin/sh", "bash"} {
		t.Run(shell, func(t *testing.T) {
			parsed.Env.Shell = shell
			root, output, code := runBuildShell(t, parsed)
			t.Logf("native generated-shell output (exit %d):\n%s", code, output)
			if code != 7 {
				t.Fatalf("exit = %d, want 7", code)
			}
			for _, line := range []string{"stackd-failure-finally", "stackd-failure-post"} {
				if !strings.Contains(output, "\n"+line+"\n") {
					t.Errorf("missing executed output %q", line)
				}
			}
			if strings.Contains(output, "stackd-must-not-run") {
				t.Error("executed command after failure")
			}
			assertBuildPhase(t, root, "BUILD", "FAILED", "7")
			assertBuildPhase(t, root, "POST_BUILD", "SUCCEEDED", "0")
			if actual := readBuildFile(t, root, "src/output/result.txt"); actual != "stackd-failed-build-artifact\n" {
				t.Fatalf("artifact = %q", actual)
			}
		})
	}
}

func TestBuildShellPreservesStateAndFirstFailure(t *testing.T) {
	for _, shell := range []string{"/bin/sh", "bash"} {
		t.Run(shell, func(t *testing.T) {
			parsed := buildspec{Version: "0.2", Phases: map[string]phaseSpec{
				"pre_build": {Commands: []string{"mkdir work; cd work", "export RESULT=before; unset REMOVE_ME"}},
				"build": {
					Commands: []string{"test \"$RESULT\" = before; test \"${REMOVE_ME+set}\" != set; test \"$PWD\" = \"$CODEBUILD_SRC_DIR/work\"", "export RESULT=failed", "exit 7", "touch forbidden"},
					Finally:  []string{"test \"$RESULT\" = failed; test \"$CODEBUILD_BUILD_SUCCEEDING\" = 0", "export RESULT=finally", "printf artifact > result.txt"},
				},
				"post_build": {
					Commands: []string{"test \"$RESULT\" = finally; test \"${REMOVE_ME+set}\" != set", "exit 9", "touch forbidden"},
					Finally:  []string{"export RESULT=post-finally", "printf post >> result.txt"},
				},
			}}
			parsed.Env.Shell = shell
			parsed.Env.Exported = []string{"RESULT"}
			parsed.Artifacts = artifactSpec{Name: "builds/$RESULT/$(printf artifact).zip"}
			root, output, code := runBuildShell(t, parsed)
			if code != 7 {
				t.Fatalf("first failure changed: exit %d:\n%s", code, output)
			}
			assertBuildPhase(t, root, "BUILD", "FAILED", "7")
			assertBuildPhase(t, root, "POST_BUILD", "FAILED", "9")
			if got := readBuildFile(t, root, "state/exported"); got != "RESULT\x00post-finally\x00" {
				t.Errorf("export = %q", got)
			}
			if got := readBuildFile(t, root, "state/artifact_names"); got != "artifacts\x00builds/post-finally/artifact.zip\x00" {
				t.Errorf("artifact name = %q", got)
			}
			if got := readBuildFile(t, root, "src/work/result.txt"); got != "artifactpost" {
				t.Errorf("artifact bytes = %q", got)
			}
			if _, err := os.Stat(filepath.Join(root, "codebuild/src/work/forbidden")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("command after failure ran: %v", err)
			}
		})
	}
}

func TestBuildShellFailureTransitions(t *testing.T) {
	for _, tc := range []struct {
		name, phase, policy, command, final string
		next                                bool
		code                                int
	}{
		{"post-build-command", "post_build", "", "exit 9", "printf cleanup > result", false, 9},
		{"post-build-finally", "post_build", "", "printf build > result", "exit 11", false, 11},
		{"build-finally", "build", "", "printf build > result", "exit 11", true, 11},
		{"explicit-abort", "build", "ABORT", "exit 7", "printf cleanup > result", false, 7},
		{"install-default", "install", "", "exit 7", "printf cleanup > result", false, 7},
		{"install-continue", "install", "CONTINUE", "exit 7", "printf cleanup > result", true, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := buildspec{Version: "0.2", Phases: map[string]phaseSpec{
				tc.phase: {Commands: []string{tc.command, "printf forbidden > forbidden"}, Finally: []string{tc.final}, OnFailure: tc.policy},
			}}
			if tc.phase != "post_build" {
				parsed.Phases["post_build"] = phaseSpec{Commands: []string{"printf next > next"}}
			}
			root, output, code := runBuildShell(t, parsed)
			if code != tc.code {
				t.Fatalf("exit = %d, want %d:\n%s", code, tc.code, output)
			}
			assertBuildPhase(t, root, strings.ToUpper(tc.phase), "FAILED", strconv.Itoa(tc.code))
			_, err := os.Stat(filepath.Join(root, "codebuild/src/next"))
			if tc.next && err != nil {
				t.Fatal(err)
			}
			if !tc.next && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("next phase ran: %v", err)
			}
			if tc.command == "exit 7" || tc.command == "exit 9" {
				if got := readBuildFile(t, root, "src/result"); got != "cleanup" {
					t.Errorf("finally did not execute: %q", got)
				}
			}
		})
	}
}

func TestBuildspec01IsolatesCommands(t *testing.T) {
	parsed, err := parseBuildspec(Specification{Buildspec: `version: 0.1
phases:
  pre_build:
    commands:
      - mkdir child; cd child; export TRANSIENT=hidden
      - test "$PWD" = "$CODEBUILD_SRC_DIR"; test -z "${TRANSIENT-}"
  build:
    commands:
      - test -z "${TRANSIENT-}"; printf isolated > result.txt
`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, output, code := runBuildShell(t, parsed)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, output)
	}
	if got := readBuildFile(t, root, "src/result.txt"); got != "isolated" {
		t.Errorf("result = %q", got)
	}
}

func TestBuildspec02RetainsNativeShellState(t *testing.T) {
	for _, shell := range []string{"/bin/sh", "bash"} {
		t.Run(shell, func(t *testing.T) {
			parsed := buildspec{Version: "0.2", Phases: map[string]phaseSpec{
				"install": {Commands: []string{
					"mkdir work; cd work",
					"set +a; LOCAL_ONLY=private; retained() { printf '%s' \"$LOCAL_ONLY\"; }; set -f",
				}},
				"pre_build": {Commands: []string{
					"test \"$(retained)\" = private",
					"/bin/sh -c 'test -z \"${LOCAL_ONLY-}\"'",
				}, Finally: []string{"LOCAL_ONLY=changed"}},
				"build": {Commands: []string{
					"test \"$PWD\" = \"$CODEBUILD_SRC_DIR/work\"",
					"touch existing; test \"$(printf '%s' *)\" = '*'",
					"retained > result.txt",
				}},
			}}
			parsed.Env.Shell = shell
			root, output, code := runBuildShell(t, parsed)
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, output)
			}
			if got := readBuildFile(t, root, "src/work/result.txt"); got != "changed" {
				t.Fatalf("retained function/local state = %q", got)
			}
		})
	}
}

func TestBuildShellRetryUsesActualFailures(t *testing.T) {
	for _, tc := range []struct {
		name, policy              string
		failUntil, attempts, code int
	}{
		{"default-retry", "RETRY", 2, 3, 0},
		{"bounded-retry", "RETRY-1", 3, 2, 7},
		{"matching-error", "RETRY-2-transient[[:space:]]+failure", 2, 3, 0},
		{"unmatched-error", "RETRY-2-permanent", 2, 1, 7},
		{"pattern-default-count", "RETRY-transient", 1, 2, 0},
		{"zero-retries", "RETRY-0", 1, 1, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := "attempt=$(cat attempts 2>/dev/null || printf 0); attempt=$((attempt + 1)); printf '%s' \"$attempt\" > attempts; if [ \"$attempt\" -le " + strconv.Itoa(tc.failUntil) + " ]; then printf 'transient failure\\n'; exit 7; fi; printf built > result"
			parsed := buildspec{Version: "0.2", Phases: map[string]phaseSpec{
				"build":      {OnFailure: tc.policy, Commands: []string{command}, Finally: []string{"printf f >> cleanups"}},
				"post_build": {Commands: []string{"printf '%s' \"$CODEBUILD_BUILD_SUCCEEDING\" > succeeding"}},
			}}
			root, output, code := runBuildShell(t, parsed)
			if code != tc.code {
				t.Fatalf("exit = %d, want %d:\n%s", code, tc.code, output)
			}
			if got := readBuildFile(t, root, "src/attempts"); got != strconv.Itoa(tc.attempts) {
				t.Errorf("attempts = %q", got)
			}
			if got := readBuildFile(t, root, "src/cleanups"); got != strings.Repeat("f", tc.attempts) {
				t.Errorf("finally executions = %q", got)
			}
			wantSucceeding := "1"
			if tc.code != 0 {
				wantSucceeding = "0"
			}
			if got := readBuildFile(t, root, "src/succeeding"); got != wantSucceeding {
				t.Errorf("succeeding = %q", got)
			}
			if tc.code == 0 {
				assertBuildPhase(t, root, "BUILD", "SUCCEEDED", "0")
				if got := readBuildFile(t, root, "src/result"); got != "built" {
					t.Errorf("result = %q", got)
				}
			} else {
				assertBuildPhase(t, root, "BUILD", "FAILED", "7")
			}
		})
	}
}

func TestBuildspecEnvironmentOverrideSkipsParameterLookup(t *testing.T) {
	parsed, err := parseBuildspec(Specification{Buildspec: "version: 0.2\nenv:\n  variables:\n    SELECTED: buildspec\n  parameter-store:\n    SELECTED: /missing-or-denied\n"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Project/start-build variables win even when the shadowed parameter is
	// missing, denied, or the Parameter Store dependency is unavailable.
	environment, err := buildEnvironment(context.Background(), Specification{Environment: []string{"SELECTED=override"}}, parsed)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range environment {
		if strings.HasPrefix(entry, "SELECTED=") {
			if entry != "SELECTED=override" {
				t.Fatalf("lower-precedence buildspec won: %q", entry)
			}
			return
		}
	}
	t.Fatal("effective environment omitted override")
}

func TestBuildspecParametersFailClosed(t *testing.T) {
	parsed, err := parseBuildspec(Specification{Buildspec: "version: 0.2\nenv:\n  parameter-store:\n    REQUIRED: /required\n"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	denied := errors.New("parameter access denied")
	for _, tc := range []struct {
		name   string
		values map[string]string
		err    error
	}{
		{name: "missing"},
		{name: "denied", err: denied},
		{name: "invalid native value", values: map[string]string{"/required": "private\x00value"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			environment, err := buildEnvironment(context.Background(), Specification{ResolveParameters: func(context.Context, []string) (map[string]string, error) { return tc.values, tc.err }}, parsed)
			if err == nil || environment != nil {
				t.Fatal("failed parameter resolution produced a runnable environment")
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("parameter authority error lost: %v", err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("diagnostic exposed parameter contents")
			}
		})
	}
}

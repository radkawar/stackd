package codebuild

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"stackd/compute/docker"
)

func nativeBuildExecutor(t *testing.T, imageVariable string) (context.Context, *DockerExecutor, string) {
	t.Helper()
	image := os.Getenv(imageVariable)
	if image == "" {
		t.Skip("set " + imageVariable + " to an explicitly selected local build image")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	client, err := docker.New(ctx, docker.Config{Host: os.Getenv("STACKD_CODEBUILD_TEST_DOCKER_HOST")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	executor, err := NewDockerExecutor(client, DockerConfig{Namespace: fmt.Sprintf("codebuild-shell-test-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := executor.Dispose(ctx); err != nil {
			t.Error(err)
		}
	})
	return ctx, executor, image
}

func executeNativeBuild(t *testing.T, ctx context.Context, executor *DockerExecutor, image, buildspec string) (Status, []File) {
	t.Helper()
	return executeNativeSpecification(t, ctx, executor, Specification{ARN: "arn:aws:codebuild:us-east-1:123456789012:build/native-shell:owned", Image: image, Buildspec: buildspec, MemoryBytes: 256 << 20, CPUQuota: 100000})
}

func executeNativeSpecification(t *testing.T, ctx context.Context, executor *DockerExecutor, spec Specification) (Status, []File) {
	t.Helper()
	execution, err := executor.Prepare(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := execution.Inspect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if status.State == "exited" {
			logs, _, err := execution.Logs(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("native output:\n%s", logs)
			if status.ExitCode != 0 {
				t.Fatalf("native failure: %+v", status)
			}
			files, err := execution.Files(ctx, "artifacts")
			if err != nil {
				t.Fatal(err)
			}
			return status, files
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestDockerBuildRunAsAndArtifactNames(t *testing.T) {
	ctx, executor, image := nativeBuildExecutor(t, "STACKD_CODEBUILD_TEST_IMAGE")
	status, files := executeNativeBuild(t, ctx, executor, image, `version: 0.2
run-as: nobody
env:
  exported-variables: [RESULT]
phases:
  pre_build:
    commands:
      - test "$(id -un)" = nobody
      - mkdir work; cd work
      - export RESULT=unprivileged
  build:
    run-as: root
    commands:
      - test "$(id -u)" = 0; test "$RESULT" = unprivileged
      - test "$PWD" = "$CODEBUILD_SRC_DIR/work"
      - printf root-built > result.txt
  post_build:
    commands:
      - test "$(id -un)" = nobody
      - export RESULT=completed
      - printf nobody-finished >> result.txt
artifacts:
  name: builds/$RESULT/$(printf native).zip
  files: [work/result.txt]
`)
	if status.ExportedVariables["RESULT"] != "completed" {
		t.Fatalf("exports = %#v", status.ExportedVariables)
	}
	if status.ArtifactNames["artifacts"] != "builds/completed/native.zip" {
		t.Fatalf("artifact names = %#v", status.ArtifactNames)
	}
	if len(files) != 1 || files[0].Path != "work/result.txt" || string(files[0].Body) != "root-builtnobody-finished" {
		t.Fatalf("actual output = %#v", files)
	}
}

// Requires an actual AWS image with the official runtime manifest and installed
// Corretto 17. A generic JDK image or a fabricated selector is not equivalent.
func TestDockerBuildImageRuntimeSelection(t *testing.T) {
	ctx, executor, image := nativeBuildExecutor(t, "STACKD_CODEBUILD_RUNTIME_TEST_IMAGE")
	_, files := executeNativeBuild(t, ctx, executor, image, `version: 0.2
env:
  shell: bash
phases:
  install:
    runtime-versions:
      java: corretto17
  build:
    commands:
      - java -version > result.txt 2>&1
      - '"$JAVA_HOME/bin/java" -version > selected.txt 2>&1'
artifacts:
  files: [result.txt, selected.txt]
`)
	if len(files) != 2 {
		t.Fatalf("runtime output = %#v", files)
	}
	for _, file := range files {
		output := string(file.Body)
		if !strings.Contains(output, `version "17.`) || !strings.Contains(output, "Corretto") {
			t.Fatalf("%s did not execute Corretto 17: %s", file.Path, output)
		}
	}
}

func TestDockerBuildRejectsMissingRuntimeManifest(t *testing.T) {
	ctx, executor, image := nativeBuildExecutor(t, "STACKD_CODEBUILD_TEST_IMAGE")
	arn := "arn:aws:codebuild:us-east-1:123456789012:build/missing-runtime:owned"
	_, err := executor.Prepare(ctx, Specification{ARN: arn, Image: image, MemoryBytes: 128 << 20, CPUQuota: 100000, Buildspec: "version: 0.2\nphases:\n  install:\n    runtime-versions:\n      java: corretto11\n"})
	if err == nil {
		t.Fatal("runtime selector without an image-owned manifest was accepted")
	}
	if _, err := executor.Open(ctx, arn); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed runtime preparation left an execution: %v", err)
	}
}

func pipelineSourceZIP(t *testing.T, files ...File) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, file := range files {
		entry, err := writer.Create(file.Path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write(file.Body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestDockerPipelineSourceDirectoriesAndSecondaryArtifacts(t *testing.T) {
	ctx, executor, image := nativeBuildExecutor(t, "STACKD_CODEBUILD_TEST_IMAGE")
	arn := "arn:aws:codebuild:us-east-1:123456789012:build/pipeline-sources:owned"
	spec := Specification{
		ARN: arn, Image: image, MemoryBytes: 256 << 20, CPUQuota: 100000,
		SourceZIP: pipelineSourceZIP(t,
			File{Path: "value.txt", Body: []byte("17")},
			File{Path: "buildspec.yml", Body: []byte(`version: 0.2
run-as: nobody
phases:
  build:
    commands:
      - test "$PWD" = "$CODEBUILD_SRC_DIR"
      - test "$CODEBUILD_RESOLVED_SOURCE_VERSION" = original-source-version
      - test -d "$CODEBUILD_SRC_DIR_Empty"
      - printf '%s' "$(( $(cat value.txt) + $(cat "$CODEBUILD_SRC_DIR_Aux/value.txt") ))" > result.txt
      - mkdir "$CODEBUILD_SRC_DIR_Aux/output"
      - cp result.txt "$CODEBUILD_SRC_DIR_Aux/output/combined.txt"
artifacts:
  files: [result.txt]
  secondary-artifacts:
    Combined:
      base-directory: $CODEBUILD_SRC_DIR_Aux/output
      files: [combined.txt]
`)}),
		SecondarySources: []Source{
			{Identifier: "Aux", ZIP: pipelineSourceZIP(t,
				File{Path: "value.txt", Body: []byte("23")},
				File{Path: "buildspec.yml", Body: []byte("version: 0.2\nphases:\n  build:\n    commands: [exit 19]\n")})},
			{Identifier: "Empty", ZIP: pipelineSourceZIP(t)},
		},
		Environment: []string{"CODEBUILD_RESOLVED_SOURCE_VERSION=original-source-version"},
	}
	_, files := executeNativeSpecification(t, ctx, executor, spec)
	if len(files) != 1 || files[0].Path != "result.txt" || string(files[0].Body) != "40" {
		t.Fatalf("primary source workspace result = %#v", files)
	}
	reopened, err := NewDockerExecutor(executor.client, executor.config)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := reopened.Open(ctx, arn)
	if err != nil {
		t.Fatal(err)
	}
	defer execution.Close()
	files, err = execution.Files(ctx, "artifacts:Combined")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "combined.txt" || string(files[0].Body) != "40" {
		t.Fatalf("retained secondary output = %#v", files)
	}
	if _, err = execution.Files(ctx, "artifacts:Missing"); err == nil {
		t.Fatal("missing secondary artifact selected unrelated primary output")
	}
}

func TestArtifactWorkspaceRejectsEscapesAfterExpansion(t *testing.T) {
	for _, base := range []string{"$CODEBUILD_SRC_DIR_Aux/../../control", "$OUTSIDE", "$UNKNOWN_SOURCE"} {
		_, _, err := artifactWorkspace(base, []string{
			"CODEBUILD_SRC_DIR_Aux=/codebuild/secondary/Aux",
			"OUTSIDE=/etc", "UNKNOWN_SOURCE=/codebuild/secondary/Foreign",
		})
		if err == nil {
			t.Fatalf("artifact directory %q escaped admitted workspaces", base)
		}
	}
}

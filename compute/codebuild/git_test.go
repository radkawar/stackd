package codebuild

import (
	"bytes"
	"context"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The HTTP handler executes the real Git smart-protocol backend. Source and
// submodule bytes are committed and fetched by native Git, not response mocks.
func TestGitSourceSubmodulesScopeCredentials(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("native Git is required")
	}
	root := t.TempDir()
	runGit := func(directory string, arguments ...string) string {
		t.Helper()
		cmd := exec.Command(git, arguments...)
		cmd.Dir = directory
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=CodeBuild Test", "GIT_AUTHOR_EMAIL=codebuild@example.invalid", "GIT_COMMITTER_NAME=CodeBuild Test", "GIT_COMMITTER_EMAIL=codebuild@example.invalid")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", arguments, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	backend := &cgi.Handler{Path: git, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	const username, password = "source-user", "owned-source-password"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="native-git"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	defer server.Close()
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	runGit(work, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(work, "module.txt"), []byte("real-submodule-bytes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit(work, "add", "module.txt")
	runGit(work, "commit", "--quiet", "-m", "owned submodule")
	revision := runGit(work, "rev-parse", "HEAD")
	runGit(root, "clone", "--quiet", "--bare", work, "module.git")
	main := filepath.Join(root, "main-work")
	if err := os.Mkdir(main, 0700); err != nil {
		t.Fatal(err)
	}
	runGit(main, "init", "--quiet")
	runGit(main, "config", "--file", ".gitmodules", "submodule.module.path", "module")
	runGit(main, "config", "--file", ".gitmodules", "submodule.module.url", "../module.git")
	runGit(main, "add", ".gitmodules")
	runGit(main, "update-index", "--add", "--cacheinfo", "160000,"+revision+",module")
	runGit(main, "commit", "--quiet", "-m", "owned main")
	runGit(root, "clone", "--quiet", "--bare", main, "main.git")

	fetch := func(name string, submodules bool) (string, string, error) {
		t.Helper()
		workspace := filepath.Join(root, name)
		control := filepath.Join(workspace, "codebuild/control")
		if err := os.MkdirAll(control, 0700); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string]string{"git.sh": gitScript, "credential.sh": gitCredentialScript} {
			body = strings.ReplaceAll(body, "/codebuild/", workspace+"/codebuild/")
			if err := os.WriteFile(filepath.Join(control, name), []byte(body), 0700); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(control, "git.sh"))
		flag := "false"
		if submodules {
			flag = "true"
		}
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + workspace + "/codebuild/home", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "GIT_SOURCE_ORIGIN=" + server.URL, "GIT_SOURCE_URL=" + server.URL + "/main.git", "GIT_SOURCE_VERSION=HEAD", "GIT_SOURCE_DEPTH=1", "GIT_SOURCE_USERNAME=" + username, "GIT_SOURCE_PASSWORD=" + password, "GIT_SOURCE_SUBMODULES=" + flag}
		output, err := cmd.CombinedOutput()
		if strings.Contains(string(output), password) {
			t.Fatal("Git output leaked source password")
		}
		return filepath.Join(workspace, "codebuild/src"), string(output), err
	}
	workspace, output, err := fetch("enabled", true)
	if err != nil {
		t.Fatalf("submodule retrieval: %v\n%s", err, output)
	}
	body, err := os.ReadFile(filepath.Join(workspace, "module/module.txt"))
	if err != nil || string(body) != "real-submodule-bytes\n" {
		t.Fatalf("submodule bytes: %q, %v", body, err)
	}
	workspace, output, err = fetch("disabled", false)
	if err != nil {
		t.Fatalf("main retrieval: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(workspace, "module/module.txt")); !os.IsNotExist(err) {
		t.Fatalf("unrequested submodule checkout: %v", err)
	}
	t.Run("staged repository remains usable", func(t *testing.T) {
		tarBinary, err := exec.LookPath("tar")
		if err != nil {
			t.Skip("native tar is required")
		}
		// Docker's archive endpoint includes directory entries. Exercise the
		// same read/stage boundary with the actual fetched detached repository,
		// whose .git/refs directory can legitimately be empty.
		archive, err := exec.Command(tarBinary, "-C", filepath.Dir(workspace), "-cf", "-", "src").Output()
		if err != nil {
			t.Fatal(err)
		}
		files, err := readArchive(bytes.NewReader(archive), "src")
		if err != nil {
			t.Fatal(err)
		}
		files, err = prepareSource(nil, files)
		if err != nil {
			t.Fatal(err)
		}
		staged, err := writeArchive(files)
		if err != nil {
			t.Fatal(err)
		}
		directory := t.TempDir()
		extract := exec.Command(tarBinary, "-C", directory, "-xf", "-")
		extract.Stdin = bytes.NewReader(staged)
		if output, err := extract.CombinedOutput(); err != nil {
			t.Fatalf("extract staged source: %v\n%s", err, output)
		}
		if got, want := runGit(directory, "rev-parse", "HEAD"), runGit(main, "rev-parse", "HEAD"); got != want {
			t.Fatalf("staged repository revision = %s, want %s", got, want)
		}
	})

	var leaked atomic.Bool
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="foreign-git"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer foreign.Close()
	runGit(main, "config", "--file", ".gitmodules", "submodule.module.url", foreign.URL+"/module.git")
	runGit(main, "add", ".gitmodules")
	runGit(main, "commit", "--quiet", "-m", "foreign submodule")
	runGit(main, "push", "--quiet", filepath.Join(root, "main.git"), "HEAD")
	_, output, err = fetch("foreign", true)
	if err == nil {
		t.Fatalf("unauthorized foreign submodule succeeded:\n%s", output)
	}
	if leaked.Load() {
		t.Fatal("source credentials reached a different submodule authority")
	}
}

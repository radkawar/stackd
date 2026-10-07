package lambda

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"stackd/compute/docker"
)

const imageRegressionFirstID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// Native image execution and retention are exercised by the real Docker RIC
// integration fixture. This boundary fixture only injects rejected platforms.
type imageRegressionEngine struct {
	mu                   sync.Mutex
	id, os, architecture string
	requests             []string
}

func imageRegressionDocker(t *testing.T) (*DockerExecutor, *imageRegressionEngine) {
	t.Helper()
	backend := &imageRegressionEngine{id: imageRegressionFirstID, os: "linux", architecture: "amd64"}
	server := httptest.NewServer(http.HandlerFunc(backend.serve))
	t.Cleanup(server.Close)
	client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return &DockerExecutor{engine: client}, backend
}

func (b *imageRegressionEngine) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1.41")
	b.mu.Lock()
	b.requests = append(b.requests, r.Method+" "+path)
	id, platformOS, architecture := b.id, b.os, b.architecture
	b.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case path == "/version":
		fmt.Fprint(w, `{"ApiVersion":"1.41","Os":"linux"}`)
	case path == "/info":
		fmt.Fprint(w, `{"MemoryLimit":true,"SwapLimit":true,"CPUCfsQuota":true,"CPUCfsPeriod":true}`)
	case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
		if strings.Contains(path, "missing") {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"No such image"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"Id": id, "Os": platformOS, "Architecture": architecture, "Size": int64(4096), "Config": map[string]any{"Entrypoint": []string{"/opt/bootstrap", "--runtime"}, "Cmd": []string{"default.handler"}, "WorkingDir": "/image/work", "Env": []string{"IMAGE_DEFAULT=present", "SHARED=image"}}})
	default:
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(w, `{"message":%q}`, "unexpected Engine request: "+r.Method+" "+path)
	}
}

func TestDockerImageAdmissionRejectsUnavailableAndWrongPlatform(t *testing.T) {
	for _, test := range []struct{ name, uri, os, architecture, lambdaArchitecture string }{
		{"missing-local-tag", "missing:latest", "linux", "amd64", "x86_64"},
		{"arm-image-for-x86", "local:latest", "linux", "arm64", "x86_64"},
		{"x86-image-for-arm", "local:latest", "linux", "amd64", "arm64"},
		{"non-linux", "local:latest", "windows", "amd64", "x86_64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor, backend := imageRegressionDocker(t)
			backend.mu.Lock()
			backend.os, backend.architecture = test.os, test.architecture
			backend.mu.Unlock()
			image, err := executor.ResolveImage(t.Context(), test.uri, test.lambdaArchitecture)
			if err == nil || image.ID != "" {
				t.Fatalf("dishonest image admission: image=%+v err=%v", image, err)
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			for _, request := range backend.requests {
				if strings.HasPrefix(request, "POST ") {
					t.Errorf("image admission pulled or executed an image: %s", request)
				}
			}
		})
	}
}

func TestDockerImageConfigCommandAndWorkingDirectory(t *testing.T) {
	image := &Image{EntryPoint: []string{"/image/bootstrap", "--flag"}, Command: []string{"original.handler"}, WorkingDirectory: "/image/work"}
	for _, test := range []struct {
		name      string
		config    *ImageConfig
		command   []string
		directory string
	}{
		{"image-defaults", nil, []string{"/image/bootstrap", "--flag", "original.handler"}, "/image/work"},
		{"command-only", &ImageConfig{Command: []string{"replacement.handler", "argument with spaces"}}, []string{"/image/bootstrap", "--flag", "replacement.handler", "argument with spaces"}, "/image/work"},
		{"entrypoint-only", &ImageConfig{EntryPoint: []string{"/override/bootstrap"}}, []string{"/override/bootstrap", "original.handler"}, "/image/work"},
		{"all-overrides", &ImageConfig{EntryPoint: []string{"/override/bootstrap"}, Command: []string{"override.handler"}, WorkingDirectory: "/override/work"}, []string{"/override/bootstrap", "override.handler"}, "/override/work"},
		{"explicit-empty-entrypoint", &ImageConfig{EntryPoint: []string{}}, []string{"original.handler"}, "/image/work"},
		{"explicit-empty-command", &ImageConfig{Command: []string{}}, []string{"/image/bootstrap", "--flag"}, "/image/work"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, directory, err := imageCommand(image, test.config)
			if err != nil || !reflect.DeepEqual(command, test.command) || directory != test.directory {
				t.Fatalf("image command=%q directory=%q err=%v; want %q %q", command, directory, err, test.command, test.directory)
			}
			command[0] = "mutated-result"
			if image.EntryPoint[0] != "/image/bootstrap" || image.Command[0] != "original.handler" {
				t.Fatal("command construction mutated admitted image")
			}
		})
	}
	if _, _, err := imageCommand(image, &ImageConfig{EntryPoint: []string{}, Command: []string{}}); err == nil {
		t.Fatal("empty executable command admitted")
	}
}

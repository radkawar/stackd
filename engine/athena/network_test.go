package athena

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"stackd/compute/docker"
)

type networkFixture struct {
	t                 *testing.T
	local             bool
	mu                sync.Mutex
	containers        map[string]*networkContainer
	entered           chan string
	release           chan struct{}
	probeError        bool
	wrongNode         bool
	createEntered     chan struct{}
	createRelease     chan struct{}
	queryPages        bool
	nativeCreates     int
	parserError       string
	parserRemoveError bool
	queryError        string
	loseOwnerOnQuery  bool
	dropError         bool
	ctasPlan          *ctasPlan
}

type networkContainer struct {
	config     containerConfig
	files      map[string]string
	server     *httptest.Server
	output     []byte
	catalogs   map[string]map[string]string
	statements []nativeStatement
	canceled   []string
	queries    int
	stopped    bool
	ctasSQL    string
}

// Uses only the imported warm implementation's fixture/API so the same test can
// demonstrate the missing reuse witness against that implementation unchanged.
func TestWarmEngineRechecksNativeWorkerOnReuse(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	executeFixture(t, d, fixtureRequest("first-owned-query"), nil)
	name := <-f.entered
	f.wrongNode = true
	published := false
	err := d.Execute(t.Context(), fixtureRequest("foreign-worker-reuse"), func(string) error { published = true; return nil }, func(Page) error { return nil })
	f.wrongNode = false
	if err == nil || published {
		t.Fatalf("foreign warm worker accepted next caller: handlePublished=%t err=%v", published, err)
	}
	f.mu.Lock()
	container := f.containers[name]
	f.mu.Unlock()
	if container != nil && (container.queries != 1 || len(container.catalogs) != 0) {
		t.Fatal("foreign warm worker received customer SQL or callback catalog")
	}
}

func archiveFiles(t *testing.T, data []byte) map[string]string {
	t.Helper()
	files := make(map[string]string)
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		files[strings.TrimPrefix(header.Name, "stackd-athena/")] = string(body)
	}
}

func property(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		if value, found := strings.CutPrefix(line, key+"="); found {
			return value
		}
	}
	return ""
}

func newNetworkFixture(t *testing.T, local bool) (*networkFixture, *Docker) {
	t.Helper()
	return newNetworkFixtureConfig(t, local, DockerConfig{})
}

func newNetworkFixtureConfig(t *testing.T, local bool, config DockerConfig) (*networkFixture, *Docker) {
	t.Helper()
	f := &networkFixture{t: t, local: local, containers: make(map[string]*networkContainer), entered: make(chan string, 8), release: make(chan struct{})}
	server := httptest.NewServer(http.HandlerFunc(f.serveDocker))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		select {
		case <-f.release:
		default:
			close(f.release)
		}
	})
	client, err := docker.New(t.Context(), docker.Config{Host: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	config.Client = client
	if config.StateDirectory == "" {
		config.StateDirectory = filepath.Join(t.TempDir(), "athena")
	}
	if !local {
		// A remote daemon needs an explicit controller-reachable callback route.
		config.CallbackListen, config.CallbackHost = "127.0.0.1:0", "127.0.0.1"
	}
	d, err := NewDocker(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if d.hostNetwork != local {
		t.Fatalf("witnessed host network = %t, want %t", d.hostNetwork, local)
	}
	return f, d
}

func (f *networkFixture) serveDocker(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1.48")
	writeJSON := func(value any) { _ = json.NewEncoder(w).Encode(value) }
	switch {
	case path == "/version":
		writeJSON(map[string]any{"ApiVersion": "1.48", "Os": "linux"})
		return
	case path == "/info":
		writeJSON(map[string]any{"MemoryLimit": true, "SwapLimit": true, "CpuCfsQuota": true, "CpuCfsPeriod": true})
		return
	case strings.HasPrefix(path, "/images/"):
		writeJSON(map[string]any{"Id": DockerImage, "Os": "linux"})
		return
	case strings.HasPrefix(path, "/exec/"):
		execID, action, _ := strings.Cut(strings.TrimPrefix(path, "/exec/"), "/")
		name := strings.TrimSuffix(execID, "-ctas")
		f.mu.Lock()
		container := f.containers[name]
		f.mu.Unlock()
		if container == nil || container.ctasSQL == "" {
			http.Error(w, `{"message":"unknown parser exec"}`, 404)
			return
		}
		switch action {
		case "json":
			writeJSON(map[string]any{"Running": false, "ExitCode": 0})
		case "start":
			// Ownership/protocol fixture only: explicit typed input, no mock
			// SQL parser. The opt-in CTAS fixture uses the real pinned parser.
			body, err := json.Marshal(map[string]any{"plan": f.ctasPlan})
			if err != nil {
				f.t.Fatal(err)
			}
			var header [8]byte
			header[0] = 1
			binary.BigEndian.PutUint32(header[4:], uint32(len(body)))
			w.Write(header[:])
			w.Write(body)
		default:
			f.t.Errorf("unexpected parser exec operation %s", action)
			http.Error(w, "unexpected parser operation", 500)
		}
		return
	case path == "/containers/create":
		var config containerConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			f.t.Error(err)
			http.Error(w, err.Error(), 400)
			return
		}
		container := &networkContainer{config: config, catalogs: make(map[string]map[string]string)}
		for _, entry := range config.Env {
			if encoded, found := strings.CutPrefix(entry, "STACKD_TRINO_CONFIG="); found {
				data, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					f.t.Error(err)
					return
				}
				container.files = archiveFiles(f.t, data)
			}
		}
		if container.files == nil && f.probeError {
			http.Error(w, `{"message":"helper admission failed"}`, 500)
			return
		}
		name := r.URL.Query().Get("name")
		f.mu.Lock()
		f.containers[name] = container
		if container.files != nil {
			f.nativeCreates++
		}
		f.mu.Unlock()
		if container.files != nil && f.createEntered != nil {
			close(f.createEntered)
			<-f.createRelease
		}
		writeJSON(map[string]string{"Id": name})
		return
	}
	name, action, _ := strings.Cut(strings.TrimPrefix(path, "/containers/"), "/")
	f.mu.Lock()
	container := f.containers[name]
	f.mu.Unlock()
	if container == nil {
		http.Error(w, `{"message":"not found"}`, 404)
		return
	}
	if r.Method == http.MethodDelete {
		if strings.HasSuffix(name, "-hiveddl") && f.parserRemoveError {
			http.Error(w, `{"message":"parser cleanup unavailable"}`, 500)
			return
		}
		if container.server != nil {
			container.server.Close()
		}
		f.mu.Lock()
		delete(f.containers, name)
		f.mu.Unlock()
		w.WriteHeader(204)
		return
	}
	switch action {
	case "exec":
		var command struct {
			Cmd                        []string
			AttachStdout, AttachStderr bool
		}
		if err := json.NewDecoder(r.Body).Decode(&command); err != nil {
			f.t.Error(err)
			http.Error(w, "parser exec", 500)
			return
		}
		if len(command.Cmd) < 5 || command.Cmd[0] != "/bin/sh" || command.Cmd[3] != "stackd-ctas" || !command.AttachStdout || !command.AttachStderr {
			f.t.Errorf("unexpected parser launch: %+v", command)
			http.Error(w, "parser exec command", 500)
			return
		}
		if container.files["StackdCTAS.java"] != ctasParserSource {
			f.t.Error("parser source must be staged with startup configuration")
		}
		sql, err := base64.StdEncoding.DecodeString(strings.Join(command.Cmd[4:], ""))
		if err != nil {
			f.t.Error(err)
			http.Error(w, "parser SQL", 500)
			return
		}
		container.ctasSQL = string(sql)
		writeJSON(map[string]string{"Id": name + "-ctas"})
	case "start":
		if container.config.HostConfig.NetworkMode == "none" {
			container.output, _ = json.Marshal(map[string]string{"error": "fixture parser rejection", "errorKind": f.parserError})
			w.WriteHeader(204)
			return
		}
		if container.files == nil {
			if container.config.HostConfig.NetworkMode != "host" || len(container.config.HostConfig.PortBindings) != 0 {
				f.t.Error("locality witness must not create a bridge endpoint")
			}
			if f.local {
				response, err := http.Get(container.config.Cmd[2])
				if err != nil {
					f.t.Error(err)
					return
				}
				container.output, _ = io.ReadAll(response.Body)
				response.Body.Close()
			}
		} else {
			listener, err := net.Listen("tcp4", "127.0.0.1:"+f.nativePort(container))
			if err != nil {
				f.t.Error(err)
				http.Error(w, err.Error(), 500)
				return
			}
			container.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				f.serveTrino(container, name, w, r)
			}))
			container.server.Listener.Close()
			container.server.Listener = listener
			container.server.Start()
		}
		w.WriteHeader(204)
	case "wait":
		writeJSON(map[string]int{"StatusCode": 0})
	case "logs":
		var header [8]byte
		header[0] = 1
		binary.BigEndian.PutUint32(header[4:], uint32(len(container.output)))
		w.Write(header[:])
		w.Write(container.output)
	case "json":
		ports := map[string][]portBinding{}
		if container.server != nil && !f.local {
			_, port, _ := net.SplitHostPort(container.server.Listener.Addr().String())
			ports["8080/tcp"] = []portBinding{{HostIP: "127.0.0.1", HostPort: port}}
		}
		writeJSON(map[string]any{"Id": name, "Image": container.config.Image, "Config": container.config.ContainerConfig, "State": map[string]bool{"Running": !container.stopped}, "NetworkSettings": map[string]any{"Ports": ports}})
	default:
		f.t.Errorf("unexpected Docker operation: %s %s", r.Method, r.URL)
		http.Error(w, "unexpected operation", 500)
	}
}

func (f *networkFixture) nativePort(c *networkContainer) string {
	if !f.local {
		return "0"
	}
	return property(c.files["config.properties"], "http-server.http.port")
}

func fixtureRequest(id string) Request {
	return Request{ID: id, Partition: "aws", AccountID: "123456789012", Region: "us-east-1", SQL: "SELECT 1", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, id) })}
}

func awaitExecution(t *testing.T, entered <-chan string) string {
	t.Helper()
	select {
	case handle := <-entered:
		return handle
	case <-time.After(5 * time.Second):
		t.Fatal("independent query did not enter native execution")
		return ""
	}
}

func TestDockerNetworkConcurrentIsolationAndCancellation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local namespace boundary is Linux-specific")
	}
	for _, local := range []bool{true, false} {
		t.Run(fmt.Sprintf("local=%t", local), func(t *testing.T) {
			f, d := newNetworkFixture(t, local)
			// Separate adapters already have independent admission gates. Exercise
			// concurrent exact ownership without changing per-adapter capacity.
			sibling, err := NewDocker(t.Context(), DockerConfig{Client: d.client, StateDirectory: filepath.Join(t.TempDir(), "athena"), CallbackListen: "127.0.0.1:0", CallbackHost: "127.0.0.1"})
			if err != nil {
				t.Fatal(err)
			}
			defer sibling.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			results := make(chan error, 2)
			var owners sync.Map
			for index, id := range []string{"same-query-id", "same-query-id"} {
				owner := []*Docker{d, sibling}[index]
				go func() {
					results <- owner.Execute(ctx, fixtureRequest(id), func(handle string) error {
						engine, _, _ := strings.Cut(handle, "/")
						owners.Store(engine, struct {
							runtime *Docker
							handle  string
						}{owner, handle})
						return nil
					}, func(Page) error { return nil })
				}()
			}
			first, second := awaitExecution(t, f.entered), awaitExecution(t, f.entered)
			if first == second {
				t.Fatal("concurrent queries share execution ownership")
			}
			f.mu.Lock()
			one, two := f.containers[first], f.containers[second]
			f.mu.Unlock()
			for _, c := range []*networkContainer{one, two} {
				if local {
					if c.config.HostConfig.NetworkMode != "host" || len(c.config.HostConfig.PortBindings) != 0 || len(c.config.ExposedPorts) != 0 {
						t.Fatal("local query config would create a veth or publish a port")
					}
					if property(c.files["node.properties"], "node.bind-ip") != "127.0.0.1" || property(c.files["config.properties"], "http-server.http.port") == "8080" {
						t.Fatal("local SQL does not use an allocated, actually loopback-bound endpoint")
					}
				} else if c.config.HostConfig.NetworkMode != "bridge" || c.config.HostConfig.PortBindings["8080/tcp"][0].HostIP != "127.0.0.1" || len(c.config.HostConfig.ExtraHosts) != 1 {
					t.Fatal("remote bridge publication/callback route changed")
				}
			}
			if local && f.nativePort(one) == f.nativePort(two) {
				t.Fatal("concurrent local endpoints collide")
			}
			checkCallbackCapabilities(t, one.catalogs["awsdatacatalog"], two.catalogs["awsdatacatalog"])
			owner, _ := owners.Load(first)
			target := owner.(struct {
				runtime *Docker
				handle  string
			})
			if err := target.runtime.Cancel(ctx, target.handle); err != nil {
				t.Fatal(err)
			}
			if err := <-results; !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled query result: %v", err)
			}
			f.mu.Lock()
			_, retained := f.containers[second]
			_, removed := f.containers[first]
			f.mu.Unlock()
			if !retained || removed {
				t.Fatal("cancellation did not preserve exact sibling ownership")
			}
			close(f.release)
			if err := <-results; err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			remaining := len(f.containers)
			f.mu.Unlock()
			if remaining != 1 {
				t.Fatalf("warm cleanup retained %d containers, want one idle sibling", remaining)
			}
		})
	}
}

func checkCallbackCapabilities(t *testing.T, first, second map[string]string) {
	t.Helper()
	endpoint := first["hive.metastore.glue.endpoint-url"]
	for _, test := range []struct {
		token  string
		status int
	}{
		{first["hive.metastore.glue.aws-access-key"], 200},
		{second["hive.metastore.glue.aws-access-key"], 403},
		{"", 403},
	} {
		req, err := http.NewRequest(http.MethodPost, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Amz-Target", "AWSGlue.GetDatabases")
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+test.token+"/scope")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("callback capability isolation: got %d, want %d", response.StatusCode, test.status)
		}
	}
}

func TestDockerNetworkWitnessErrorsAndExplicitCallbacks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local namespace boundary is Linux-specific")
	}
	f, d := newNetworkFixture(t, true)
	explicit, err := NewDocker(t.Context(), DockerConfig{Client: d.client, StateDirectory: filepath.Join(t.TempDir(), "athena"), CallbackListen: "0.0.0.0:0", CallbackHost: "172.17.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer explicit.Close()
	if explicit.callbackListen != "0.0.0.0:0" || explicit.callbackHost != "172.17.0.1" {
		t.Fatal("local network selection rewrote explicit callback routing")
	}
	f.probeError = true
	if _, err := NewDocker(t.Context(), DockerConfig{Client: d.client, StateDirectory: filepath.Join(t.TempDir(), "athena")}); err == nil {
		t.Fatal("helper failure silently selected bridge networking")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := localNetwork(ctx, d.client, DockerImage); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled witness did not propagate cancellation: %v", err)
	}
}

func TestDockerNetworkRejectsForeignWorker(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local namespace boundary is Linux-specific")
	}
	f, d := newNetworkFixture(t, true)
	f.wrongNode = true
	err := d.Execute(t.Context(), fixtureRequest("foreign"), func(string) error { return nil }, func(Page) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "unexpected native worker") {
		t.Fatalf("foreign endpoint identity accepted: %v", err)
	}
	select {
	case <-f.entered:
		t.Fatal("customer SQL reached a foreign worker")
	default:
	}
}

func TestDockerNetworkCanceledCreateAndRecovery(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local namespace boundary is Linux-specific")
	}
	f, d := newNetworkFixture(t, true)
	f.createEntered, f.createRelease = make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		result <- d.Execute(ctx, fixtureRequest("late-create"), func(string) error { return nil }, func(Page) error { return nil })
	}()
	select {
	case <-f.createEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("native create did not arrive")
	}
	cancel()
	close(f.createRelease)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("late-create cancellation: %v", err)
	}
	f.mu.Lock()
	remaining := len(f.containers)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatal("late accepted create escaped cleanup")
	}
	handle := "stackd-athena-" + strings.Repeat("a", 64)
	foreign := "stackd-athena-" + strings.Repeat("b", 64)
	owned := d.containerConfig(handle, nil)
	other := d.containerConfig(foreign, nil)
	other.Labels["stackd.athena.execution"] = "foreign"
	f.mu.Lock()
	f.containers[handle] = &networkContainer{config: owned}
	f.containers[foreign] = &networkContainer{config: other}
	f.mu.Unlock()
	if err := d.Cancel(t.Context(), handle); err != nil {
		t.Fatalf("persisted handle recovery: %v", err)
	}
	if err := d.Cancel(t.Context(), foreign); err == nil {
		t.Fatal("recovery removed a foreign container")
	}
	f.mu.Lock()
	_, kept := f.containers[foreign]
	f.mu.Unlock()
	if !kept {
		t.Fatal("foreign container lost")
	}
}

func TestDockerNetworkKeepsSerialAdmission(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local namespace boundary is Linux-specific")
	}
	f, d := newNetworkFixture(t, true)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	first := make(chan error, 1)
	var execution string
	go func() {
		first <- d.Execute(ctx, fixtureRequest("admitted"), func(handle string) error { execution = handle; return nil }, func(Page) error { return nil })
	}()
	awaitExecution(t, f.entered)
	queued, stop := context.WithCancel(ctx)
	stop()
	if err := d.Execute(queued, fixtureRequest("queued"), func(string) error {
		t.Error("canceled queued query acquired native execution ownership")
		return nil
	}, func(Page) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation: %v", err)
	}
	if err := d.Cancel(ctx, execution); err != nil {
		t.Fatal(err)
	}
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("admitted cancellation: %v", err)
	}
}

// Run with: go run ./scripts/lambda_storage_smoke -telemetry bin/lambda-telemetry-amd64
// Requires the pinned Lambda Python and Ubuntu storage images already installed
// on a rootful Linux Docker daemon with privileged helpers, loop devices, ext4,
// and at least 12 GiB available. The client itself needs only Docker API access.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	"stackd/compute/lambda"
)

var host = flag.String("docker-host", "unix:///var/run/docker.sock", "Docker Engine endpoint")
var telemetry = flag.String("telemetry", "bin/lambda-telemetry-amd64", "installed telemetry helper")
var child = flag.String("child", "", "internal child namespace")

const handler = `import os, errno, json

def handle(event, context):
    op = event.get('op')
    if op == 'exit':
        os._exit(42)
    if op == 'stat':
        s = os.statvfs('/tmp')
        return {'available': s.f_bavail * s.f_frsize, 'total': s.f_blocks * s.f_frsize}
    if op == 'fill':
        count = 0
        chunk = b'x' * (1024 * 1024)
        try:
            with open('/tmp/fill', 'wb', buffering=0) as f:
                while count < 600 * 1024 * 1024:
                    count += f.write(chunk)
            raise RuntimeError('disk limit was not enforced')
        except OSError as e:
            if e.errno != errno.ENOSPC:
                raise
        # Reclaimable file cache must not pin the function memory budget.
        allocation = bytearray(64 * 1024 * 1024)
        for i in range(0, len(allocation), 4096): allocation[i] = 1
        os.remove('/tmp/fill')
        with open('/tmp/warm', 'w') as f: f.write('retained')
        return {'written': count, 'allocation': len(allocation), 'memory_limit': int(open('/sys/fs/cgroup/memory.max').read())}
    if op == 'read':
        return {'warm': open('/tmp/warm').read()}
    return {'alive': True}
`

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func configuration(engine *docker.Client, namespace string) lambda.DockerConfig {
	path, err := filepath.Abs(*telemetry)
	must(err)
	return lambda.DockerConfig{Client: engine, Namespace: namespace, StartupTimeout: 60 * time.Second, TelemetryHelpers: map[string]string{"x86_64": path}}
}

func spec(size int) lambda.Specification {
	var code bytes.Buffer
	z := zip.NewWriter(&code)
	w, err := z.Create("handler.py")
	must(err)
	_, err = io.WriteString(w, handler)
	must(err)
	must(z.Close())
	return lambda.Specification{FunctionARN: "arn:aws:lambda:us-east-1:123456789012:function:storage-smoke", FunctionName: "storage-smoke", Runtime: "python3.12", Architecture: "x86_64", Handler: "handler.handle", Code: code.Bytes(), Timeout: 30 * time.Second, MemoryMB: 128, EphemeralMB: size, Credentials: lambda.Credentials{AccessKeyID: "storage-smoke", SecretAccessKey: "storage-smoke", SessionToken: "storage-smoke"}}
}

func invoke(ctx context.Context, e lambda.Environment, operation string) (lambda.Result, lambda.Report) {
	var result lambda.Result
	report, err := e.Invoke(ctx, lambda.Invocation{RequestID: rand.Text(), FunctionARN: spec(512).FunctionARN, Payload: []byte(fmt.Sprintf(`{"op":%q}`, operation))}, func(value lambda.Result) { result = value })
	must(err)
	if operation != "exit" && (result.FunctionError != "" || report.Status != lambda.InvocationSuccess) {
		panic(fmt.Sprintf("invoke failed: %+v %s", report, result.Payload))
	}
	return result, report
}

func filter(namespace, kind string) string {
	data, _ := json.Marshal(map[string][]string{"label": {"io.stackd.lambda.instance=" + namespace, "io.stackd.kind=" + kind}})
	return url.QueryEscape(string(data))
}

func inventory(ctx context.Context, engine *docker.Client, namespace string) (containers, volumes int) {
	var c []json.RawMessage
	var v struct{ Volumes []json.RawMessage }
	must(engine.JSON(ctx, "GET", "/containers/json?all=true&filters="+filter(namespace, "lambda-runtime"), nil, &c))
	must(engine.JSON(ctx, "GET", "/volumes?filters="+filter(namespace, "lambda-runtime"), nil, &v))
	return len(c), len(v.Volumes)
}

func assertEmpty(ctx context.Context, engine *docker.Client, namespace string) {
	c, v := inventory(ctx, engine, namespace)
	if c != 0 || v != 0 {
		panic(fmt.Sprintf("owned resources remain: containers=%d volumes=%d", c, v))
	}
}

func loopInventory(ctx context.Context, engine *docker.Client) map[string]string {
	output, err := docker.RunHelper(ctx, engine, "lambda-smoke-loops", docker.ContainerConfig{Image: lambda.StorageImage, Entrypoint: []string{"/usr/sbin/losetup"}, Cmd: []string{"--list", "--noheadings", "--raw", "--output", "NAME,BACK-INO,BACK-MAJ:MIN"}, HostConfig: docker.ContainerHostConfig{Privileged: true, NetworkMode: "none", LogConfig: docker.ContainerLogConfig{Type: "json-file"}}})
	must(err)
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 {
			result[fields[0]] = fields[1] + " " + fields[2]
		}
	}
	return result
}

func ownedLoops(ctx context.Context, engine *docker.Client, namespace string) map[string]string {
	var volumes struct {
		Volumes []struct{ Options map[string]string }
	}
	must(engine.JSON(ctx, "GET", "/volumes?filters="+filter(namespace, "lambda-runtime"), nil, &volumes))
	native := loopInventory(ctx, engine)
	result := make(map[string]string)
	for _, volume := range volumes.Volumes {
		if device := volume.Options["device"]; device != "" {
			signature, ok := native[device]
			if !ok {
				panic("owned loop missing: " + device)
			}
			result[device] = signature
		}
	}
	if len(result) == 0 {
		panic("fixture has no owned loop device")
	}
	return result
}

func assertLoopsRemoved(ctx context.Context, engine *docker.Client, previous map[string]string) {
	current := loopInventory(ctx, engine)
	for device, signature := range previous {
		if current[device] == signature {
			panic("owned loop survived cleanup: " + device)
		}
	}
}

func waitOwnerExit(ctx context.Context, engine *docker.Client, namespace string) {
	var c []struct {
		ID string `json:"Id"`
	}
	must(engine.JSON(ctx, "GET", "/containers/json?all=true&filters="+filter(namespace, "lambda-owner"), nil, &c))
	for _, item := range c {
		must(engine.JSON(ctx, "POST", "/containers/"+item.ID+"/wait?condition=not-running", nil, nil))
	}
}

func startChild(namespace, endpoint string) (*exec.Cmd, *bufio.Reader) {
	cmd := exec.Command(os.Args[0], "-child", namespace, "-docker-host", endpoint, "-telemetry", *telemetry)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	must(err)
	must(cmd.Start())
	return cmd, bufio.NewReader(stdout)
}

// The proxy retains one real create request across controller death. Releasing
// it after startup recovery deterministically exposes the same native effects
// as an Engine create completing late, including implicit volume recreation.
func prepareBarrier(engine *docker.Client) (string, <-chan struct{}, func() (string, error), func()) {
	u, err := url.Parse(*host)
	must(err)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if u.Scheme == "unix" {
		socket := u.Path
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}
		u, _ = url.Parse("http://docker")
	} else if u.Scheme == "tcp" {
		u.Scheme = "http"
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = transport
	reached := make(chan struct{})
	release := make(chan struct{})
	completed := make(chan error, 1)
	lifetime, cancel := context.WithCancel(context.Background())
	controller := ""
	var once sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/containers/create") && strings.HasSuffix(r.URL.Query().Get("name"), "-code") {
			body, err := io.ReadAll(r.Body)
			var config docker.ContainerConfig
			if err == nil {
				err = json.Unmarshal(body, &config)
			}
			controller = config.Labels["io.stackd.lambda.controller"]
			if err != nil {
				completed <- err
				once.Do(func() { close(reached) })
				return
			}
			once.Do(func() { close(reached) })
			select {
			case <-release:
			case <-lifetime.Done():
				return
			}
			ctx, stop := context.WithTimeout(lifetime, 30*time.Second)
			defer stop()
			response, err := engine.Request(ctx, r.Method, strings.TrimPrefix(r.URL.RequestURI(), "/v1.41"), bytes.NewReader(body), "application/json")
			if err == nil {
				response.Body.Close()
			}
			completed <- err
			return
		}
		proxy.ServeHTTP(w, r)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	go server.Serve(listener)
	return "http://" + listener.Addr().String(), reached, func() (string, error) { close(release); return controller, <-completed }, func() { cancel(); server.Close(); transport.CloseIdleConnections() }
}

func waitOlderControllerGone(ctx context.Context, engine *docker.Client, namespace, controller string) {
	data, _ := json.Marshal(map[string][]string{"label": {"io.stackd.lambda.instance=" + namespace, "io.stackd.kind=lambda-runtime", "io.stackd.lambda.controller=" + controller}})
	query := url.QueryEscape(string(data))
	deadline, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	observed := false
	for {
		var containers []json.RawMessage
		var volumes struct{ Volumes []json.RawMessage }
		must(engine.JSON(deadline, "GET", "/containers/json?all=true&filters="+query, nil, &containers))
		must(engine.JSON(deadline, "GET", "/volumes?filters="+query, nil, &volumes))
		if len(containers) == 0 && len(volumes.Volumes) == 0 {
			if !observed {
				panic("late-create fixture never reached native Docker")
			}
			return
		}
		observed = true
		select {
		case <-ticker.C:
		case <-deadline.Done():
			panic("late-create resources survived recovery")
		}
	}
}

func main() {
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	engine, err := docker.New(ctx, docker.Config{Host: *host})
	must(err)
	defer engine.Close()
	if *child != "" {
		d, err := lambda.NewDockerExecutor(ctx, configuration(engine, *child))
		must(err)
		_, err = d.Prepare(ctx, spec(512))
		must(err)
		fmt.Println("prepared")
		<-ctx.Done()
		return
	}
	namespace := "storage-smoke-" + rand.Text()
	other, err := lambda.NewDockerExecutor(ctx, configuration(engine, namespace+"-other"))
	must(err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		must(other.Close(cleanup))
	}()
	otherEnvironment, err := other.Prepare(ctx, spec(512))
	must(err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		must(otherEnvironment.Close(cleanup))
	}()
	d, err := lambda.NewDockerExecutor(ctx, configuration(engine, namespace))
	must(err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		must(d.Close(cleanup))
	}()
	if duplicate, err := lambda.NewDockerExecutor(ctx, configuration(engine, namespace)); err == nil {
		duplicate.Close(ctx)
		panic("same-instance controller acquired live owner's flock")
	}
	e, err := d.Prepare(ctx, spec(512))
	must(err)
	result, _ := invoke(ctx, e, "fill")
	var details map[string]int
	must(json.Unmarshal(result.Payload, &details))
	if details["written"] < 512<<20 || details["written"] > 514<<20 || details["allocation"] != 64<<20 || details["memory_limit"] != 128<<20 {
		panic(string(result.Payload))
	}
	fmt.Printf("disk-full under 128MiB runtime: %s\n", result.Payload)
	for _, phase := range []string{"warm", "reset"} {
		if phase == "reset" {
			_, report := invoke(ctx, e, "exit")
			if report.Status != lambda.InvocationFailure {
				panic("runtime exit did not fail")
			}
		}
		result, _ = invoke(ctx, e, "read")
		var read struct{ Warm string }
		must(json.Unmarshal(result.Payload, &read))
		if read.Warm != "retained" {
			panic(string(result.Payload))
		}
		fmt.Println(phase + " contents retained")
	}
	loops := ownedLoops(ctx, engine, namespace)
	must(e.Close(ctx))
	assertEmpty(ctx, engine, namespace)
	assertLoopsRemoved(ctx, engine, loops)
	large, err := d.Prepare(ctx, spec(10240))
	must(err)
	result, _ = invoke(ctx, large, "stat")
	must(json.Unmarshal(result.Payload, &details))
	if details["available"] < 10240<<20 || details["available"] > 10242<<20 {
		panic(string(result.Payload))
	}
	fmt.Printf("10GiB usable filesystem boundary: %s\n", result.Payload)
	loops = ownedLoops(ctx, engine, namespace)
	must(large.Close(ctx))
	must(d.Close(ctx))
	assertEmpty(ctx, engine, namespace)
	assertLoopsRemoved(ctx, engine, loops)
	fmt.Println("normal cleanup removed owned containers, volumes and loop devices")
	for _, mid := range []bool{false, true} {
		endpoint := *host
		var reached <-chan struct{}
		var releaseLate func() (string, error)
		closeProxy := func() {}
		if mid {
			endpoint, reached, releaseLate, closeProxy = prepareBarrier(engine)
		}
		cmd, stdout := startChild(namespace, endpoint)
		func() {
			defer closeProxy()
			defer func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			if mid {
				select {
				case <-reached:
				case <-ctx.Done():
					panic(ctx.Err())
				}
			} else {
				line, err := stdout.ReadString('\n')
				must(err)
				if line != "prepared\n" {
					panic(line)
				}
			}
			c, v := inventory(ctx, engine, namespace)
			if v == 0 || (!mid && c == 0) {
				panic("crash fixture has no native resources")
			}
			loops := ownedLoops(ctx, engine, namespace)
			must(cmd.Process.Kill())
			err := cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				panic(err)
			}
			waitOwnerExit(ctx, engine, namespace)
			d, err = lambda.NewDockerExecutor(ctx, configuration(engine, namespace))
			must(err)
			assertEmpty(ctx, engine, namespace)
			assertLoopsRemoved(ctx, engine, loops)
			if mid {
				successor, err := d.Prepare(ctx, spec(512))
				must(err)
				older, err := releaseLate()
				must(err)
				waitOlderControllerGone(ctx, engine, namespace, older)
				result, _ := invoke(ctx, successor, "alive")
				var alive struct{ Alive bool }
				must(json.Unmarshal(result.Payload, &alive))
				if !alive.Alive {
					panic(string(result.Payload))
				}
				must(successor.Close(ctx))
				assertEmpty(ctx, engine, namespace)
				fmt.Println("accepted create replayed after startup: stale container and implicitly recreated volumes reclaimed; current generation alive")
			}
			result, _ := invoke(ctx, otherEnvironment, "alive")
			var alive struct{ Alive bool }
			must(json.Unmarshal(result.Payload, &alive))
			if !alive.Alive {
				panic(string(result.Payload))
			}
			must(d.Close(ctx))
			fmt.Printf("controller SIGKILL recovery (mid-prepare=%t): containers, volumes and loops removed; other instance alive\n", mid)
		}()
	}
	must(otherEnvironment.Close(ctx))
	must(other.Close(ctx))
	// With no concurrent owner handoff, native references are gone and even
	// ephemeral instance lock infrastructure must be reclaimed by Close.
	for _, n := range []string{namespace, namespace + "-other"} {
		var volumes struct{ Volumes []struct{ Name string } }
		must(engine.JSON(ctx, "GET", "/volumes?filters="+filter(n, "lambda-owner"), nil, &volumes))
		if len(volumes.Volumes) != 0 {
			panic("owner-lock volume survived normal Close")
		}
	}
	fmt.Println("unreferenced namespace owner-lock volumes reclaimed")
}

package stackd_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"stackd/compute/docker"
	computelambda "stackd/compute/lambda"
)

// This is deliberately a real-process regression, not an assertion about queue
// fields or synthetic memory counters. PID 1 RSS and cgroup consumption are read
// by the customer handler, and an actual HTTP extension blocks/releases delivery.
func TestLambdaRuntimeMemoryDocker(t *testing.T) {
	if os.Getenv("STACKD_LAMBDA_DOCKER") != "1" {
		t.Skip("requires official runtime containers and prebuilt telemetry helper")
	}
	architecture := "x86_64"
	if os.Getenv("STACKD_LAMBDA_MEMORY_ARCH") == "arm64" {
		architecture = "arm64"
	}
	engine, err := docker.New(t.Context(), docker.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	executor, err := computelambda.NewDockerExecutor(t.Context(), computelambda.DockerConfig{Client: engine, Namespace: "lambda-memory-test-" + rand.Text(), TelemetryHelpers: lambdaTelemetryHelpers(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := executor.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	shutdowns := make(chan string, 8)
	observer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Reason string }
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		shutdowns <- body.Reason
		w.WriteHeader(204)
	})}
	go observer.Serve(listener)
	defer observer.Close()
	callback := "http://host.docker.internal:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	type observation struct {
		Boot, Marker, Extension, Cgroup, HelperCgroup string
		HelperRSS, Memory, MemoryLimit                int64
		ChildAlive                                    bool
		Delivered, Dropped                            int
	}
	const maxBytes = 1048576
	name := fmt.Sprintf("runtime-memory-%d-%d", time.Now().UnixNano(), maxBytes)
	arn := "arn:aws:lambda:us-east-1:111111111111:function:" + name
	environment, err := executor.Prepare(t.Context(), computelambda.Specification{
		FunctionARN: arn, FunctionName: name, Runtime: "python3.12", Handler: "handler.handler", Architecture: architecture,
		Code:      lambdaZIP(t, map[string]string{"handler.py": lambdaRuntimeMemoryHandler}),
		Layers:    [][]byte{lambdaZIP(t, map[string]string{"extensions/memory": "#!/bin/bash\nexec /var/lang/bin/python3 /opt/memory.py\n", "memory.py": lambdaRuntimeMemoryExtension}, "extensions/memory")},
		Variables: map[string]string{"BUFFER_BYTES": strconv.Itoa(maxBytes), "SHUTDOWN_OBSERVER": callback},
		Timeout:   30 * time.Second, MemoryMB: 512, EphemeralMB: 512,
		Credentials: computelambda.Credentials{AccessKeyID: "local", SecretAccessKey: "local", SessionToken: "local"},
	})
	if environment != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := environment.Close(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	sequence := 0
	invoke := func(action string, success bool) observation {
		t.Helper()
		sequence++
		var result computelambda.Result
		report, err := environment.Invoke(t.Context(), computelambda.Invocation{RequestID: fmt.Sprintf("memory-%d", sequence), Payload: []byte(fmt.Sprintf(`{"action":%q}`, action))}, func(value computelambda.Result) { result = value })
		if err != nil {
			t.Fatal(err)
		}
		if !success {
			if result.FunctionError == "" || report.Status != computelambda.InvocationFailure {
				t.Fatalf("crash did not fail invocation: %+v %+v", result, report)
			}
			return observation{}
		}
		if result.FunctionError != "" || report.Status != computelambda.InvocationSuccess {
			t.Fatalf("%s: %+v %s", action, report, result.Payload)
		}
		var value observation
		if err := json.Unmarshal(result.Payload, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	cold := invoke("state", true)
	if cold.Cgroup != cold.HelperCgroup || cold.MemoryLimit != 512<<20 {
		t.Fatalf("runtime and actual buffer owner do not share the enforced execution budget: %+v", cold)
	}
	warm := invoke("state", true)
	if cold.Boot != warm.Boot || cold.Marker != warm.Marker || cold.Extension != warm.Extension {
		t.Fatal("ordinary invocation did not reuse warm runtime and /tmp")
	}
	pressure := invoke("pressure", true)
	if pressure.Memory <= cold.Memory || pressure.HelperRSS <= cold.HelperRSS {
		t.Fatalf("actual buffered data did not increase environment/PID1 memory: before=%+v after=%+v", cold, pressure)
	}
	invoke("crash", false)
	reset := invoke("state", true)
	if reset.Boot == cold.Boot || reset.Extension == cold.Extension || reset.Marker != cold.Marker || reset.ChildAlive {
		t.Fatalf("reset failed process replacement, descendant termination or /tmp retention: cold=%+v reset=%+v", cold, reset)
	}
	if reset.Cgroup != reset.HelperCgroup || reset.MemoryLimit != 512<<20 {
		t.Fatalf("reset escaped the shared execution budget: %+v", reset)
	}
	released := invoke("release", true)
	if released.Delivered == 0 || released.Dropped == 0 {
		t.Fatalf("retained pressure records/drop signal did not reach restarted extension: %+v", released)
	}
	if err := environment.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"failure", "spindown"} {
		select {
		case got := <-shutdowns:
			if got != reason {
				t.Fatalf("shutdown reason %q, want %q", got, reason)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("missing actual %s extension shutdown", reason)
		}
	}
	filter, _ := json.Marshal(map[string][]string{"label": {"io.stackd.function=" + arn}})
	var containers []struct{ ID string }
	if err := engine.JSON(t.Context(), "GET", "/containers/json?all=true&filters="+url.QueryEscape(string(filter)), nil, &containers); err != nil {
		t.Fatal(err)
	}
	var volumes struct{ Volumes []struct{ Name string } }
	if err := engine.JSON(t.Context(), "GET", "/volumes?filters="+url.QueryEscape(string(filter)), nil, &volumes); err != nil {
		t.Fatal(err)
	}
	if len(containers) != 0 || len(volumes.Volumes) != 0 {
		t.Fatalf("owned runtime cleanup incomplete: containers=%+v volumes=%+v", containers, volumes.Volumes)
	}
}

const lambdaRuntimeMemoryHandler = `import json, os, pathlib, subprocess, time, urllib.request, uuid
boot = str(uuid.uuid4())
marker = pathlib.Path('/tmp/marker')
if not marker.exists(): marker.write_text(str(uuid.uuid4()))
def state():
    with urllib.request.urlopen('http://127.0.0.1:8123/state') as response: value = json.load(response)
    value.update(Boot=boot, Marker=marker.read_text(), Cgroup=pathlib.Path('/proc/self/cgroup').read_text())
    value['HelperRSS'] = int(next(line.split()[1] for line in pathlib.Path('/proc/1/status').read_text().splitlines() if line.startswith('VmRSS:'))) * 1024
    value['Memory'] = int(pathlib.Path('/sys/fs/cgroup/memory.current').read_text())
    value['MemoryLimit'] = int(pathlib.Path('/sys/fs/cgroup/memory.max').read_text())
    value['HelperCgroup'] = pathlib.Path('/proc/1/cgroup').read_text()
    value['ChildAlive'] = False
    child = pathlib.Path('/tmp/child')
    if child.exists(): value['ChildAlive'] = pathlib.Path('/proc/'+child.read_text().strip()).exists()
    return value
def handler(event, context):
    action = event['action']
    if action == 'pressure':
        for index in range(1600): print('PRESSURE-%04d-' % index + 'x'*4096, flush=True)
        time.sleep(1)
    if action == 'crash':
        child = subprocess.Popen(['/var/lang/bin/python3', '-c', 'import time; time.sleep(600)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        pathlib.Path('/tmp/child').write_text(str(child.pid))
        os._exit(17)
    if action == 'release':
        pathlib.Path('/tmp/blocked').unlink(missing_ok=True)
        deadline = time.monotonic()+20
        while time.monotonic()<deadline:
            value = state()
            if value['Delivered'] and value['Dropped']: return value
            time.sleep(.05)
        raise RuntimeError('retained telemetry did not drain after reset')
    return state()
`

const lambdaRuntimeMemoryExtension = `import http.server, json, os, pathlib, threading, urllib.request, uuid
boot = str(uuid.uuid4())
blocked = pathlib.Path('/tmp/blocked')
if not pathlib.Path('/tmp/extension-started').exists():
    blocked.touch()
    pathlib.Path('/tmp/extension-started').touch()
state = {'Extension': boot, 'Delivered': 0, 'Dropped': 0}
class Listener(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        body=json.dumps(state).encode(); self.send_response(200); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        data=self.rfile.read(int(self.headers['Content-Length']))
        if blocked.exists(): self.send_response(503); self.end_headers(); return
        for event in json.loads(data):
            if event['type']=='function' and 'PRESSURE-' in event['record']: state['Delivered'] += 1
            if event['type']=='platform.logsDropped': state['Dropped'] += event['record']['droppedRecords']
        self.send_response(200); self.end_headers()
server=http.server.ThreadingHTTPServer(('0.0.0.0',8123),Listener)
threading.Thread(target=server.serve_forever,daemon=True).start()
base='http://'+os.environ['AWS_LAMBDA_RUNTIME_API']
def call(path, body=None, headers=None, method=None):
    request=urllib.request.Request(base+path, data=None if body is None else json.dumps(body).encode(), headers=headers or {}, method=method)
    return urllib.request.urlopen(request)
with call('/2020-01-01/extension/register', {'events':['INVOKE','SHUTDOWN']}, {'Lambda-Extension-Name':'memory'}) as response: identifier=response.headers['Lambda-Extension-Identifier']
headers={'Lambda-Extension-Identifier':identifier}
for index in range(16):
    with call('/2022-07-01/telemetry', {'schemaVersion':'2022-12-13','types':['function','platform'],'buffering':{'maxBytes':int(os.environ['BUFFER_BYTES']),'maxItems':10000,'timeoutMs':30000},'destination':{'protocol':'HTTP','URI':'http://sandbox.localdomain:8123/buffer-'+str(index)}}, headers, 'PUT') as response: response.read()
while True:
    with call('/2020-01-01/extension/event/next', headers=headers) as response: event=json.load(response)
    if event['eventType']=='SHUTDOWN':
        request=urllib.request.Request(os.environ['SHUTDOWN_OBSERVER'], data=json.dumps({'Reason':event['shutdownReason']}).encode())
        with urllib.request.urlopen(request) as response: response.read()
        break
`

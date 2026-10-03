package glue

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Credentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}
type CredentialProvider func(context.Context) (Credentials, error)
type credentialCallback struct {
	server         *http.Server
	address, token string
	provider       CredentialProvider
	mu             sync.RWMutex
}
type credentialCallbacks struct {
	mu        sync.Mutex
	callbacks map[string]*credentialCallback
}

// SetCredentials rebinds the same retained host port after controller restart.
// It never restarts an execution to repair missing credentials, and the only
// issuer is the service's current IAM/STS authority behind provider.
func (r *DockerRuntime) SetCredentials(ctx context.Context, key string, provider CredentialProvider) error {
	if provider == nil {
		return errors.New("glue credential provider is required")
	}
	r.credentials.mu.Lock()
	defer r.credentials.mu.Unlock()
	if existing := r.credentials.callbacks[key]; existing != nil {
		existing.mu.Lock()
		existing.provider = provider
		existing.mu.Unlock()
		return nil
	}
	var native struct {
		Config struct {
			Labels map[string]string
			Env    []string
		}
	}
	err := r.config.Client.JSON(ctx, http.MethodGet, containerPath(key)+"/json", nil, &native)
	if err != nil && !missing(err) {
		return err
	}
	address, token := "0.0.0.0:0", rand.Text()
	if err == nil {
		if native.Config.Labels["stackd.glue.run"] != key {
			return errors.New("glue credential container ownership mismatch")
		}
		address = native.Config.Labels["stackd.glue.credentials.address"]
		token = ""
		for _, entry := range native.Config.Env {
			if value, ok := strings.CutPrefix(entry, "AWS_CONTAINER_AUTHORIZATION_TOKEN="); ok {
				token = value
			}
		}
		if address == "" || token == "" {
			return errors.New("retained Glue execution has no credential callback metadata")
		}
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", address)
	if err != nil {
		return err
	}
	callback := &credentialCallback{address: listener.Addr().String(), token: token, provider: provider}
	callback.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/credentials" || subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte(callback.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		callback.mu.RLock()
		get := callback.provider
		callback.mu.RUnlock()
		value, err := get(request.Context())
		if err != nil {
			http.Error(w, "current Glue execution-role assumption rejected", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	})}
	if r.credentials.callbacks == nil {
		r.credentials.callbacks = map[string]*credentialCallback{}
	}
	r.credentials.callbacks[key] = callback
	go func() { _ = callback.server.Serve(listener) }()
	return nil
}
func (r *DockerRuntime) credentialEnvironment(key string) ([]string, map[string]string, error) {
	r.credentials.mu.Lock()
	defer r.credentials.mu.Unlock()
	c := r.credentials.callbacks[key]
	if c == nil {
		return nil, nil, errors.New("glue credential callback is not configured")
	}
	_, port, err := net.SplitHostPort(c.address)
	if err != nil {
		return nil, nil, err
	}
	return []string{"AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:48888/credentials", "AWS_CONTAINER_AUTHORIZATION_TOKEN=" + c.token, "STACKD_GLUE_CREDENTIAL_CALLBACK=http://host.docker.internal:" + port + "/credentials"}, map[string]string{"stackd.glue.run": key, "stackd.glue.credentials.address": c.address}, nil
}
func (r *DockerRuntime) closeCredentials(key string) error {
	r.credentials.mu.Lock()
	c := r.credentials.callbacks[key]
	delete(r.credentials.callbacks, key)
	r.credentials.mu.Unlock()
	if c != nil {
		return c.server.Close()
	}
	return nil
}

// Close releases controller-owned callbacks without killing retained executions.
func (r *DockerRuntime) Close() error {
	r.credentials.mu.Lock()
	all := r.credentials.callbacks
	r.credentials.callbacks = nil
	r.credentials.mu.Unlock()
	var err error
	for _, c := range all {
		err = errors.Join(err, c.server.Close())
	}
	return err
}

// The SDK credential endpoint is loopback-only. The bootstrap is not a second
// issuer: it forwards authenticated refreshes to the shared IAM/STS owner.
const bootstrapScript = `import http.server, os, subprocess, sys, threading, urllib.request
class Credentials(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/credentials':
            self.send_error(404); return
        if self.headers.get('Authorization') != os.environ['AWS_CONTAINER_AUTHORIZATION_TOKEN']:
            self.send_error(403); return
        try:
            request=urllib.request.Request(os.environ['STACKD_GLUE_CREDENTIAL_CALLBACK'],headers={'Authorization':self.headers['Authorization']})
            with urllib.request.urlopen(request,timeout=20) as response:
                body=response.read()
            self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(body)
        except Exception:
            self.send_error(403,'Glue credential refresh rejected')
    def log_message(self,*args): pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',48888),Credentials)
threading.Thread(target=server.serve_forever,daemon=True).start()
if os.environ.get('STACKD_GLUE_PROFILE') == '1':
    os.environ['PYTHONPATH'] = '/tmp/stackd-profiling:' + os.environ.get('PYTHONPATH', '')
try:
    sys.exit(subprocess.call(sys.argv[1:]))
finally:
    server.shutdown()
`

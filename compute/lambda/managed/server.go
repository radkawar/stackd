package managed

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	runtime "stackd/compute/lambda"
)

// AgentConfig is installed inside the selected AMI by its official SSM agent.
// No ambient host AWS credentials or host Docker socket are forwarded to a guest.
type AgentConfig struct {
	Identity                                                                   Identity
	ListenAddress, CertificateFile, PrivateKeyFile, StateDirectory, DockerHost string
	Images                                                                     []Image
}
type Image struct{ Runtime, Architecture, Reference string }
type Server struct {
	config       AgentConfig
	engine       *docker.Client
	network      string
	mu           sync.Mutex
	environments map[string]*environment
}

var environmentID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func NewServer(ctx context.Context, config AgentConfig) (*Server, error) {
	if config.Identity.ProviderARN == "" || config.Identity.Generation == "" || len(config.Identity.Token) < 32 {
		return nil, errors.New("managed guest identity is incomplete")
	}
	if !filepath.IsAbs(config.StateDirectory) {
		return nil, errors.New("managed guest state directory must be absolute")
	}
	if len(config.Images) == 0 {
		return nil, errors.New("managed guest requires explicitly installed immutable runtime images")
	}
	for _, image := range config.Images {
		if !strings.Contains(image.Reference, "@sha256:") {
			return nil, errors.New("managed guest image must be pinned by digest")
		}
	}
	if err := os.MkdirAll(config.StateDirectory, 0700); err != nil {
		return nil, err
	}
	engine, err := docker.New(ctx, docker.Config{Host: config.DockerHost})
	if err != nil {
		return nil, err
	}
	s := &Server{config: config, engine: engine, environments: map[string]*environment{}}
	if err = s.ensureNetwork(ctx); err != nil {
		engine.Close()
		return nil, err
	}
	// The guest owns native resources independently of the controller. A restarted
	// agent rebuilds Runtime API listeners from its retained deployment manifests;
	// a controller restart does not enter this path or disturb running containers.
	entries, err := os.ReadDir(config.StateDirectory)
	if err != nil {
		engine.Close()
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !environmentID.MatchString(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(config.StateDirectory, entry.Name(), "deployment.json"))
		if err != nil {
			engine.Close()
			return nil, err
		}
		var retained retainedDeployment
		if err = json.Unmarshal(data, &retained); err != nil {
			engine.Close()
			return nil, err
		}
		if retained.ProviderARN != config.Identity.ProviderARN || retained.Generation != config.Identity.Generation || retained.Deployment.ID != entry.Name() {
			engine.Close()
			return nil, errors.New("managed guest deployment ownership mismatch")
		}
		if err = s.removeContainer(ctx, entry.Name()); err != nil {
			engine.Close()
			return nil, err
		}
		if _, err = s.prepare(ctx, retained.Deployment); err != nil {
			slog.Error("Retained Lambda guest environment failed to recover", "environment", entry.Name(), "error", err)
		}
	}
	return s, nil
}

type retainedDeployment struct {
	ProviderARN, Generation string
	Deployment              Deployment
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.config.Identity.Token)) != 1 || r.Header.Get("X-Stackd-Capacity-Provider") != s.config.Identity.ProviderARN || r.Header.Get("X-Stackd-Guest-Generation") != s.config.Identity.Generation {
		http.Error(w, "Guest source identity rejected", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/ready" {
		if err := s.engine.JSON(r.Context(), http.MethodGet, "/_ping", nil, nil); err != nil {
			guestError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/environments/")
	if rest == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	if !environmentID.MatchString(parts[0]) || len(parts) > 2 {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	if r.Method == http.MethodPut && len(parts) == 1 {
		var d Deployment
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 360<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&d); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if d.ID != id {
			http.Error(w, "Deployment identity mismatch", 400)
			return
		}
		e, err := s.prepare(r.Context(), d)
		if err == nil {
			err = e.waitReady(r.Context())
		}
		if err != nil {
			guestError(w, err)
			return
		}
		out, err := e.observation(r.Context())
		if err != nil {
			guestError(w, err)
			return
		}
		guestJSON(w, out)
		return
	}
	s.mu.Lock()
	e := s.environments[id]
	s.mu.Unlock()
	if e == nil {
		if r.Method == http.MethodDelete && len(parts) == 1 {
			s.mu.Lock()
			err := s.removeRetained(r.Context(), id)
			s.mu.Unlock()
			if err != nil {
				guestError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "Execution environment does not exist", 404)
		return
	}
	switch {
	case r.Method == http.MethodPut && len(parts) == 2 && parts[1] == "credentials":
		var credentials runtime.Credentials
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&credentials); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := e.updateCredentials(credentials); err != nil {
			guestError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "logs":
		batch, err := e.readLogs()
		if err != nil {
			guestError(w, err)
			return
		}
		guestJSON(w, batch)
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "logs":
		var request struct{ Offset int64 }
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if e.logs == nil {
			http.Error(w, "Runtime output is not initialized", http.StatusConflict)
			return
		}
		if err := e.logs.acknowledge(request.Offset); err != nil {
			guestError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && len(parts) == 1:
		out, err := e.observation(r.Context())
		if err != nil {
			guestError(w, err)
			return
		}
		guestJSON(w, out)
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "invocations":
		var in Invocation
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 9<<20)).Decode(&in); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if in.RequestID == "" || len(in.RequestID) > 128 || in.FunctionARN == "" {
			http.Error(w, "Invocation identity is missing", 400)
			return
		}
		// The guest, not this TCP connection, owns an accepted invocation's deadline.
		out, err := e.invoke(in)
		if err != nil {
			guestError(w, err)
			return
		}
		guestJSON(w, out)
	case r.Method == http.MethodDelete && len(parts) == 1:
		if err := s.remove(r.Context(), e); err != nil {
			guestError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
func guestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func guestError(w http.ResponseWriter, err error) {
	var remote *RemoteError
	if errors.As(err, &remote) {
		http.Error(w, remote.Message, remote.Status)
		return
	}
	http.Error(w, err.Error(), 500)
}

func (s *Server) prepare(ctx context.Context, d Deployment) (*environment, error) {
	if !environmentID.MatchString(d.ID) || d.Revision == "" || d.MaxConcurrency < 1 || d.MaxConcurrency > 64*d.VCPUs || d.VCPUs < 1 || d.Specification.MemoryMB < 2048 || d.Specification.MemoryMB > 32768 {
		return nil, errors.New("invalid managed execution environment limits")
	}
	if d.Specification.Timeout <= 0 || d.Specification.Timeout > 5400*time.Second {
		return nil, errors.New("invalid managed function timeout")
	}
	if d.Specification.EphemeralMB != 512 {
		return nil, errors.New("managed instances support 512 MB ephemeral storage")
	}
	if d.Specification.Credentials.AccessKeyID == "" || d.Specification.Credentials.SecretAccessKey == "" || d.Specification.Credentials.SessionToken == "" {
		return nil, errors.New("execution role credentials are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.environments[d.ID]; current != nil {
		if current.deployment.Revision != d.Revision || current.deployment.Specification.FunctionARN != d.Specification.FunctionARN {
			return nil, &RemoteError{409, "Execution environment incarnation differs"}
		}
		current.mu.Lock()
		failed := current.initError != nil
		current.mu.Unlock()
		if !failed {
			return current, nil
		}
		if err := s.removeLocked(ctx, current); err != nil {
			return nil, err
		}
	}
	directory, err := s.retainDeployment(d)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", credentialGateway+":0")
	if err != nil {
		return nil, err
	}
	e := &environment{deployment: d, owner: s, listener: listener, ready: make(chan struct{}), done: make(chan struct{}), pending: map[string]*attempt{}, queue: make(chan *attempt, d.MaxConcurrency), container: "stackd-lambda-managed-" + d.ID, directory: directory, credentialsToken: newCredentialsToken(), startupDeadline: time.Now().Add(min(900*time.Second, max(130*time.Second, d.Specification.Timeout)))}
	e.server = &http.Server{Handler: http.HandlerFunc(e.runtimeAPI), ReadHeaderTimeout: 5 * time.Second}
	s.environments[d.ID] = e
	err = e.restoreCredentials()
	if err == nil {
		err = s.startContainer(ctx, e)
	}
	if err == nil {
		err = e.startLogs()
	}
	if err != nil {
		e.mu.Lock()
		e.initError = err
		e.mu.Unlock()
		e.readyOnce.Do(func() { close(e.ready) })
		e.server.Close()
		return e, err
	}
	go e.server.Serve(listener)
	return e, nil
}
func (s *Server) remove(ctx context.Context, e *environment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeLocked(ctx, e)
}
func (s *Server) removeLocked(ctx context.Context, e *environment) error {
	e.mu.Lock()
	e.draining = true
	busy := len(e.pending) != 0
	e.mu.Unlock()
	if busy {
		observation, err := e.observation(ctx)
		if err != nil {
			return err
		}
		if observation.Ready {
			return &RemoteError{409, "Execution environment is draining active runtime workers"}
		}
	}
	if err := s.removeContainer(ctx, e.deployment.ID); err != nil {
		return err
	}
	e.stopOnce.Do(func() { close(e.done) })
	e.mu.Lock()
	e.terminated = true
	e.mu.Unlock()
	if err := e.server.Close(); err != nil {
		return err
	}
	if err := e.stopLogs(); err != nil {
		return err
	}
	if e.logs != nil {
		batch, err := e.logs.batch()
		if err != nil {
			return err
		}
		if len(batch.Data) != 0 {
			return &RemoteError{409, "Execution environment is draining retained runtime output"}
		}
		if err = e.logs.Close(); err != nil {
			return err
		}
	}
	if err := unmountTemporary(ctx, e.directory); err != nil {
		return err
	}
	if err := os.RemoveAll(e.directory); err != nil {
		return err
	}
	delete(s.environments, e.deployment.ID)
	return nil
}
func (s *Server) removeContainer(ctx context.Context, id string) error {
	name := "stackd-lambda-managed-" + id
	var current struct {
		Config struct{ Labels map[string]string }
	}
	err := s.engine.JSON(ctx, "GET", "/containers/"+name+"/json", nil, &current)
	var absent *docker.Error
	if errors.As(err, &absent) && absent.StatusCode == 404 {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Config.Labels["stackd.lambda.capacity-provider"] != s.config.Identity.ProviderARN || current.Config.Labels["stackd.lambda.guest-generation"] != s.config.Identity.Generation || current.Config.Labels["stackd.lambda.environment"] != id {
		return fmt.Errorf("refusing to remove a container owned by another guest incarnation")
	}
	return s.engine.RemoveContainer(ctx, name)
}

package eks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// LogRecord contains unmodified bytes from one identified native source.
type LogRecord struct {
	Category, Stream, Message string
	Timestamp                 time.Time
}
type LogSink interface {
	PutControlPlaneLogs(context.Context, string, []LogRecord) error
}

type LoggingRuntime interface {
	ConfigureControlPlaneLogging(context.Context, string, []string, LogSink) error
}

func (k *K3d) ConfigureControlPlaneLogging(ctx context.Context, id string, categories []string, sink LogSink) error {
	k.op.Lock()
	defer k.op.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	c, err := k.componentCluster(id)
	if err != nil {
		return err
	}
	return c.logs.configure(Specification{Logging: categories, LogSink: sink}, false)
}

type logCursor struct {
	Timestamp    time.Time
	Ordinal      int
	AuthOffset   int64
	AuditOffset  int64
	EnabledSince map[string]time.Time
}
type nativeLogs struct {
	mu          sync.Mutex
	runtime     *K3d
	authMu      sync.Mutex
	closed      bool
	containerID string
	state       diskState
	dir         string
	sink        LogSink
	cursor      logCursor
	cancel      context.CancelFunc
	done        chan struct{}
	wake        <-chan struct{}
	audit       *auditSpool
}

func logStream(category, token string) string {
	prefix := map[string]string{"api": "kube-apiserver", "audit": "kube-apiserver-audit", "authenticator": "authenticator", "controllerManager": "kube-controller-manager", "scheduler": "kube-scheduler"}[category]
	return prefix + "-" + token[:32]
}

var klogSource = regexp.MustCompile(`^[IWEF][0-9]{4} [0-9:.]+[ ]+[0-9]+ ([a-z_]+\.go):[0-9]+\]`)

// nativeLogCategory is an intentionally conservative source map. k3s runs the
// components in one process. Shared-library records (secure_serving.go, reflector,
// controller.go, leaderelection.go, etc.) CANNOT identify their caller and are not
// exported as a made-up component. Audit events arrive only through the webhook.
func nativeLogCategory(message string) string {
	// k3s' executor logs its actual component invocation before starting it.
	for _, source := range []struct{ prefix, category string }{{"Running kube-apiserver ", "api"}, {"Running kube-controller-manager ", "controllerManager"}, {"Running kube-scheduler ", "scheduler"}} {
		if strings.Contains(message, "msg=\""+source.prefix) {
			return source.category
		}
	}
	source := klogSource.FindStringSubmatch(message)
	if len(source) != 2 {
		return ""
	}
	switch source[1] {
	case "schedule_one.go":
		return "scheduler"
	case "deployment_controller.go", "replica_set.go", "namespace_controller.go", "garbagecollector.go":
		return "controllerManager"
	case "apiextensions.go", "crd_finalizer.go", "customresource_discovery_controller.go":
		return "api"
	}
	return ""
}

func (k *K3d) startLogs(ctx context.Context, state diskState, dir string, specification Specification, bridge *nativeBridge) (*nativeLogs, error) {
	logs := &nativeLogs{runtime: k, state: state, dir: dir, sink: specification.LogSink, done: make(chan struct{}), wake: bridge.wake, audit: bridge.audit}
	containers, err := k.ownedContainers(ctx, state)
	if err != nil {
		return nil, err
	}
	for _, container := range containers {
		if container.Name == "/k3d-"+state.Name+"-server-0" {
			logs.containerID = container.ID
		}
	}
	if logs.containerID == "" {
		return nil, errors.New("eks: owned native log source disappeared")
	}
	data, err := readPrivate(filepath.Join(dir, "log-cursor.json"))
	first := errors.Is(err, os.ErrNotExist)
	if err != nil && !first {
		return nil, err
	}
	if !first {
		if err = json.Unmarshal(data, &logs.cursor); err != nil {
			return nil, err
		}
	}
	if logs.cursor.EnabledSince == nil {
		logs.cursor.EnabledSince = make(map[string]time.Time)
	}
	if err = logs.configure(specification, first); err != nil {
		return nil, err
	}
	captureCtx, cancel := context.WithCancel(context.Background())
	logs.cancel = cancel
	go logs.run(captureCtx)
	return logs, nil
}
func (l *nativeLogs) save(cursor logCursor) error {
	body, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	return writePrivate(l.dir, "log-cursor.json", body)
}
func (l *nativeLogs) configure(spec Specification, first bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(spec.Logging) != 0 && spec.LogSink == nil {
		return errors.New("eks: control plane log sink unavailable")
	}
	previous := l.cursor.EnabledSince
	next := l.cursor
	next.EnabledSince = make(map[string]time.Time, len(spec.Logging))
	for _, category := range []string{"api", "audit", "authenticator", "controllerManager", "scheduler"} {
		if !slices.Contains(spec.Logging, category) {
			continue
		}
		since, exists := previous[category]
		if !exists && !first {
			since = time.Now().UTC()
		}
		next.EnabledSince[category] = since
	}
	if err := l.save(next); err != nil {
		return err
	}
	l.cursor = next
	l.sink = spec.LogSink
	return nil
}
func (l *nativeLogs) enabled(category string, at time.Time) bool {
	since, ok := l.cursor.EnabledSince[category]
	return ok && !at.Before(since)
}
func (l *nativeLogs) close() {
	if l == nil {
		return
	}
	l.authMu.Lock()
	l.closed = true
	l.authMu.Unlock()
	l.cancel()
	<-l.done
}
func (l *nativeLogs) run(ctx context.Context) {
	defer close(l.done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := l.collect(ctx); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "EKS native log delivery failed", "clusterID", l.state.ID, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-l.wake:
		}
	}
}

type timestampedLine struct {
	at      time.Time
	message string
}

func (l *nativeLogs) collect(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := l.collectAudit(ctx); err != nil {
		return err
	}
	if err := l.collectAuthentication(ctx); err != nil {
		return err
	}
	if err := l.save(l.cursor); err != nil {
		return err
	}
	args := []string{"logs", "--timestamps", "--until", time.Now().UTC().Format(time.RFC3339Nano)}
	if !l.cursor.Timestamp.IsZero() {
		args = append(args, "--since", l.cursor.Timestamp.Format(time.RFC3339Nano))
	}
	args = append(args, l.containerID)
	command := exec.CommandContext(ctx, "docker", args...)
	command.Env = l.runtime.commandEnvironment()
	body, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("eks: reading owned native control plane logs: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), 2<<20)
	var lines []timestampedLine
	for scanner.Scan() {
		raw := scanner.Text()
		stamp, message, ok := strings.Cut(raw, " ")
		if !ok {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			continue
		}
		lines = append(lines, timestampedLine{at, message})
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	slices.SortStableFunc(lines, func(a, b timestampedLine) int { return a.at.Compare(b.at) })
	next := l.cursor
	var records []LogRecord
	ordinal := 0
	var timestamp time.Time
	for _, line := range lines {
		if !line.at.Equal(timestamp) {
			timestamp, ordinal = line.at, 0
		}
		ordinal++
		if line.at.Before(l.cursor.Timestamp) || line.at.Equal(l.cursor.Timestamp) && ordinal <= l.cursor.Ordinal {
			continue
		}
		category := nativeLogCategory(line.message)
		if category != "" && l.enabled(category, line.at) {
			records = append(records, LogRecord{Category: category, Stream: logStream(category, l.state.Token), Message: line.message, Timestamp: line.at})
		}
		next.Timestamp, next.Ordinal = line.at, ordinal
	}
	if len(records) != 0 {
		if err = l.sink.PutControlPlaneLogs(ctx, l.state.ID, records); err != nil {
			return err
		}
	}
	l.cursor.Timestamp, l.cursor.Ordinal = next.Timestamp, next.Ordinal
	return l.save(l.cursor)
}

func (k *K3d) RecordAuthentication(ctx context.Context, id string, record LogRecord) error {
	k.mu.RLock()
	c := k.clusters[id]
	k.mu.RUnlock()
	if c == nil || c.logs == nil {
		return errors.New("eks: native authenticator log capture unavailable")
	}
	l := c.logs
	l.authMu.Lock()
	defer l.authMu.Unlock()
	if l.closed {
		return errors.New("eks: native authenticator log capture closed")
	}
	record.Category, record.Stream = "authenticator", logStream("authenticator", l.state.Token)
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(l.dir, "authenticator.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return file.Sync()
}
func (l *nativeLogs) collectAuthentication(ctx context.Context) error {
	file, err := os.Open(filepath.Join(l.dir, "authenticator.jsonl"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Seek(l.cursor.AuthOffset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var record LogRecord
		if err = json.Unmarshal(line, &record); err != nil {
			return err
		}
		// The control owner admits authenticator decisions while logging is
		// enabled. Their service timestamps cannot be compared with the native
		// wall-clock enable watermark used for Kubernetes source records.
		if _, enabled := l.cursor.EnabledSince["authenticator"]; enabled {
			if err = l.sink.PutControlPlaneLogs(ctx, l.state.ID, []LogRecord{record}); err != nil {
				return err
			}
		}
		l.cursor.AuthOffset += int64(len(line))
	}
}

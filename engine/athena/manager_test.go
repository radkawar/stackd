package athena

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type nativeStatement struct {
	sql     string
	headers http.Header
}

var fixtureCreateCatalog = regexp.MustCompile(`^CREATE CATALOG "([^"]+)" USING ([a-z_]+) WITH \((.*)\)$`)
var fixtureCatalogProperty = regexp.MustCompile(`"([^"]+)" = '((?:[^']|'')*)'`)

// This protocol fixture tests ownership and lifecycle, not SQL execution. The
// opt-in TestDockerNetworkNative below executes the actual pinned Trino engine.
func (f *networkFixture) serveTrino(container *networkContainer, name string, w http.ResponseWriter, r *http.Request) {
	writeJSON := func(value any) { _ = json.NewEncoder(w).Encode(value) }
	if r.URL.Path == "/v1/info" {
		writeJSON(map[string]any{"starting": false, "nodeVersion": map[string]string{"version": "476"}})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/query/") {
		if r.Method == http.MethodDelete {
			f.mu.Lock()
			container.canceled = append(container.canceled, strings.TrimPrefix(r.URL.Path, "/v1/query/"))
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		fmt.Fprint(w, `{"queryType":"SELECT"}`)
		return
	}
	if r.Header.Get("X-Trino-User") == "stackd-readiness" {
		node := property(container.files["node.properties"], "node.id")
		if f.wrongNode {
			node = "foreign-worker"
		}
		writeJSON(map[string]any{"id": "probe", "data": [][]string{{node}}})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	if r.Header.Get("X-Trino-User") == "stackd-catalog-manager" {
		sql := string(body)
		if f.dropError && strings.HasPrefix(sql, "DROP CATALOG ") {
			writeJSON(map[string]any{"id": "catalog", "error": map[string]string{"errorName": "PERMISSION_DENIED", "errorType": "USER_ERROR", "message": "fixture catalog cleanup denied"}})
			return
		}
		f.mu.Lock()
		if match := fixtureCreateCatalog.FindStringSubmatch(sql); match != nil {
			properties := make(map[string]string)
			for _, pair := range fixtureCatalogProperty.FindAllStringSubmatch(match[3], -1) {
				properties[pair[1]] = strings.ReplaceAll(pair[2], "''", "'")
			}
			container.catalogs[match[1]] = properties
		} else if catalog, found := strings.CutPrefix(sql, "DROP CATALOG IF EXISTS "); found {
			delete(container.catalogs, strings.Trim(catalog, `"`))
		} else {
			f.t.Errorf("unexpected catalog manager SQL %q", sql)
		}
		f.mu.Unlock()
		fmt.Fprint(w, `{"id":"catalog"}`)
		return
	}
	if r.Method == http.MethodPost {
		f.mu.Lock()
		container.statements = append(container.statements, nativeStatement{sql: string(body), headers: r.Header.Clone()})
		container.queries++
		queryID := fmt.Sprintf("query-%d", container.queries)
		f.mu.Unlock()
		f.entered <- name
		if f.queryError != "" {
			if f.loseOwnerOnQuery {
				f.mu.Lock()
				container.config.Labels["stackd.athena.owner"] = "foreign-owner"
				f.mu.Unlock()
			}
			writeJSON(map[string]any{"id": queryID, "error": map[string]string{"errorName": f.queryError, "errorType": "USER_ERROR", "message": "fixture native rejection"}})
			return
		}
		if f.queryPages {
			writeJSON(map[string]any{"id": queryID, "nextUri": container.server.URL + "/v1/statement/" + queryID})
			return
		}
	}
	select {
	case <-f.release:
		fmt.Fprint(w, `{"id":"query","data":[[1]]}`)
	case <-r.Context().Done():
	}
}

func executeFixture(t *testing.T, d *Docker, request Request, consume func(Page) error) string {
	t.Helper()
	var handle string
	if consume == nil {
		consume = func(Page) error { return nil }
	}
	if err := d.Execute(t.Context(), request, func(value string) error { handle = value; return nil }, consume); err != nil {
		t.Fatal(err)
	}
	return handle
}

func callbackResponse(endpoint, token string) (int, string, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("X-Amz-Target", "AWSGlue.GetDatabases")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+token+"/scope")
	response, err := (&http.Client{Timeout: time.Second}).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, string(body), err
}

func TestWarmEngineReuseCallerAndCatalogIsolation(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	var first, second map[string]string
	var calls [2]atomic.Int32
	var engines [2]string
	var handles [2]string
	for index := range 2 {
		request := fixtureRequest(fmt.Sprint(index))
		request.Catalog, request.Database, request.CatalogID = "customer", "analytics", "other-catalog"
		request.SQL = "SELECT ?"
		request.PreparedStatements = map[string]string{"lookup": "SELECT * FROM awsdatacatalog.analytics.events"}
		request.Parameters = []string{"7"}
		request.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls[index].Add(1)
			fmt.Fprint(w, index)
		})
		handles[index] = executeFixture(t, d, request, func(Page) error {
			engine := <-f.entered
			engines[index] = engine
			f.mu.Lock()
			container := f.containers[engine]
			properties := maps.Clone(container.catalogs["customer"])
			defaultProperties := maps.Clone(container.catalogs["awsdatacatalog"])
			statement := container.statements[len(container.statements)-1]
			for path := range container.files {
				if strings.HasPrefix(path, "catalog/") && path != "catalog/__stackd_worker.properties" {
					t.Errorf("warm bootstrap retained caller catalog %s", path)
				}
			}
			f.mu.Unlock()
			if properties["hive.metastore.glue.catalogid"] != request.CatalogID || defaultProperties["hive.metastore.glue.catalogid"] != request.AccountID || defaultProperties["hive.iceberg-catalog-name"] != "awsdatacatalog_iceberg" {
				t.Error("logical catalog/account redirection changed")
			}
			if statement.sql != "EXECUTE IMMEDIATE 'SELECT ?' USING 7" || statement.headers.Get("X-Trino-Catalog") != "customer" || statement.headers.Get("X-Trino-Schema") != "analytics" || !strings.Contains(statement.headers.Get("X-Trino-Prepared-Statement"), "lookup=") {
				t.Errorf("session/prepared/parameter semantics changed: %+v", statement)
			}
			status, body, err := callbackResponse(properties["hive.metastore.glue.endpoint-url"], properties["hive.metastore.glue.aws-access-key"])
			if err != nil || status != 200 || body != fmt.Sprint(index) {
				t.Errorf("wrong callback caller: %d %q %v", status, body, err)
			}
			if index == 0 {
				first = properties
			} else {
				second = properties
				status, _, err := callbackResponse(second["hive.metastore.glue.endpoint-url"], first["hive.metastore.glue.aws-access-key"])
				if err != nil || status != 403 {
					t.Errorf("old token reached new caller: %d %v", status, err)
				}
				status, body, err := callbackResponse(first["hive.metastore.glue.endpoint-url"], first["hive.metastore.glue.aws-access-key"])
				if err == nil && status != 403 {
					t.Errorf("old callback still admitted: %d %q", status, body)
				}
			}
			return nil
		})
	}
	if engines[0] != engines[1] || handles[0] == handles[1] || f.nativeCreates != 1 {
		t.Fatalf("warm ownership reuse: engines %v handles %v creates %d", engines, handles, f.nativeCreates)
	}
	if first["s3.aws-access-key"] == second["s3.aws-access-key"] || first["s3.aws-access-key"] != first["hive.metastore.glue.aws-access-key"] {
		t.Fatal("callback capabilities reused or inconsistent")
	}
	if calls[0].Load() != 1 || calls[1].Load() != 1 {
		t.Fatalf("cross-query callback admitted: %d %d", calls[0].Load(), calls[1].Load())
	}
	f.mu.Lock()
	catalogs := len(f.containers[engines[0]].catalogs)
	f.mu.Unlock()
	if catalogs != 0 {
		t.Fatal("query catalogs survived completion")
	}
	if err := d.Cancel(t.Context(), handles[0]); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	retained := f.containers[engines[1]] != nil
	f.mu.Unlock()
	if !retained {
		t.Fatal("completed query handle destroyed reusable engine")
	}
}

func TestWarmEngineScopeAndScanLimitIsolation(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	requests := []Request{fixtureRequest("base"), fixtureRequest("account"), fixtureRequest("region"), fixtureRequest("partition"), fixtureRequest("capped"), fixtureRequest("capped-again"), fixtureRequest("new-cap")}
	requests[1].AccountID = "other-account"
	requests[2].Region = "us-west-2"
	requests[3].Partition = "aws-us-gov"
	requests[4].BytesCutoff, requests[5].BytesCutoff, requests[6].BytesCutoff = 1024, 1024, 2048
	var engines []string
	for _, request := range requests {
		executeFixture(t, d, request, nil)
		engines = append(engines, <-f.entered)
	}
	if engines[0] == engines[1] || engines[0] == engines[2] || engines[0] == engines[3] || engines[0] == engines[4] || engines[4] != engines[5] || engines[5] == engines[6] {
		t.Fatalf("scope/cap isolation: %v", engines)
	}
	f.mu.Lock()
	config := f.containers[engines[6]].files["config.properties"]
	f.mu.Unlock()
	if property(config, "query.max-scan-physical-bytes") != "2048B" {
		t.Fatal("immutable native scan cap not retained")
	}
}

func TestWarmEngineIdleAndActiveCancellation(t *testing.T) {
	f, d := newNetworkFixtureConfig(t, false, DockerConfig{IdleTimeout: 40 * time.Millisecond})
	f.queryPages = true
	result := make(chan error, 1)
	var handle string
	pageSeen := make(chan struct{}, 1)
	go func() {
		result <- d.Execute(t.Context(), fixtureRequest("active"), func(value string) error { handle = value; return nil }, func(Page) error {
			select {
			case pageSeen <- struct{}{}:
			default:
			}
			return nil
		})
	}()
	engine := awaitExecution(t, f.entered)
	select {
	case <-pageSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("native query ID was not observed")
	}
	time.Sleep(100 * time.Millisecond)
	f.mu.Lock()
	container := f.containers[engine]
	f.mu.Unlock()
	if container == nil {
		t.Fatal("idle sweeper removed active query")
	}
	if err := d.Cancel(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("native cancel: %v", err)
	}
	f.mu.Lock()
	canceled := append([]string(nil), container.canceled...)
	f.mu.Unlock()
	if len(canceled) != 1 || canceled[0] != "query-1" {
		t.Fatalf("native cancellation did not target observed ID: %v", canceled)
	}
	close(f.release)
	f.queryPages = false
	newHandle := executeFixture(t, d, fixtureRequest("after-cancel"), nil)
	newEngine := <-f.entered
	if newEngine == engine {
		t.Fatal("uncertain canceled execution incarnation was reused")
	}
	if err := d.Cancel(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	if newHandle == handle {
		t.Fatal("query identity was reused")
	}
	deadline := time.After(2 * time.Second)
	for {
		f.mu.Lock()
		remaining := len(f.containers)
		f.mu.Unlock()
		if remaining == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("idle engine was not removed")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Simulate SIGKILL: stop Go workers and release the kernel lock, deliberately
// leaving Docker resources and private fsynced receipts untouched.
func abandonFixtureManager(d *Docker) {
	d.mu.Lock()
	d.closed = true
	d.stop()
	d.mu.Unlock()
	d.work.Wait()
	_ = d.stateLock.Close()
	d.closeOnce.Do(func() { close(d.closeDone) })
}

func TestWarmEngineRestartOrphanRecoveryAndLock(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	handle := executeFixture(t, d, fixtureRequest("before-crash"), nil)
	engineName := <-f.entered
	config := DockerConfig{Client: d.client, StateDirectory: d.stateDirectory, CallbackListen: d.callbackListen, CallbackHost: d.callbackHost}
	if duplicate, err := NewDocker(t.Context(), config); err == nil {
		duplicate.Close()
		t.Fatal("two managers acquired one private state")
	}
	d.mu.Lock()
	var receipt engineReceipt
	for _, engine := range d.engines {
		receipt = engine.receipt
	}
	d.mu.Unlock()
	parser := d.containerConfig(receipt.Parser, nil)
	parser.Image = receipt.ParserImage
	parser.Labels["stackd.athena.owner"] = receipt.Owner
	f.mu.Lock()
	f.containers[receipt.Parser+"-hiveddl"] = &networkContainer{config: parser}
	f.mu.Unlock()
	abandonFixtureManager(d)
	successor, err := NewDocker(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	f.mu.Lock()
	remaining := len(f.containers)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("restart retained %d exact-owned engine/parser orphans", remaining)
	}
	newHandle := executeFixture(t, successor, fixtureRequest("after-crash"), nil)
	newEngine := <-f.entered
	if newEngine == engineName || newHandle == handle {
		t.Fatal("restart adopted/replayed old query incarnation")
	}
	if err := successor.Cancel(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	retained := f.containers[newEngine] != nil
	f.mu.Unlock()
	if !retained {
		t.Fatal("recovered stale handle killed successor query engine")
	}
}

func TestWarmEngineForeignOwnershipAndReceiptPaths(t *testing.T) {
	for _, corruption := range []string{"label", "image", "parser-path"} {
		t.Run(corruption, func(t *testing.T) {
			f, d := newNetworkFixture(t, false)
			close(f.release)
			executeFixture(t, d, fixtureRequest("foreign"), nil)
			name := <-f.entered
			d.mu.Lock()
			var receipt engineReceipt
			for _, engine := range d.engines {
				receipt = engine.receipt
			}
			d.mu.Unlock()
			f.mu.Lock()
			if corruption == "label" {
				f.containers[name].config.Labels["stackd.athena.owner"] = "foreign"
			}
			if corruption == "image" {
				f.containers[name].config.Image = "sha256:" + strings.Repeat("f", 64)
			}
			f.mu.Unlock()
			if corruption == "parser-path" {
				receipt.Parser = "../../foreign"
				data, err := json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d.stateDirectory, name+".json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			abandonFixtureManager(d)
			if successor, err := NewDocker(t.Context(), DockerConfig{Client: d.client, StateDirectory: d.stateDirectory, CallbackListen: d.callbackListen, CallbackHost: d.callbackHost}); err == nil {
				successor.Close()
				t.Fatal("foreign/path-altered ownership receipt accepted")
			}
			f.mu.Lock()
			container := f.containers[name]
			f.mu.Unlock()
			if container == nil {
				t.Fatal("foreign resource removed")
			}
			if _, err := os.Stat(filepath.Join(d.stateDirectory, name+".json")); err != nil {
				t.Fatal("failed cleanup lost ownership evidence")
			}
			// This test's fake native server is not managed by httptest's Docker
			// server cleanup; close its socket without issuing a foreign DELETE.
			container.server.Close()
		})
	}
}

func TestWarmEngineCloseCancelsActiveAndRejectsAdmission(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	result := make(chan error, 1)
	go func() {
		result <- d.Execute(t.Context(), fixtureRequest("shutdown"), func(string) error { return nil }, func(Page) error { return nil })
	}()
	awaitExecution(t, f.entered)
	closed := make(chan struct{})
	go func() { d.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("cooperative native shutdown was not bounded")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown query: %v", err)
	}
	if err := d.Execute(t.Context(), fixtureRequest("closed"), func(string) error { t.Error("closed runtime published ownership"); return nil }, func(Page) error { return nil }); err == nil {
		t.Fatal("closed runtime admitted query")
	}
	f.mu.Lock()
	remaining := len(f.containers)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatal("shutdown retained warm engine")
	}
}

func TestWarmEngineCloseBoundsUncooperativeConsumer(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- d.Execute(t.Context(), fixtureRequest("blocked-consumer"), func(string) error { return nil }, func(Page) error { close(entered); <-release; return nil })
	}()
	<-entered
	closed := make(chan struct{})
	go func() { d.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(cleanupTimeout + 2*time.Second):
		close(release)
		t.Fatal("Close exceeded its hard wait bound")
	}
	if successor, err := NewDocker(t.Context(), DockerConfig{Client: d.client, StateDirectory: d.stateDirectory, CallbackListen: d.callbackListen, CallbackHost: d.callbackHost}); err == nil {
		successor.Close()
		close(release)
		t.Fatal("shutdown timeout released ownership before native effects joined")
	}
	close(release)
	<-result
	select {
	case <-d.closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("released callback did not finish teardown")
	}
}

func TestWarmEngineBoundsDroppedConnectorLifetime(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	executeFixture(t, d, fixtureRequest("first"), nil)
	first := <-f.entered
	d.mu.Lock()
	for _, engine := range d.engines {
		engine.used = maxEngineQueries - 1
	}
	d.mu.Unlock()
	executeFixture(t, d, fixtureRequest("last-warm"), nil)
	if engine := <-f.entered; engine != first {
		t.Fatal("engine retired before its bounded connector lifetime")
	}
	executeFixture(t, d, fixtureRequest("fresh-incarnation"), nil)
	if engine := <-f.entered; engine == first {
		t.Fatal("dropped connector resources accumulated without retirement")
	}
	if f.nativeCreates != 2 {
		t.Fatalf("bounded warm engine creates = %d, want 2", f.nativeCreates)
	}
}

func TestWarmEngineCatalogStoreConfiguration(t *testing.T) {
	config, err := configuration(Request{}, "bootstrap", &executionNetwork{port: "8080"})
	if err != nil {
		t.Fatal(err)
	}
	files := archiveFiles(t, config)
	if strings.Contains(files["config.properties"], "catalog.config-dir=") {
		t.Fatal("dynamic store properties entered the server configuration")
	}
	if got := property(files["catalog-store.properties"], "catalog.config-dir"); got != "/tmp/stackd-athena/catalog" {
		t.Fatalf("catalog store directory = %q", got)
	}
	if got := property(files["config.properties"], "plugin.dir"); got != "/usr/lib/trino/plugin" {
		t.Fatalf("plugin directory = %q", got)
	}
	container := (&Docker{}).containerConfig("bootstrap", config)
	if !strings.Contains(container.Cmd[0], "--data-dir /data/trino") {
		t.Fatal("launcher data directory does not own the relative catalog store")
	}
}

func TestWarmEngineRechecksOwnershipBeforeCapability(t *testing.T) {
	for _, fault := range []string{"dead", "owner", "image", "endpoint", "node"} {
		t.Run(fault, func(t *testing.T) {
			f, d := newNetworkFixture(t, false)
			close(f.release)
			executeFixture(t, d, fixtureRequest("before"), nil)
			name := <-f.entered
			f.mu.Lock()
			container := f.containers[name]
			owner, image := container.config.Labels["stackd.athena.owner"], container.config.Image
			f.mu.Unlock()
			switch fault {
			case "dead":
				container.stopped = true
			case "owner":
				container.config.Labels["stackd.athena.owner"] = "foreign-owner"
			case "image":
				container.config.Image = "sha256:" + strings.Repeat("f", 64)
			case "endpoint":
				for _, engine := range d.engines {
					// A different native listener must not receive catalog SQL.
					engine.endpoint = "http://127.0.0.1:1"
				}
			case "node":
				f.wrongNode = true
			}
			published := false
			err := d.Execute(t.Context(), fixtureRequest("after"), func(string) error { published = true; return nil }, func(Page) error { return nil })
			if err == nil || published || container.queries != 1 || len(container.catalogs) != 0 {
				t.Fatalf("unwitnessed reuse admitted fresh capability/query: published=%t queries=%d catalogs=%d err=%v", published, container.queries, len(container.catalogs), err)
			}
			// Restore fake foreign ownership only for this fixture's teardown.
			container.config.Labels["stackd.athena.owner"], container.config.Image = owner, image
			f.wrongNode = false
			f.mu.Lock()
			retained := f.containers[name] != nil
			f.mu.Unlock()
			if fault == "owner" || fault == "image" {
				if !retained {
					t.Fatal("foreign container removed")
				}
				if _, err := os.Stat(filepath.Join(d.stateDirectory, name+".json")); err != nil {
					t.Fatal("foreign receipt lost")
				}
			}
			executeFixture(t, d, fixtureRequest("replacement"), nil)
			if replacement := <-f.entered; replacement == name {
				t.Fatal("unwitnessed incarnation adopted")
			}
		})
	}
}

func TestWarmEngineParserCleanupFailureRetainsOrphan(t *testing.T) {
	for _, kind := range []string{"SYNTAX_ERROR", "UNSUPPORTED_DDL"} {
		t.Run(kind, func(t *testing.T) {
			f, d := newNetworkFixture(t, false)
			close(f.release)
			f.queryError, f.parserError, f.parserRemoveError = "SYNTAX_ERROR", kind, true
			err := d.Execute(t.Context(), fixtureRequest("parser-orphan"), func(string) error { return nil }, func(Page) error { return nil })
			oldEngine := <-f.entered
			if err == nil || terminalQueryError(err) {
				t.Fatalf("cleanup failure hidden by native error: %v", err)
			}
			var native *QueryError
			if errors.As(err, &native) {
				t.Fatal("infrastructure failure exposed as terminal native query error")
			}
			data, err := os.ReadFile(filepath.Join(d.stateDirectory, oldEngine+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var receipt engineReceipt
			if err := json.Unmarshal(data, &receipt); err != nil {
				t.Fatal(err)
			}
			if f.containers[receipt.Parser+"-hiveddl"] == nil {
				t.Fatal("failed parser removal did not leave expected orphan")
			}
			f.queryError = ""
			executeFixture(t, d, fixtureRequest("next-caller"), nil)
			if next := <-f.entered; next == oldEngine {
				t.Fatal("parser cleanup failure reused engine")
			}
			after, err := os.ReadFile(filepath.Join(d.stateDirectory, oldEngine+".json"))
			if err != nil || string(after) != string(data) {
				t.Fatal("next query overwrote orphan ownership")
			}
			f.parserRemoveError = false
			config := DockerConfig{Client: d.client, StateDirectory: d.stateDirectory, CallbackListen: d.callbackListen, CallbackHost: d.callbackHost}
			abandonFixtureManager(d)
			successor, err := NewDocker(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer successor.Close()
			if len(f.containers) != 0 {
				t.Fatal("restart failed to reap parser orphan and replacement")
			}
		})
	}
}

func TestWarmEngineBareHandleCannotCancelReceiptOwner(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	executeFixture(t, d, fixtureRequest("modern"), nil)
	name := <-f.entered
	if err := d.Cancel(t.Context(), name); err == nil {
		t.Fatal("bare handle accepted receipt-owned engine")
	}
	if f.containers[name] == nil {
		t.Fatal("bare handle removed modern engine")
	}
	// Owner labels independently fence modern containers if a receipt is absent.
	if err := os.Remove(filepath.Join(d.stateDirectory, name+".json")); err != nil {
		t.Fatal(err)
	}
	if err := d.Cancel(t.Context(), name); err == nil || f.containers[name] == nil {
		t.Fatal("legacy cleanup bypassed modern owner label")
	}
	for _, engine := range d.engines {
		if err := d.saveReceipt(engine.receipt); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWarmEngineSelectedCatalogAliasCollisions(t *testing.T) {
	for _, selected := range []string{"awsdatacatalog_iceberg", "awsdatacatalog_deltalake", "iceberg", "deltalake"} {
		for _, catalogID := range []string{"123456789012", "222222222222"} {
			t.Run(selected+"/"+catalogID, func(t *testing.T) {
				request := fixtureRequest("aliases")
				request.Catalog, request.CatalogID = selected, catalogID
				byName := make(map[string]queryCatalog)
				for _, catalog := range queryCatalogs(request, "http://127.0.0.1:1", "fixture-token") {
					if _, duplicate := byName[catalog.name]; duplicate {
						t.Fatalf("duplicate native catalog %q", catalog.name)
					}
					byName[catalog.name] = catalog
				}
				chosen := byName[selected]
				if chosen.connector != "hive" || chosen.properties["hive.metastore.glue.catalogid"] != catalogID {
					t.Fatal("explicit selected Glue catalog lost its semantics")
				}
				for _, name := range []string{selected, "awsdatacatalog"} {
					catalog := byName[name]
					for _, property := range []string{"hive.iceberg-catalog-name", "hive.delta-lake-catalog-name"} {
						redirect := byName[catalog.properties[property]]
						if redirect.properties["hive.metastore.glue.catalogid"] != catalog.properties["hive.metastore.glue.catalogid"] {
							t.Fatalf("%s redirects across catalog authority", name)
						}
					}
				}
				plan := &HiveDDL{Kind: "CREATE_TABLE", Identifier: []string{selected, "analytics", "events"}, Columns: []DDLColumn{{Name: "id", Type: "bigint", TrinoType: "bigint"}}, Location: "s3://fixture-data/events/", Properties: map[string]string{"table_type": "ICEBERG"}}
				sql, err := icebergDDL(plan, request)
				iceberg, _, _ := catalogAliases(request)
				if err != nil || !strings.Contains(sql, quoteSQLIdentifier(iceberg)+".") {
					t.Fatalf("emitted Iceberg DDL lost selected authority: %s: %v", sql, err)
				}
			})
		}
	}
}

func TestWarmEngineNativeErrorCannotHideOwnershipLoss(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	f.queryError, f.loseOwnerOnQuery = "NOT_SUPPORTED", true
	var name string
	err := d.Execute(t.Context(), fixtureRequest("native-error-owner-loss"), func(handle string) error {
		name, _, _ = strings.Cut(handle, "/")
		return nil
	}, func(Page) error { return nil })
	var native *QueryError
	var infrastructure *InfrastructureError
	if err == nil || errors.As(err, &native) || !errors.As(err, &infrastructure) {
		t.Fatalf("ownership loss disguised as terminal SQL failure: %v", err)
	}
	f.mu.Lock()
	container := f.containers[name]
	f.mu.Unlock()
	if container == nil {
		t.Fatal("foreign resource deleted after native error")
	}
	if _, err := os.Stat(filepath.Join(d.stateDirectory, name+".json")); err != nil {
		t.Fatal("ownership loss discarded receipt")
	}
	// Restore only the fixture's private fake resource for exact cleanup.
	data, err := os.ReadFile(filepath.Join(d.stateDirectory, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt engineReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	container.config.Labels["stackd.athena.owner"] = receipt.Owner
}

func TestWarmEngineCatalogCleanupErrorIsInfrastructure(t *testing.T) {
	f, d := newNetworkFixture(t, false)
	close(f.release)
	f.dropError = true
	err := d.Execute(t.Context(), fixtureRequest("cleanup-denial"), func(string) error { return nil }, func(Page) error { return nil })
	var native *QueryError
	var infrastructure *InfrastructureError
	if err == nil || errors.As(err, &native) || !errors.As(err, &infrastructure) {
		t.Fatalf("catalog cleanup disguised as terminal SQL failure: %v", err)
	}
	name := <-f.entered
	f.mu.Lock()
	retained := f.containers[name] != nil
	f.mu.Unlock()
	if retained {
		t.Fatal("catalog cleanup failure retained reusable engine")
	}
}

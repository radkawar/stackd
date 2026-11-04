package athena

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"stackd/compute/docker"
)

// TestDockerNetworkNative needs a quiet, local Linux Docker host and the two
// explicitly installed Athena images. It executes real pinned Trino SQL twice
// on one engine with different caller catalogs, then cancels a third native
// query by its observed ID. No SQL response is mocked. Only Glue's callback
// metadata is a fixture; the normal native connector consumes it over HTTP.
func TestDockerNetworkNative(t *testing.T) {
	host := os.Getenv("STACKD_ATHENA_NETWORK_DOCKER_HOST")
	if host == "" {
		t.Skip("set STACKD_ATHENA_NETWORK_DOCKER_HOST for the real local Linux boundary fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	before := interfaceAddresses(t)
	client, err := docker.New(ctx, docker.Config{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	d, err := NewDocker(ctx, DockerConfig{Client: client, StateDirectory: filepath.Join(t.TempDir(), "athena")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !d.hostNetwork {
		t.Fatal("fixture requires a daemon sharing this Linux controller's loopback")
	}
	var handles [2]string
	var engines [2]string
	var callbacks [2]atomic.Int32
	var nativeIDs [2]string
	for index, database := range []string{"first", "second"} {
		request := fixtureRequest("native-warm-" + database)
		request.Catalog = "awsdatacatalog"
		request.Database = database
		catalogID := request.AccountID
		if index == 0 {
			request.SQL = "SELECT catalog_name, schema_name FROM awsdatacatalog.information_schema.schemata WHERE schema_name = ?"
			request.Parameters = []string{quoteSQLString(database)}
		} else {
			request.Catalog, request.CatalogID = "customer", "other-catalog"
			catalogID = request.CatalogID
			request.SQL = "EXECUTE lookup USING " + quoteSQLString(database)
			request.PreparedStatements = map[string]string{"lookup": "SELECT catalog_name, schema_name FROM customer.information_schema.schemata WHERE schema_name = ?"}
		}
		request.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callbacks[index].Add(1)
			var input struct {
				CatalogID string `json:"CatalogId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
				http.Error(w, "invalid Glue input", 400)
				return
			}
			if input.CatalogID != catalogID {
				t.Errorf("native query crossed catalog account: %q, want %q", input.CatalogID, catalogID)
			}
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			switch {
			case strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".GetDatabases"):
				_ = json.NewEncoder(w).Encode(map[string]any{"DatabaseList": []map[string]string{{"Name": database}}})
			case strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".GetDatabase"):
				_ = json.NewEncoder(w).Encode(map[string]any{"Database": map[string]string{"Name": database}})
			default:
				t.Errorf("unexpected native Glue callback %s", r.Header.Get("X-Amz-Target"))
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"__type":"AccessDeniedException","Message":"unexpected fixture operation"}`)
			}
		})
		rows, inspected := 0, false
		err := d.Execute(ctx, request, func(value string) error {
			handles[index] = value
			engines[index], _, _ = strings.Cut(value, "/")
			return nil
		}, func(page Page) error {
			nativeIDs[index] = page.ID
			for _, row := range page.Data {
				if len(row) != 2 {
					return fmt.Errorf("unexpected native metadata row %s", row)
				}
				var catalog, schema string
				if err := json.Unmarshal(row[0], &catalog); err != nil {
					return err
				}
				if err := json.Unmarshal(row[1], &schema); err != nil {
					return err
				}
				if catalog != request.Catalog || schema != database {
					return fmt.Errorf("wrong native scoped metadata %q.%q", catalog, schema)
				}
				rows++
			}
			if inspected {
				return nil
			}
			inspected = true
			return inspectNativeNetwork(ctx, t, client, engines[index], before)
		})
		if err != nil {
			t.Fatal(err)
		}
		if rows != 1 || !inspected || callbacks[index].Load() == 0 {
			t.Fatalf("native query %d rows=%d callbacks=%d inspected=%t", index, rows, callbacks[index].Load(), inspected)
		}
	}
	if engines[0] != engines[1] || handles[0] == handles[1] || nativeIDs[0] == nativeIDs[1] {
		t.Fatalf("native warm reuse/query identity: engines=%v handles=%v native=%v", engines, handles, nativeIDs)
	}
	// The customer's native user can query catalogs, but cannot replace/drop
	// one or inject credentials through dynamic catalog management.
	for _, sql := range []string{"CREATE CATALOG intruder USING memory", "DROP CATALOG awsdatacatalog"} {
		request := fixtureRequest("native-catalog-owner-check")
		request.SQL = sql
		err := d.Execute(ctx, request, func(string) error { return nil }, func(Page) error { return nil })
		var nativeError *QueryError
		if !errors.As(err, &nativeError) || nativeError.ErrorName != "PERMISSION_DENIED" {
			t.Fatalf("customer acquired native catalog ownership: %s: %v", sql, err)
		}
	}
	request := fixtureRequest("native-active-cancel")
	request.SQL = "SELECT sum(a.x * b.x) FROM UNNEST(sequence(1, 10000)) a(x) CROSS JOIN UNNEST(sequence(1, 10000)) b(x)"
	started, firstPage := make(chan string, 1), make(chan string, 1)
	result := make(chan error, 1)
	go func() {
		result <- d.Execute(ctx, request, func(value string) error { started <- value; return nil }, func(page Page) error {
			select {
			case firstPage <- page.ID:
			default:
			}
			return nil
		})
	}()
	var handle, nativeID string
	select {
	case handle = <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case nativeID = <-firstPage:
	case err := <-result:
		t.Fatalf("cancel target completed before its first native page: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	engine, _, _ := strings.Cut(handle, "/")
	if engine != engines[0] || nativeID == "" {
		t.Fatal("native cancellation target did not use warm engine/observed query ID")
	}
	// Cancel a previous query while the new one owns the same engine. It must
	// neither cancel this ID nor remove its container.
	if err := d.Cancel(ctx, handles[0]); err != nil {
		t.Fatal(err)
	}
	var state containerState
	if err := client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(engine)+"/json", nil, &state); err != nil || !state.State.Running {
		t.Fatalf("stale query handle killed active engine: %v", err)
	}
	if err := d.Cancel(ctx, handle); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("real native query cancellation: %v", err)
	}
	t.Logf("reused native engine %s for distinct native queries %v; canceled native query %s", engine, nativeIDs, nativeID)
	d.Close()
	if err := client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(engine)+"/json", nil, &state); err == nil {
		t.Fatal("native shutdown retained container")
	} else if remote, ok := err.(*docker.Error); !ok || remote.StatusCode != http.StatusNotFound {
		t.Fatal(err)
	}
	for address := range interfaceAddresses(t) {
		if !before[address] {
			t.Fatalf("native warm lifecycle retained host interface/address %s", address)
		}
	}
}

func inspectNativeNetwork(ctx context.Context, t *testing.T, client *docker.Client, engine string, before map[string]bool) error {
	t.Helper()
	var state struct {
		Config     struct{ Env []string }
		HostConfig struct {
			NetworkMode  string
			PortBindings map[string][]portBinding
		}
	}
	if err := client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(engine)+"/json", nil, &state); err != nil {
		return err
	}
	if state.HostConfig.NetworkMode != "host" || len(state.HostConfig.PortBindings) != 0 {
		return fmt.Errorf("native query acquired a bridged or published endpoint")
	}
	var files map[string]string
	for _, entry := range state.Config.Env {
		if encoded, found := strings.CutPrefix(entry, "STACKD_TRINO_CONFIG="); found {
			data, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return err
			}
			files = archiveFiles(t, data)
		}
	}
	if property(files["node.properties"], "node.bind-ip") != "127.0.0.1" {
		return fmt.Errorf("native HTTP listener is not explicitly loopback-bound")
	}
	if property(files["config.properties"], "catalog.management") != "dynamic" || property(files["config.properties"], "catalog.store") != "file" {
		return fmt.Errorf("native dynamic file catalog configuration absent")
	}
	for path := range files {
		if strings.HasPrefix(path, "catalog/") && path != "catalog/__stackd_worker.properties" {
			return fmt.Errorf("native bootstrap retained caller catalog %s", path)
		}
	}
	port := property(files["config.properties"], "http-server.http.port")
	if port == "" {
		return fmt.Errorf("native HTTP port is absent")
	}
	for address := range interfaceAddresses(t) {
		if !before[address] {
			return fmt.Errorf("native query created host interface/address %s", address)
		}
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, address := range interfaces {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort(ip.String(), port), 200*time.Millisecond)
		if err == nil {
			connection.Close()
			return fmt.Errorf("native SQL port is reachable through nonloopback interface %s", ip)
		}
	}
	return nil
}

func interfaceAddresses(t *testing.T) map[string]bool {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]bool)
	for _, device := range interfaces {
		result[device.Name] = true
		addresses, err := device.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			result[device.Name+"/"+address.String()] = true
		}
	}
	return result
}

// This opt-in gate exercises real Docker resources, including cold host-network
// creation, idle retirement, restart orphan recovery and an occupied old port.
// Restart abandons the manager lock without cleanup; it does not claim an OS
// process-crash test. Glue/S3 IAM and physical scan caps belong in service smokes.
func TestWarmEngineNativeLifecycle(t *testing.T) {
	host := os.Getenv("STACKD_ATHENA_NETWORK_DOCKER_HOST")
	if host == "" {
		t.Skip("set STACKD_ATHENA_NETWORK_DOCKER_HOST for the real local Linux lifecycle fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 9*time.Minute)
	defer cancel()
	client, err := docker.New(ctx, docker.Config{Host: host})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	config := DockerConfig{Client: client, StateDirectory: filepath.Join(t.TempDir(), "athena"), IdleTimeout: 2 * time.Second}
	d, err := NewDocker(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !d.hostNetwork {
		t.Fatal("fixture requires a daemon sharing the controller loopback")
	}
	run := func(manager *Docker, id string) string {
		t.Helper()
		var handle string
		rows := 0
		if err := manager.Execute(ctx, fixtureRequest(id), func(value string) error { handle = value; return nil }, func(page Page) error {
			rows += len(page.Data)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if rows != 1 {
			t.Fatalf("native SELECT returned %d rows", rows)
		}
		engine, _, _ := strings.Cut(handle, "/")
		return engine
	}
	absent := func(name string) bool {
		t.Helper()
		var state containerState
		err := client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
		var remote *docker.Error
		if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
			return true
		}
		if err != nil {
			t.Fatal(err)
		}
		return false
	}
	first := run(d, "native-idle")
	deadline := time.Now().Add(30 * time.Second)
	for !absent(first) {
		if time.Now().After(deadline) {
			t.Fatal("real idle expiry retained exact-owned container")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(config.StateDirectory, first+".json")); !os.IsNotExist(err) {
		t.Fatalf("idle expiry retained ownership receipt: %v", err)
	}
	// The short timeout belongs only to the idle boundary. Native parser and
	// restart setup must not race a deliberately two-second idle sweeper.
	d.Close()
	config.IdleTimeout = 2 * time.Minute
	d, err = NewDocker(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	second := run(d, "native-restart-orphan")
	d.mu.Lock()
	var old *warmEngine
	for _, engine := range d.engines {
		old = engine
	}
	d.mu.Unlock()
	if old == nil || second == first {
		t.Fatal("idle query adopted retired incarnation")
	}
	// Exercise native Hive parsing, with no Spark SQL/metastore execution.
	request := fixtureRequest("native-hive-fallback")
	request.SQL = "CREATE EXTERNAL TABLE fixture_events (id bigint) STORED AS TEXTFILE LOCATION 's3://fixture-data/events/'"
	plans := 0
	if err := d.Execute(ctx, request, func(string) error { return nil }, func(page Page) error {
		if page.HiveDDL != nil {
			plans++
		}
		return nil
	}); err != nil || plans != 1 {
		t.Fatalf("real native Hive fallback plans=%d: %v", plans, err)
	}
	// Deliberately leave an exact-owned, real parser container to recover.
	parser := d.containerConfig(old.receipt.Parser, nil)
	parser.Image = old.receipt.ParserImage
	parser.Labels["stackd.athena.owner"] = old.receipt.Owner
	parser.HostConfig.NetworkMode = "none"
	parser.HostConfig.ExtraHosts = nil
	parser.ExposedPorts, parser.HostConfig.PortBindings = nil, nil
	var created struct {
		ID string `json:"Id"`
	}
	if err := client.JSON(ctx, http.MethodPost, "/containers/create?name="+old.receipt.Parser+"-hiveddl", parser, &created); err != nil {
		t.Fatal(err)
	}
	abandonFixtureManager(d)
	successor, err := NewDocker(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	if !absent(second) || !absent(created.ID) {
		t.Fatal("restart retained exact-owned real engine/parser orphans")
	}
	third := run(successor, "native-port-takeover")
	successor.mu.Lock()
	var warm *warmEngine
	for _, engine := range successor.engines {
		warm = engine
	}
	// Keep the idle sweeper out while the test deliberately occupies the port.
	warm.busy = true
	successor.mu.Unlock()
	address := strings.TrimPrefix(warm.endpoint, "http://")
	if err := client.RemoveContainer(ctx, warm.containerID); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	var foreignRequests atomic.Int32
	foreign := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		foreignRequests.Add(1)
		http.Error(w, "foreign endpoint", http.StatusForbidden)
	}))
	foreign.Listener.Close()
	foreign.Listener = listener
	foreign.Start()
	defer foreign.Close()
	if err := successor.Execute(ctx, fixtureRequest("must-not-reach-foreign"), func(string) error { t.Error("unwitnessed query published"); return nil }, func(Page) error { return nil }); err == nil {
		t.Fatal("dead warm incarnation accepted")
	}
	if foreignRequests.Load() != 0 {
		t.Fatal("foreign old port received a native request or capability")
	}
	fourth := run(successor, "native-safe-replacement")
	if fourth == third {
		t.Fatal("port takeover adopted dead native incarnation")
	}
	successor.Close()
	if !absent(fourth) {
		t.Fatal("native Close retained replacement")
	}
	t.Log("observed native idle removal, Hive fallback, exact restart orphan cleanup, foreign-port refusal and fresh replacement")
}

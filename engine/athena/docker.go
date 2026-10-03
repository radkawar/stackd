package athena

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"stackd/compute/docker"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
	"stackd/internal/identity"
)

// DockerImage is Trino 476, Apache-2.0, resolved from the upstream OCI tag.
// Installation is explicit: this adapter never pulls images or contacts AWS.
const DockerImage = "trinodb/trino@sha256:00125e40d063bc4816d165482f6044872b18b56026fb959d3b28ce1f96ffbbee"

// DockerConfig uses a caller-owned Docker transport. CallbackListen is an owned
// local listener; CallbackHost is its container-reachable hostname, not an AWS
// endpoint. Remote Docker hosts need explicitly configured routes in both ways.
type DockerConfig struct {
	Client                                                          *docker.Client
	Image, HiveDDLImage, EndpointHost, CallbackListen, CallbackHost string
	StartupTimeout                                                  time.Duration
}

type Docker struct {
	client                                                              *docker.Client
	imageID, hiveDDLImageID, endpointHost, callbackListen, callbackHost string
	startupTimeout                                                      time.Duration
	transport                                                           *http.Transport
	http                                                                *http.Client
	gate                                                                chan struct{}
	mu                                                                  sync.Mutex
	active                                                              map[string]*activeExecution
}

type activeExecution struct {
	cancel     context.CancelFunc
	done       chan struct{}
	cleanupErr error // published before done closes
}

var _ Runtime = (*Docker)(nil)
var immutableImage = regexp.MustCompile(`^(?:[^\s@]+@)?sha256:[a-f0-9]{64}$`)
var executionHandle = regexp.MustCompile(`^stackd-athena-[a-f0-9]{64}$`)
var catalogName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,127}$`)

func NewDocker(ctx context.Context, config DockerConfig) (*Docker, error) {
	if config.Client == nil {
		return nil, errors.New("athena Docker client is required")
	}
	if config.Image == "" {
		config.Image = DockerImage
	}
	if !immutableImage.MatchString(config.Image) {
		return nil, errors.New("trino image must be an immutable sha256 ID or digest-qualified reference")
	}
	if config.HiveDDLImage == "" {
		config.HiveDDLImage = HiveDDLImage
	}
	if !immutableImage.MatchString(config.HiveDDLImage) {
		return nil, errors.New("hive DDL parser image must be an immutable sha256 ID or digest-qualified reference")
	}
	if config.EndpointHost == "" {
		config.EndpointHost = "127.0.0.1"
	}
	if config.CallbackListen == "" {
		config.CallbackListen = "0.0.0.0:0"
	}
	if config.CallbackHost == "" {
		config.CallbackHost = "host.docker.internal"
	}
	for _, host := range []string{config.EndpointHost, config.CallbackHost} {
		if net.ParseIP(host) == nil && strings.ContainsAny(host, ":/?#@[]\\ \t\r\n") {
			return nil, errors.New("trino endpoint and callback hosts must be plain hostnames or IP addresses")
		}
	}
	if _, _, err := net.SplitHostPort(config.CallbackListen); err != nil {
		return nil, fmt.Errorf("trino callback listener: %w", err)
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 2 * time.Minute
	}
	if config.StartupTimeout < 0 {
		return nil, errors.New("trino startup timeout must be positive")
	}
	var image struct {
		ID string `json:"Id"`
		OS string `json:"Os"`
	}
	if err := config.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(config.Image)+"/json", nil, &image); err != nil {
		return nil, fmt.Errorf("trino image must be installed locally: %w", err)
	}
	if image.ID == "" || image.OS != "linux" {
		return nil, errors.New("trino requires a Linux image")
	}
	var parserImage struct {
		ID string `json:"Id"`
		OS string `json:"Os"`
	}
	if err := config.Client.JSON(ctx, http.MethodGet, "/images/"+url.PathEscape(config.HiveDDLImage)+"/json", nil, &parserImage); err != nil {
		return nil, fmt.Errorf("hive DDL parser image must be installed locally: %w", err)
	}
	if parserImage.ID == "" || parserImage.OS != "linux" {
		return nil, errors.New("hive DDL parser requires a Linux image")
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, IdleConnTimeout: 90 * time.Second}
	return &Docker{client: config.Client, imageID: image.ID, hiveDDLImageID: parserImage.ID, endpointHost: config.EndpointHost, callbackListen: config.CallbackListen, callbackHost: config.CallbackHost, startupTimeout: config.StartupTimeout, transport: transport, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, gate: make(chan struct{}, 1), active: make(map[string]*activeExecution)}, nil
}

// Close detaches idle client connections; it never destroys a retained query.
// The service cancels active calls on shutdown. After abrupt controller loss,
// its persisted handles allow Cancel to destroy only those owned containers.
func (d *Docker) Close() { d.transport.CloseIdleConnections() }

func (d *Docker) Execute(ctx context.Context, request Request, started func(string) error, consume func(Page) error) (err error) {
	if request.ID == "" || request.Partition == "" || request.AccountID == "" || request.Region == "" || request.Handler == nil || started == nil || consume == nil {
		return errors.New("trino execution requires scoped identity, callbacks and a query ID")
	}
	if request.Catalog == "" {
		request.Catalog = "awsdatacatalog"
	}
	request.Catalog = strings.ToLower(request.Catalog)
	if !catalogName.MatchString(request.Catalog) || strings.ContainsAny(request.Region+request.CatalogID+request.AccountID, "\r\n\\") {
		return errors.New("invalid native catalog configuration")
	}
	select {
	case d.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-d.gate }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	handle := fmt.Sprintf("stackd-athena-%x", sha256.Sum256([]byte(request.Partition+"\x00"+request.AccountID+"\x00"+request.Region+"\x00"+request.ID)))
	active := &activeExecution{cancel: cancel, done: make(chan struct{})}
	d.mu.Lock()
	d.active[handle] = active
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.active, handle)
		close(active.done)
		d.mu.Unlock()
	}()
	if err := started(handle); err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer stop()
		active.cleanupErr = d.remove(cleanup, handle)
		err = errors.Join(err, active.cleanupErr)
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", d.callbackListen)
	if err != nil {
		return err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		listener.Close()
		return err
	}
	token := hex.EncodeToString(tokenBytes)
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is an ephemeral callback capability, not an AWS credential or
		// principal. The service adapter supplies the retained caller context.
		_, credential, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=")
		credential, _, _ = strings.Cut(credential, "/")
		if subtle.ConstantTimeCompare([]byte(credential), []byte(token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<20)
		if r.Header.Get("X-Amz-Target") == "" {
			if rejected := gateway.VerifyS3SignedRequest(r, identity.Credential{AccessKeyID: token, SecretAccessKey: "callback-capability"}, request.Region, time.Now()); rejected != nil {
				model, _ := awscatalog.LookupService("s3")
				awswire.RESTXMLError(w, r, &model, rejected)
				return
			}
		}
		r.Header.Del("Authorization")
		request.Handler.ServeHTTP(w, r)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	callback := "http://" + net.JoinHostPort(d.callbackHost, fmt.Sprint(port))
	config, err := configuration(request, callback, token)
	if err != nil {
		return err
	}
	startup, stop := context.WithTimeout(ctx, d.startupTimeout)
	defer stop()
	if err := startup.Err(); err != nil {
		return err
	}
	// Finish native create even if cancellation arrives while Docker admits it;
	// deferred owned cleanup then cannot miss a late-created container.
	createCtx, createStop := context.WithTimeout(context.WithoutCancel(startup), 30*time.Second)
	var created struct {
		ID string `json:"Id"`
	}
	err = d.client.JSON(createCtx, http.MethodPost, "/containers/create?name="+handle, d.containerConfig(handle, config), &created)
	createStop()
	if err != nil {
		return err
	}
	if err := startup.Err(); err != nil {
		return err
	}
	if err := d.client.JSON(startup, http.MethodPost, "/containers/"+created.ID+"/start", nil, nil); err != nil {
		return err
	}
	var state containerState
	if err := d.client.JSON(startup, http.MethodGet, "/containers/"+created.ID+"/json", nil, &state); err != nil {
		return err
	}
	ports := state.NetworkSettings.Ports["8080/tcp"]
	if len(ports) != 1 || ports[0].HostIP != "127.0.0.1" {
		return errors.New("trino container has no owned loopback endpoint")
	}
	endpoint := "http://" + net.JoinHostPort(d.endpointHost, ports[0].HostPort)
	if err := d.ready(startup, endpoint, created.ID); err != nil {
		return err
	}
	err = executeSQL(ctx, d.http, endpoint, request, "athena", consume)
	var sqlError *QueryError
	if !errors.As(err, &sqlError) || sqlError.ErrorName != "SYNTAX_ERROR" || len(request.Parameters) != 0 {
		return err
	}
	// Hive DDL is parsed by Spark's real Hive-compatible parser, not executed
	// by Spark. Native Trino remains the only SQL/data/format execution engine.
	parseStarted := time.Now()
	plan, parseErr := d.parseHiveDDL(ctx, handle, request.SQL)
	if parseErr != nil {
		return parseErr
	}
	nativeSQL, emitErr := icebergDDL(plan, request)
	if emitErr != nil {
		return emitErr
	}
	if nativeSQL != "" {
		request.SQL = nativeSQL
		return executeSQL(ctx, d.http, endpoint, request, "athena", consume)
	}
	return consume(Page{HiveDDL: plan, UpdateType: strings.ReplaceAll(plan.Kind, "_", " "), Stats: Statistics{State: "FINISHED", ElapsedMillis: time.Since(parseStarted).Milliseconds()}})
}

func (d *Docker) Cancel(ctx context.Context, handle string) error {
	if !executionHandle.MatchString(handle) {
		return errors.New("invalid Trino execution handle")
	}
	d.mu.Lock()
	active := d.active[handle]
	d.mu.Unlock()
	if active != nil {
		// Execute owns in-flight create/start and parser cleanup. Join it instead
		// of racing a second Docker removal against those native effects.
		active.cancel()
		select {
		case <-active.done:
			return active.cleanupErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return d.remove(ctx, handle)
}

func (d *Docker) remove(ctx context.Context, handle string) error {
	return errors.Join(d.removeOwned(ctx, handle+"-hiveddl", handle), d.removeOwned(ctx, handle, handle))
}

func (d *Docker) removeOwned(ctx context.Context, name, handle string) error {
	var state containerState
	err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
	var remote *docker.Error
	if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Config.Labels["stackd.athena.execution"] != handle || state.Config.Labels["stackd.athena.engine"] != "trino-476" {
		return errors.New("refusing to remove foreign Trino container")
	}
	return d.client.RemoveContainer(ctx, state.ID)
}

type portBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string
}
type containerState struct {
	ID              string `json:"Id"`
	Config          struct{ Labels map[string]string }
	NetworkSettings struct{ Ports map[string][]portBinding }
	State           struct {
		Running  bool
		ExitCode int
		Error    string
	}
}
type containerConfig struct {
	docker.ContainerConfig
	Hostname     string `json:",omitempty"`
	ExposedPorts map[string]struct{}
	HostConfig   struct {
		docker.ContainerHostConfig
		PortBindings map[string][]portBinding
		Tmpfs        map[string]string
	}
}

func (d *Docker) containerConfig(handle string, configuration []byte) containerConfig {
	var c containerConfig
	c.Image, c.User = d.imageID, "1000:1000"
	c.Labels = map[string]string{"stackd.athena.execution": handle, "stackd.athena.engine": "trino-476"}
	c.Entrypoint = []string{"/bin/sh", "-c"}
	c.Cmd = []string{"set -eu; printf '%s' \"$STACKD_TRINO_CONFIG\" | base64 -d | tar -xf - -C /tmp; unset STACKD_TRINO_CONFIG; exec /usr/lib/trino/bin/launcher run --etc-dir /tmp/stackd-athena"}
	c.Env = []string{"AWS_EC2_METADATA_DISABLED=true", "STACKD_TRINO_CONFIG=" + base64.StdEncoding.EncodeToString(configuration)}
	c.HostConfig.ContainerHostConfig = docker.ContainerHostConfig{NetworkMode: "bridge", ReadonlyRootfs: true, Memory: 4 << 30, MemorySwap: 4 << 30, CPUPeriod: 100000, CPUQuota: 200000, PidsLimit: 512, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, ExtraHosts: []string{"host.docker.internal:host-gateway"}, LogConfig: docker.ContainerLogConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "2"}}}
	// Trino's JNA/codec libraries extract native code into java.io.tmpdir.
	// Docker tmpfs defaults to noexec; only this bounded scratch mount needs exec.
	c.HostConfig.Tmpfs = map[string]string{"/tmp": "rw,nosuid,nodev,exec,size=256m,mode=1777", "/data/trino": "rw,nosuid,nodev,size=256m,uid=1000,gid=1000"}
	c.ExposedPorts = map[string]struct{}{"8080/tcp": {}}
	c.HostConfig.PortBindings = map[string][]portBinding{"8080/tcp": {{HostIP: "127.0.0.1"}}}
	return c
}

func (d *Docker) ready(ctx context.Context, endpoint, id string) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/info", nil)
		response, err := d.http.Do(req)
		if err == nil {
			var info struct {
				Starting    bool
				NodeVersion struct{ Version string }
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&info)
			response.Body.Close()
			if response.StatusCode == 200 && decodeErr == nil && !info.Starting {
				if info.NodeVersion.Version != "476" {
					return fmt.Errorf("expected Trino 476, got %q", info.NodeVersion.Version)
				}
				// HTTP startup and information_schema reads precede static catalog
				// publication to the scheduler. A real JMX split must run on the
				// owned worker before any customer SQL is submitted. The helper
				// catalog shares the same atomic native announcement as Glue.
				ownedWorker := false
				probe := Request{Catalog: "__stackd_worker", SQL: `SELECT node FROM __stackd_worker.current."java.lang:type=runtime"`}
				probeErr := executeSQL(ctx, d.http, endpoint, probe, "stackd-readiness", func(page Page) error {
					for _, row := range page.Data {
						if len(row) != 1 {
							return errors.New("invalid native worker readiness row")
						}
						var node string
						if err := json.Unmarshal(row[0], &node); err != nil {
							return err
						}
						if node != "athena" {
							return fmt.Errorf("unexpected native worker %q", node)
						}
						ownedWorker = true
					}
					return nil
				})
				if probeErr == nil && ownedWorker {
					return nil
				}
				if probeErr != nil {
					var nativeError *QueryError
					if !errors.As(probeErr, &nativeError) || nativeError.ErrorName != "NO_NODES_AVAILABLE" {
						return fmt.Errorf("trino worker readiness: %w", probeErr)
					}
				}
			}
		}
		var state containerState
		if err := d.client.JSON(ctx, http.MethodGet, "/containers/"+id+"/json", nil, &state); err != nil {
			return err
		}
		if !state.State.Running {
			return fmt.Errorf("trino exited during startup (exit %d): %s", state.State.ExitCode, state.State.Error)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("trino readiness: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func configuration(request Request, endpoint, token string) ([]byte, error) {
	files := map[string]string{
		"node.properties":                    "node.environment=stackd\nnode.id=athena\nnode.data-dir=/data/trino\n",
		"jvm.config":                         "-server\n-Xms512m\n-Xmx2g\n-XX:+ExitOnOutOfMemoryError\n-XX:ReservedCodeCacheSize=256M\n-Djdk.attach.allowAttachSelf=true\n-XX:+EnableDynamicAgentLoading\n-Dfile.encoding=UTF-8\n",
		"config.properties":                  "coordinator=true\nnode-scheduler.include-coordinator=true\nhttp-server.http.port=8080\ndiscovery.uri=http://127.0.0.1:8080\nquery.max-memory=1GB\nquery.max-memory-per-node=1GB\nmemory.heap-headroom-per-node=512MB\nquery.max-run-time=30m\nquery.client.timeout=2m\n",
		"log.properties":                     "io.trino=INFO\n",
		"catalog/__stackd_worker.properties": "connector.name=jmx\n",
		"access-control.properties":          "access-control.name=file\nsecurity.config-file=/tmp/stackd-athena/access-control.json\n",
		// This protects only the private native worker probe. Real AWS catalog
		// and object access remains with the ordinary current Glue/S3/IAM owners.
		"access-control.json": `{"catalogs":[{"user":"stackd-readiness","catalog":"__stackd_worker","allow":"read-only"},{"catalog":"__stackd_worker","allow":"none"},{"user":"athena","catalog":".*","allow":"all"}]}`,
	}
	if request.BytesCutoff > 0 {
		// The native engine accounts physical scan bytes, not S3 metadata or
		// unrelated object traffic. A cluster cap cannot be raised by SQL session settings.
		files["config.properties"] = fmt.Sprintf("%squery.max-scan-physical-bytes=%dB\n", files["config.properties"], request.BytesCutoff)
	}
	common := "hive.metastore.glue.region=" + request.Region + "\nhive.metastore.glue.endpoint-url=" + endpoint + "\nhive.metastore.glue.aws-access-key=" + token + "\nhive.metastore.glue.aws-secret-key=callback-capability\nhive.metastore.glue.max-error-retries=1\nhive.metastore-cache-ttl=0s\nhive.metastore-stats-cache-ttl=0s\nfs.native-s3.enabled=true\ns3.endpoint=" + endpoint + "\ns3.region=" + request.Region + "\ns3.path-style-access=true\ns3.aws-access-key=" + token + "\ns3.aws-secret-key=callback-capability\ns3.max-error-retries=1\n"
	selectedID := request.CatalogID
	if selectedID == "" {
		selectedID = request.AccountID
	}
	addCatalog := func(name, connector, catalogID, redirectPrefix string) {
		properties := "connector.name=" + connector + "\n" + common + "hive.metastore.glue.catalogid=" + catalogID + "\n"
		switch connector {
		case "iceberg":
			properties += "iceberg.catalog.type=glue\n"
		case "delta_lake":
			// Athena Delta is read-only. Native Trino write support must not
			// silently enlarge that AWS contract.
			properties += "hive.metastore=glue\ndelta.security=READ_ONLY\n"
		default:
			properties += "hive.metastore=glue\nhive.iceberg-catalog-name=" + redirectPrefix + "iceberg\nhive.delta-lake-catalog-name=" + redirectPrefix + "deltalake\n"
		}
		files["catalog/"+name+".properties"] = properties
	}
	addCatalog("iceberg", "iceberg", selectedID, "")
	addCatalog("deltalake", "delta_lake", selectedID, "")
	defaultRedirect := ""
	if selectedID != request.AccountID {
		defaultRedirect = "awsdatacatalog_"
		addCatalog("awsdatacatalog_iceberg", "iceberg", request.AccountID, "")
		addCatalog("awsdatacatalog_deltalake", "delta_lake", request.AccountID, "")
	}
	addCatalog("awsdatacatalog", "hive", request.AccountID, defaultRedirect)
	if request.Catalog != "awsdatacatalog" && request.Catalog != "iceberg" && request.Catalog != "deltalake" {
		addCatalog(request.Catalog, "hive", selectedID, "")
	}
	// TODO: Comeback expose all authorized Athena catalog registrations for
	// multi-catalog SQL and S3Tables federated ownership. Hive DDL uses native
	// Spark logical plans, but ALTER/MSCK/views, bucket transforms and Athena
	// CTAS-specific properties still require evidenced typed projections.
	var buffer bytes.Buffer
	archive := tar.NewWriter(&buffer)
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		body := files[path]
		if err := archive.WriteHeader(&tar.Header{Name: "stackd-athena/" + path, Mode: 0400, Uid: 1000, Gid: 1000, Size: int64(len(body))}); err != nil {
			return nil, err
		}
		if _, err := io.WriteString(archive, body); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

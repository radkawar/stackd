package athena

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"stackd/compute/docker"
)

const cleanupTimeout = 30 * time.Second

// Trino 476 documents incomplete resource release in dropped object-storage
// connectors. Bound accumulated connector resources as well as idle lifetime.
const maxEngineQueries = 64

type warmEngine struct {
	receipt         engineReceipt
	scope, endpoint string
	containerID     string
	bytesCutoff     int64
	used            int
	busy            bool // protected by Docker.mu
	idleSince       time.Time
}

type engineReceipt struct {
	Engine      string `json:"engine"`
	Owner       string `json:"owner"`
	Image       string `json:"image"`
	Parser      string `json:"parser,omitempty"`
	ParserImage string `json:"parserImage"`
}

// Close cancels this manager's calls and removes its exact-owned warm engines.
// The wait is bounded. If a caller-supplied callback refuses cancellation, the
// private state lock stays held until background teardown actually completes;
// a successor cannot race a late native create or adopt ambiguous SQL writes.
func (d *Docker) Close() {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.stop()
		for _, active := range d.active {
			active.cancel()
		}
		d.mu.Unlock()
		go func() {
			d.work.Wait()
			ctx, stop := context.WithTimeout(context.Background(), cleanupTimeout)
			defer stop()
			if err := d.recoverReceipts(ctx); err != nil {
				slog.Error("close Athena warm engines; ownership receipts retained", "error", err)
			}
			d.transport.CloseIdleConnections()
			_ = d.stateLock.Close()
			close(d.closeDone)
		}()
	})
	timer := time.NewTimer(cleanupTimeout)
	defer timer.Stop()
	select {
	case <-d.closeDone:
	case <-timer.C:
	}
}

func (d *Docker) Execute(ctx context.Context, request Request, started func(string) error, consume func(Page) error) (err error) {
	defer func() {
		var native *QueryError
		if err != nil && !terminalQueryError(err) && errors.As(err, &native) {
			err = &InfrastructureError{cause: err}
		}
	}()
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
	case <-d.lifetime.Done():
		return errors.New("athena runtime is closed")
	}
	defer func() { <-d.gate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(d.lifetime, cancel)
	defer stop()
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return errors.New("athena runtime is closed")
	}
	d.work.Add(1)
	d.mu.Unlock()
	defer d.work.Done()
	scope := request.Partition + "\x00" + request.AccountID + "\x00" + request.Region
	d.mu.Lock()
	engine := d.engines[scope]
	if engine != nil {
		engine.busy = true
	}
	d.mu.Unlock()
	if engine != nil && (engine.bytesCutoff != request.BytesCutoff || engine.used >= maxEngineQueries) {
		if err := d.retireEngine(engine); err != nil {
			return err
		}
		engine = nil
	}
	if engine != nil {
		witness, stop := context.WithTimeout(ctx, d.startupTimeout)
		witnessErr := d.witnessEngine(witness, engine)
		stop()
		if witnessErr != nil {
			// Never publish a fresh caller capability to an unwitnessed warm
			// endpoint. Exact-owned dead engines may be recreated next call;
			// foreign resources retain their receipt and are never removed.
			return errors.Join(witnessErr, d.retireEngine(engine))
		}
	}
	if engine == nil {
		name := fmt.Sprintf("stackd-athena-%x", sha256.Sum256([]byte(scope+"\x00"+rand.Text())))
		engine = &warmEngine{scope: scope, busy: true, bytesCutoff: request.BytesCutoff, receipt: engineReceipt{Engine: name, Owner: rand.Text(), Image: d.imageID}}
		d.mu.Lock()
		d.engines[scope] = engine
		d.mu.Unlock()
	}
	query := make([]byte, 32)
	if _, err := rand.Read(query); err != nil {
		return errors.Join(err, d.retireEngine(engine))
	}
	handle := engine.receipt.Engine + "/" + hex.EncodeToString(query)
	engine.receipt.Parser = engine.receipt.Engine + "-" + hex.EncodeToString(query)
	engine.receipt.ParserImage = d.hiveDDLImageID
	active := &activeExecution{cancel: cancel, done: make(chan struct{})}
	d.mu.Lock()
	d.active[handle] = active
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.active, handle)
		engine.busy = false
		engine.idleSince = time.Now()
		close(active.done)
		d.mu.Unlock()
	}()
	// Both the private engine receipt and service query handle precede native
	// creation. Recovery removes the whole old incarnation; it never replays SQL.
	if err := d.saveReceipt(engine.receipt); err != nil {
		return errors.Join(err, d.retireEngine(engine))
	}
	if err := started(handle); err != nil {
		if engine.endpoint == "" {
			return errors.Join(err, d.retireEngine(engine))
		}
		return err
	}
	if engine.endpoint == "" {
		if err := d.startEngine(ctx, engine, request); err != nil {
			active.cleanupErr = d.retireEngine(engine)
			return errors.Join(err, active.cleanupErr)
		}
	}
	callback, err := d.newCallback(request)
	if err != nil {
		return err
	}
	catalogs := queryCatalogs(request, callback.endpoint, callback.token)
	createdCatalogs := make([]string, 0, len(catalogs))
	// Revoke the old capability before dropping catalogs or publishing any later
	// query's catalogs, even if a connector's background requests outlive DROP.
	defer func() {
		callback.close()
		cleanup, stop := context.WithTimeout(context.Background(), cleanupTimeout)
		defer stop()
		cleanupErr := d.witnessEngine(cleanup, engine)
		if cleanupErr == nil {
			for _, name := range createdCatalogs {
				cleanupErr = errors.Join(cleanupErr, d.catalogSQL(cleanup, engine, "DROP CATALOG IF EXISTS "+quoteSQLIdentifier(name)))
			}
		}
		// Transport/cancellation failures can leave an unobserved native query.
		// Retire this incarnation rather than risk it sharing later catalogs.
		if cleanupErr != nil || (err != nil && !terminalQueryError(err)) {
			cleanupErr = errors.Join(cleanupErr, d.retireEngine(engine))
		}
		if cleanupErr != nil {
			cleanupErr = &InfrastructureError{cause: cleanupErr}
		}
		active.cleanupErr = cleanupErr
		err = errors.Join(err, cleanupErr)
	}()
	for _, catalog := range catalogs {
		if err := d.catalogSQL(ctx, engine, catalog.createSQL()); err != nil {
			return &InfrastructureError{cause: err}
		}
		createdCatalogs = append(createdCatalogs, catalog.name)
	}
	engine.used++
	// Athena CTAS syntax is accepted by Trino's parser even when its property
	// names have different connector semantics. Translate its typed AST before
	// any native statement can create metadata or write objects.
	ctas, parseErr := d.parseCTAS(ctx, engine, request.SQL)
	if parseErr != nil {
		return parseErr
	}
	if ctas != nil {
		nativeSQL, session, emitErr := ctasDDL(ctas, request)
		if emitErr != nil {
			return emitErr
		}
		request.SQL = nativeSQL
		return executeCTAS(ctx, d.http, engine.endpoint, request, session, consume)
	}
	err = executeSQL(ctx, d.http, engine.endpoint, request, "athena", consume)
	var sqlError *QueryError
	if !terminalQueryError(err) || !errors.As(err, &sqlError) || sqlError.ErrorName != "SYNTAX_ERROR" || len(request.Parameters) != 0 {
		return err
	}
	// Spark supplies native Hive-compatible syntax trees only. Trino remains
	// the sole query/data/format engine, including emitted Iceberg CREATE.
	parseStarted := time.Now()
	plan, parseErr := d.parseHiveDDL(ctx, engine.receipt.Parser, engine.receipt.Owner, request.SQL)
	if parseErr != nil {
		return parseErr
	}
	nativeSQL, emitErr := hiveNativeDDL(plan, request)
	if emitErr != nil {
		return emitErr
	}
	if nativeSQL != "" {
		request.SQL = nativeSQL
		return executeSQL(ctx, d.http, engine.endpoint, request, "athena", consume)
	}
	return consume(Page{HiveDDL: plan, UpdateType: strings.ReplaceAll(plan.Kind, "_", " "), Stats: Statistics{State: "FINISHED", ElapsedMillis: time.Since(parseStarted).Milliseconds()}})
}

func (d *Docker) catalogSQL(ctx context.Context, engine *warmEngine, sql string) error {
	return executeSQL(ctx, d.http, engine.endpoint, Request{SQL: sql}, "stackd-catalog-manager", func(Page) error { return nil })
}

func (d *Docker) startEngine(ctx context.Context, engine *warmEngine, request Request) error {
	network, err := d.executionNetwork()
	if err != nil {
		return err
	}
	defer network.close()
	config, err := configuration(request, engine.receipt.Engine, network)
	if err != nil {
		return err
	}
	startup, stop := context.WithTimeout(ctx, d.startupTimeout)
	defer stop()
	if err := startup.Err(); err != nil {
		return err
	}
	container := d.containerConfig(engine.receipt.Engine, config)
	container.Labels["stackd.athena.owner"] = engine.receipt.Owner
	createCtx, createStop := context.WithTimeout(context.WithoutCancel(startup), cleanupTimeout)
	var created struct {
		ID string `json:"Id"`
	}
	err = d.client.JSON(createCtx, http.MethodPost, "/containers/create?name="+engine.receipt.Engine, container, &created)
	createStop()
	if err != nil {
		return err
	}
	if err := startup.Err(); err != nil {
		return err
	}
	// The native JMX identity witness fences the unavoidable release/start gap.
	network.close()
	if err := d.client.JSON(startup, http.MethodPost, "/containers/"+created.ID+"/start", nil, nil); err != nil {
		return err
	}
	var state containerState
	if err := d.client.JSON(startup, http.MethodGet, "/containers/"+created.ID+"/json", nil, &state); err != nil {
		return err
	}
	endpoint := network.endpoint
	if !d.hostNetwork {
		ports := state.NetworkSettings.Ports["8080/tcp"]
		if len(ports) != 1 || ports[0].HostIP != "127.0.0.1" {
			return errors.New("trino container has no owned loopback endpoint")
		}
		endpoint = "http://" + net.JoinHostPort(d.endpointHost, ports[0].HostPort)
	}
	engine.endpoint, engine.containerID = endpoint, created.ID
	if err := d.witnessEngine(startup, engine); err != nil {
		return err
	}
	return nil
}

// terminalQueryError requires every leaf to be a terminal native error. Merely
// finding one QueryError in a joined error would hide parser/container cleanup
// failures and allow the next query to overwrite an orphan's receipt.
func terminalQueryError(err error) bool {
	switch err := err.(type) {
	case *QueryError:
		return true
	case interface{ Unwrap() []error }:
		children := err.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !terminalQueryError(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return terminalQueryError(err.Unwrap())
	default:
		return false
	}
}

// Witness both Docker ownership and the native node before publishing each
// query's capability. The second inspect fences death/replacement during JMX.
func (d *Docker) witnessEngine(ctx context.Context, engine *warmEngine) (err error) {
	defer func() {
		if err != nil {
			err = &InfrastructureError{cause: err}
		}
	}()
	observe := func() error {
		var state containerState
		if err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(engine.receipt.Engine)+"/json", nil, &state); err != nil {
			return err
		}
		if state.ID != engine.containerID || !state.State.Running || state.Image != engine.receipt.Image ||
			state.Config.Labels["stackd.athena.owner"] != engine.receipt.Owner ||
			state.Config.Labels["stackd.athena.execution"] != engine.receipt.Engine ||
			state.Config.Labels["stackd.athena.engine"] != "trino-476" {
			return errors.New("trino engine ownership or running identity lost")
		}
		if !d.hostNetwork {
			ports := state.NetworkSettings.Ports["8080/tcp"]
			if len(ports) != 1 || ports[0].HostIP != "127.0.0.1" || engine.endpoint != "http://"+net.JoinHostPort(d.endpointHost, ports[0].HostPort) {
				return errors.New("trino engine endpoint identity lost")
			}
		}
		return nil
	}
	if err := observe(); err != nil {
		return err
	}
	if err := d.ready(ctx, engine.endpoint, engine.containerID, engine.receipt.Engine); err != nil {
		return err
	}
	return observe()
}

func (d *Docker) Cancel(ctx context.Context, handle string) error {
	engine, query, modern := strings.Cut(handle, "/")
	if !executionHandle.MatchString(engine) || (modern && (len(query) != 64 || !hexString(query))) {
		return errors.New("invalid Trino execution handle")
	}
	d.mu.Lock()
	active := d.active[handle]
	d.mu.Unlock()
	if active != nil {
		active.cancel()
		select {
		case <-active.done:
			return active.cleanupErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if modern {
		// Completed/stale query handles never authorize killing a later query.
		// NewDocker has already reaped old-incarnation engine receipts.
		return nil
	}
	if _, err := os.Lstat(filepath.Join(d.stateDirectory, engine+".json")); err == nil {
		return errors.New("bare handle cannot cancel a receipt-owned Trino engine")
	} else if !os.IsNotExist(err) {
		return err
	}
	// Pre-warm persisted handles named one owned container per query. They are
	// still crash-cleanup authority, but never identify a new warm incarnation.
	return d.remove(ctx, handle)
}

func hexString(value string) bool {
	for _, c := range value {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func (d *Docker) retireEngine(engine *warmEngine) error {
	d.mu.Lock()
	if d.engines[engine.scope] == engine {
		delete(d.engines, engine.scope)
	}
	d.mu.Unlock()
	ctx, stop := context.WithTimeout(context.Background(), cleanupTimeout)
	defer stop()
	return d.destroyEngine(ctx, engine.receipt)
}

func (d *Docker) expireIdle() {
	defer d.work.Done()
	interval := min(d.idleTimeout/2, time.Second)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-d.lifetime.Done():
			return
		case now := <-ticker.C:
			d.mu.Lock()
			var expired []*warmEngine
			for scope, engine := range d.engines {
				if !engine.busy && now.Sub(engine.idleSince) >= d.idleTimeout {
					delete(d.engines, scope)
					expired = append(expired, engine)
				}
			}
			d.mu.Unlock()
			ctx, stop := context.WithTimeout(d.lifetime, cleanupTimeout)
			for _, engine := range expired {
				if err := d.destroyEngine(ctx, engine.receipt); err != nil {
					slog.Error("expire Athena warm engine; ownership receipt retained", "engine", engine.receipt.Engine, "error", err)
				}
			}
			stop()
		}
	}
}

func (d *Docker) openState(ctx context.Context) (err error) {
	if d.stateDirectory == "" {
		return errors.New("athena private durable state directory is required")
	}
	if err := os.MkdirAll(d.stateDirectory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(d.stateDirectory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("athena state directory must be a private non-symlink directory")
	}
	fd, err := unix.Open(filepath.Join(d.stateDirectory, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	d.stateLock = os.NewFile(uintptr(fd), "athena ownership lock")
	defer func() {
		if err != nil {
			_ = d.stateLock.Close()
		}
	}()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("athena state directory already in use: %w", err)
	}
	return d.recoverReceipts(ctx)
}

func (d *Docker) recoverReceipts(ctx context.Context) error {
	entries, err := os.ReadDir(d.stateDirectory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name, found := strings.CutSuffix(entry.Name(), ".json")
		if !found || !executionHandle.MatchString(name) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("invalid Athena ownership receipt file")
		}
		data, err := os.ReadFile(filepath.Join(d.stateDirectory, entry.Name()))
		if err != nil {
			return err
		}
		var receipt engineReceipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			return err
		}
		if receipt.Engine != name || !validReceipt(receipt) {
			return errors.New("invalid Athena engine ownership receipt")
		}
		if err := d.destroyEngine(ctx, receipt); err != nil {
			return err
		}
	}
	return nil
}

func validReceipt(receipt engineReceipt) bool {
	if !executionHandle.MatchString(receipt.Engine) || receipt.Owner == "" || !immutableImage.MatchString(receipt.Image) {
		return false
	}
	if receipt.Parser == "" {
		return true
	}
	query, found := strings.CutPrefix(receipt.Parser, receipt.Engine+"-")
	return found && len(query) == 64 && hexString(query) && immutableImage.MatchString(receipt.ParserImage)
}

func (d *Docker) saveReceipt(receipt engineReceipt) error {
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(d.stateDirectory, ".receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(d.stateDirectory, receipt.Engine+".json")); err != nil {
		return err
	}
	return d.syncState()
}

func (d *Docker) syncState() error {
	directory, err := os.Open(d.stateDirectory)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func (d *Docker) destroyEngine(ctx context.Context, receipt engineReceipt) error {
	if !validReceipt(receipt) {
		return errors.New("invalid Athena engine ownership receipt")
	}
	remove := func(name, execution, image string) error {
		var state containerState
		err := d.client.JSON(ctx, http.MethodGet, "/containers/"+url.PathEscape(name)+"/json", nil, &state)
		var remote *docker.Error
		if errors.As(err, &remote) && remote.StatusCode == http.StatusNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		if state.Config.Labels["stackd.athena.execution"] != execution || state.Config.Labels["stackd.athena.owner"] != receipt.Owner || state.Config.Labels["stackd.athena.engine"] != "trino-476" || state.Image != image {
			return errors.New("refusing to remove foreign Trino container; ownership receipt retained")
		}
		return d.client.RemoveContainer(ctx, state.ID)
	}
	var err error
	if receipt.Parser != "" {
		// Parser image may have changed across controller versions; its exact
		// immutable ID is persisted in the receipt alongside the engine image.
		err = remove(receipt.Parser+"-hiveddl", receipt.Parser, receipt.ParserImage)
	}
	err = errors.Join(err, remove(receipt.Engine, receipt.Engine, receipt.Image))
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(d.stateDirectory, receipt.Engine+".json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return d.syncState()
}

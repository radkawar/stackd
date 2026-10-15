package rds

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPostgresCertificatesVerifyConfiguredHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "native.stackd.test"} {
		t.Run(host, func(t *testing.T) {
			ca, certificate, key, err := postgresCertificates(host)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := tls.X509KeyPair(certificate, key)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ca) {
				t.Fatal("public CA is not PEM")
			}
			if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
				t.Fatal(err)
			}
			if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "wrong.stackd.test"}); err == nil {
				t.Fatal("wrong host accepted")
			}
			other, _, _, err := postgresCertificates(host)
			if err != nil {
				t.Fatal(err)
			}
			wrongRoots := x509.NewCertPool()
			wrongRoots.AppendCertsFromPEM(other)
			if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: wrongRoots, DNSName: host}); err == nil {
				t.Fatal("different incarnation CA accepted")
			}
			if bytes.Contains(ca, []byte("PRIVATE KEY")) {
				t.Fatal("public trust contains a private key")
			}
		})
	}
}

func TestPostgresForceSSLCatalog(t *testing.T) {
	for _, engine := range []string{"postgres", "aurora-postgresql"} {
		if value, ok := DefaultParameter(engine, "rds.force_ssl"); !ok || value != "1" {
			t.Fatalf("%s default=%q known=%t", engine, value, ok)
		}
		if StaticParameter(engine, "rds.force_ssl") {
			t.Fatalf("%s version 17 rds.force_ssl must be dynamic", engine)
		}
		for _, value := range []string{"0", "1"} {
			if err := ValidateParameters(engine, map[string]string{"rds.force_ssl": value}); err != nil {
				t.Fatal(err)
			}
		}
		for _, value := range []string{"on", "off", "2", "true", ""} {
			if err := ValidateParameters(engine, map[string]string{"rds.force_ssl": value}); err == nil {
				t.Fatalf("accepted invalid force_ssl=%q", value)
			}
		}
		d := &Docker{}
		for _, value := range []string{"0", "1"} {
			config := d.databaseConfig(Specification{Engine: engine, Parameters: map[string]string{"rds.force_ssl": value}})
			if strings.Contains(strings.Join(config.Cmd, " "), "rds.force_ssl") {
				t.Fatal("RDS policy passed through as nonexistent PostgreSQL GUC")
			}
			if !strings.Contains(strings.Join(config.Cmd, " "), "ssl=on") {
				t.Fatal("TLS disabled when plaintext was permitted")
			}
		}
		if db, err := Open(t.Context(), engine, Endpoint{Address: "127.0.0.1", Port: 1}, "postgres", "owner", "secret"); err == nil {
			db.Close()
			t.Fatal("PostgreSQL Open accepted missing CA")
		}
	}
	for _, engine := range []string{"mysql", "aurora-mysql"} {
		if _, ok := DefaultParameter(engine, "rds.force_ssl"); ok {
			t.Fatal("PostgreSQL policy leaked to MySQL")
		}
		if err := ValidateParameters(engine, map[string]string{"rds.force_ssl": "1"}); err == nil {
			t.Fatal("MySQL accepted PostgreSQL policy")
		}
	}
}

func plaintextPostgres(ctx context.Context, endpoint Endpoint, spec Specification) error {
	config, err := pgx.ParseConfig("postgres://localhost/postgres?sslmode=disable")
	if err != nil {
		return err
	}
	config.Host, config.Port = endpoint.Address, uint16(endpoint.Port)
	config.Database, config.User, config.Password = spec.Database, spec.Username, spec.Password
	config.TLSConfig, config.Fallbacks = nil, nil
	config.RuntimeParams = map[string]string{}
	config.ConnectTimeout = 3 * time.Second
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return err
	}
	return conn.Close(ctx)
}

func TestNativePostgresTLSLifecycle(t *testing.T) {
	for _, engine := range []string{"postgres", "aurora-postgresql"} {
		t.Run(engine, func(t *testing.T) {
			d := nativeRuntime(t)
			d.endpointHost = "localhost"
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
			defer cancel()
			source := Specification{ID: rand.Text(), Engine: engine, Database: "appdb", Username: "owner", Password: rand.Text()}
			target := source
			target.ID = rand.Text()
			snapshot := rand.Text()
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				for _, id := range []string{target.ID, source.ID} {
					if err := d.Delete(cleanup, id); err != nil {
						t.Error(err)
					}
				}
				if err := d.DeleteSnapshot(cleanup, snapshot); err != nil {
					t.Error(err)
				}
				d.Close()
			})
			endpoint, err := d.Ensure(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				assertPostgresTLSVersion(t, ctx, source, endpoint, version)
			}
			db, err := Open(ctx, engine, endpoint, source.Database, source.Username, source.Password)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.ExecContext(ctx, "CREATE TABLE tls_retained (payload bytea NOT NULL); INSERT INTO tls_retained VALUES (decode('00ff0100c328', 'hex'))"); err != nil {
				t.Fatal(err)
			}
			var encrypted bool
			if err := db.QueryRowContext(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&encrypted); err != nil || !encrypted {
				t.Fatalf("connection is not encrypted: %t %v", encrypted, err)
			}
			if err := plaintextPostgres(ctx, endpoint, source); err == nil {
				t.Fatal("default plaintext connection accepted")
			}
			wrong := endpoint
			wrong.Address = "127.0.0.1"
			if invalid, err := Open(ctx, engine, wrong, source.Database, source.Username, source.Password); err == nil {
				invalid.Close()
				t.Fatal("wrong hostname accepted")
			} else {
				var hostname x509.HostnameError
				if !errors.As(err, &hostname) {
					t.Fatalf("wrong hostname failed without hostname verification: %v", err)
				}
			}
			wrong = endpoint
			wrong.CA, _, _, err = postgresCertificates("localhost")
			if err != nil {
				t.Fatal(err)
			}
			if invalid, err := Open(ctx, engine, wrong, source.Database, source.Username, source.Password); err == nil {
				invalid.Close()
				t.Fatal("wrong CA accepted")
			}
			if invalid, err := Open(ctx, engine, endpoint, source.Database, source.Username, "wrong-password"); err == nil {
				invalid.Close()
				t.Fatal("wrong password accepted")
			}
			state, err := d.inspect(ctx, d.name(source.ID, "database"))
			if err != nil {
				t.Fatal(err)
			}
			held, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			if _, err := held.ExecContext(ctx, "CREATE TEMP TABLE tls_uninterrupted (id integer)"); err != nil {
				t.Fatal(err)
			}
			for _, force := range []string{"0", "1", "0", ""} {
				source.Parameters = nil
				if force != "" {
					source.Parameters = map[string]string{"rds.force_ssl": force}
				}
				changed, err := d.Ensure(ctx, source)
				if err != nil {
					t.Fatal(err)
				}
				current, err := d.inspect(ctx, state.ID)
				if err != nil || current.ID != state.ID || !bytes.Equal(changed.CA, endpoint.CA) {
					t.Fatalf("dynamic force change replaced process/trust: %v", err)
				}
				if _, err := held.ExecContext(ctx, "INSERT INTO tls_uninterrupted VALUES (42)"); err != nil {
					t.Fatalf("dynamic force change interrupted session: %v", err)
				}
				plainErr := plaintextPostgres(ctx, changed, source)
				if (force == "0") != (plainErr == nil) {
					t.Fatalf("force_ssl=%s plaintext error=%v", force, plainErr)
				}
				tlsDB, err := Open(ctx, engine, changed, source.Database, source.Username, source.Password)
				if err != nil {
					t.Fatal(err)
				}
				tlsDB.Close()
			}
			held.Close()
			db.Close()
			if err := d.Snapshot(ctx, source, snapshot); err != nil {
				t.Fatal(err)
			}
			restored, err := d.Restore(ctx, target, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(restored.CA, endpoint.CA) {
				t.Fatal("restore reused source incarnation trust")
			}
			assertTLSBytes(t, ctx, target, restored)
			if err := d.Stop(ctx, source.ID); err != nil {
				t.Fatal(err)
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			d, err = NewDocker(DockerConfig{Host: os.Getenv("DOCKER_HOST"), Namespace: d.namespace, EndpointHost: "localhost"})
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := d.Ensure(ctx, source)
			if err != nil || !bytes.Equal(reopened.CA, endpoint.CA) || reopened.Port != endpoint.Port {
				t.Fatalf("restart lost endpoint/trust: %v", err)
			}
			assertTLSBytes(t, ctx, source, reopened)
			if err := plaintextPostgres(ctx, reopened, source); err == nil {
				t.Fatal("restart lost required TLS policy")
			}
		})
	}
}

func assertTLSBytes(t *testing.T, ctx context.Context, spec Specification, endpoint Endpoint) {
	t.Helper()
	db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var payload []byte
	if err := db.QueryRowContext(ctx, "SELECT payload FROM tls_retained").Scan(&payload); err != nil || !bytes.Equal(payload, []byte{0, 255, 1, 0, 195, 40}) {
		t.Fatalf("binary SQL bytes changed: %x %v", payload, err)
	}
}

func TestNativePostgresLegacyTLSUpgrade(t *testing.T) {
	d := nativeRuntime(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	spec := Specification{ID: rand.Text(), Engine: "postgres", Database: "appdb", Username: "owner", Password: rand.Text()}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := d.Delete(cleanup, spec.ID); err != nil {
			t.Error(err)
		}
	})
	// Build the exact previous native-v1 process layout, with the same owned
	// volume and identity, rather than pretending an already-TLS server is old.
	spec.Port = unusedRDSPort(t)
	labels := d.labels(spec.ID, "data")
	labels[labelPrefix+"engine"] = spec.Engine
	labels[labelPrefix+"port"] = portText(spec.Port)
	if _, err := d.volume(ctx, spec.ID, "data", labels, true); err != nil {
		t.Fatal(err)
	}
	config := d.databaseConfig(spec)
	config.Cmd = []string{"postgres", "-c", "listen_addresses=*", "-c", "log_statement=none", "-c", "log_min_error_statement=panic"}
	if err := d.client.JSON(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(d.name(spec.ID, "database")), config, nil); err != nil {
		t.Fatal(err)
	}
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		t.Fatal(err)
	}
	// MySQL initialization would differ, so provision only PostgreSQL's prior
	// credential files here, without calling the new TLS initialization path.
	if err := d.initializeLegacyPostgres(ctx, state, spec); err != nil {
		t.Fatal(err)
	}
	if err := d.start(ctx, state); err != nil {
		t.Fatal(err)
	}
	var conn *pgx.Conn
	for {
		cfg, err := pgx.ParseConfig("postgres://localhost/postgres?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		cfg.Host, cfg.Port = d.endpointHost, uint16(spec.Port)
		cfg.Database, cfg.User, cfg.Password = spec.Database, spec.Username, spec.Password
		cfg.TLSConfig, cfg.Fallbacks = nil, nil
		cfg.RuntimeParams = map[string]string{}
		conn, err = pgx.ConnectConfig(ctx, cfg)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(150 * time.Millisecond):
		}
	}
	if _, err := conn.Exec(ctx, "CREATE TABLE tls_retained (payload bytea NOT NULL); INSERT INTO tls_retained VALUES (decode('00ff0100c328', 'hex'))"); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := conn.QueryRow(ctx, "SELECT system_identifier::text FROM pg_control_system()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	endpoint, err := d.Ensure(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	assertTLSBytes(t, ctx, spec, endpoint)
	if err := plaintextPostgres(ctx, endpoint, spec); err == nil {
		t.Fatal("legacy upgrade retained insecure TCP policy")
	}
	db, err := Open(ctx, spec.Engine, endpoint, spec.Database, spec.Username, spec.Password)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var after string
	if err := db.QueryRowContext(ctx, "SELECT system_identifier::text FROM pg_control_system()").Scan(&after); err != nil || before != after {
		t.Fatalf("legacy upgrade reseeded the cluster: before=%s after=%s error=%v", before, after, err)
	}
}

func unusedRDSPort(t *testing.T) int32 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return int32(port)
}

func portText(port int32) string { return strconv.Itoa(int(port)) }

func (d *Docker) initializeLegacyPostgres(ctx context.Context, state containerState, spec Specification) error {
	var content bytes.Buffer
	archive := tar.NewWriter(&content)
	if err := archive.WriteHeader(&tar.Header{Name: "run/stackd-rds-password", Mode: 0400, Size: int64(len(spec.Password)), Uid: 999, Gid: 999}); err != nil {
		return err
	}
	if _, err := archive.Write([]byte(spec.Password)); err != nil {
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	response, err := d.client.Request(ctx, http.MethodPut, "/containers/"+url.PathEscape(state.ID)+"/archive?path=/", &content, "application/x-tar")
	if err != nil {
		return err
	}
	return response.Body.Close()
}

func assertPostgresTLSVersion(t *testing.T, ctx context.Context, spec Specification, endpoint Endpoint, version uint16) {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(endpoint.CA) {
		t.Fatal("invalid public CA")
	}
	config, err := pgx.ParseConfig("postgres://localhost/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.Host, config.Port = endpoint.Address, uint16(endpoint.Port)
	config.Database, config.User, config.Password = spec.Database, spec.Username, spec.Password
	config.TLSConfig = &tls.Config{RootCAs: roots, ServerName: endpoint.Address, MinVersion: version, MaxVersion: version}
	config.Fallbacks = nil
	config.RuntimeParams = map[string]string{}
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatalf("%s verified native connection: %v", tls.VersionName(version), err)
	}
	defer conn.Close(ctx)
	var negotiated string
	expected := "TLSv1.2"
	if version == tls.VersionTLS13 {
		expected = "TLSv1.3"
	}
	if err := conn.QueryRow(ctx, "SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&negotiated); err != nil || negotiated != expected {
		t.Fatalf("TLS negotiation=%q want %s error=%v", negotiated, expected, err)
	}
}

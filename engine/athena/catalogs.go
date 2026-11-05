package athena

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/gateway"
	"stackd/internal/identity"
)

type queryCallback struct {
	endpoint, token string
	server          *http.Server
	revoked         atomic.Bool
	once            sync.Once
}

func (d *Docker) newCallback(request Request) (*queryCallback, error) {
	listener, err := net.Listen("tcp", d.callbackListen)
	if err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		listener.Close()
		return nil, err
	}
	callback := &queryCallback{token: hex.EncodeToString(token), endpoint: "http://" + net.JoinHostPort(d.callbackHost, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))}
	callback.server = &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A capability belongs to exactly this immutable caller handler. It is
		// never rebound to another query, even when its catalog name is reused.
		_, credential, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=")
		credential, _, _ = strings.Cut(credential, "/")
		if callback.revoked.Load() || subtle.ConstantTimeCompare([]byte(credential), []byte(callback.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128<<20)
		if r.Header.Get("X-Amz-Target") == "" {
			if rejected := gateway.VerifyS3SignedRequest(r, identity.Credential{AccessKeyID: callback.token, SecretAccessKey: "callback-capability"}, request.Region, time.Now()); rejected != nil {
				model, _ := awscatalog.LookupService("s3")
				awswire.RESTXMLError(w, r, &model, rejected)
				return
			}
		}
		if !admitCatalogCallback(w, r, request) {
			return
		}
		r.Header.Del("Authorization")
		request.Handler.ServeHTTP(w, r)
	})}
	go func() { _ = callback.server.Serve(listener) }()
	return callback, nil
}

func (callback *queryCallback) close() {
	callback.once.Do(func() {
		callback.revoked.Store(true)
		_ = callback.server.Close()
	})
}

type queryCatalog struct {
	name, connector string
	properties      map[string]string
}

func (catalog queryCatalog) createSQL() string {
	keys := make([]string, 0, len(catalog.properties))
	for key := range catalog.properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var sql strings.Builder
	sql.WriteString("CREATE CATALOG " + quoteSQLIdentifier(catalog.name) + " USING " + catalog.connector + " WITH (")
	for i, key := range keys {
		if i > 0 {
			sql.WriteString(", ")
		}
		sql.WriteString(quoteSQLIdentifier(key) + " = " + quoteSQLString(catalog.properties[key]))
	}
	sql.WriteByte(')')
	return sql.String()
}

// Public selected catalogs keep their Hive/Glue meaning even when their name
// collides with a convenience redirect. Only private connector aliases move.
func catalogAliases(request Request) (iceberg, delta, defaultPrefix string) {
	redirects := registrationRedirects(request)
	selected := strings.ToLower(request.Catalog)
	if selected == "" {
		selected = "awsdatacatalog"
	}
	iceberg, delta = redirects[selected].iceberg, redirects[selected].delta
	if defaults, ok := redirects["awsdatacatalog"]; ok && defaults.iceberg != iceberg {
		defaultPrefix = strings.TrimSuffix(defaults.iceberg, "iceberg")
	}
	return
}

func queryCatalogs(request Request, endpoint, token string) []queryCatalog {
	catalogs := make([]queryCatalog, 0, len(publicCatalogs(request))*3)
	redirects := registrationRedirects(request)
	add := func(name, connector, catalogID, publicName, redirectIceberg, redirectDelta string) {
		scopedEndpoint := catalogEndpoint(request, endpoint, publicName)
		properties := map[string]string{
			"hive.metastore.glue.region":            request.Region,
			"hive.metastore.glue.endpoint-url":      scopedEndpoint,
			"hive.metastore.glue.aws-access-key":    token,
			"hive.metastore.glue.aws-secret-key":    "callback-capability",
			"hive.metastore.glue.max-error-retries": "1",
			"hive.metastore-cache-ttl":              "0s",
			"hive.metastore-stats-cache-ttl":        "0s",
			"hive.metastore.glue.catalogid":         catalogID,
			"fs.native-s3.enabled":                  "true",
			"s3.endpoint":                           scopedEndpoint,
			"s3.region":                             request.Region,
			"s3.path-style-access":                  "true",
			"s3.aws-access-key":                     token,
			"s3.aws-secret-key":                     "callback-capability",
			"s3.max-error-retries":                  "1",
		}
		switch connector {
		case "iceberg":
			properties["iceberg.catalog.type"] = "glue"
		case "delta_lake":
			properties["hive.metastore"] = "glue"
			properties["delta.security"] = "READ_ONLY"
		default:
			properties["hive.metastore"] = "glue"
			properties["hive.non-managed-table-writes-enabled"] = "true"
			properties["hive.iceberg-catalog-name"] = redirectIceberg
			properties["hive.delta-lake-catalog-name"] = redirectDelta
		}
		catalogs = append(catalogs, queryCatalog{name: name, connector: connector, properties: properties})
	}
	created := map[string]bool{}
	for _, registration := range publicCatalogs(request) {
		if registration.Kind != "GLUE" {
			continue
		}
		name := strings.ToLower(registration.Name)
		redirect := redirects[name]
		if !created[redirect.iceberg] {
			add(redirect.iceberg, "iceberg", registration.CatalogID, name, "", "")
			created[redirect.iceberg] = true
		}
		if !created[redirect.delta] {
			add(redirect.delta, "delta_lake", registration.CatalogID, name, "", "")
			created[redirect.delta] = true
		}
		add(name, "hive", registration.CatalogID, name, redirect.iceberg, redirect.delta)
	}
	// TODO: Comeback execute non-GLUE HIVE, LAMBDA and FEDERATED Athena
	// registrations through their actual connector runtimes and authorization
	// boundaries; these registrations are not native Glue catalogs.
	return catalogs
}

func configuration(request Request, handle string, network *executionNetwork) ([]byte, error) {
	files := map[string]string{
		"node.properties":                    "node.environment=stackd\nnode.id=" + handle + "\nnode.data-dir=/data/trino\n" + network.nodeProperties,
		"jvm.config":                         "-server\n-Xms512m\n-Xmx2g\n-XX:+ExitOnOutOfMemoryError\n-XX:ReservedCodeCacheSize=256M\n-Djdk.attach.allowAttachSelf=true\n-XX:+EnableDynamicAgentLoading\n-Dfile.encoding=UTF-8\n",
		"config.properties":                  "coordinator=true\nnode-scheduler.include-coordinator=true\nhttp-server.http.port=" + network.port + "\ndiscovery.uri=http://127.0.0.1:" + network.port + "\nplugin.dir=/usr/lib/trino/plugin\nquery.max-memory=1GB\nquery.max-memory-per-node=1GB\nmemory.heap-headroom-per-node=512MB\nquery.max-run-time=30m\nquery.client.timeout=2m\ncatalog.management=dynamic\ncatalog.store=file\ncatalog.prune.update-interval=1s\n",
		"log.properties":                     "io.trino=INFO\n",
		"catalog/__stackd_worker.properties": "connector.name=jmx\n",
		"access-control.properties":          "access-control.name=file\nsecurity.config-file=/tmp/stackd-athena/access-control.json\n",
		// OWNER is required by native CREATE/DROP CATALOG. Customer ALL is not
		// OWNER, and can neither replace callback properties nor read the probe.
		"access-control.json": `{"catalogs":[{"user":"stackd-readiness","catalog":"__stackd_worker","allow":"read-only"},{"catalog":"__stackd_worker","allow":"none"},{"user":"stackd-catalog-manager","catalog":".*","allow":"owner"},{"user":"athena","catalog":".*","allow":"all"}]}`,
		// The launcher links DATA_DIR/etc to --etc-dir. Dynamic store options
		// belong in this separate file, not the server's main configuration.
		"catalog-store.properties": "catalog.config-dir=/tmp/stackd-athena/catalog\n",
		"StackdCTAS.java":          ctasParserSource,
	}
	if request.BytesCutoff > 0 {
		// Keep the unraisable cluster cap: a changed workgroup limit retires the
		// old scoped engine instead of relying on a customer-mutable session cap.
		files["config.properties"] = fmt.Sprintf("%squery.max-scan-physical-bytes=%dB\n", files["config.properties"], request.BytesCutoff)
	}
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

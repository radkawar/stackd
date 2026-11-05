package glue

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
	"stackd/internal/services/glue/icebergmeta"
)

// IcebergObjects is the caller-authorized S3 boundary. All I/O takes place
// outside catalog transactions; only the immutable metadata pointer is retained.
type IcebergObjects interface {
	Read(context.Context, string) ([]byte, error)
	Write(context.Context, string, []byte) error
}

type icebergRoute struct {
	catalog, namespace, table, resource string
}

type icebergFailure struct {
	Code    int    `json:"code"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

type icebergErrorResponse struct {
	Error icebergFailure `json:"error"`
}

func icebergError(code int, kind, message string) error {
	return &icebergmeta.Error{Code: code, Type: kind, Message: message}
}

func writeIceberg(w http.ResponseWriter, status int, out any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if out != nil {
		_ = json.NewEncoder(w).Encode(out)
	}
}

func writeIcebergError(w http.ResponseWriter, err error) {
	var native *icebergmeta.Error
	if errors.As(err, &native) {
		writeIceberg(w, native.Code, icebergErrorResponse{icebergFailure{Code: native.Code, Type: native.Type, Message: native.Message}})
		return
	}
	status, kind, message := 500, "ServiceFailureException", "Unable to complete Glue Iceberg operation."
	if errors.Is(err, ErrNotFound) {
		status, kind, message = 404, "NoSuchTableException", "The catalog object does not exist."
	} else {
		var wire *awswire.Error
		if errors.As(err, &wire) {
			status, kind, message = wire.StatusCode, wire.Code, wire.Message
			switch wire.Code {
			case "AccessDenied", "AccessDeniedException":
				status, kind = 403, "ForbiddenException"
			case "AlreadyExistsException":
				status = 409
			case "EntityNotFoundException", "NoSuchKey", "NoSuchBucket":
				status = 404
			case "ConcurrentModificationException":
				status, kind = 409, "CommitFailedException"
			}
		}
	}
	writeIceberg(w, status, icebergErrorResponse{icebergFailure{Code: status, Type: kind, Message: message}})
}

func decodeIceberg(r *http.Request, out any) error {
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(out); err != nil {
		return icebergError(400, "BadRequestException", "Invalid JSON request body.")
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return icebergError(400, "BadRequestException", "Expected a single JSON request body.")
	}
	return nil
}

// PrivateOperation selects the separately specified Iceberg REST protocol. The
// gateway still verifies genuine SigV4 credentials with signing service glue.
func (s *Service) PrivateOperation(r *http.Request) (string, bool) {
	if r.URL.Path != "/iceberg" && !strings.HasPrefix(r.URL.Path, "/iceberg/") {
		return "", false
	}
	route, _ := parseIcebergRoute(r)
	action := "GetCatalog"
	switch route.resource {
	case "namespaces":
		action = "GetDatabases"
		if r.Method == http.MethodPost {
			action = "CreateDatabase"
		}
	case "namespace":
		action = "GetDatabase"
		if r.Method == http.MethodDelete {
			action = "DeleteDatabase"
		}
	case "properties":
		action = "UpdateDatabase"
	case "tables":
		action = "GetTables"
		if r.Method == http.MethodPost {
			action = "CreateTable"
		}
	case "table":
		action = "GetTable"
		if r.Method == http.MethodPost {
			action = "UpdateTable"
		}
		if r.Method == http.MethodDelete {
			action = "DeleteTable"
		}
	}
	return action, true
}

func parseIcebergRoute(r *http.Request) (icebergRoute, error) {
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/iceberg/v1/")
	if path == r.URL.EscapedPath() {
		return icebergRoute{}, icebergError(404, "NoSuchResourceException", "Unknown Iceberg REST route.")
	}
	if path == "config" {
		return icebergRoute{resource: "config", catalog: r.URL.Query().Get("warehouse")}, nil
	}
	parts := strings.Split(path, "/")
	for i := range parts {
		var err error
		parts[i], err = url.PathUnescape(parts[i])
		if err != nil || i != 1 && strings.Contains(parts[i], "/") || parts[i] == "" {
			return icebergRoute{}, icebergError(400, "BadRequestException", "Invalid Iceberg REST path component.")
		}
	}
	if len(parts) < 3 || parts[0] != "catalogs" || parts[2] != "namespaces" {
		return icebergRoute{}, icebergError(404, "NoSuchResourceException", "Unknown Iceberg REST route.")
	}
	route := icebergRoute{catalog: parts[1], resource: "namespaces"}
	if len(parts) == 3 {
		return route, nil
	}
	if !validIcebergName(parts[3]) {
		return route, icebergError(400, "BadRequestException", "Glue supports single-level lowercase namespaces.")
	}
	route.namespace, route.resource = parts[3], "namespace"
	if len(parts) == 4 {
		return route, nil
	}
	if len(parts) == 5 && parts[4] == "properties" {
		route.resource = "properties"
		return route, nil
	}
	if parts[4] != "tables" {
		return route, icebergError(404, "NoSuchResourceException", "Unknown Iceberg REST route.")
	}
	route.resource = "tables"
	if len(parts) == 5 {
		return route, nil
	}
	if len(parts) != 6 || !validIcebergName(parts[5]) {
		return route, icebergError(400, "BadRequestException", "Invalid Glue table name.")
	}
	route.table, route.resource = parts[5], "table"
	return route, nil
}

func validIcebergName(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || name != strings.ToLower(name) {
		return false
	}
	for _, c := range name {
		if c == '/' || unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func icebergCatalog(ctx context.Context, name string) (CatalogKey, error) {
	scope := scopeFor(ctx)
	if name == "" || name == ":" {
		name = scope.AccountID
	}
	// Glue's catalog identifier is account[:child[:grandchild]]. Nested
	// catalogs use the same typed Glue repository, not a REST-only warehouse.
	account, _, _ := strings.Cut(name, ":")
	if len(account) != 12 {
		return CatalogKey{}, icebergError(400, "BadRequestException", "Warehouse must be a Glue catalog account identifier.")
	}
	for _, c := range account {
		if c < '0' || c > '9' {
			return CatalogKey{}, icebergError(400, "BadRequestException", "Invalid Glue catalog account.")
		}
	}
	scope.AccountID = account
	return CatalogKey{Scope: scope, CatalogID: name}, nil
}

func (s *Service) ServePrivateOperation(w http.ResponseWriter, r *http.Request) {
	route, err := parseIcebergRoute(r)
	if err != nil {
		writeIcebergError(w, err)
		return
	}
	catalog, err := icebergCatalog(r.Context(), route.catalog)
	if err != nil {
		writeIcebergError(w, err)
		return
	}
	bucket, managed, err := s.icebergFederation(r.Context(), catalog)
	if err != nil {
		writeIcebergError(w, err)
		return
	}
	if managed {
		out, status, err := s.serveFederatedIceberg(r, catalog, bucket, route)
		if err != nil {
			writeIcebergError(w, err)
		} else {
			writeIceberg(w, status, out)
		}
		return
	}
	var out any
	status := http.StatusOK
	switch route.resource {
	case "config":
		if r.Method != http.MethodGet {
			err = icebergMethodError()
			break
		}
		out, err = s.icebergConfig(r.Context(), catalog)
	case "namespaces", "namespace", "properties":
		out, status, err = s.icebergNamespace(r, catalog, route)
	case "tables":
		key := DatabaseKey{CatalogKey: catalog, Name: route.namespace}
		switch r.Method {
		case http.MethodGet:
			out, err = s.icebergListTables(r, key)
		case http.MethodPost:
			var in icebergmeta.CreateRequest
			if err = decodeIceberg(r, &in); err == nil {
				out, err = s.icebergCreateTable(r.Context(), key, in)
			}
		default:
			err = icebergMethodError()
		}
	case "table":
		key := TableKey{DatabaseKey: DatabaseKey{CatalogKey: catalog, Name: route.namespace}, TableName: route.table}
		switch r.Method {
		case http.MethodGet:
			out, err = s.icebergLoadTable(r.Context(), key)
		case http.MethodHead:
			err = s.icebergTableExists(r.Context(), key)
			status = http.StatusNoContent
		case http.MethodPost:
			var in icebergmeta.CommitRequest
			if err = decodeIceberg(r, &in); err == nil {
				out, err = s.icebergCommitTable(r.Context(), key, in)
			}
		case http.MethodDelete:
			err = s.icebergDropTable(r, key)
			status = http.StatusNoContent
		default:
			err = icebergMethodError()
		}
	}
	if err != nil {
		writeIcebergError(w, err)
		return
	}
	writeIceberg(w, status, out)
}

func icebergMethodError() error {
	return icebergError(405, "UnsupportedOperationException", "Unsupported Iceberg REST method.")
}

func icebergPage(r *http.Request, binding string) (string, int, error) {
	limit := 100
	if raw := r.URL.Query().Get("pageSize"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 1000 {
			return "", 0, icebergError(400, "BadRequestException", "pageSize must be between 1 and 1000.")
		}
	}
	// The REST specification requires an unpaginated response when pageToken
	// is absent, even if a client supplied pageSize.
	if !r.URL.Query().Has("pageToken") {
		limit = math.MaxInt
	}
	token := r.URL.Query().Get("pageToken")
	if token == "" {
		return "", limit, nil
	}
	after, err := catalogPageAfter(new(api.Token(token)), binding)
	return after, limit, err
}

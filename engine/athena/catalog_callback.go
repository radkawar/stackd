package athena

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"stackd/internal/awswire"
)

// admitCatalogCallback binds both metastore and object operations to the public
// registration that supplied their connector endpoint. Revalidation is on every
// request, including S3 calls after Trino has cached table metadata.
func admitCatalogCallback(w http.ResponseWriter, r *http.Request, request Request) bool {
	if request.AuthorizeCatalog == nil {
		return true
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/__stackd_catalog/")
	if !ok {
		http.Error(w, "catalog capability required", http.StatusForbidden)
		return false
	}
	name, suffix, _ := strings.Cut(path, "/")
	var registration CatalogRegistration
	found := false
	for _, candidate := range request.Catalogs {
		if strings.EqualFold(name, candidate.Name) && candidate.Kind == "GLUE" {
			registration = candidate
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "catalog not admitted", http.StatusForbidden)
		return false
	}
	if err := request.AuthorizeCatalog(r.Context(), registration); err != nil {
		awswire.JSONError(w, r, &awswire.Error{Code: "AccessDeniedException", Message: "The current caller is not authorized for this catalog registration.", StatusCode: http.StatusForbidden})
		return false
	}
	if target := r.Header.Get("X-Amz-Target"); target != "" {
		_, operation, valid := awswire.JSONTarget(target)
		if !valid || !nativeGlueOperation(operation) {
			http.Error(w, "unsupported catalog capability operation", http.StatusForbidden)
			return false
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid catalog request", http.StatusBadRequest)
			return false
		}
		var input map[string]json.RawMessage
		if json.Unmarshal(body, &input) != nil || input == nil {
			http.Error(w, "invalid catalog request", http.StatusBadRequest)
			return false
		}
		var id string
		if raw, exists := input["CatalogId"]; exists {
			if json.Unmarshal(raw, &id) != nil || id != registration.CatalogID {
				http.Error(w, "catalog capability mismatch", http.StatusForbidden)
				return false
			}
		} else {
			input["CatalogId"], _ = json.Marshal(registration.CatalogID)
		}
		body, err = json.Marshal(input)
		if err != nil {
			http.Error(w, "invalid catalog request", http.StatusBadRequest)
			return false
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	r.URL.Path = "/" + suffix
	r.URL.RawPath = ""
	r.RequestURI = r.URL.RequestURI()
	return true
}

func nativeGlueOperation(operation string) bool {
	switch operation {
	case "GetDatabase", "GetDatabases", "CreateDatabase", "UpdateDatabase", "DeleteDatabase",
		"GetTable", "GetTables", "CreateTable", "UpdateTable", "DeleteTable", "BatchDeleteTable", "GetTableVersion", "GetTableVersions",
		"GetPartition", "GetPartitions", "BatchGetPartition", "CreatePartition", "BatchCreatePartition", "UpdatePartition", "BatchUpdatePartition", "DeletePartition", "BatchDeletePartition",
		"GetColumnStatisticsForTable", "UpdateColumnStatisticsForTable", "DeleteColumnStatisticsForTable", "GetColumnStatisticsForPartition", "UpdateColumnStatisticsForPartition", "DeleteColumnStatisticsForPartition":
		return true
	default:
		return false
	}
}

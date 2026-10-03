package glue

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"

	api "stackd/internal/awsapi/glue"
)

func registerCatalog(s *Service) {
	registerControl(s, "CreateCatalog", s.createCatalog)
	registerControl(s, "GetCatalog", s.getCatalog)
	registerControl(s, "GetCatalogs", s.getCatalogs)
	registerControl(s, "DeleteCatalog", s.deleteCatalog)
	registerControl(s, "CreateDatabase", s.createDatabase)
	registerControl(s, "GetDatabase", s.getDatabase)
	registerControl(s, "GetDatabases", s.getDatabases)
	registerControl(s, "UpdateDatabase", s.updateDatabase)
	registerControl(s, "DeleteDatabase", s.deleteDatabase)
	registerControl(s, "CreateTable", s.createTable)
	registerControl(s, "GetTable", s.getTable)
	registerControl(s, "GetTables", s.getTables)
	registerControl(s, "UpdateTable", s.updateTable)
	registerControl(s, "DeleteTable", s.deleteTable)
	registerControl(s, "BatchDeleteTable", s.batchDeleteTable)
	registerControl(s, "GetTableVersion", s.getTableVersion)
	registerControl(s, "GetTableVersions", s.getTableVersions)
	registerControl(s, "DeleteTableVersion", s.deleteTableVersion)
	registerControl(s, "CreatePartition", s.createPartition)
	registerControl(s, "GetPartition", s.getPartition)
	registerControl(s, "GetPartitions", s.getPartitions)
	registerControl(s, "UpdatePartition", s.updatePartition)
	registerControl(s, "DeletePartition", s.deletePartition)
	registerControl(s, "BatchCreatePartition", s.batchCreatePartition)
	registerControl(s, "BatchGetPartition", s.batchGetPartition)
	registerControl(s, "BatchUpdatePartition", s.batchUpdatePartition)
	registerControl(s, "BatchDeletePartition", s.batchDeletePartition)
	registerControl(s, "CreatePartitionIndex", s.createPartitionIndex)
	registerControl(s, "GetPartitionIndexes", s.getPartitionIndexes)
	registerControl(s, "DeletePartitionIndex", s.deletePartitionIndex)
	registerControl(s, "CreateUserDefinedFunction", s.createUserDefinedFunction)
	registerControl(s, "GetUserDefinedFunction", s.getUserDefinedFunction)
	registerControl(s, "GetUserDefinedFunctions", s.getUserDefinedFunctions)
	registerControl(s, "UpdateUserDefinedFunction", s.updateUserDefinedFunction)
	registerControl(s, "DeleteUserDefinedFunction", s.deleteUserDefinedFunction)
	registerControl(s, "GetColumnStatisticsForTable", s.getColumnStatisticsForTable)
	registerControl(s, "UpdateColumnStatisticsForTable", s.updateColumnStatisticsForTable)
	registerControl(s, "DeleteColumnStatisticsForTable", s.deleteColumnStatisticsForTable)
	registerControl(s, "GetColumnStatisticsForPartition", s.getColumnStatisticsForPartition)
	registerControl(s, "UpdateColumnStatisticsForPartition", s.updateColumnStatisticsForPartition)
	registerControl(s, "DeleteColumnStatisticsForPartition", s.deleteColumnStatisticsForPartition)
	registerControl(s, "PutResourcePolicy", s.putResourcePolicy)
	registerControl(s, "GetResourcePolicy", s.getResourcePolicy)
	registerControl(s, "DeleteResourcePolicy", s.deleteResourcePolicy)
	registerControl(s, "ImportCatalogToGlue", s.importCatalogToGlue)
	registerControl(s, "GetCatalogImportStatus", s.getCatalogImportStatus)
}

type catalogCursor struct{ Binding, After string }

func catalogPageBinding(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}
func catalogPageAfter(token *api.Token, binding string) (string, error) {
	if token == nil {
		return "", nil
	}
	data, err := base64.RawURLEncoding.DecodeString(string(*token))
	if err != nil {
		return "", failure("InvalidInputException", "Invalid continuation token.")
	}
	var cursor catalogCursor
	if json.Unmarshal(data, &cursor) != nil || cursor.Binding != binding {
		return "", failure("InvalidInputException", "Continuation token does not match the request.")
	}
	return cursor.After, nil
}
func catalogNextToken(binding, after string) *api.Token {
	data, _ := json.Marshal(catalogCursor{Binding: binding, After: after})
	return new(api.Token(base64.RawURLEncoding.EncodeToString(data)))
}
func catalogPageSize[T ~int32](size *T) int {
	if size == nil {
		return 100
	}
	return int(*size)
}
func catalogNameFilter(expression string) (*regexp.Regexp, error) {
	if expression == "" {
		return nil, nil
	}
	pattern, err := regexp.Compile("^(?:" + expression + ")$")
	if err != nil {
		return nil, failure("InvalidInputException", "Invalid name filter expression.")
	}
	return pattern, nil
}
func catalogTags(tags api.TagsMap) map[string]string {
	out := make(map[string]string, len(tags))
	for key, v := range tags {
		out[string(key)] = string(v)
	}
	return out
}
func catalogErrorDetail(err error) *api.ErrorDetail {
	e := wireError(err)
	return &api.ErrorDetail{ErrorCode: new(api.NameString(e.Code)), ErrorMessage: new(api.DescriptionString(e.Message))}
}

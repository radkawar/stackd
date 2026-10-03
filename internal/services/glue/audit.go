package glue

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, ok := awscatalog.LookupService("glue")
	if !ok {
		return errors.New("glue audit metadata is missing")
	}
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "BatchGet") || strings.HasPrefix(action, "Check") || strings.HasPrefix(action, "Query")}
	// Connection property maps contain passwords and credential-bearing endpoints
	// not modeled as sensitive leaves. Omit them even when the call is rejected.
	in = sanitizeConnectionAudit(in)
	switch action {
	case "CreateConnection", "UpdateConnection":
		projection.Request = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"ConnectionInput.AuthenticationConfiguration.CustomAuthenticationCredentials": {Mode: awsapi.OmitField}, "ConnectionInput.AuthenticationConfiguration.OAuth2Properties.OAuth2Credentials": {Mode: awsapi.OmitField}}}
	}
	call, err := projection.Call(model, operation, in, out, rejected)
	if err != nil {
		return err
	}
	if err := completeCatalogAudit(ctx, in, &call); err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

// These defaults and resource sets come from exact-request native catalog
// captures. Read responses/resources remain distinct from write observations.
func completeCatalogAudit(ctx context.Context, input any, call *journal.APICallCompleted) error {
	switch in := input.(type) {
	case *api.GetDatabaseInput:
		var request map[string]any
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
		if request == nil {
			return nil
		}
		if _, present := request["federateToSource"]; !present {
			request["federateToSource"] = false
		}
		var err error
		call.RequestParameters, err = json.Marshal(request)
		return err
	case *api.UpdateDatabaseInput:
		if call.ErrorCode == "" {
			key := databaseKey(ctx, in.CatalogId, in.Name)
			call.EventResources = []journal.APIEventResource{
				{AccountID: key.AccountID, Type: "AWS::Glue::Catalog", ARN: key.CatalogKey.ARN()},
				{AccountID: key.AccountID, Type: "AWS::Glue::Database", ARN: key.ARN()},
			}
		}
	case *api.CreateTableInput:
		var request map[string]any
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
		if table, ok := request["tableInput"].(map[string]any); ok {
			if _, present := table["retention"]; !present {
				table["retention"] = 0
			}
			table["isRowFilteringEnabled"] = false
			if storage, ok := table["storageDescriptor"].(map[string]any); ok {
				for field, value := range map[string]any{"compressed": false, "numberOfBuckets": 0, "storedAsSubDirectories": false} {
					if _, present := storage[field]; !present {
						storage[field] = value
					}
				}
			}
		}
		var err error
		call.RequestParameters, err = json.Marshal(request)
		if err != nil {
			return err
		}
		if call.ErrorCode == "" {
			key := tableKey(ctx, in.CatalogId, in.DatabaseName, in.TableInput.Name)
			call.EventResources = []journal.APIEventResource{
				{AccountID: key.AccountID, Type: "AWS::Glue::Catalog", ARN: key.CatalogKey.ARN()},
				{AccountID: key.AccountID, Type: "AWS::Glue::Database", ARN: key.DatabaseKey.ARN()},
				{AccountID: key.AccountID, Type: "AWS::Glue::Table", ARN: key.ARN()},
			}
		}
	}
	return nil
}
func auditConnectionProperties[M ~map[K]V, K ~string, V ~string](properties M) (M, bool) {
	var out M
	for key, value := range properties {
		property := strings.ToUpper(string(key))
		omit := strings.Contains(property, "PASSWORD") || strings.Contains(property, "TOKEN") || strings.Contains(property, "CLIENT_KEY")
		if strings.HasSuffix(property, "_URL") || strings.HasSuffix(property, "_URI") {
			omit = omit || !safeConnectionAuditEndpoint(string(value))
		}
		if omit {
			if out == nil {
				out = maps.Clone(properties)
			}
			delete(out, key)
		}
	}
	return out, out != nil
}

func safeConnectionAuditEndpoint(raw string) bool {
	// JDBC adds a wrapper scheme. Opaque vendor DSNs cannot be safely projected.
	endpoint, err := url.Parse(strings.TrimPrefix(raw, "jdbc:"))
	if err != nil || endpoint.Scheme == "" || endpoint.Hostname() == "" || endpoint.Opaque != "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return false
	}
	// Vendor path/host parameters and nested escaping can hide credentials even
	// when net/url cannot classify them as userinfo or a query.
	return !strings.ContainsAny(endpoint.Host, "@;=\\") && !strings.ContainsAny(endpoint.Path, "@:;=?#\\%")
}
func sanitizeConnectionAudit(in any) any {
	switch input := in.(type) {
	case *api.CreateConnectionInput:
		if input != nil && input.ConnectionInput != nil {
			if connection := auditConnectionInput(input.ConnectionInput); connection != input.ConnectionInput {
				copy := *input
				copy.ConnectionInput = connection
				return &copy
			}
		}
	case *api.UpdateConnectionInput:
		if input != nil && input.ConnectionInput != nil {
			if connection := auditConnectionInput(input.ConnectionInput); connection != input.ConnectionInput {
				copy := *input
				copy.ConnectionInput = connection
				return &copy
			}
		}
	}
	return in
}

func auditConnectionInput(input *api.ConnectionInput) *api.ConnectionInput {
	connection := *input
	changed := false
	if properties, omitted := auditConnectionProperties(input.ConnectionProperties); omitted {
		connection.ConnectionProperties, changed = properties, true
	}
	if properties, omitted := auditConnectionProperties(input.AthenaProperties); omitted {
		connection.AthenaProperties, changed = properties, true
	}
	if properties, omitted := auditConnectionProperties(input.SparkProperties); omitted {
		connection.SparkProperties, changed = properties, true
	}
	if properties, omitted := auditConnectionProperties(input.PythonProperties); omitted {
		connection.PythonProperties, changed = properties, true
	}
	if changed {
		return &connection
	}
	return input
}

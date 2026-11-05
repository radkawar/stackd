package glue

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/glue"
	"stackd/internal/awswire"
	"stackd/internal/services/glue/icebergmeta"
)

type icebergNamespaceRequest struct {
	Namespace  []string          `json:"namespace"`
	Properties map[string]string `json:"properties"`
}

type icebergNamespaceResponse struct {
	Namespace  []string          `json:"namespace"`
	Properties map[string]string `json:"properties"`
}

type icebergNamespaceList struct {
	Namespaces    [][]string `json:"namespaces"`
	NextPageToken string     `json:"next-page-token,omitempty"`
}

// icebergTransaction joins catalog changes, API outcomes and catalog events in
// the existing Glue transaction domain. Native S3 effects happen before entry.
func (s *Service) icebergTransaction(ctx context.Context, catalog CatalogKey, action string, input any, fn func(context.Context, Transaction) error) error {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return err
	}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		if err := s.authorizeCatalog(ctx, tx, "GetCatalog", catalog); err != nil {
			return err
		}
		if err := s.requireOrdinaryIcebergCatalog(ctx, tx, catalog); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		if err := s.publishCatalogCall(ctx, action, input); err != nil {
			return err
		}
		return s.recordCall(ctx, action, input, nil, nil)
	})
	if err != nil {
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		var rejected *awswire.Error
		var native *icebergmeta.Error
		if errors.As(err, &native) {
			rejected = &awswire.Error{Code: native.Type, Message: native.Message, StatusCode: native.Code}
		} else {
			rejected = wireError(err)
		}
		if recorded := s.recordCall(completion, action, input, nil, rejected); recorded != nil {
			return recorded
		}
	}
	return err
}

func (s *Service) icebergConfig(ctx context.Context, catalog CatalogKey) (any, error) {
	err := s.icebergTransaction(ctx, catalog, "GetCatalog", &api.GetCatalogInput{CatalogId: new(api.CatalogIdString(catalog.CatalogID))}, func(context.Context, Transaction) error { return nil })
	if err != nil {
		return nil, err
	}
	return struct {
		Defaults  map[string]string `json:"defaults"`
		Overrides map[string]string `json:"overrides"`
		Endpoints []string          `json:"endpoints"`
	}{Defaults: map[string]string{}, Overrides: map[string]string{"prefix": "catalogs/" + catalog.CatalogID}, Endpoints: []string{
		"GET /v1/{prefix}/namespaces", "POST /v1/{prefix}/namespaces",
		"GET /v1/{prefix}/namespaces/{namespace}", "HEAD /v1/{prefix}/namespaces/{namespace}",
		"DELETE /v1/{prefix}/namespaces/{namespace}", "POST /v1/{prefix}/namespaces/{namespace}/properties",
		"GET /v1/{prefix}/namespaces/{namespace}/tables", "POST /v1/{prefix}/namespaces/{namespace}/tables",
		"GET /v1/{prefix}/namespaces/{namespace}/tables/{table}", "HEAD /v1/{prefix}/namespaces/{namespace}/tables/{table}",
		"POST /v1/{prefix}/namespaces/{namespace}/tables/{table}", "DELETE /v1/{prefix}/namespaces/{namespace}/tables/{table}",
	}}, nil
}

func namespaceProperties(db api.Database) map[string]string {
	properties := make(map[string]string, len(db.Parameters)+2)
	for k, v := range db.Parameters {
		properties[string(k)] = string(v)
	}
	if db.LocationUri != nil {
		properties["location"] = string(*db.LocationUri)
	}
	if db.Description != nil {
		properties["comment"] = string(*db.Description)
	}
	return properties
}

func namespaceInput(name string, properties map[string]string) *api.DatabaseInput {
	in := &api.DatabaseInput{Name: new(api.NameString(name)), Parameters: api.ParametersMap{}}
	for k, v := range properties {
		switch k {
		case "location":
			in.LocationUri = new(api.URI(v))
		case "comment":
			in.Description = new(api.DescriptionString(v))
		default:
			in.Parameters[api.KeyString(k)] = api.ParametersMapValue(v)
		}
	}
	return in
}

func (s *Service) icebergNamespace(r *http.Request, catalog CatalogKey, route icebergRoute) (any, int, error) {
	ctx := r.Context()
	id := new(api.CatalogIdString(catalog.CatalogID))
	key := DatabaseKey{CatalogKey: catalog, Name: route.namespace}
	var out any
	status := http.StatusOK
	var err error
	switch {
	case route.resource == "namespaces" && r.Method == http.MethodGet:
		binding := catalogPageBinding("IcebergListNamespaces", catalog.ARN(), r.URL.Query().Get("parent"))
		after, limit, pageErr := icebergPage(r, binding)
		if pageErr != nil {
			return nil, 0, pageErr
		}
		in := &api.GetDatabasesInput{CatalogId: id}
		list := icebergNamespaceList{Namespaces: [][]string{}}
		err = s.icebergTransaction(ctx, catalog, "GetDatabases", in, func(ctx context.Context, tx Transaction) error {
			if err := s.authorizeCatalog(ctx, tx, "GetDatabases", catalog); err != nil {
				return err
			}
			if parent := r.URL.Query().Get("parent"); parent != "" {
				parentKey := DatabaseKey{CatalogKey: catalog, Name: parent}
				if !validIcebergName(parent) {
					return icebergError(400, "BadRequestException", "Glue supports single-level namespaces.")
				}
				if err := s.authorizeDatabase(ctx, tx, "GetDatabase", parentKey); err != nil {
					return err
				}
				if _, err := tx.Database(parentKey); errors.Is(err, ErrNotFound) {
					return icebergError(404, "NoSuchNamespaceException", "Parent namespace does not exist.")
				} else {
					return err
				}
			}
			rows, err := tx.Databases(catalog)
			if err != nil {
				return err
			}
			for _, row := range rows {
				if row.Key.Name <= after {
					continue
				}
				if err := s.authorizeDatabase(ctx, tx, "GetDatabases", row.Key); err != nil {
					if wireError(err).Code == "AccessDeniedException" {
						continue
					}
					return err
				}
				if len(list.Namespaces) == limit {
					list.NextPageToken = string(*catalogNextToken(binding, list.Namespaces[len(list.Namespaces)-1][0]))
					break
				}
				list.Namespaces = append(list.Namespaces, []string{row.Key.Name})
			}
			return nil
		})
		out = list
	case route.resource == "namespaces" && r.Method == http.MethodPost:
		var request icebergNamespaceRequest
		if err = decodeIceberg(r, &request); err != nil {
			break
		}
		if len(request.Namespace) != 1 || !validIcebergName(request.Namespace[0]) {
			err = icebergError(400, "BadRequestException", "Glue requires one lowercase namespace name.")
			break
		}
		in := &api.CreateDatabaseInput{CatalogId: id, DatabaseInput: namespaceInput(request.Namespace[0], request.Properties)}
		err = s.icebergTransaction(ctx, catalog, "CreateDatabase", in, func(ctx context.Context, tx Transaction) error {
			_, err := s.createDatabase(ctx, tx, in)
			return err
		})
		out = icebergNamespaceResponse{Namespace: request.Namespace, Properties: namespaceProperties(databaseDescription(DatabaseKey{CatalogKey: catalog, Name: request.Namespace[0]}, in.DatabaseInput))}
	case route.resource == "namespace" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		in := &api.GetDatabaseInput{CatalogId: id, Name: new(api.NameString(key.Name))}
		err = s.icebergTransaction(ctx, catalog, "GetDatabase", in, func(ctx context.Context, tx Transaction) error {
			result, err := s.getDatabase(ctx, tx, in)
			if errors.Is(err, ErrNotFound) {
				return icebergError(404, "NoSuchNamespaceException", "Namespace does not exist.")
			}
			if err == nil {
				out = icebergNamespaceResponse{Namespace: []string{key.Name}, Properties: namespaceProperties(*result.Database)}
			}
			return err
		})
		if r.Method == http.MethodHead {
			status, out = http.StatusNoContent, nil
		}
	case route.resource == "namespace" && r.Method == http.MethodDelete:
		in := &api.DeleteDatabaseInput{CatalogId: id, Name: new(api.NameString(key.Name))}
		err = s.icebergTransaction(ctx, catalog, "DeleteDatabase", in, func(ctx context.Context, tx Transaction) error {
			if err := s.authorizeDatabase(ctx, tx, "DeleteDatabase", key); err != nil {
				return err
			}
			if _, err := tx.Database(key); errors.Is(err, ErrNotFound) {
				return icebergError(404, "NoSuchNamespaceException", "Namespace does not exist.")
			} else if err != nil {
				return err
			}
			tables, err := tx.Tables(key)
			if err != nil {
				return err
			}
			if len(tables) != 0 {
				return icebergError(409, "NamespaceNotEmptyException", "Namespace still contains tables.")
			}
			_, err = s.deleteDatabase(ctx, tx, in)
			return err
		})
		status = http.StatusNoContent
	case route.resource == "properties" && r.Method == http.MethodPost:
		var request struct {
			Updates  map[string]string `json:"updates"`
			Removals []string          `json:"removals"`
		}
		if err = decodeIceberg(r, &request); err != nil {
			break
		}
		in := &api.UpdateDatabaseInput{CatalogId: id, Name: new(api.NameString(key.Name))}
		updated, removed, missing := []string{}, []string{}, []string{}
		err = s.icebergTransaction(ctx, catalog, "UpdateDatabase", in, func(ctx context.Context, tx Transaction) error {
			if err := s.authorizeDatabase(ctx, tx, "UpdateDatabase", key); err != nil {
				return err
			}
			record, err := tx.Database(key)
			if err != nil {
				return err
			}
			properties := namespaceProperties(record.Database)
			for _, k := range request.Removals {
				if _, overlaps := request.Updates[k]; overlaps {
					return icebergError(422, "UnprocessableEntityException", "Property cannot be updated and removed together.")
				}
				if _, exists := properties[k]; exists {
					delete(properties, k)
					removed = append(removed, k)
				} else {
					missing = append(missing, k)
				}
			}
			for k, v := range request.Updates {
				properties[k] = v
				updated = append(updated, k)
			}
			in.DatabaseInput = namespaceInput(key.Name, properties)
			in.DatabaseInput.CreateTableDefaultPermissions = record.Database.CreateTableDefaultPermissions
			in.DatabaseInput.TargetDatabase = record.Database.TargetDatabase
			_, err = s.updateDatabase(ctx, tx, in)
			return err
		})
		slices.Sort(updated)
		slices.Sort(removed)
		slices.Sort(missing)
		out = struct {
			Updated []string `json:"updated"`
			Removed []string `json:"removed"`
			Missing []string `json:"missing"`
		}{updated, removed, missing}
	default:
		err = icebergMethodError()
	}
	return out, status, err
}

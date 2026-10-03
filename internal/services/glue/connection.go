package glue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/glue"
	"stackd/internal/awsctx"
)

func registerConnections(s *Service) {
	registerControl(s, "CreateConnection", s.createConnection)
	registerControl(s, "GetConnection", s.getConnection)
	registerControl(s, "GetConnections", s.getConnections)
	registerControl(s, "UpdateConnection", s.updateConnection)
	registerControl(s, "DeleteConnection", s.deleteConnection)
}

func connectionScope(ctx context.Context, catalog *api.CatalogIdString) (Scope, error) {
	scope := scopeFor(ctx)
	if catalog != nil && string(*catalog) != scope.AccountID {
		return Scope{}, failure("AccessDeniedException", "Cross-account connection access is not supported.")
	}
	return scope, nil
}
func (s *Service) loadConnection(ctx context.Context, tx Reader, key ResourceKey, action string) (ConnectionRecord, error) {
	row, err := tx.Connection(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return ConnectionRecord{}, err
	}
	if denied := s.authorize(ctx, tx, action, key.Scope, key.ARN("connection"), row.Tags); denied != nil {
		return ConnectionRecord{}, denied
	}
	return row, err
}
func connectionInput(in *api.ConnectionInput) (api.Connection, error) {
	if in == nil || value(in.Name) == "" || value(in.ConnectionType) == "" {
		return api.Connection{}, failure("InvalidInputException", "Connection name and type are required.")
	}
	// TODO: Comeback implement connector OAuth/custom authentication and credential validation through their native owners.
	if in.AuthenticationConfiguration != nil || in.ValidateCredentials != nil && bool(*in.ValidateCredentials) || len(in.ValidateForComputeEnvironments) != 0 {
		return api.Connection{}, unsupported("Connection authentication v2 and create-time native credential validation are not supported.")
	}
	for key := range in.ConnectionProperties {
		if strings.Contains(string(key), "PASSWORD") && key != "PASSWORD" || strings.Contains(string(key), "CLIENT_KEY") {
			return api.Connection{}, unsupported("This connection credential property is not supported; use a Secrets Manager SECRET_ID.")
		}
	}
	for _, overrides := range []api.PropertyMap{in.AthenaProperties, in.SparkProperties, in.PythonProperties} {
		for key := range overrides {
			if strings.Contains(strings.ToUpper(string(key)), "PASSWORD") || strings.Contains(strings.ToUpper(string(key)), "TOKEN") {
				return api.Connection{}, unsupported("Credentials in compute overrides are not supported; use the connection password or Secrets Manager.")
			}
		}
	}
	if value(in.ConnectionType) == "JDBC" {
		if in.ConnectionProperties["JDBC_CONNECTION_URL"] == "" {
			return api.Connection{}, failure("InvalidInputException", "JDBC_CONNECTION_URL is required.")
		}
		if in.ConnectionProperties["SECRET_ID"] == "" && (in.ConnectionProperties["USERNAME"] == "" || in.ConnectionProperties["PASSWORD"] == "") {
			return api.Connection{}, failure("InvalidInputException", "JDBC username and password or SECRET_ID are required.")
		}
	}
	return api.CloneConnection(api.Connection{Name: in.Name, ConnectionSchemaVersion: new(api.ConnectionSchemaVersion(1)), ConnectionType: in.ConnectionType, ConnectionProperties: in.ConnectionProperties, Description: in.Description, MatchCriteria: in.MatchCriteria, PhysicalConnectionRequirements: in.PhysicalConnectionRequirements, AthenaProperties: in.AthenaProperties, SparkProperties: in.SparkProperties, PythonProperties: in.PythonProperties}), nil
}
func (s *Service) createConnection(ctx context.Context, tx Transaction, in *api.CreateConnectionInput) (*api.CreateConnectionOutput, error) {
	scope, err := connectionScope(ctx, in.CatalogId)
	if err != nil {
		return nil, err
	}
	v, err := connectionInput(in.ConnectionInput)
	if err != nil {
		return nil, err
	}
	key := ResourceKey{Scope: scope, Name: value(v.Name)}
	tags := map[string]string{}
	for k, v := range in.Tags {
		tags[string(k)] = string(v)
	}
	if err := s.authorizeCreate(ctx, tx, "CreateConnection", scope, key.ARN("connection"), tags); err != nil {
		return nil, err
	}
	if _, err := tx.Connection(key); err == nil {
		return nil, failure("AlreadyExistsException", "Connection already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := s.clock.Now().UTC()
	v.CreationTime, v.LastUpdatedTime = &now, &now
	v.LastUpdatedBy = connectionUpdatedBy(ctx)
	row := ConnectionRecord{Key: key, Connection: v, Tags: tags, Password: string(v.ConnectionProperties["PASSWORD"])}
	delete(row.Connection.ConnectionProperties, "PASSWORD")
	if err := s.protectConnectionPassword(ctx, tx, &row); err != nil {
		return nil, err
	}
	if err := tx.PutConnection(row); err != nil {
		return nil, err
	}
	return &api.CreateConnectionOutput{}, nil
}
func (s *Service) connectionProjection(ctx context.Context, r Reader, row ConnectionRecord, hide bool) (api.Connection, error) {
	v := api.CloneConnection(row.Connection)
	if hide {
		return v, nil
	}
	password := row.Password
	if len(row.PasswordCipher) != 0 {
		settings, err := connectionEncryption(r, row.Key.Scope)
		if err != nil {
			return api.Connection{}, err
		}
		if settings.ReturnEncrypted {
			if v.ConnectionProperties == nil {
				v.ConnectionProperties = api.ConnectionProperties{}
			}
			v.ConnectionProperties["ENCRYPTED_PASSWORD"] = api.ValueString(base64.StdEncoding.EncodeToString(row.PasswordCipher))
			return v, nil
		}
		if s.connectionCrypto == nil {
			return api.Connection{}, unsupported("Connection password KMS adapter is not configured.")
		}
		plain, _, rejected := s.connectionCrypto.Decrypt(ctx, row.PasswordCipher, connectionEncryptionContext(row.Key))
		if rejected != nil {
			return api.Connection{}, rejected
		}
		password = string(plain)
	}
	if password != "" {
		if v.ConnectionProperties == nil {
			v.ConnectionProperties = api.ConnectionProperties{}
		}
		v.ConnectionProperties["PASSWORD"] = api.ValueString(password)
	}
	return v, nil
}
func connectionUpdatedBy(ctx context.Context) *api.NameString {
	parts := strings.SplitN(awsctx.FromContext(ctx).PrincipalARN, ":", 6)
	if len(parts) == 6 {
		return new(api.NameString(parts[5]))
	}
	return nil
}
func connectionEncryptionContext(key ResourceKey) map[string]string {
	return map[string]string{"aws:glue:connection:arn": key.ARN("connection")}
}
func (s *Service) getConnection(ctx context.Context, tx Transaction, in *api.GetConnectionInput) (*api.GetConnectionOutput, error) {
	scope, err := connectionScope(ctx, in.CatalogId)
	if err != nil {
		return nil, err
	}
	key := ResourceKey{Scope: scope, Name: value(in.Name)}
	row, err := s.loadConnection(ctx, tx, key, "GetConnection")
	if err != nil {
		return nil, err
	}
	v, err := s.connectionProjection(ctx, tx, row, in.HidePassword != nil && bool(*in.HidePassword))
	if err != nil {
		return nil, err
	}
	if in.ApplyOverrideForComputeEnvironment != nil {
		var props api.PropertyMap
		switch value(in.ApplyOverrideForComputeEnvironment) {
		case "SPARK":
			props = v.SparkProperties
		case "ATHENA":
			props = v.AthenaProperties
		case "PYTHON":
			props = v.PythonProperties
		default:
			return nil, failure("InvalidInputException", "Invalid compute environment.")
		}
		for k, vv := range props {
			if v.ConnectionProperties == nil {
				v.ConnectionProperties = api.ConnectionProperties{}
			}
			v.ConnectionProperties[api.ConnectionPropertyKey(k)] = api.ValueString(vv)
		}
	}
	return &api.GetConnectionOutput{Connection: &v}, nil
}
func (s *Service) getConnections(ctx context.Context, tx Transaction, in *api.GetConnectionsInput) (*api.GetConnectionsOutput, error) {
	scope, err := connectionScope(ctx, in.CatalogId)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, tx, "GetConnections", scope, "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Connections(scope)
	if err != nil {
		return nil, err
	}
	selected := rows[:0]
	for _, row := range rows {
		if in.Filter != nil {
			if in.Filter.ConnectionType != nil && value(in.Filter.ConnectionType) != value(row.Connection.ConnectionType) {
				continue
			}
			if in.Filter.ConnectionSchemaVersion != nil && int64(*in.Filter.ConnectionSchemaVersion) != 1 {
				continue
			}
			matched := true
			for _, criterion := range in.Filter.MatchCriteria {
				if !slices.Contains(row.Connection.MatchCriteria, criterion) {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
		}
		selected = append(selected, row)
	}
	filter, _ := json.Marshal(in.Filter)
	start, end, next, err := crawlerPage(scope, "connections", string(filter), in.NextToken, in.MaxResults, len(selected))
	if err != nil {
		return nil, err
	}
	out := &api.GetConnectionsOutput{ConnectionList: api.ConnectionList{}, NextToken: next}
	for _, row := range selected[start:end] {
		v, err := s.connectionProjection(ctx, tx, row, in.HidePassword != nil && bool(*in.HidePassword))
		if err != nil {
			return nil, err
		}
		out.ConnectionList = append(out.ConnectionList, v)
	}
	return out, nil
}
func (s *Service) updateConnection(ctx context.Context, tx Transaction, in *api.UpdateConnectionInput) (*api.UpdateConnectionOutput, error) {
	scope, err := connectionScope(ctx, in.CatalogId)
	if err != nil {
		return nil, err
	}
	key := ResourceKey{Scope: scope, Name: value(in.Name)}
	row, err := s.loadConnection(ctx, tx, key, "UpdateConnection")
	if err != nil {
		return nil, err
	}
	v, err := connectionInput(in.ConnectionInput)
	if err != nil {
		return nil, err
	}
	if value(v.Name) != key.Name {
		return nil, failure("InvalidInputException", "Connection name cannot be changed.")
	}
	v.CreationTime, v.LastUpdatedTime = row.Connection.CreationTime, new(s.clock.Now().UTC())
	v.LastUpdatedBy = connectionUpdatedBy(ctx)
	row.Connection, row.Password, row.PasswordCipher = v, string(v.ConnectionProperties["PASSWORD"]), nil
	delete(row.Connection.ConnectionProperties, "PASSWORD")
	if err := s.protectConnectionPassword(ctx, tx, &row); err != nil {
		return nil, err
	}
	if err := tx.PutConnection(row); err != nil {
		return nil, err
	}
	return &api.UpdateConnectionOutput{}, nil
}
func (s *Service) deleteConnection(ctx context.Context, tx Transaction, in *api.DeleteConnectionInput) (*api.DeleteConnectionOutput, error) {
	scope, err := connectionScope(ctx, in.CatalogId)
	if err != nil {
		return nil, err
	}
	key := ResourceKey{Scope: scope, Name: value(in.ConnectionName)}
	if _, err := s.loadConnection(ctx, tx, key, "DeleteConnection"); err != nil {
		return nil, err
	}
	if err := tx.DeleteConnection(key); err != nil {
		return nil, err
	}
	return &api.DeleteConnectionOutput{}, nil
}
func connectionResourceTags(tx Reader, scope Scope, arn string) (map[string]string, error) {
	prefix := ResourceKey{Scope: scope}.ARN("connection")
	if !strings.HasPrefix(arn, prefix) {
		return nil, ErrNotFound
	}
	row, err := tx.Connection(ResourceKey{Scope: scope, Name: strings.TrimPrefix(arn, prefix)})
	if err != nil {
		return nil, err
	}
	return maps.Clone(row.Tags), nil
}
func tagConnectionResource(tx Transaction, scope Scope, arn string, tags map[string]string) error {
	prefix := ResourceKey{Scope: scope}.ARN("connection")
	if !strings.HasPrefix(arn, prefix) {
		return ErrNotFound
	}
	row, err := tx.Connection(ResourceKey{Scope: scope, Name: strings.TrimPrefix(arn, prefix)})
	if err != nil {
		return err
	}
	row.Tags = maps.Clone(tags)
	return tx.PutConnection(row)
}

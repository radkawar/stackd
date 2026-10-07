package eventbridge

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/eventbridge"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/eventbridge/internal/sqlcgen"
)

func connection(v sqlcgen.EventbridgeConnection) domain.ConnectionRecord {
	out := domain.ConnectionRecord{Key: domain.ConnectionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.Name}, ID: v.ID, Description: v.Description, AuthorizationType: v.AuthorizationType, State: v.State, StateReason: v.StateReason, SecretARN: v.SecretArn, KmsKeyIdentifier: v.KmsKeyIdentifier, Username: v.Username, APIKeyName: v.ApiKeyName, ClientID: v.ClientID, AuthorizationEndpoint: v.AuthorizationEndpoint, OAuthMethod: v.OauthMethod, HasAuth: v.HasAuth, HasInvocation: v.HasInvocation, HasOAuthHTTP: v.HasOauthHttp, Created: v.Created, Modified: v.Modified, Version: uint64(v.Version)}
	out.CFNOwner = v.CfnOwner
	if v.LastAuthorized.Valid {
		out.LastAuthorized = v.LastAuthorized.Time
	}
	if v.DueSeconds.Valid {
		out.Due = time.Unix(v.DueSeconds.Int64, v.DueNanos).UTC()
	}
	return out
}
func (r reader) connectionParameters(v domain.ConnectionRecord) (domain.ConnectionRecord, error) {
	rows, err := r.q.GetConnectionParameters(r.ctx, v.ID)
	if err != nil {
		return v, err
	}
	v.Parameters = make([]domain.ConnectionParameter, 0, len(rows))
	for _, p := range rows {
		v.Parameters = append(v.Parameters, domain.ConnectionParameter{Target: p.Target, Location: p.Location, Key: p.Key, Value: p.Value, Secret: p.Secret})
	}
	return v, nil
}
func (r reader) Connection(k domain.ConnectionKey) (domain.ConnectionRecord, error) {
	v, err := r.q.GetConnection(r.ctx, sqlcgen.GetConnectionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.ConnectionRecord{}, missing(err)
	}
	return r.connectionParameters(connection(v))
}
func (r reader) ConnectionByID(id string) (domain.ConnectionRecord, error) {
	v, err := r.q.GetConnectionByID(r.ctx, id)
	if err != nil {
		return domain.ConnectionRecord{}, missing(err)
	}
	return r.connectionParameters(connection(v))
}
func (r reader) Connections(scope domain.Scope) ([]domain.ConnectionRecord, error) {
	rows, err := r.q.ListConnections(r.ctx, sqlcgen.ListConnectionsParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ConnectionRecord, 0, len(rows))
	for _, v := range rows {
		item, err := r.connectionParameters(connection(v))
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
func (r reader) ConnectionARNs(partition, account string) ([]string, error) {
	return r.q.ConnectionARNs(r.ctx, sqlcgen.ConnectionARNsParams{Partition: partition, Account: account})
}
func (r reader) NextConnectionJob() (domain.ConnectionRecord, bool, error) {
	v, err := r.q.NextConnectionJob(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ConnectionRecord{}, false, nil
	}
	if err != nil {
		return domain.ConnectionRecord{}, false, err
	}
	item, err := r.connectionParameters(connection(v))
	return item, err == nil, err
}
func (w writer) PutConnection(v domain.ConnectionRecord) error {
	err := w.q.PutConnection(w.ctx, sqlcgen.PutConnectionParams{Partition: v.Key.Partition, Account: v.Key.Account, Region: v.Key.Region, Name: v.Key.Name, ID: v.ID, CfnOwner: v.CFNOwner, Description: v.Description, AuthorizationType: v.AuthorizationType, State: v.State, StateReason: v.StateReason, SecretArn: v.SecretARN, KmsKeyIdentifier: v.KmsKeyIdentifier, Username: v.Username, ApiKeyName: v.APIKeyName, ClientID: v.ClientID, AuthorizationEndpoint: v.AuthorizationEndpoint, OauthMethod: v.OAuthMethod, HasAuth: v.HasAuth, HasInvocation: v.HasInvocation, HasOauthHttp: v.HasOAuthHTTP, Created: v.Created, Modified: v.Modified, LastAuthorized: sql.NullTime{Time: v.LastAuthorized, Valid: !v.LastAuthorized.IsZero()}, DueSeconds: archiveOptionalSeconds(v.Due), DueNanos: int64(v.Due.Nanosecond()), Version: sqlite.Uint64(v.Version)})
	if err != nil {
		return err
	}
	if err = w.q.DeleteConnectionParameters(w.ctx, v.ID); err != nil {
		return err
	}
	for i, p := range v.Parameters {
		if err = w.q.PutConnectionParameter(w.ctx, sqlcgen.PutConnectionParameterParams{ConnectionID: v.ID, Ordinal: int64(i), Target: p.Target, Location: p.Location, Key: p.Key, Value: p.Value, Secret: p.Secret}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteConnection(k domain.ConnectionKey) error {
	return w.q.DeleteConnection(w.ctx, sqlcgen.DeleteConnectionParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
}

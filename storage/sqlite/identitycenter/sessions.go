package identitycenter

import (
	domain "stackd/storage/identitycenter"
	"stackd/storage/sqlite/identitycenter/internal/sqlcgen"
)

func (r reader) Client(id string) (domain.Client, error) {
	row, err := r.q.GetClient(r.ctx, id)
	if err != nil {
		return domain.Client{}, missing(err)
	}
	scopes, err := r.q.ListClientScopes(r.ctx, id)
	if err != nil {
		return domain.Client{}, err
	}
	v := domain.Client{ID: row.ID, SecretHash: row.SecretHash, Name: row.Name, Region: row.Region, Partition: row.Partition, Created: row.Created.UTC(), Expires: row.Expires.UTC(), IssuerURL: row.IssuerUrl, Scopes: make([]string, len(scopes))}
	for i, scope := range scopes {
		v.Scopes[i] = scope.Scope
	}
	grants, err := r.q.ListClientGrantTypes(r.ctx, id)
	if err != nil {
		return domain.Client{}, err
	}
	v.GrantTypes = make([]string, len(grants))
	for i, grant := range grants {
		v.GrantTypes[i] = grant.GrantType
	}
	redirects, err := r.q.ListClientRedirectURIs(r.ctx, id)
	if err != nil {
		return domain.Client{}, err
	}
	if len(redirects) > 0 {
		v.RedirectURIs = make([]string, len(redirects))
	}
	for i, redirect := range redirects {
		v.RedirectURIs[i] = redirect.Uri
	}
	return v, nil
}

func (w writer) PutClient(v domain.Client) error {
	if err := w.q.PutClient(w.ctx, sqlcgen.PutClientParams{ID: v.ID, SecretHash: v.SecretHash, Name: v.Name, Region: v.Region, Partition: v.Partition, Created: v.Created.UTC(), Expires: v.Expires.UTC(), IssuerUrl: v.IssuerURL}); err != nil {
		return err
	}
	if err := w.q.DeleteClientScopes(w.ctx, v.ID); err != nil {
		return err
	}
	for i, scope := range v.Scopes {
		if err := w.q.PutClientScope(w.ctx, sqlcgen.PutClientScopeParams{ClientID: v.ID, Position: int64(i), Scope: scope}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteClientGrantTypes(w.ctx, v.ID); err != nil {
		return err
	}
	for i, grant := range v.GrantTypes {
		if err := w.q.PutClientGrantType(w.ctx, sqlcgen.PutClientGrantTypeParams{ClientID: v.ID, Position: int64(i), GrantType: grant}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteClientRedirectURIs(w.ctx, v.ID); err != nil {
		return err
	}
	for i, uri := range v.RedirectURIs {
		if err := w.q.PutClientRedirectURI(w.ctx, sqlcgen.PutClientRedirectURIParams{ClientID: v.ID, Position: int64(i), Uri: uri}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) Device(hash string) (domain.Device, error) {
	row, err := r.q.GetDevice(r.ctx, hash)
	if err != nil {
		return domain.Device{}, missing(err)
	}
	return device(row), nil
}

func (r reader) DeviceByUserCode(code string) (domain.Device, error) {
	row, err := r.q.GetDeviceByUserCode(r.ctx, code)
	if err != nil {
		return domain.Device{}, missing(err)
	}
	return device(row), nil
}

func device(row sqlcgen.IdentitycenterDevice) domain.Device {
	return domain.Device{CodeHash: row.CodeHash, UserCode: row.UserCode, ClientID: row.ClientID, InstanceARN: row.InstanceArn, UserID: row.UserID, CSRF: row.Csrf, State: row.State, Created: row.Created.UTC(), Expires: row.Expires.UTC(), LastPoll: row.LastPoll.UTC(), Interval: int32(row.Interval)}
}

func (w writer) PutDevice(v domain.Device) error {
	return w.q.PutDevice(w.ctx, sqlcgen.PutDeviceParams{CodeHash: v.CodeHash, UserCode: v.UserCode, ClientID: v.ClientID, InstanceArn: v.InstanceARN, UserID: v.UserID, Csrf: v.CSRF, State: v.State, Created: v.Created.UTC(), Expires: v.Expires.UTC(), LastPoll: v.LastPoll.UTC(), Interval: int64(v.Interval)})
}

func (r reader) SessionByAccess(hash string) (domain.Session, error) {
	row, err := r.q.GetSessionByAccess(r.ctx, hash)
	if err != nil {
		return domain.Session{}, missing(err)
	}
	return session(row), nil
}

func (r reader) SessionByRefresh(hash string) (domain.Session, error) {
	row, err := r.q.GetSessionByRefresh(r.ctx, hash)
	if err != nil {
		return domain.Session{}, missing(err)
	}
	return session(row), nil
}

func (r reader) Sessions(familyID string) ([]domain.Session, error) {
	rows, err := r.q.ListSessions(r.ctx, familyID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, len(rows))
	for i, row := range rows {
		out[i] = session(row)
	}
	return out, nil
}

func session(row sqlcgen.IdentitycenterSession) domain.Session {
	return domain.Session{ID: row.ID, FamilyID: row.FamilyID, ClientID: row.ClientID, InstanceARN: row.InstanceArn, UserID: row.UserID, AccessHash: row.AccessHash, RefreshHash: row.RefreshHash, Created: row.Created.UTC(), AccessExpires: row.AccessExpires.UTC(), RefreshExpires: row.RefreshExpires.UTC(), Revoked: row.Revoked}
}

func (w writer) PutSession(v domain.Session) error {
	return w.q.PutSession(w.ctx, sqlcgen.PutSessionParams{ID: v.ID, FamilyID: v.FamilyID, ClientID: v.ClientID, InstanceArn: v.InstanceARN, UserID: v.UserID, AccessHash: v.AccessHash, RefreshHash: v.RefreshHash, Created: v.Created.UTC(), AccessExpires: v.AccessExpires.UTC(), RefreshExpires: v.RefreshExpires.UTC(), Revoked: v.Revoked})
}

func authorization(row sqlcgen.IdentitycenterAuthorization) domain.Authorization {
	return domain.Authorization{ID: row.ID, CodeHash: row.CodeHash, ClientID: row.ClientID, InstanceARN: row.InstanceArn, UserID: row.UserID, RedirectURI: row.RedirectUri, Challenge: row.Challenge, Scope: row.Scope, OAuthState: row.OauthState, CSRF: row.Csrf, State: row.State, Created: row.Created.UTC(), Expires: row.Expires.UTC()}
}
func (r reader) Authorization(id string) (domain.Authorization, error) {
	row, err := r.q.GetAuthorization(r.ctx, id)
	if err != nil {
		return domain.Authorization{}, missing(err)
	}
	return authorization(row), nil
}
func (r reader) AuthorizationByCode(hash string) (domain.Authorization, error) {
	row, err := r.q.GetAuthorizationByCode(r.ctx, hash)
	if err != nil {
		return domain.Authorization{}, missing(err)
	}
	return authorization(row), nil
}
func (w writer) PutAuthorization(v domain.Authorization) error {
	return w.q.PutAuthorization(w.ctx, sqlcgen.PutAuthorizationParams{ID: v.ID, CodeHash: v.CodeHash, ClientID: v.ClientID, InstanceArn: v.InstanceARN, UserID: v.UserID, RedirectUri: v.RedirectURI, Challenge: v.Challenge, Scope: v.Scope, OauthState: v.OAuthState, Csrf: v.CSRF, State: v.State, Created: v.Created.UTC(), Expires: v.Expires.UTC()})
}

package iam

import (
	"database/sql"
	"errors"

	"stackd/storage/identity"
	"stackd/storage/sqlite/iam/internal/sqlcgen"
)

func (r reader) Credential(key string) (identity.Record, error) {
	var result identity.Record
	row, err := r.q.GetCredential(r.ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return result, identity.ErrNotFound
	}
	if err != nil {
		return result, err
	}
	var record identity.Record
	record.Credential.AccessKeyID = row.CredentialAccessKeyID
	record.Credential.SecretAccessKey = row.CredentialSecretAccessKey
	record.Credential.SessionToken = row.CredentialSessionToken
	record.Credential.AccountID = row.CredentialAccountID
	record.Credential.PrincipalARN = row.CredentialPrincipalArn
	record.Credential.PrincipalID = row.CredentialPrincipalID
	record.Credential.UserName = row.CredentialUserName
	record.Credential.IssuerARN = row.CredentialIssuerArn
	record.Credential.IssuerID = row.CredentialIssuerID
	record.Credential.FederatedProvider = row.CredentialFederatedProvider
	record.Credential.SourceIdentity = row.CredentialSourceIdentity
	record.Credential.RequestParentEventID = row.CredentialRequestParentEventID
	record.Credential.InScopeOf.IssuerType = row.CredentialInScopeOfIssuerType
	record.Credential.InScopeOf.CredentialsIssuedTo = row.CredentialInScopeOfCredentialsIssuedTo
	record.LastUsed.Service = row.LastUsedService
	record.LastUsed.Region = row.LastUsedRegion
	record.Credential.DefaultRegionsOnly = row.CredentialDefaultRegionsOnly
	record.Credential.HasSessionPolicy = row.CredentialHasSessionPolicy
	record.Credential.MFAPresent = row.CredentialMfaPresent
	record.Credential.Expiration = row.CredentialExpiration
	record.Credential.CreateDate = row.CredentialCreateDate
	record.Credential.MFAAuthenticatedAt = row.CredentialMfaAuthenticatedAt
	record.LastUsed.Date = row.LastUsedDate
	record.Credential.SessionType = identity.SessionType(row.CredentialSessionType)
	record.Status = identity.Status(row.Status)
	{
		child, err := r.readCredentialSessionPolicies(row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Credential.SessionPolicies = child
	}
	{
		child, err := r.readCredentialSessionPolicyARNs(row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Credential.SessionPolicyARNs = child
	}
	{
		child, err := r.readCredentialSessionContext(row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Credential.SessionContext = child
	}
	{
		child, err := r.readCredentialSessionTags(row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Credential.SessionTags = child
	}
	{
		child, err := r.readCredentialTransitiveTagKeys(row.ResourceKey)
		if err != nil {
			return result, err
		}
		record.Credential.TransitiveTagKeys = child
	}
	return record, nil
}

func (w writer) PutCredential(record identity.Record) error {
	if _, err := w.q.DeleteCredential(w.ctx, record.Credential.AccessKeyID); err != nil {
		return err
	}
	if err := w.q.InsertCredential(w.ctx, sqlcgen.InsertCredentialParams{ResourceKey: record.Credential.AccessKeyID, CredentialAccessKeyID: record.Credential.AccessKeyID, CredentialSecretAccessKey: record.Credential.SecretAccessKey, CredentialSessionToken: record.Credential.SessionToken, CredentialAccountID: record.Credential.AccountID, CredentialPrincipalArn: record.Credential.PrincipalARN, CredentialPrincipalID: record.Credential.PrincipalID, CredentialUserName: record.Credential.UserName, CredentialIssuerArn: record.Credential.IssuerARN, CredentialIssuerID: record.Credential.IssuerID, CredentialFederatedProvider: record.Credential.FederatedProvider, CredentialSourceIdentity: record.Credential.SourceIdentity, LastUsedService: record.LastUsed.Service, LastUsedRegion: record.LastUsed.Region, CredentialDefaultRegionsOnly: record.Credential.DefaultRegionsOnly, CredentialHasSessionPolicy: record.Credential.HasSessionPolicy, CredentialMfaPresent: record.Credential.MFAPresent, CredentialExpiration: record.Credential.Expiration, CredentialCreateDate: record.Credential.CreateDate, CredentialMfaAuthenticatedAt: record.Credential.MFAAuthenticatedAt, LastUsedDate: record.LastUsed.Date, CredentialSessionType: string(record.Credential.SessionType), Status: string(record.Status), CredentialRequestParentEventID: record.Credential.RequestParentEventID, CredentialInScopeOfIssuerType: record.Credential.InScopeOf.IssuerType, CredentialInScopeOfCredentialsIssuedTo: record.Credential.InScopeOf.CredentialsIssuedTo}); err != nil {
		return err
	}
	if err := w.writeCredentialSessionPolicies(record.Credential.AccessKeyID, record.Credential.SessionPolicies); err != nil {
		return err
	}
	if err := w.writeCredentialSessionPolicyARNs(record.Credential.AccessKeyID, record.Credential.SessionPolicyARNs); err != nil {
		return err
	}
	if err := w.writeCredentialSessionContext(record.Credential.AccessKeyID, record.Credential.SessionContext); err != nil {
		return err
	}
	if err := w.writeCredentialSessionTags(record.Credential.AccessKeyID, record.Credential.SessionTags); err != nil {
		return err
	}
	if err := w.writeCredentialTransitiveTagKeys(record.Credential.AccessKeyID, record.Credential.TransitiveTagKeys); err != nil {
		return err
	}
	return nil
}

func (w writer) DeleteCredential(key string) error {
	count, err := w.q.DeleteCredential(w.ctx, key)
	if err != nil {
		return err
	}
	if count == 0 {
		return identity.ErrNotFound
	}
	return nil
}

func (r reader) readCredentialSessionPolicies(resourceKey string) ([]string, error) {
	var result []string
	rows, err := r.q.ListCredentialSessionPolicies(r.ctx, resourceKey)
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readCredentialSessionPolicyARNs(resourceKey string) ([]string, error) {
	var result []string
	rows, err := r.q.ListCredentialSessionPolicyARNs(r.ctx, resourceKey)
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readCredentialSessionContext(resourceKey string) (map[string][]string, error) {
	var result map[string][]string
	rows, err := r.q.ListCredentialSessionContext(r.ctx, resourceKey)
	if err != nil {
		return result, err
	}
	result = make(map[string][]string, len(rows))
	for _, row := range rows {
		var record []string
		{
			child, err := r.readCredentialSessionContextValues(row.ResourceKey, row.Entry1)
			if err != nil {
				return result, err
			}
			record = child
		}
		result[row.Entry1] = record
	}
	return result, nil
}

func (r reader) readCredentialSessionContextValues(resourceKey string, entry1 string) ([]string, error) {
	var result []string
	rows, err := r.q.ListCredentialSessionContextValues(r.ctx, sqlcgen.ListCredentialSessionContextValuesParams{ResourceKey: resourceKey, Entry1: entry1})
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (r reader) readCredentialSessionTags(resourceKey string) (map[string]string, error) {
	var result map[string]string
	rows, err := r.q.ListCredentialSessionTags(r.ctx, resourceKey)
	if err != nil {
		return result, err
	}
	result = make(map[string]string, len(rows))
	for _, row := range rows {
		record := row.Value
		result[row.Entry1] = record
	}
	return result, nil
}

func (r reader) readCredentialTransitiveTagKeys(resourceKey string) ([]string, error) {
	var result []string
	rows, err := r.q.ListCredentialTransitiveTagKeys(r.ctx, resourceKey)
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		record := row.Value
		result = append(result, record)
	}
	return result, nil
}

func (w writer) writeCredentialSessionPolicies(resourceKey string, value []string) error {
	for position1, record := range value {
		if err := w.q.InsertCredentialSessionPolicies(w.ctx, sqlcgen.InsertCredentialSessionPoliciesParams{ResourceKey: resourceKey, Position1: int64(position1), Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeCredentialSessionPolicyARNs(resourceKey string, value []string) error {
	for position1, record := range value {
		if err := w.q.InsertCredentialSessionPolicyARNs(w.ctx, sqlcgen.InsertCredentialSessionPolicyARNsParams{ResourceKey: resourceKey, Position1: int64(position1), Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeCredentialSessionContext(resourceKey string, value map[string][]string) error {
	for entry1, record := range value {
		if err := w.q.InsertCredentialSessionContext(w.ctx, sqlcgen.InsertCredentialSessionContextParams{ResourceKey: resourceKey, Entry1: entry1}); err != nil {
			return err
		}
		if err := w.writeCredentialSessionContextValues(resourceKey, entry1, record); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeCredentialSessionContextValues(resourceKey string, entry1 string, value []string) error {
	for position2, record := range value {
		if err := w.q.InsertCredentialSessionContextValues(w.ctx, sqlcgen.InsertCredentialSessionContextValuesParams{ResourceKey: resourceKey, Entry1: entry1, Position2: int64(position2), Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeCredentialSessionTags(resourceKey string, value map[string]string) error {
	for entry1, record := range value {
		if err := w.q.InsertCredentialSessionTags(w.ctx, sqlcgen.InsertCredentialSessionTagsParams{ResourceKey: resourceKey, Entry1: entry1, Value: record}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) writeCredentialTransitiveTagKeys(resourceKey string, value []string) error {
	for position1, record := range value {
		if err := w.q.InsertCredentialTransitiveTagKeys(w.ctx, sqlcgen.InsertCredentialTransitiveTagKeysParams{ResourceKey: resourceKey, Position1: int64(position1), Value: record}); err != nil {
			return err
		}
	}
	return nil
}

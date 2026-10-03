package ssm

import (
	"stackd/storage/sqlite/ssm/internal/sqlcgen"
	domain "stackd/storage/ssm"
)

func (r reader) ValidationJob(key domain.VersionKey) (domain.ValidationJob, error) {
	p := key.Parameter
	row, err := r.q.GetValidationJob(r.ctx, sqlcgen.GetValidationJobParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, Name: p.Name, Version: key.Version})
	if err != nil {
		return domain.ValidationJob{}, missing(err)
	}
	return r.validationJob(row)
}
func (r reader) NextValidationJob() (domain.ValidationJob, error) {
	row, err := r.q.NextValidationJob(r.ctx)
	if err != nil {
		return domain.ValidationJob{}, missing(err)
	}
	return r.validationJob(sqlcgen.GetValidationJobRow(row))
}

func (r reader) validationJob(row sqlcgen.GetValidationJobRow) (domain.ValidationJob, error) {
	v := domain.ValidationJob{Key: domain.VersionKey{Parameter: domain.ParameterKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name}, Version: row.Version}, Due: row.Due.UTC()}
	v.Caller.AccountID = row.CallerAccountID
	v.Caller.Region = row.CallerRegion
	v.Caller.Partition = row.CallerPartition
	v.Caller.AccessKeyID = row.CallerAccessKeyID
	v.Caller.RequestID = row.CallerRequestID
	v.Caller.ParentEventID = row.CallerParentEventID
	v.Caller.TraceHeader = row.CallerTraceHeader
	v.Caller.PrincipalARN = row.CallerPrincipalArn
	v.Caller.PrincipalID = row.CallerPrincipalID
	v.Caller.UserName = row.CallerUserName
	v.Caller.SessionType = row.CallerSessionType
	v.Caller.IssuerARN = row.CallerIssuerArn
	v.Caller.IssuerID = row.CallerIssuerID
	v.Caller.HasSessionPolicy = row.CallerHasSessionPolicy
	v.Caller.FederatedProvider = row.CallerFederatedProvider
	v.Caller.SourceIdentity = row.CallerSourceIdentity
	v.Caller.MFAPresent = row.CallerMfaPresent
	v.Caller.MFAAuthenticatedAt = row.CallerMfaAuthenticatedAt.UTC()
	v.Caller.TokenIssueTime = row.CallerTokenIssueTime.UTC()
	v.Caller.TransportKnown = row.CallerTransportKnown
	v.Caller.SourceIP = row.CallerSourceIp
	v.Caller.SecureTransport = row.CallerSecureTransport
	v.Caller.UserAgent = row.CallerUserAgent
	v.Caller.SignatureVersion = row.CallerSignatureVersion
	v.Caller.AuthenticationMethod = row.CallerAuthenticationMethod
	v.Caller.ServicePrincipal.Name = row.CallerServicePrincipalName
	v.Caller.ServicePrincipal.SourceARN = row.CallerServicePrincipalSourceArn
	v.Caller.ServicePrincipal.Type = row.CallerServicePrincipalType
	v.Caller.InvokedBy = row.CallerInvokedBy
	v.Caller.InScopeOf.IssuerType = row.CallerInScopeOfIssuerType
	v.Caller.InScopeOf.CredentialsIssuedTo = row.CallerInScopeOfCredentialsIssuedTo
	if row.CallerSessionPoliciesPresent {
		values, err := r.q.ListCallerSessionPolicies(r.ctx, row.ID)
		if err != nil {
			return domain.ValidationJob{}, err
		}
		v.Caller.SessionPolicies = make([]string, 0, len(values))
		for _, value := range values {
			v.Caller.SessionPolicies = append(v.Caller.SessionPolicies, value.Value)
		}
	}
	if row.CallerSessionPolicyArnsPresent {
		values, err := r.q.ListCallerSessionPolicyARNs(r.ctx, row.ID)
		if err != nil {
			return domain.ValidationJob{}, err
		}
		v.Caller.SessionPolicyARNs = make([]string, 0, len(values))
		for _, value := range values {
			v.Caller.SessionPolicyARNs = append(v.Caller.SessionPolicyARNs, value.Value)
		}
	}
	if row.CallerTransitiveTagKeysPresent {
		values, err := r.q.ListCallerTransitiveTagKeys(r.ctx, row.ID)
		if err != nil {
			return domain.ValidationJob{}, err
		}
		v.Caller.TransitiveTagKeys = make([]string, 0, len(values))
		for _, value := range values {
			v.Caller.TransitiveTagKeys = append(v.Caller.TransitiveTagKeys, value.Value)
		}
	}
	if row.CallerCalledViaPresent {
		values, err := r.q.ListCallerCalledVia(r.ctx, row.ID)
		if err != nil {
			return domain.ValidationJob{}, err
		}
		v.Caller.CalledVia = make([]string, 0, len(values))
		for _, value := range values {
			v.Caller.CalledVia = append(v.Caller.CalledVia, value.Value)
		}
	}
	if row.CallerServicePrincipalAliasesPresent {
		values, err := r.q.ListCallerServicePrincipalAliases(r.ctx, row.ID)
		if err != nil {
			return domain.ValidationJob{}, err
		}
		v.Caller.ServicePrincipal.Aliases = make([]string, 0, len(values))
		for _, value := range values {
			v.Caller.ServicePrincipal.Aliases = append(v.Caller.ServicePrincipal.Aliases, value.Value)
		}
	}
	if row.CallerSessionTagsPresent {
		values, err := r.q.ListCallerSessionTags(r.ctx, row.ID)
		if err != nil {
			return domain.ValidationJob{}, err
		}
		v.Caller.SessionTags = make(map[string]string, len(values))
		for _, value := range values {
			v.Caller.SessionTags[value.MapKey] = value.Value
		}
	}
	if row.CallerSessionContextPresent {
		claims, err := r.q.ListCallerSessionContext(r.ctx, row.ID)
		if err != nil {
			return domain.ValidationJob{}, err
		}
		v.Caller.SessionContext = make(map[string][]string, len(claims))
		for _, claim := range claims {
			var values []string
			if claim.ValuePresent {
				entries, err := r.q.ListCallerSessionContextValues(r.ctx, claim.ID)
				if err != nil {
					return domain.ValidationJob{}, err
				}
				values = make([]string, 0, len(entries))
				for _, entry := range entries {
					values = append(values, entry.Value)
				}
			}
			v.Caller.SessionContext[claim.MapKey] = values
		}
	}
	return v, nil
}

func (w writer) PutValidationJob(v domain.ValidationJob) error {
	version, err := w.versionRow(v.Key)
	if err != nil {
		return err
	}
	p := sqlcgen.PutValidationJobParams{ParentID: version.ID, Due: v.Due.UTC()}
	p.CallerAccountID = v.Caller.AccountID
	p.CallerRegion = v.Caller.Region
	p.CallerPartition = v.Caller.Partition
	p.CallerAccessKeyID = v.Caller.AccessKeyID
	p.CallerRequestID = v.Caller.RequestID
	p.CallerParentEventID = v.Caller.ParentEventID
	p.CallerTraceHeader = v.Caller.TraceHeader
	p.CallerPrincipalArn = v.Caller.PrincipalARN
	p.CallerPrincipalID = v.Caller.PrincipalID
	p.CallerUserName = v.Caller.UserName
	p.CallerSessionType = v.Caller.SessionType
	p.CallerIssuerArn = v.Caller.IssuerARN
	p.CallerIssuerID = v.Caller.IssuerID
	p.CallerHasSessionPolicy = v.Caller.HasSessionPolicy
	p.CallerFederatedProvider = v.Caller.FederatedProvider
	p.CallerSourceIdentity = v.Caller.SourceIdentity
	p.CallerMfaPresent = v.Caller.MFAPresent
	p.CallerMfaAuthenticatedAt = v.Caller.MFAAuthenticatedAt.UTC()
	p.CallerTokenIssueTime = v.Caller.TokenIssueTime.UTC()
	p.CallerTransportKnown = v.Caller.TransportKnown
	p.CallerSourceIp = v.Caller.SourceIP
	p.CallerSecureTransport = v.Caller.SecureTransport
	p.CallerUserAgent = v.Caller.UserAgent
	p.CallerSignatureVersion = v.Caller.SignatureVersion
	p.CallerAuthenticationMethod = v.Caller.AuthenticationMethod
	p.CallerServicePrincipalName = v.Caller.ServicePrincipal.Name
	p.CallerServicePrincipalSourceArn = v.Caller.ServicePrincipal.SourceARN
	p.CallerServicePrincipalType = v.Caller.ServicePrincipal.Type
	p.CallerInvokedBy = v.Caller.InvokedBy
	p.CallerInScopeOfIssuerType = v.Caller.InScopeOf.IssuerType
	p.CallerInScopeOfCredentialsIssuedTo = v.Caller.InScopeOf.CredentialsIssuedTo
	p.CallerSessionPoliciesPresent = v.Caller.SessionPolicies != nil
	p.CallerSessionPolicyArnsPresent = v.Caller.SessionPolicyARNs != nil
	p.CallerTransitiveTagKeysPresent = v.Caller.TransitiveTagKeys != nil
	p.CallerCalledViaPresent = v.Caller.CalledVia != nil
	p.CallerServicePrincipalAliasesPresent = v.Caller.ServicePrincipal.Aliases != nil
	p.CallerSessionContextPresent = v.Caller.SessionContext != nil
	p.CallerSessionTagsPresent = v.Caller.SessionTags != nil
	id, err := w.q.PutValidationJob(w.ctx, p)
	if err != nil {
		return err
	}
	if err := w.q.DeleteCallerSessionPolicies(w.ctx, id); err != nil {
		return err
	}
	for i, value := range v.Caller.SessionPolicies {
		if err := w.q.PutCallerSessionPolicies(w.ctx, sqlcgen.PutCallerSessionPoliciesParams{ParentID: id, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerSessionPolicyARNs(w.ctx, id); err != nil {
		return err
	}
	for i, value := range v.Caller.SessionPolicyARNs {
		if err := w.q.PutCallerSessionPolicyARNs(w.ctx, sqlcgen.PutCallerSessionPolicyARNsParams{ParentID: id, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerTransitiveTagKeys(w.ctx, id); err != nil {
		return err
	}
	for i, value := range v.Caller.TransitiveTagKeys {
		if err := w.q.PutCallerTransitiveTagKeys(w.ctx, sqlcgen.PutCallerTransitiveTagKeysParams{ParentID: id, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerCalledVia(w.ctx, id); err != nil {
		return err
	}
	for i, value := range v.Caller.CalledVia {
		if err := w.q.PutCallerCalledVia(w.ctx, sqlcgen.PutCallerCalledViaParams{ParentID: id, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerServicePrincipalAliases(w.ctx, id); err != nil {
		return err
	}
	for i, value := range v.Caller.ServicePrincipal.Aliases {
		if err := w.q.PutCallerServicePrincipalAliases(w.ctx, sqlcgen.PutCallerServicePrincipalAliasesParams{ParentID: id, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerSessionTags(w.ctx, id); err != nil {
		return err
	}
	for key, value := range v.Caller.SessionTags {
		if err := w.q.PutCallerSessionTags(w.ctx, sqlcgen.PutCallerSessionTagsParams{ParentID: id, MapKey: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerSessionContext(w.ctx, id); err != nil {
		return err
	}
	for key, values := range v.Caller.SessionContext {
		claimID, err := w.q.PutCallerSessionContext(w.ctx, sqlcgen.PutCallerSessionContextParams{ParentID: id, MapKey: key, ValuePresent: values != nil})
		if err != nil {
			return err
		}
		for i, value := range values {
			if err := w.q.PutCallerSessionContextValues(w.ctx, sqlcgen.PutCallerSessionContextValuesParams{ParentID: claimID, Position: int64(i), Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteValidationJob(k domain.VersionKey) error {
	p := k.Parameter
	return w.q.DeleteValidationJob(w.ctx, sqlcgen.DeleteValidationJobParams{Partition: p.Partition, AccountID: p.AccountID, Region: p.Region, Name: p.Name, Version: k.Version})
}

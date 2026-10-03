package cloudformation

import (
	"database/sql"
	domain "stackd/storage/cloudformation"
	"stackd/storage/sqlite/cloudformation/internal/sqlcgen"
)

func (r reader) Operation(id string) (domain.OperationRecord, error) {
	row, err := r.q.Operation(r.ctx, id)
	if err != nil {
		return domain.OperationRecord{}, missing(err)
	}
	return r.decodeOperation(row)
}

func (r reader) NextOperation() (domain.OperationRecord, bool, error) {
	row, err := r.q.NextOperation(r.ctx)
	if missing(err) == domain.ErrNotFound {
		return domain.OperationRecord{}, false, nil
	}
	if err != nil {
		return domain.OperationRecord{}, false, err
	}
	v, err := r.decodeOperation(row)
	return v, err == nil, err
}

func (r reader) decodeOperation(row sqlcgen.CloudformationOperation) (domain.OperationRecord, error) {
	var out domain.OperationRecord
	out.ID = row.ID
	out.StackID = row.StackID
	out.Kind = row.Kind
	out.Phase = row.Phase
	out.Token = row.Token
	out.RequestHash = row.RequestHash
	out.ChangeSetID = row.ChangeSetID
	out.Reason = row.Reason
	out.Template = row.Template
	out.RoleARN = row.RoleArn
	out.Caller.AccountID = row.CallerAccountID
	out.Caller.Region = row.CallerRegion
	out.Caller.Partition = row.CallerPartition
	out.Caller.AccessKeyID = row.CallerAccessKeyID
	out.Caller.RequestID = row.CallerRequestID
	out.Caller.ParentEventID = row.CallerParentEventID
	out.Caller.TraceHeader = row.CallerTraceHeader
	out.Caller.PrincipalARN = row.CallerPrincipalArn
	out.Caller.PrincipalID = row.CallerPrincipalID
	out.Caller.UserName = row.CallerUserName
	out.Caller.SessionType = row.CallerSessionType
	out.Caller.IssuerARN = row.CallerIssuerArn
	out.Caller.IssuerID = row.CallerIssuerID
	out.Caller.HasSessionPolicy = row.CallerHasSessionPolicy
	out.Caller.FederatedProvider = row.CallerFederatedProvider
	out.Caller.SourceIdentity = row.CallerSourceIdentity
	out.Caller.MFAPresent = row.CallerMfaPresent
	out.Caller.MFAAuthenticatedAt = row.CallerMfaAuthenticatedAt.UTC()
	out.Caller.TokenIssueTime = row.CallerTokenIssueTime.UTC()
	out.Caller.TransportKnown = row.CallerTransportKnown
	out.Caller.SourceIP = row.CallerSourceIp
	out.Caller.SecureTransport = row.CallerSecureTransport
	out.Caller.UserAgent = row.CallerUserAgent
	out.Caller.SignatureVersion = row.CallerSignatureVersion
	out.Caller.AuthenticationMethod = row.CallerAuthenticationMethod
	out.Caller.ServicePrincipal.Name = row.CallerServicePrincipalName
	out.Caller.ServicePrincipal.SourceARN = row.CallerServicePrincipalSourceArn
	out.Caller.ServicePrincipal.Type = row.CallerServicePrincipalType
	out.Caller.InvokedBy = row.CallerInvokedBy
	out.Caller.InScopeOf.IssuerType = row.CallerInScopeOfIssuerType
	out.Caller.InScopeOf.CredentialsIssuedTo = row.CallerInScopeOfCredentialsIssuedTo
	out.Cursor = int(row.Cursor)
	out.Revision = uint64(row.Revision)
	out.Due = row.Due.UTC()
	out.Started = row.Started.UTC()
	out.Cancel = row.Cancel
	out.DisableRollback = row.DisableRollback
	if row.ParametersPresent {
		values, err := r.q.OperationParameters(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Parameters = make(map[string]string, len(values))
		for _, v := range values {
			out.Parameters[v.Key] = v.Value
			if v.ResolvedValue.Valid {
				if out.ResolvedParameters == nil {
					out.ResolvedParameters = map[string]string{}
				}
				out.ResolvedParameters[v.Key] = v.ResolvedValue.String
			}
		}
	}
	if row.TagsPresent {
		values, err := r.q.OperationTags(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Tags = make(map[string]string, len(values))
		for _, v := range values {
			out.Tags[v.Key] = v.Value
		}
	}
	if row.CapabilitiesPresent {
		values, err := r.q.OperationCapabilities(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Capabilities = make([]string, len(values))
		for i, v := range values {
			out.Capabilities[i] = v.Value
		}
	}
	if row.CallerSessionPoliciesPresent {
		values, err := r.q.CallerPolicies(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.SessionPolicies = make([]string, len(values))
		for i, v := range values {
			out.Caller.SessionPolicies[i] = v.Value
		}
	}
	if row.CallerSessionPolicyArnsPresent {
		values, err := r.q.CallerPolicyARNs(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.SessionPolicyARNs = make([]string, len(values))
		for i, v := range values {
			out.Caller.SessionPolicyARNs[i] = v.Value
		}
	}
	if row.CallerTransitiveTagKeysPresent {
		values, err := r.q.CallerTransitiveTagKeys(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.TransitiveTagKeys = make([]string, len(values))
		for i, v := range values {
			out.Caller.TransitiveTagKeys[i] = v.Value
		}
	}
	if row.CallerCalledViaPresent {
		values, err := r.q.CallerCalledVias(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.CalledVia = make([]string, len(values))
		for i, v := range values {
			out.Caller.CalledVia[i] = v.Value
		}
	}
	if row.CallerServicePrincipalAliasesPresent {
		values, err := r.q.CallerServiceAliases(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.ServicePrincipal.Aliases = make([]string, len(values))
		for i, v := range values {
			out.Caller.ServicePrincipal.Aliases[i] = v.Value
		}
	}
	if row.CallerSessionTagsPresent {
		values, err := r.q.CallerTags(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.SessionTags = make(map[string]string, len(values))
		for _, v := range values {
			out.Caller.SessionTags[v.Key] = v.Value
		}
	}
	if row.CallerSessionContextPresent {
		values, err := r.q.CallerContextKeys(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Caller.SessionContext = make(map[string][]string, len(values))
		for _, v := range values {
			if v.ValuesPresent {
				out.Caller.SessionContext[v.Key] = []string{}
			} else {
				out.Caller.SessionContext[v.Key] = nil
			}
		}
		claims, err := r.q.CallerContextValues(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		for _, v := range claims {
			out.Caller.SessionContext[v.Key] = append(out.Caller.SessionContext[v.Key], v.Value)
		}
	}
	if row.StepsPresent {
		values, err := r.q.Steps(r.ctx, row.ID)
		if err != nil {
			return out, err
		}
		out.Steps = make([]domain.StepRecord, len(values))
		for i, v := range values {
			out.Steps[i], err = decodeStep(v)
			if err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

func encodeOperation(v domain.OperationRecord) (sqlcgen.PutOperationParams, error) {
	var p sqlcgen.PutOperationParams
	var err error
	p.ID = v.ID
	p.StackID = v.StackID
	p.Kind = v.Kind
	p.Phase = v.Phase
	p.Token = v.Token
	p.RequestHash = v.RequestHash
	p.ChangeSetID = v.ChangeSetID
	p.Reason = v.Reason
	p.Template = v.Template
	p.ParametersPresent = v.Parameters != nil
	p.TagsPresent = v.Tags != nil
	p.CapabilitiesPresent = v.Capabilities != nil
	p.RoleArn = v.RoleARN
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
	p.CallerSessionPoliciesPresent = v.Caller.SessionPolicies != nil
	p.CallerSessionPolicyArnsPresent = v.Caller.SessionPolicyARNs != nil
	p.CallerHasSessionPolicy = v.Caller.HasSessionPolicy
	p.CallerSessionContextPresent = v.Caller.SessionContext != nil
	p.CallerFederatedProvider = v.Caller.FederatedProvider
	p.CallerSessionTagsPresent = v.Caller.SessionTags != nil
	p.CallerTransitiveTagKeysPresent = v.Caller.TransitiveTagKeys != nil
	p.CallerSourceIdentity = v.Caller.SourceIdentity
	p.CallerMfaPresent = v.Caller.MFAPresent
	p.CallerMfaAuthenticatedAt = v.Caller.MFAAuthenticatedAt.UTC()
	p.CallerTokenIssueTime = v.Caller.TokenIssueTime.UTC()
	p.CallerCalledViaPresent = v.Caller.CalledVia != nil
	p.CallerTransportKnown = v.Caller.TransportKnown
	p.CallerSourceIp = v.Caller.SourceIP
	p.CallerSecureTransport = v.Caller.SecureTransport
	p.CallerUserAgent = v.Caller.UserAgent
	p.CallerSignatureVersion = v.Caller.SignatureVersion
	p.CallerAuthenticationMethod = v.Caller.AuthenticationMethod
	p.CallerServicePrincipalName = v.Caller.ServicePrincipal.Name
	p.CallerServicePrincipalSourceArn = v.Caller.ServicePrincipal.SourceARN
	p.CallerServicePrincipalType = v.Caller.ServicePrincipal.Type
	p.CallerServicePrincipalAliasesPresent = v.Caller.ServicePrincipal.Aliases != nil
	p.CallerInvokedBy = v.Caller.InvokedBy
	p.CallerInScopeOfIssuerType = v.Caller.InScopeOf.IssuerType
	p.CallerInScopeOfCredentialsIssuedTo = v.Caller.InScopeOf.CredentialsIssuedTo
	p.StepsPresent = v.Steps != nil
	p.Cursor = int64(v.Cursor)
	p.Revision, err = signed(v.Revision)
	if err != nil {
		return p, err
	}
	p.Due = v.Due.UTC()
	p.Started = v.Started.UTC()
	p.Cancel = v.Cancel
	p.DisableRollback = v.DisableRollback
	return p, nil
}

func (w writer) PutOperation(v domain.OperationRecord) error {
	p, err := encodeOperation(v)
	if err != nil {
		return err
	}
	if err := w.q.PutOperation(w.ctx, p); err != nil {
		return err
	}
	if err := w.q.DeleteOperationParameters(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Parameters {
		resolved, present := v.ResolvedParameters[key]
		if err := w.q.PutOperationParameter(w.ctx, sqlcgen.PutOperationParameterParams{ParentID: v.ID, Key: key, Value: value, ResolvedValue: sql.NullString{String: resolved, Valid: present}}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteOperationTags(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutOperationTag(w.ctx, sqlcgen.PutOperationTagParams{ParentID: v.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteOperationCapabilities(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Capabilities {
		if err := w.q.PutOperationCapability(w.ctx, sqlcgen.PutOperationCapabilityParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerPolicies(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Caller.SessionPolicies {
		if err := w.q.PutCallerPolicy(w.ctx, sqlcgen.PutCallerPolicyParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerPolicyARNs(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Caller.SessionPolicyARNs {
		if err := w.q.PutCallerPolicyARN(w.ctx, sqlcgen.PutCallerPolicyARNParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerTransitiveTagKeys(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Caller.TransitiveTagKeys {
		if err := w.q.PutCallerTransitiveTagKey(w.ctx, sqlcgen.PutCallerTransitiveTagKeyParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerCalledVias(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Caller.CalledVia {
		if err := w.q.PutCallerCalledVia(w.ctx, sqlcgen.PutCallerCalledViaParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerServiceAliases(w.ctx, v.ID); err != nil {
		return err
	}
	for i, value := range v.Caller.ServicePrincipal.Aliases {
		if err := w.q.PutCallerServiceAlias(w.ctx, sqlcgen.PutCallerServiceAliasParams{ParentID: v.ID, Position: int64(i), Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerTags(w.ctx, v.ID); err != nil {
		return err
	}
	for key, value := range v.Caller.SessionTags {
		if err := w.q.PutCallerTag(w.ctx, sqlcgen.PutCallerTagParams{ParentID: v.ID, Key: key, Value: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteCallerContextKeys(w.ctx, v.ID); err != nil {
		return err
	}
	if err := w.q.DeleteCallerContextValues(w.ctx, v.ID); err != nil {
		return err
	}
	for key, values := range v.Caller.SessionContext {
		if err := w.q.PutCallerContextKey(w.ctx, sqlcgen.PutCallerContextKeyParams{ParentID: v.ID, Key: key, ValuesPresent: values != nil}); err != nil {
			return err
		}
		for i, value := range values {
			if err := w.q.PutCallerContextValue(w.ctx, sqlcgen.PutCallerContextValueParams{ParentID: v.ID, Key: key, Position: int64(i), Value: value}); err != nil {
				return err
			}
		}
	}
	if err := w.q.DeleteSteps(w.ctx, v.ID); err != nil {
		return err
	}
	for i, step := range v.Steps {
		p, err := encodeStep(v.ID, i, step)
		if err != nil {
			return err
		}
		if err := w.q.PutStep(w.ctx, p); err != nil {
			return err
		}
	}
	return nil
}

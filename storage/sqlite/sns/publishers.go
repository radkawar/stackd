package sns

import (
	"database/sql"
	"errors"

	domain "stackd/storage/sns"
	"stackd/storage/sqlite/sns/internal/sqlcgen"
)

func (r reader) publisher(key domain.MessageKey) (domain.CallerMetadata, error) {
	var m domain.CallerMetadata
	row, err := r.q.GetPublisher(r.ctx, sqlcgen.GetPublisherParams{MessageID: key.ID, Protocol: key.Protocol})
	if errors.Is(err, sql.ErrNoRows) {
		// Pre-migration live work has no verified caller; public KMS authorization
		// rejects that empty identity rather than borrowing the topic owner's.
		return m, nil
	}
	if err != nil {
		return m, err
	}
	m.AccountID = row.AccountID
	m.Region = row.Region
	m.Partition = row.Partition
	m.AccessKeyID = row.AccessKeyID
	m.RequestID = row.RequestID
	m.ParentEventID = row.ParentEventID
	m.TraceHeader = row.TraceHeader
	m.PrincipalARN = row.PrincipalArn
	m.PrincipalID = row.PrincipalID
	m.UserName = row.UserName
	m.SessionType = row.SessionType
	m.IssuerARN = row.IssuerArn
	m.IssuerID = row.IssuerID
	m.HasSessionPolicy = row.HasSessionPolicy
	m.FederatedProvider = row.FederatedProvider
	m.SourceIdentity = row.SourceIdentity
	m.MFAPresent = row.MfaPresent
	m.MFAAuthenticatedAt = row.MfaAuthenticatedAt
	m.TokenIssueTime = row.TokenIssueTime
	m.TransportKnown = row.TransportKnown
	m.SourceIP = row.SourceIp
	m.SecureTransport = row.SecureTransport
	m.UserAgent = row.UserAgent
	m.SignatureVersion = row.SignatureVersion
	m.AuthenticationMethod = row.AuthenticationMethod
	m.InvokedBy = row.InvokedBy
	m.ServicePrincipal.Name = row.ServiceName
	m.ServicePrincipal.SourceARN = row.ServiceSourceArn
	m.ServicePrincipal.Type = row.ServiceType
	lists, err := r.q.ListPublisherLists(r.ctx, sqlcgen.ListPublisherListsParams{MessageID: key.ID, Protocol: key.Protocol})
	if err != nil {
		return m, err
	}
	for _, row := range lists {
		switch row.Kind {
		case "policy":
			m.SessionPolicies = append(m.SessionPolicies, row.Value)
		case "policy_arn":
			m.SessionPolicyARNs = append(m.SessionPolicyARNs, row.Value)
		case "transitive_tag":
			m.TransitiveTagKeys = append(m.TransitiveTagKeys, row.Value)
		case "called_via":
			m.CalledVia = append(m.CalledVia, row.Value)
		case "service_alias":
			m.ServicePrincipal.Aliases = append(m.ServicePrincipal.Aliases, row.Value)
		}
	}
	tags, err := r.q.ListPublisherTags(r.ctx, sqlcgen.ListPublisherTagsParams{MessageID: key.ID, Protocol: key.Protocol})
	if err != nil {
		return m, err
	}
	if len(tags) > 0 {
		m.SessionTags = make(map[string]string, len(tags))
		for _, row := range tags {
			m.SessionTags[row.TagKey] = row.TagValue
		}
	}
	claims, err := r.q.ListPublisherContext(r.ctx, sqlcgen.ListPublisherContextParams{MessageID: key.ID, Protocol: key.Protocol})
	if err != nil {
		return m, err
	}
	if len(claims) > 0 {
		m.SessionContext = make(map[string][]string)
		for _, row := range claims {
			m.SessionContext[row.ContextKey] = append(m.SessionContext[row.ContextKey], row.Value)
		}
	}
	return m, nil
}

func (w writer) putPublisher(key domain.MessageKey, m domain.CallerMetadata) error {
	if err := w.q.PutPublisher(w.ctx, sqlcgen.PutPublisherParams{
		MessageID: key.ID, Protocol: key.Protocol,
		AccountID:            m.AccountID,
		Region:               m.Region,
		Partition:            m.Partition,
		AccessKeyID:          m.AccessKeyID,
		RequestID:            m.RequestID,
		ParentEventID:        m.ParentEventID,
		TraceHeader:          m.TraceHeader,
		PrincipalArn:         m.PrincipalARN,
		PrincipalID:          m.PrincipalID,
		UserName:             m.UserName,
		SessionType:          m.SessionType,
		IssuerArn:            m.IssuerARN,
		IssuerID:             m.IssuerID,
		HasSessionPolicy:     m.HasSessionPolicy,
		FederatedProvider:    m.FederatedProvider,
		SourceIdentity:       m.SourceIdentity,
		MfaPresent:           m.MFAPresent,
		MfaAuthenticatedAt:   m.MFAAuthenticatedAt,
		TokenIssueTime:       m.TokenIssueTime,
		TransportKnown:       m.TransportKnown,
		SourceIp:             m.SourceIP,
		SecureTransport:      m.SecureTransport,
		UserAgent:            m.UserAgent,
		SignatureVersion:     m.SignatureVersion,
		AuthenticationMethod: m.AuthenticationMethod,
		InvokedBy:            m.InvokedBy,
		ServiceName:          m.ServicePrincipal.Name,
		ServiceSourceArn:     m.ServicePrincipal.SourceARN,
		ServiceType:          m.ServicePrincipal.Type,
	}); err != nil {
		return err
	}
	if err := w.q.ClearPublisherLists(w.ctx, sqlcgen.ClearPublisherListsParams{MessageID: key.ID, Protocol: key.Protocol}); err != nil {
		return err
	}
	if err := w.q.ClearPublisherTags(w.ctx, sqlcgen.ClearPublisherTagsParams{MessageID: key.ID, Protocol: key.Protocol}); err != nil {
		return err
	}
	if err := w.q.ClearPublisherContext(w.ctx, sqlcgen.ClearPublisherContextParams{MessageID: key.ID, Protocol: key.Protocol}); err != nil {
		return err
	}
	for _, list := range []struct {
		kind   string
		values []string
	}{
		{"policy", m.SessionPolicies},
		{"policy_arn", m.SessionPolicyARNs},
		{"transitive_tag", m.TransitiveTagKeys},
		{"called_via", m.CalledVia},
		{"service_alias", m.ServicePrincipal.Aliases},
	} {
		for position, value := range list.values {
			if err := w.q.InsertPublisherList(w.ctx, sqlcgen.InsertPublisherListParams{MessageID: key.ID, Protocol: key.Protocol, Kind: list.kind, Position: int64(position), Value: value}); err != nil {
				return err
			}
		}
	}
	for keyName, value := range m.SessionTags {
		if err := w.q.InsertPublisherTag(w.ctx, sqlcgen.InsertPublisherTagParams{MessageID: key.ID, Protocol: key.Protocol, TagKey: keyName, TagValue: value}); err != nil {
			return err
		}
	}
	for keyName, values := range m.SessionContext {
		for position, value := range values {
			if err := w.q.InsertPublisherContext(w.ctx, sqlcgen.InsertPublisherContextParams{MessageID: key.ID, Protocol: key.Protocol, ContextKey: keyName, Position: int64(position), Value: value}); err != nil {
				return err
			}
		}
	}
	return nil
}

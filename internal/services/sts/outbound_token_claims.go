package sts

import (
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

func (s *signedSession) outboundTokenClaims(ctx context.Context, parent identity.Credential, audiences []string, tags map[string]string, issued, expiration time.Time) (map[string]any, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	subject := parent.PrincipalARN
	custom := map[string]any{"aws_account": m.AccountID, "source_region": m.Region}
	if parent.SessionType == identity.SessionTypeAssumeRole {
		subject = parent.IssuerARN
	}
	custom["principal_id"] = subject
	if parent.SessionType != "" {
		custom["original_session_exp"] = parent.Expiration.UTC().Format(time.RFC3339)
	}
	if parent.SourceIdentity != "" {
		custom["source_identity"] = parent.SourceIdentity
	}
	if parent.FederatedProvider != "" {
		custom["federated_provider"] = parent.FederatedProvider
	}
	principalTags := map[string]string{}
	if parent.PrincipalID != parent.AccountID {
		if s.identity == nil {
			return nil, outboundTokenFailure("The current IAM identity source is unavailable.")
		}
		set, err := s.identity.IdentityPolicies(ctx)
		if err != nil {
			return nil, stsDenied("Unable to resolve the current IAM identity.")
		}
		principalTags = set.PrincipalTags
	}
	principalTags = authorization.MergePrincipalTags(principalTags, parent.SessionTags)
	if len(principalTags) != 0 {
		custom["principal_tags"] = principalTags
	}
	if len(tags) != 0 {
		custom["request_tags"] = maps.Clone(tags)
	}
	if s.organizations != nil {
		id, path, err := s.organizations.PrincipalOrganization(ctx)
		if err != nil {
			return nil, outboundTokenFailure("Unable to resolve the caller's organization.")
		}
		if id != "" {
			custom["org_id"] = id
		}
		if path != "" {
			custom["ou_path"] = []string{path}
		}
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, outboundTokenFailure("Unable to create a token identifier.")
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	var audience any = audiences
	if len(audiences) == 1 {
		audience = audiences[0]
	}
	return map[string]any{
		"sub": subject, "aud": audience, "iat": issued.Unix(), "exp": expiration.Unix(),
		"jti": fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), "https://sts.amazonaws.com/": custom,
	}, nil
}

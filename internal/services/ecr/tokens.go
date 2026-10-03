package ecr

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	api "stackd/internal/awsapi/ecr"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"time"
)

func tokenHash(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}
func (s *Service) issueToken(tx Transaction, download RepositoryKey, digest string, lifetime time.Duration) (string, TokenRecord, error) {
	password := identifier() + identifier()
	identity := awsctx.FromContext(tx.Context())
	record := TokenRecord{Hash: tokenHash(password), Partition: identity.Partition, Region: identity.Region, Identity: identity, Expires: s.clock.Now().Add(lifetime), DownloadRepository: download, DownloadDigest: digest}
	if err := tx.DeleteExpiredTokens(s.clock.Now()); err != nil {
		return "", TokenRecord{}, err
	}
	if err := tx.PutToken(record); err != nil {
		return "", TokenRecord{}, err
	}
	return password, record, nil
}
func (s *Service) authorizationData(tx Transaction) (*api.GetAuthorizationTokenOutput, error) {
	origin, err := s.origin()
	if err != nil {
		return nil, err
	}
	password, record, err := s.issueToken(tx, RepositoryKey{}, "", 12*time.Hour)
	if err != nil {
		return nil, err
	}
	return &api.GetAuthorizationTokenOutput{AuthorizationData: api.AuthorizationDataList{{AuthorizationToken: new(api.Base64(base64.StdEncoding.EncodeToString([]byte("AWS:" + password)))), ExpiresAt: new(record.Expires), ProxyEndpoint: new(api.ProxyEndpoint(origin))}}}, nil
}
func (s *Service) getAuthorizationToken(tx Transaction, _ *api.GetAuthorizationTokenInput) (*api.GetAuthorizationTokenOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "GetAuthorizationToken", RepositoryRecord{Key: RepositoryKey{Scope: scope}}, nil); err != nil {
		return nil, err
	}
	return s.authorizationData(tx)
}

// ServiceAuthorization is reserved for the trusted CodeBuild service principal.
// It issues an ordinary retained registry token; every resource access still
// passes the current repository, registry and Organizations policy evaluator.
func (s *Service) ServiceAuthorization(ctx context.Context) (*api.GetAuthorizationTokenOutput, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	if m.ServicePrincipal.Name != "codebuild.amazonaws.com" || m.ServicePrincipal.SourceARN == "" {
		return nil, failure("AccessDeniedException", "Only trusted CodeBuild source principals may obtain service registry authorization.")
	}
	var out *api.GetAuthorizationTokenOutput
	err := s.repository.Attempt(ctx, func(tx Transaction) error { var err error; out, err = s.authorizationData(tx); return err })
	return out, wireError(err)
}
func (s *Service) registryIdentity(r *http.Request, key RepositoryKey, digest string) (context.Context, error) {
	user, password, ok := r.BasicAuth()
	download := false
	if !ok {
		password = r.URL.Query().Get("token")
		download = password != ""
	}
	if password == "" || (!download && user != "AWS") {
		return nil, failure("RegistryAuthenticationException", "Registry authentication is required.")
	}
	var token TokenRecord
	err := s.repository.View(r.Context(), func(tx Reader) error { var err error; token, err = tx.Token(tokenHash(password)); return err })
	if err != nil || !s.clock.Now().Before(token.Expires) {
		return nil, failure("RegistryAuthenticationException", "Registry authorization token is invalid or expired.")
	}
	if key.Name != "" && (token.Partition != key.Partition || token.Region != key.Region) {
		return nil, failure("RegistryAuthenticationException", "Registry authorization token belongs to another partition or region.")
	}
	if download {
		if token.DownloadDigest == "" || token.DownloadRepository != key || token.DownloadDigest != digest || (r.Method != "GET" && r.Method != "HEAD") {
			return nil, failure("RegistryAuthenticationException", "The download token does not authorize this resource.")
		}
	} else if token.DownloadDigest != "" {
		return nil, failure("RegistryAuthenticationException", "A layer download token cannot authenticate registry requests.")
	}
	m := token.Identity
	m.RequestID = identifier()
	m.TransportKnown = true
	m.SecureTransport = r.TLS != nil
	m.UserAgent = r.UserAgent()
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		m.SourceIP = host
	} else {
		m.SourceIP = r.RemoteAddr
	}
	m.AuthenticationMethod = "Basic"
	return awsctx.WithMetadata(r.Context(), m), nil
}

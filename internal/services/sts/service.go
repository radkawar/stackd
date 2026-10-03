// Package sts implements AWS Security Token Service credential lifecycles.
package sts

import (
	"context"
	"net/http"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

const Namespace = "https://sts.amazonaws.com/doc/2011-06-15/"

type Service struct {
	credentials         CredentialStore
	roles               RoleSource
	authorizer          authorization.Authorizer
	mfa                 MFAVerifier
	oidcProviders       OIDCProviderSource
	oidcKeys            oidcKeyCache
	samlProviders       SAMLProviderSource
	oauthTokens         OAuthTokenSource
	federation          FederationAuthority
	sessions            SessionAuthority
	rootSessions        RootSessionSource
	outboundWebIdentity OutboundWebIdentityIssuer
	identity            authorization.IdentitySource
	organizations       authorization.OrganizationSource
	tokenPreferences    TokenPreferences
	regions             RegionAccess
	now                 func() time.Time
	apiEvents           apievents.Recorder
}

func New() *Service { return NewWithIdentity(identity.NewStore("")) }
func NewWithIdentity(store *identity.Store) *Service {
	return NewWithDependencies(Dependencies{Credentials: store, Sessions: credentialAuthority{store}})
}

func (*Service) Operations() []string {
	return []string{"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity", "AssumeRoot", "GetAccessKeyInfo", "GetCallerIdentity", "GetFederationToken", "GetSessionToken", "GetWebIdentityToken"}
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.WithValue(r.Context(), globalEndpointKey{}, isGlobalSTSEndpoint(r.Host))
	r = r.WithContext(ctx)
	params, err := awswire.ParseQuery(r, awscatalog.AWSQuery)
	if err != nil {
		apiErr := stsValidation(err.Error())
		request, known := awsapi.FromContext(ctx)
		if !known && len(r.Form["Action"]) == 1 {
			model, _ := awscatalog.LookupService("sts")
			request.Operation, known = model.Operation(r.Form.Get("Action"))
		}
		if known {
			request.Input = nil
			if err := s.RecordRequestError(ctx, request, apiErr); err != nil {
				apiErr = stsAuditFailure()
			}
		}
		awswire.QueryError(w, r, Namespace, apiErr)
		return
	}
	action := params.Get("Action")
	if (action == "AssumeRoot" || action == "GetWebIdentityToken") && isGlobalSTSEndpoint(r.Host) {
		apiErr := &awswire.Error{Code: "InvalidAction", Message: "Unknown Operation", StatusCode: 400}
		model, _ := awscatalog.LookupService("sts")
		operation, _ := model.Operation(action)
		if err := s.RecordRequestError(ctx, awsapi.DecodedRequest{Operation: operation}, apiErr); err != nil {
			apiErr = stsAuditFailure()
		}
		awswire.QueryError(w, r, Namespace, apiErr)
		return
	}
	if _, ok := awsapi.FromContext(r.Context()); !ok {
		decoded, err := stsapi.DecodeRequest(action, awsapi.Request{Query: params})
		if err != nil {
			apiErr := awswire.QueryInputError(awscatalog.AWSQuery, err)
			if decoded.Operation.Name != "" {
				if err := s.RecordRequestError(ctx, decoded, apiErr); err != nil {
					apiErr = stsAuditFailure()
				}
			}
			awswire.QueryError(w, r, Namespace, apiErr)
			return
		}
		r = r.WithContext(awsapi.WithDecodedRequest(r.Context(), decoded))
	}
	ctx = r.Context()
	output, apiErr := s.dispatch(ctx, action)
	if apiErr != nil {
		awswire.QueryError(w, r, Namespace, apiErr)
		return
	}
	body, err := stsapi.EncodeResponse(action, output)
	if err != nil {
		awswire.QueryError(w, r, Namespace, &awswire.Error{Code: "InternalFailure", Message: "Unable to serialize STS response.", StatusCode: 500})
		return
	}
	awswire.WriteQueryBytes(w, r, Namespace, action, body)
}

// ExecuteCommand runs an admitted generated request through STS's authority.
func (s *Service) ExecuteCommand(ctx context.Context, decoded awsapi.DecodedRequest) (any, *awswire.Error) {
	return s.dispatch(awsapi.WithDecodedRequest(ctx, decoded), string(decoded.Operation.Name))
}

func (s *Service) dispatch(ctx context.Context, action string) (output any, apiErr *awswire.Error) {
	federationDispatched := false
	defer func() {
		// Issuance has already appended in its native authority transaction.
		// Reads and rejections reach this point only after that transaction closes.
		if (apiErr != nil && !federationDispatched) || action == "GetCallerIdentity" || action == "GetAccessKeyInfo" {
			if err := s.appendAPICall(ctx, s.now(), action, output, apiErr); err != nil {
				output, apiErr = nil, stsAuditFailure()
			}
		}
	}()
	m := awsctx.FromContext(ctx)
	if m.SessionType == string(identity.SessionTypeGetSessionToken) && action != "AssumeRole" && action != "GetCallerIdentity" && action != "GetWebIdentityToken" {
		return nil, stsDenied("GetSessionToken credentials can call only AssumeRole, GetCallerIdentity and GetWebIdentityToken in STS.")
	}
	if m.SessionType == string(identity.SessionTypeFederation) && action != "GetCallerIdentity" {
		return nil, stsDenied("Federated credentials can call only GetCallerIdentity in STS.")
	}
	switch action {
	case "GetCallerIdentity":
		arn, id := m.PrincipalARN, m.PrincipalID
		if arn == "" {
			arn = "arn:" + m.Partition + ":iam::" + m.AccountID + ":root"
		}
		if id == "" {
			id = m.AccountID
		}
		return &stsapi.GetCallerIdentityOutput{Account: ptr(stsapi.AccountType(m.AccountID)), Arn: ptr(stsapi.ArnType(arn)), UserId: ptr(stsapi.UserIdType(id))}, nil
	case "GetSessionToken":
		return s.getSessionToken(ctx)
	case "AssumeRole":
		return s.assumeRole(ctx)
	case "AssumeRoot":
		return s.assumeRoot(ctx)
	case "AssumeRoleWithSAML":
		federationDispatched = true
		return s.assumeRoleWithSAML(ctx)
	case "AssumeRoleWithWebIdentity":
		federationDispatched = true
		return s.assumeRoleWithWebIdentity(ctx)
	case "GetFederationToken":
		return s.getFederationToken(ctx)
	case "GetAccessKeyInfo":
		return s.getAccessKeyInfo(ctx)
	case "GetWebIdentityToken":
		return s.getWebIdentityToken(ctx)
	default:
		// TODO: Comeback implement delegated access tokens and signed authorization diagnostics.
		return nil, &awswire.Error{Code: "InvalidAction", Message: "Operation is not implemented: " + action, StatusCode: 400}
	}
}
func ptr[T any](v T) *T { return &v }
func value[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}

func credentialOutput(c identity.Credential) *stsapi.Credentials {
	return &stsapi.Credentials{AccessKeyId: ptr(stsapi.AccessKeyIdType(c.AccessKeyID)), SecretAccessKey: ptr(stsapi.AccessKeySecretType(c.SecretAccessKey)), SessionToken: ptr(stsapi.TokenType(c.SessionToken)), Expiration: &c.Expiration}
}

package iam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"strings"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const outboundIdentityPath = "/_stackd/oidc/"

func (s *Service) enableOutboundWebIdentityFederation(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	if a.settings.OutboundWebIdentity != nil && a.settings.OutboundWebIdentity.Enabled.Value {
		return nil, outboundIdentityError("FeatureEnabled", "Outbound identity federation is already enabled for this account.", http.StatusConflict)
	}
	if a.settings.OutboundWebIdentity == nil {
		if s.publicEndpoint == "" {
			return nil, outboundIdentityError("InternalFailure", "A public endpoint must be configured before enabling outbound identity federation.", http.StatusInternalServerError)
		}
		id, err := randomUUID()
		if err != nil {
			return nil, outboundIdentityFailure()
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, outboundIdentityFailure()
		}
		ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, outboundIdentityFailure()
		}
		rs256, err := newOutboundSigningKey(rsaKey)
		if err != nil {
			return nil, outboundIdentityFailure()
		}
		es384, err := newOutboundSigningKey(ecKey)
		if err != nil {
			return nil, outboundIdentityFailure()
		}
		a.settings.OutboundWebIdentity = &OutboundWebIdentityRecord{IssuerID: id, IssuerURL: strings.TrimSuffix(s.publicEndpoint, "/") + outboundIdentityPath + m.Partition + "/" + m.AccountID + "/" + id, RS256: rs256, ES384: es384}
	}
	a.settings.OutboundWebIdentity.Enabled.set(true, a.currentTime)
	return &iamapi.EnableOutboundWebIdentityFederationOutput{IssuerIdentifier: wirePointer(iamapi.StringType(a.settings.OutboundWebIdentity.IssuerURL))}, nil
}

func newOutboundSigningKey(private any) (OutboundSigningKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return OutboundSigningKey{}, err
	}
	id, err := randomUUID()
	if err != nil {
		return OutboundSigningKey{}, err
	}
	return OutboundSigningKey{ID: id, PKCS8DER: der}, nil
}

func disableOutboundWebIdentityFederation(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	if a.settings.OutboundWebIdentity == nil || !a.settings.OutboundWebIdentity.Enabled.Value {
		return nil, outboundIdentityDisabled()
	}
	a.settings.OutboundWebIdentity.Enabled.set(false, a.currentTime)
	return &iamapi.DisableOutboundWebIdentityFederationOutput{}, nil
}

func getOutboundWebIdentityFederationInfo(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	record := a.settings.OutboundWebIdentity
	if record == nil || !record.Enabled.Value {
		return nil, outboundIdentityDisabled()
	}
	return &iamapi.GetOutboundWebIdentityFederationInfoOutput{IssuerIdentifier: wirePointer(iamapi.StringType(record.IssuerURL)), JwtVendingEnabled: wirePointer(iamapi.BooleanType(true))}, nil
}

func outboundIdentityDisabled() *awswire.Error {
	return outboundIdentityError("FeatureDisabled", "Outbound identity federation is disabled for this account.", http.StatusNotFound)
}

func outboundIdentityFailure() *awswire.Error {
	return outboundIdentityError("InternalFailure", "Unable to access outbound identity signing material.", http.StatusInternalServerError)
}

func outboundIdentityError(code, message string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, StatusCode: status}
}

package iam

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
)

// OutboundIdentityHandler exposes the public metadata and signing keys of
// account issuers. Disabling token issuance does not revoke existing tokens.
func (s *Service) OutboundIdentityHandler() http.Handler {
	return http.HandlerFunc(s.serveOutboundIdentity)
}

func (s *Service) serveOutboundIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path, document, ok := strings.Cut(r.URL.Path, "/.well-known/")
	if !ok || (document != "openid-configuration" && document != "jwks.json") {
		http.NotFound(w, r)
		return
	}
	record, err := s.outboundIssuerRecord(r.Context(), path)
	if err != nil {
		http.Error(w, "Unable to load issuer", http.StatusInternalServerError)
		return
	}
	if record == nil {
		http.NotFound(w, r)
		return
	}
	var result any
	if document == "openid-configuration" {
		result = map[string]any{
			"issuer":                                record.IssuerURL,
			"jwks_uri":                              record.IssuerURL + "/.well-known/jwks.json",
			"id_token_signing_alg_values_supported": []string{"RS256", "ES384"},
			"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "jti", "https://sts.amazonaws.com/"},
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		}
	} else {
		keys := make([]map[string]string, 0, 2)
		for _, signing := range []struct {
			algorithm string
			stored    OutboundSigningKey
		}{{"RS256", record.RS256}, {"ES384", record.ES384}} {
			private, err := outboundPrivateKey(signing.stored, signing.algorithm)
			if err != nil {
				http.Error(w, "Unable to load signing keys", http.StatusInternalServerError)
				return
			}
			key := map[string]string{"kid": signing.stored.ID, "use": "sig", "alg": signing.algorithm}
			switch public := private.(type) {
			case *rsa.PrivateKey:
				key["kty"] = "RSA"
				key["n"] = base64.RawURLEncoding.EncodeToString(public.N.Bytes())
				key["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes())
			case *ecdsa.PrivateKey:
				point, err := public.PublicKey.Bytes()
				if err != nil {
					http.Error(w, "Unable to encode signing key", http.StatusInternalServerError)
					return
				}
				key["kty"], key["crv"] = "EC", "P-384"
				key["x"] = base64.RawURLEncoding.EncodeToString(point[1:49])
				key["y"] = base64.RawURLEncoding.EncodeToString(point[49:])
			}
			keys = append(keys, key)
		}
		result = map[string]any{"keys": keys}
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(result)
	}
}

// IsOutboundWebIdentityIssuer identifies this stack's stored issuers, including
// disabled ones, so their tokens cannot be recycled into AWS role federation.
func (s *Service) IsOutboundWebIdentityIssuer(ctx context.Context, issuer string) (bool, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return false, nil
	}
	record, err := s.outboundIssuerRecord(ctx, u.Path)
	return record != nil && record.IssuerURL == issuer, err
}

func (s *Service) outboundIssuerRecord(ctx context.Context, path string) (*OutboundWebIdentityRecord, error) {
	rest, ok := strings.CutPrefix(path, outboundIdentityPath)
	if !ok {
		return nil, nil
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" || len(parts[1]) != 12 || strings.Trim(parts[1], "0123456789") != "" {
		return nil, nil
	}
	var record *OutboundWebIdentityRecord
	err := s.view(ctx, func(tx ReadTx) error {
		settings, err := tx.AccountSettings(Scope{Partition: parts[0], AccountID: parts[1]})
		if err != nil {
			return err
		}
		if settings.OutboundWebIdentity != nil && settings.OutboundWebIdentity.IssuerID == parts[2] {
			record = settings.OutboundWebIdentity
		}
		return nil
	})
	return record, err
}

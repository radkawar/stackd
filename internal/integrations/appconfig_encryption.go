package integrations

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"stackd/internal/awsenvelope"
	"stackd/internal/services/appconfig"
)

func appConfigEncryptionContext(resource string) (string, error) {
	switch {
	case strings.Contains(resource, "/hostedconfigurationversion/"):
		return "aws:appconfig:hostedconfigurationversion:arn", nil
	case strings.Contains(resource, "/deployment/"):
		return "aws:appconfig:deployment:arn", nil
	default:
		return "", fmt.Errorf("AppConfig encryption requires the full hosted version or deployment ARN")
	}
}

func (a *AppConfigEffects) Protect(ctx context.Context, scope appconfig.Scope, identifier, resource string, plain []byte) ([]byte, string, error) {
	if a.Keys.KMS == nil {
		return nil, "", fmt.Errorf("AppConfig KMS owner is unavailable")
	}
	contextKey, err := appConfigEncryptionContext(resource)
	if err != nil {
		return nil, "", err
	}
	signer, err := awsenvelope.NewSigner()
	if err != nil {
		return nil, "", err
	}
	key, wrapped, keyARN, rejected := a.Keys.GenerateDataKey(appConfigScopeContext(ctx, scope), identifier, map[string]string{contextKey: resource, "aws-crypto-public-key": signer.PublicKey()})
	if rejected != nil {
		return nil, "", rejected
	}
	defer clear(key)
	sealed, err := signer.Seal(key, wrapped, keyARN, map[string]string{contextKey: resource}, plain)
	if err != nil {
		return nil, "", err
	}
	// Private framing retains the wrapped key beside the authenticated envelope;
	// encrypted bytes never replace the plaintext returned by AppConfig APIs.
	out := make([]byte, 4+len(wrapped), 4+len(wrapped)+len(sealed))
	binary.BigEndian.PutUint32(out, uint32(len(wrapped)))
	copy(out[4:], wrapped)
	return append(out, sealed...), keyARN, nil
}
func (a *AppConfigEffects) Unprotect(ctx context.Context, scope appconfig.Scope, keyARN, resource string, payload []byte) ([]byte, error) {
	if a.Keys.KMS == nil {
		return nil, fmt.Errorf("AppConfig KMS owner is unavailable")
	}
	contextKey, err := appConfigEncryptionContext(resource)
	if err != nil {
		return nil, err
	}
	if len(payload) < 4 {
		return nil, fmt.Errorf("invalid encrypted AppConfig content")
	}
	size := uint64(binary.BigEndian.Uint32(payload))
	if size > uint64(len(payload)-4) {
		return nil, fmt.Errorf("invalid encrypted AppConfig content")
	}
	wrapped := payload[4 : 4+size]
	envelope := payload[4+size:]
	expected := map[string]string{contextKey: resource}
	encryptionContext, err := awsenvelope.EncryptionContext(envelope, expected)
	if err != nil {
		return nil, err
	}
	key, actual, rejected := a.Keys.Decrypt(appConfigScopeContext(ctx, scope), wrapped, encryptionContext)
	if rejected != nil {
		return nil, rejected
	}
	defer clear(key)
	if actual != keyARN {
		return nil, fmt.Errorf("encrypted AppConfig content identifies a different KMS key")
	}
	return awsenvelope.Open(key, wrapped, keyARN, expected, envelope)
}

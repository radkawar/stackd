package ssm

import (
	"context"
	"encoding/base64"
	"stackd/internal/awsenvelope"
	"stackd/internal/awswire"
)

// DataKeys retains the original principal and joins the parameter transaction.
// Standard SecureString calls Encrypt; advanced values use unique data keys.
type DataKeys interface {
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Encrypt(context.Context, string, []byte, map[string]string) ([]byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
	IsAWSManagedKey(context.Context, string) (bool, error)
}

func parameterEncryptionContext(p ParameterRecord) map[string]string {
	return map[string]string{"PARAMETER_ARN": p.ARN}
}
func (s *Service) sealVersion(ctx context.Context, p ParameterRecord, v *VersionRecord, plain []byte) error {
	if v.Type != "SecureString" {
		v.Value = plain
		v.KeyID = ""
		return nil
	}
	defer clear(plain)
	if s.keys == nil {
		return failure("InternalServerError", "Parameter encryption is not configured.")
	}
	key := v.KeyID
	if key == "" || key == "alias/aws/ssm" {
		var rejected *awswire.Error
		key, rejected = s.keys.EnsureServiceKey(ctx, "ssm")
		if rejected != nil {
			return parameterKeyError(rejected)
		}
		v.KeyID = "alias/aws/ssm"
	}
	ec := parameterEncryptionContext(p)
	if v.Tier == "Standard" {
		ciphertext, arn, rejected := s.keys.Encrypt(ctx, key, plain, ec)
		if rejected != nil {
			return parameterKeyError(rejected)
		}
		v.Value = ciphertext
		v.KeyARN = arn
		return nil
	}
	dataKey, wrapped, arn, rejected := s.keys.GenerateDataKey(ctx, key, ec)
	if rejected != nil {
		return parameterKeyError(rejected)
	}
	defer clear(dataKey)
	payload, err := awsenvelope.Seal(dataKey, wrapped, arn, ec, plain)
	if err != nil {
		return err
	}
	v.Value = payload
	v.WrappedKey = wrapped
	v.KeyARN = arn
	return nil
}
func (s *Service) openVersion(r Reader, p ParameterRecord, v VersionRecord, decrypt bool) (string, error) {
	if v.Type != "SecureString" {
		return string(v.Value), nil
	}
	if !decrypt {
		return base64.StdEncoding.EncodeToString(v.Value), nil
	}
	if s.keys == nil {
		return "", failure("InternalServerError", "Parameter decryption is not configured.")
	}
	ec := parameterEncryptionContext(p)
	if len(v.WrappedKey) == 0 {
		plain, _, rejected := s.keys.Decrypt(r.Context(), v.Value, ec)
		if rejected != nil {
			return "", parameterKeyError(rejected)
		}
		defer clear(plain)
		return string(plain), nil
	}
	dataKey, _, rejected := s.keys.Decrypt(r.Context(), v.WrappedKey, ec)
	if rejected != nil {
		return "", parameterKeyError(rejected)
	}
	defer clear(dataKey)
	plain, err := awsenvelope.Open(dataKey, v.WrappedKey, v.KeyARN, ec, v.Value)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	return string(plain), nil
}
func parameterKeyError(rejected *awswire.Error) error {
	if rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" {
		return failure("AccessDeniedException", rejected.Message)
	}
	return failure("InvalidKeyId", rejected.Message)
}

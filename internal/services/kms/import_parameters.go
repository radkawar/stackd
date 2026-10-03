package kms

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"time"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func (s *Service) registerImports() {
	register(s, "GetParametersForImport", s.getParametersForImport)
	register(s, "ImportKeyMaterial", s.importKeyMaterial)
	register(s, "DeleteImportedKeyMaterial", s.deleteImportedKeyMaterial)
}

func importable(k *key) *awswire.Error {
	if k.Origin != "EXTERNAL" {
		return failure("UnsupportedOperationException", "The key origin must be EXTERNAL.")
	}
	if k.state != "PendingImport" && k.state != "Enabled" && k.state != "Disabled" {
		return failure("KMSInvalidStateException", "The key is not in a valid state for import.")
	}
	return nil
}

func (s *Service) getParametersForImport(ctx context.Context, in *kmsapi.GetParametersForImportInput) (*kmsapi.GetParametersForImportOutput, *awswire.Error) {
	algorithm, wrappingSpec := value(in.WrappingAlgorithm), value(in.WrappingKeySpec)
	ctx = withConditions(ctx, map[string][]string{"kms:WrappingAlgorithm": {algorithm}, "kms:WrappingKeySpec": {wrappingSpec}})
	k, err := s.keyIDAuthorized(ctx, value(in.KeyId))
	if err != nil {
		return nil, err
	}
	if err := importable(k); err != nil {
		return nil, err
	}
	bits, err := importWrapping(k.Spec, algorithm, wrappingSpec)
	if err != nil {
		return nil, err
	}
	private, generateErr := rsa.GenerateKey(rand.Reader, bits)
	if generateErr != nil {
		return nil, failure("KMSInternalException", "Unable to generate import wrapping key.")
	}
	public, encodeErr := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if encodeErr != nil {
		return nil, failure("KMSInternalException", "Unable to encode import wrapping key.")
	}
	parameters := ImportParametersRecord{Token: make([]byte, 32), PrivateKey: x509.MarshalPKCS1PrivateKey(private), Algorithm: algorithm, ValidTo: s.currentTime().UTC().Add(24 * time.Hour)}
	_, _ = rand.Read(parameters.Token)
	k.importParameters = append(k.importParameters, parameters)
	return &kmsapi.GetParametersForImportOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), PublicKey: public, ImportToken: parameters.Token, ParametersValidTo: ptr(parameters.ValidTo)}, nil
}

func (s *Service) decryptImportedMaterial(k *key, token, encrypted []byte) ([]byte, *awswire.Error) {
	for _, parameters := range k.importParameters {
		if !bytes.Equal(token, parameters.Token) {
			continue
		}
		if !s.currentTime().Before(parameters.ValidTo) {
			return nil, failure("ExpiredImportTokenException", "The import token has expired.")
		}
		private, err := x509.ParsePKCS1PrivateKey(parameters.PrivateKey)
		if err != nil {
			return nil, failure("KMSInternalException", "Unable to decode stored import wrapping key.")
		}
		plain, unwrapErr := unwrapImport(private, parameters.Algorithm, encrypted)
		if unwrapErr != nil {
			return nil, unwrapErr
		}
		defer clear(plain)
		return importedMaterial(k.Spec, plain)
	}
	return nil, failure("InvalidImportTokenException", "The import token is invalid or belongs to another key.")
}

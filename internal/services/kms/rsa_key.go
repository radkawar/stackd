package kms

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha1" // KMS RSAES_OAEP_SHA_1 uses SHA-1 for OAEP and MGF1.

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

type rsaEncryptionAlgorithm struct {
	name kmsapi.EncryptionAlgorithmSpec
	hash crypto.Hash
}

var rsaEncryptionAlgorithms = []rsaEncryptionAlgorithm{
	{"RSAES_OAEP_SHA_1", crypto.SHA1},
	{"RSAES_OAEP_SHA_256", crypto.SHA256},
}

var rsaSigningAlgorithms = []signingAlgorithm{
	{"RSASSA_PKCS1_V1_5_SHA_256", crypto.SHA256, false},
	{"RSASSA_PKCS1_V1_5_SHA_384", crypto.SHA384, false},
	{"RSASSA_PKCS1_V1_5_SHA_512", crypto.SHA512, false},
	{"RSASSA_PSS_SHA_256", crypto.SHA256, true},
	{"RSASSA_PSS_SHA_384", crypto.SHA384, true},
	{"RSASSA_PSS_SHA_512", crypto.SHA512, true},
}

func rsaBits(spec string) int {
	// TODO: Comeback capture and enforce RSA regional quotas, key/grant propagation, remaining authorization/error precedence and noncommercial partition behavior before KMS completion.
	switch spec {
	case "RSA_2048":
		return 2048
	case "RSA_3072":
		return 3072
	case "RSA_4096":
		return 4096
	default:
		return 0
	}
}

func rsaPrivate(k *key) (*rsa.PrivateKey, *awswire.Error) {
	decoded, err := asymmetricPrivate(k)
	if err != nil {
		return nil, err
	}
	private, ok := decoded.(*rsa.PrivateKey)
	if !ok {
		return nil, failure("KMSInternalException", "Stored key material is not RSA.")
	}
	return private, nil
}

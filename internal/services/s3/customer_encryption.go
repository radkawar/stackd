package s3

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"net/http"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// Customer headers retain presence: an absent algorithm and an empty algorithm
// are different native errors. Key material belongs only to the request.
type customerKeyHeaders struct {
	algorithm, key, md5                                string
	supplied, algorithmPresent, keyPresent, md5Present bool
}

func customerHeaders[A, K, M ~string](algorithm *A, key *K, digest *M) customerKeyHeaders {
	return customerKeyHeaders{
		algorithm: value(algorithm), key: value(key), md5: value(digest),
		supplied:         algorithm != nil || key != nil || digest != nil,
		algorithmPresent: algorithm != nil, keyPresent: key != nil, md5Present: digest != nil,
	}
}

func checkCustomerEncryption(bucket BucketRecord) *awswire.Error {
	if bucket.SSECustomerBlocked {
		return failure("AccessDenied", "Server-side encryption with customer-provided keys is blocked for this bucket.", 403)
	}
	return nil
}

// HTTPS is a transport invariant, checked before resource or key admission.
// Internal typed service calls have no transport and never trust proxy headers.
func customerTransportError(r *http.Request) *awswire.Error {
	if r.TLS != nil {
		return nil
	}
	for _, name := range [...]string{
		"X-Amz-Server-Side-Encryption-Customer-Algorithm",
		"X-Amz-Server-Side-Encryption-Customer-Key",
		"X-Amz-Server-Side-Encryption-Customer-Key-Md5",
		"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm",
		"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key",
		"X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5",
	} {
		if _, supplied := r.Header[name]; supplied {
			return invalid("Requests specifying Server Side Encryption with Customer provided keys must be made over a secure connection.")
		}
	}
	return nil
}

// parseCustomerKey admits header syntax. Reads permit an omitted key MD5 and
// defer proof of the retained key until after read preconditions.
func parseCustomerKey(headers customerKeyHeaders, writing bool) ([]byte, *awswire.Error) {
	if !headers.algorithmPresent {
		return nil, customerArgumentError("The encryption algorithm must be specified when using customer-provided keys.")
	}
	if headers.algorithm != "AES256" {
		wire := customerArgumentError("The encryption algorithm is not supported.")
		wire.Code, wire.ArgumentValue = "InvalidEncryptionAlgorithmError", new(headers.algorithm)
		return nil, wire
	}
	if !headers.keyPresent {
		return nil, customerArgumentError("The customer-provided encryption key must be specified.")
	}
	key, err := base64.StdEncoding.DecodeString(headers.key)
	if err != nil || len(key) == 0 {
		clear(key)
		wire := customerArgumentError("The customer-provided encryption key is invalid or too short.")
		wire.ArgumentValue = new(headers.key)
		return nil, wire
	}
	if writing && !headers.md5Present {
		clear(key)
		return nil, customerArgumentError("The customer-provided encryption key MD5 must be specified.")
	}
	if headers.md5Present {
		digest, err := base64.StdEncoding.DecodeString(headers.md5)
		expected := md5.Sum(key)
		if err != nil || !hmac.Equal(digest, expected[:]) {
			clear(key)
			return nil, customerArgumentError("The calculated MD5 hash of the key did not match the hash that was provided.")
		}
	}
	if writing && len(key) != 32 {
		clear(key)
		return nil, customerArgumentError("The provided key is not valid for the specified encryption algorithm.")
	}
	return key, nil
}

func customerArgumentError(message string) *awswire.Error {
	wire := invalid(message)
	wire.ArgumentName = "x-amz-server-side-encryption"
	return wire
}

func customerKeyHash(salt, key []byte) []byte {
	hash := hmac.New(sha256.New, salt)
	_, _ = hash.Write(key)
	return hash.Sum(nil)
}

func newCustomerKeyVerifier(key []byte) (*CustomerKeyVerifier, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	digest := md5.Sum(key)
	return &CustomerKeyVerifier{Salt: salt, Hash: customerKeyHash(salt, key), MD5: base64.StdEncoding.EncodeToString(digest[:])}, nil
}

func verifyCustomerKey(record ObjectRecord, key []byte, source bool) *awswire.Error {
	if hmac.Equal(customerKeyHash(record.CustomerKey.Salt, key), record.CustomerKey.Hash) {
		return nil
	}
	if source {
		return failure("InvalidRequest", "The provided encryption parameters did not match the ones used originally.", 400)
	}
	return denied()
}

func readCustomerHeaders(record ObjectRecord, headers customerKeyHeaders, writing bool) ([]byte, *awswire.Error) {
	if !headers.supplied {
		if record.CustomerKey != nil {
			return nil, failure("InvalidRequest", "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.", 400)
		}
		return nil, nil
	}
	if record.CustomerKey == nil {
		return nil, failure("InvalidRequest", "The encryption parameters are not applicable to this object.", 400)
	}
	return parseCustomerKey(headers, writing)
}

func readCustomerKey(record ObjectRecord, headers customerKeyHeaders, source, writing bool) ([]byte, *awswire.Error) {
	key, wire := readCustomerHeaders(record, headers, writing)
	if wire != nil || key == nil {
		return key, wire
	}
	if wire := verifyCustomerKey(record, key, source); wire != nil {
		clear(key)
		return nil, wire
	}
	return key, nil
}

func sseHeader(record ObjectRecord) *api.ServerSideEncryption {
	if record.CustomerKey != nil {
		return nil
	}
	return new(api.ServerSideEncryption(record.EncryptionAlgorithm))
}

func customerAlgorithm(record ObjectRecord) *api.SSECustomerAlgorithm {
	if record.CustomerKey == nil {
		return nil
	}
	return new(api.SSECustomerAlgorithm("AES256"))
}

func customerMD5(record ObjectRecord) *api.SSECustomerKeyMD5 {
	if record.CustomerKey == nil {
		return nil
	}
	return new(api.SSECustomerKeyMD5(record.CustomerKey.MD5))
}

// This is the CloudTrail response projection, not the generated wire encoder.
func encryptionResponse(record ObjectRecord) map[string]any {
	if record.CustomerKey != nil {
		return map[string]any{
			"x-amz-server-side-encryption-customer-algorithm": "AES256",
		}
	}
	response := map[string]any{"x-amz-server-side-encryption": record.EncryptionAlgorithm}
	if record.KMSKeyARN != "" {
		response["x-amz-server-side-encryption-aws-kms-key-id"] = record.KMSKeyARN
	}
	return response
}

func requestedEncryption(c *apiCall, conditions map[string][]string, in encryptionHeaders) {
	for _, header := range []struct{ name, value string }{
		{"x-amz-server-side-encryption", value(in.algorithm)},
		{"x-amz-server-side-encryption-aws-kms-key-id", value(in.keyID)},
		{"x-amz-server-side-encryption-customer-algorithm", in.customer.algorithm},
	} {
		if header.value != "" {
			conditions["s3:"+header.name] = []string{header.value}
			c.params[header.name] = header.value
		}
	}
}

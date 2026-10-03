package s3

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// EncryptionKeys performs envelope-key operations with the authenticated caller.
// Calls occur outside S3 repository callbacks; KMS owns its transaction and audit.
type EncryptionKeys interface {
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Encrypt(context.Context, string, []byte, map[string]string) ([]byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
}

func objectKMSContext(ctx context.Context, b BucketRecord) context.Context {
	m := awsctx.FromContext(ctx)
	m.Region, m.Partition = b.Region, b.Key.Partition
	// Preserve a delivering service's origin (for example Firehose) without
	// replacing the role/session that KMS must authorize.
	if m.InvokedBy == "" {
		m.InvokedBy = "fas.s3.amazonaws.com"
	}
	m.SourceIP, m.UserAgent = m.InvokedBy, m.InvokedBy
	return awsctx.WithMetadata(ctx, m)
}

func objectKeyError(wire *awswire.Error) *awswire.Error {
	if wire == nil {
		return nil
	}
	mapped := failure("KMS."+wire.Code, wire.Message, wire.StatusCode)
	if wire.Code == "AccessDeniedException" || wire.Code == "AccessDenied" {
		mapped.Code, mapped.StatusCode = "AccessDenied", 403
	}
	mapped.Cause = wire
	return mapped
}

func encryptionContext(encoded, arn string) (map[string]string, *awswire.Error) {
	out := map[string]string{"aws:s3:arn": arn}
	if encoded == "" {
		return out, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, invalid("The encryption context must be Base64-encoded JSON.")
	}
	var fields map[string]*string
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, invalid("The encryption context must be a JSON object of string values.")
	}
	for key, value := range fields {
		if value == nil {
			return nil, invalid("The encryption context must contain string values.")
		}
		if key == "aws:s3:arn" && *value != arn {
			return nil, invalid("The aws:s3:arn encryption context must match the object ARN.")
		}
		out[key] = *value
	}
	return out, nil
}

// encryptionHeaders is the common encryption choice on object writes and copies.
// Customer keys are transient; only their one-way verifier reaches a repository.
type encryptionHeaders struct {
	algorithm *api.ServerSideEncryption
	keyID     *api.SSEKMSKeyId
	context   *api.SSEKMSEncryptionContext
	customer  customerKeyHeaders
	bucketKey bool
}

// prepareEncryption chooses defaults once and returns the transient plaintext
// key. The object retains an SSE-S3 key, wrapped KMS key, or SSE-C verifier.
func (s *Service) prepareEncryption(ctx context.Context, b BucketRecord, in encryptionHeaders, record *ObjectRecord) ([]byte, *awswire.Error) {
	if in.bucketKey {
		// TODO: Comeback — implement S3 Bucket Key cryptography before admitting it.
		return nil, unsupported("S3 Bucket Keys are not implemented.")
	}
	algorithm, id := b.EncryptionAlgorithm, b.KMSKeyID
	if in.algorithm != nil {
		algorithm, id = value(in.algorithm), ""
	}
	if in.keyID != nil || in.context != nil {
		if value(in.algorithm) != "aws:kms" {
			return nil, invalid("KMS parameters require the aws:kms encryption algorithm.")
		}
		id = value(in.keyID)
	}
	if in.customer.supplied {
		if in.algorithm != nil {
			return nil, invalid("SSE-C cannot be combined with another server-side encryption method.")
		}
		key, wire := parseCustomerKey(in.customer, true)
		if wire != nil {
			return nil, wire
		}
		if wire := checkCustomerEncryption(b); wire != nil {
			clear(key)
			return nil, wire
		}
		verifier, err := newCustomerKeyVerifier(key)
		if err != nil {
			clear(key)
			return nil, wireError(err)
		}
		record.EncryptionAlgorithm, record.CustomerKey = "SSE-C", verifier
		return key, nil
	}
	record.EncryptionAlgorithm = algorithm
	switch algorithm {
	case "AES256":
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, wireError(err)
		}
		record.EncryptionKey = key
		return key, nil
	case "aws:kms":
		if s.keys == nil {
			return nil, unsupported("KMS encryption is unavailable.")
		}
		ec, wire := encryptionContext(value(in.context), record.Key.ARN())
		if wire != nil {
			return nil, wire
		}
		ctx = objectKMSContext(ctx, b)
		if id == "" {
			id, wire = s.keys.EnsureServiceKey(ctx, "s3")
			if wire != nil {
				return nil, objectKeyError(wire)
			}
		}
		plain, wrapped, arn, wire := s.keys.GenerateDataKey(ctx, id, ec)
		if wire != nil {
			return nil, objectKeyError(wire)
		}
		record.EncryptionKey, record.KMSKeyARN, record.EncryptionContext = wrapped, arn, ec
		return plain, nil
	case "aws:kms:dsse":
		// TODO: Comeback — implement dual-layer KMS encryption before admitting DSSE.
		return nil, unsupported("Dual-layer KMS encryption is not implemented.")
	default:
		return nil, invalid("The encryption algorithm is invalid.")
	}
}

// The implicit object ARN alone is not returned; retained additional context is.
func objectEncryptionContextHeader(context map[string]string) string {
	if len(context) <= 1 {
		return ""
	}
	encoded, _ := json.Marshal(context) // A string map cannot fail JSON encoding.
	return base64.StdEncoding.EncodeToString(encoded)
}

func (s *Service) objectDataKey(ctx context.Context, b BucketRecord, record ObjectRecord, customer []byte) ([]byte, *awswire.Error) {
	if record.CustomerKey != nil {
		return customer, nil
	}
	if record.EncryptionAlgorithm != "aws:kms" {
		return record.EncryptionKey, nil
	}
	if s.keys == nil {
		return nil, unsupported("KMS encryption is unavailable.")
	}
	plain, _, wire := s.keys.Decrypt(objectKMSContext(ctx, b), record.EncryptionKey, record.EncryptionContext)
	return plain, objectKeyError(wire)
}

package s3

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func objectEncryptionUpdateParameters(c *apiCall, in *api.UpdateObjectEncryptionInput) {
	if in.VersionId != nil {
		c.params["versionId"] = value(in.VersionId)
	}
	if in.ObjectEncryption == nil || in.ObjectEncryption.SSEKMS == nil {
		return
	}
	kms := in.ObjectEncryption.SSEKMS
	fields := map[string]any{}
	if kms.KMSKeyArn != nil {
		fields["KMSKeyArn"] = value(kms.KMSKeyArn)
	}
	if kms.BucketKeyEnabled != nil {
		fields["BucketKeyEnabled"] = bool(*kms.BucketKeyEnabled)
	}
	c.params["ObjectEncryption"] = map[string]any{"SSE-KMS": fields}
}

func encryptionUpdateInvalid(message string) *awswire.Error {
	return failure("InvalidRequest", message, 400)
}

// Validate the update document's deliberately narrow contract before accepting
// the model decoder's normalized values. Unknown methods and duplicate members
// must not be silently ignored, and a non-boolean BucketKeyEnabled is not false.
func objectEncryptionUpdateDocument(body []byte) *awswire.Error {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var path []string
	seen := map[string]bool{}
	var scalar strings.Builder
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return malformedXML()
		}
		switch token := token.(type) {
		case xml.StartElement:
			path = append(path, token.Name.Local)
			name := strings.Join(path, "/")
			switch name {
			case "ObjectEncryption", "ObjectEncryption/SSE-KMS", "ObjectEncryption/SSE-KMS/KMSKeyArn", "ObjectEncryption/SSE-KMS/BucketKeyEnabled":
			default:
				return encryptionUpdateInvalid("Only SSE-KMS object encryption updates are supported.")
			}
			if seen[name] {
				return encryptionUpdateInvalid("Object encryption members must not be repeated.")
			}
			seen[name] = true
			scalar.Reset()
		case xml.EndElement:
			if strings.Join(path, "/") == "ObjectEncryption/SSE-KMS/BucketKeyEnabled" {
				text := strings.TrimSpace(scalar.String())
				if text != "true" && text != "false" {
					return encryptionUpdateInvalid("BucketKeyEnabled must be true or false.")
				}
			}
			path = path[:len(path)-1]
			scalar.Reset()
		case xml.CharData:
			name := strings.Join(path, "/")
			if name == "ObjectEncryption/SSE-KMS/BucketKeyEnabled" || name == "ObjectEncryption/SSE-KMS/KMSKeyArn" {
				scalar.Write(token)
			} else if strings.TrimSpace(string(token)) != "" {
				return encryptionUpdateInvalid("The object encryption document is invalid.")
			}
		}
	}
	if !seen["ObjectEncryption/SSE-KMS"] || !seen["ObjectEncryption/SSE-KMS/KMSKeyArn"] {
		return encryptionUpdateInvalid("An SSE-KMS update requires a full KMS key ARN.")
	}
	return nil
}

func encryptionUpdateDestination(b BucketRecord, in *api.UpdateObjectEncryptionInput) (string, *awswire.Error) {
	if in.ObjectEncryption == nil || in.ObjectEncryption.SSEKMS == nil {
		return "", encryptionUpdateInvalid("A valid new encryption type is required. Specify SSE-KMS.")
	}
	requested := in.ObjectEncryption.SSEKMS
	if requested.BucketKeyEnabled != nil && bool(*requested.BucketKeyEnabled) {
		// TODO: Comeback integrate real S3 Bucket Key cryptography before accepting this transition.
		return "", unsupported("S3 Bucket Keys are not implemented.")
	}
	arn := value(requested.KMSKeyArn)
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != b.Key.Partition || parts[2] != "kms" || parts[3] == "" || !accountNumber.MatchString(parts[4]) || !strings.HasPrefix(parts[5], "key/") {
		return "", encryptionUpdateInvalid("A full KMS key ARN is required; key IDs and aliases are not supported.")
	}
	id := strings.TrimPrefix(parts[5], "key/")
	if strings.HasPrefix(id, "mrk-") {
		if len(id) != 36 || strings.Trim(id[4:], "0123456789abcdef") != "" {
			return "", encryptionUpdateInvalid("The KMS key ARN is invalid.")
		}
	} else if uuid.Validate(id) != nil || len(id) != 36 {
		return "", encryptionUpdateInvalid("The KMS key ARN is invalid.")
	}
	if parts[4] != b.AccountID {
		return "", failure("AccessDenied", "The destination KMS key must be owned by the bucket owner's account.", 403)
	}
	if parts[3] != b.Region {
		return "", encryptionUpdateInvalid("The destination KMS key must be in the bucket's Region.")
	}
	return arn, nil
}

func (s *Service) encryptionUpdateObject(r Reader, c *apiCall, in *api.UpdateObjectEncryptionInput) (BucketRecord, ObjectRecord, error) {
	b, err := s.bucket(r, c, value(in.ExpectedBucketOwner))
	if err != nil {
		return b, ObjectRecord{}, err
	}
	if wire := validateKey(c.key); wire != nil {
		return b, ObjectRecord{}, wire
	}
	conditions := map[string][]string{}
	if in.VersionId != nil {
		conditions["s3:VersionId"] = []string{value(in.VersionId)}
	}
	if in.ObjectEncryption != nil && in.ObjectEncryption.SSEKMS != nil {
		conditions["s3:x-amz-server-side-encryption"] = []string{"aws:kms"}
		conditions["s3:x-amz-server-side-encryption-aws-kms-key-id"] = []string{value(in.ObjectEncryption.SSEKMS.KMSKeyArn)}
	}
	key := ObjectKey{b.Key, c.key}
	record, err := selectObjectVersion(r, key, in.VersionId)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return b, record, err
	}
	if errors.Is(err, ErrNotFound) {
		record.Key = key
	}
	if err == nil && !record.DeleteMarker {
		tags, tagErr := r.ObjectTags(record.VersionKey())
		if tagErr != nil {
			return b, record, tagErr
		}
		existingTagConditions(conditions, tags)
	}
	if wire := s.authorizeObject(r.Context(), c, b, record, "UpdateObjectEncryption", conditions); wire != nil {
		return b, record, wire
	}
	if errors.Is(err, ErrNotFound) || record.DeleteMarker {
		if wire := s.authorize(r.Context(), c, b, "ListBucket", "", nil); wire != nil {
			return b, record, wire
		}
		return b, record, noSuchKey(c.key)
	}
	if record.CustomerKey != nil || record.EncryptionAlgorithm != "AES256" && record.EncryptionAlgorithm != "aws:kms" {
		return b, record, encryptionUpdateInvalid("Only source objects encrypted with SSE-S3 or SSE-KMS are supported.")
	}
	if record.Retention.Mode != "" || record.LegalHold == "ON" {
		return b, record, failure("AccessDenied", "The object's encryption cannot be updated while Object Lock retention or a legal hold is applied.", 403)
	}
	return b, record, nil
}

func (s *Service) updateObjectEncryption(ctx context.Context, in *api.UpdateObjectEncryptionInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "UpdateObjectEncryption", value(in.Bucket), value(in.Key), "encryption")
	objectEncryptionUpdateParameters(c, in)
	out := &preparedResponse{}
	if awsctx.FromContext(ctx).SignatureVersion != "SigV4" {
		return out, s.complete(ctx, c, encryptionUpdateInvalid("Object encryption updates require AWS Signature Version 4."))
	}
	if request, ok := awsapi.FromContext(ctx); ok && len(request.Body) != 0 {
		if wire := objectEncryptionUpdateDocument(request.Body); wire != nil {
			return out, s.complete(ctx, c, wire)
		}
	}
	var admitted BucketRecord
	var source ObjectRecord
	var destination string
	var destinationContext map[string]string
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		admitted, source, err = s.encryptionUpdateObject(r, c, in)
		if err != nil {
			return err
		}
		var wire *awswire.Error
		destination, wire = encryptionUpdateDestination(admitted, in)
		if wire != nil {
			return wire
		}
		return nil
	})
	defer clear(source.EncryptionKey)
	if err != nil {
		return out, s.complete(ctx, c, err)
	}
	if s.keys == nil {
		return out, s.complete(ctx, c, unsupported("KMS encryption is unavailable."))
	}
	destinationContext = maps.Clone(source.EncryptionContext)
	if destinationContext == nil {
		destinationContext = map[string]string{"aws:s3:arn": source.Key.ARN()}
	}
	kmsContext := objectKMSContext(ctx, admitted)
	if wire := s.keys.CheckDataKeyRewrap(kmsContext, source.KMSKeyARN, destination, sourceCiphertext(source), nil, source.EncryptionContext, destinationContext); wire != nil {
		return out, s.complete(ctx, c, objectKeyError(wire))
	}
	var wrapped []byte
	var wire *awswire.Error
	if source.EncryptionAlgorithm == "AES256" {
		wrapped, _, wire = s.keys.Encrypt(kmsContext, destination, source.EncryptionKey, destinationContext)
	} else {
		wrapped, wire = s.keys.ReEncrypt(kmsContext, source.EncryptionKey, destination, source.EncryptionContext, destinationContext)
	}
	if wire != nil {
		return out, s.complete(ctx, c, objectKeyError(wire))
	}
	wire = s.execute(ctx, c, func(tx Transaction) error {
		b, current, err := s.encryptionUpdateObject(tx, c, in)
		defer clear(current.EncryptionKey)
		if err != nil {
			return err
		}
		if b.Incarnation != admitted.Incarnation || current.VersionID != source.VersionID || current.Sequence != source.Sequence || current.CreatedOrder != source.CreatedOrder || current.EncryptionAlgorithm != source.EncryptionAlgorithm || current.KMSKeyARN != source.KMSKeyARN || !bytes.Equal(current.EncryptionKey, source.EncryptionKey) || !maps.Equal(current.EncryptionContext, source.EncryptionContext) {
			return failure("OperationAborted", "A conflicting operation changed the object or bucket during the encryption update.", 409)
		}
		if _, wire := encryptionUpdateDestination(b, in); wire != nil {
			return wire
		}
		if wire := s.keys.CheckDataKeyRewrap(objectKMSContext(tx.Context(), b), current.KMSKeyARN, destination, sourceCiphertext(current), wrapped, current.EncryptionContext, destinationContext); wire != nil {
			return objectKeyError(wire)
		}
		if err := tx.ReplaceObjectEncryption(current.VersionKey(), "aws:kms", destination, wrapped, destinationContext); err != nil {
			return err
		}
		c.additional["objectSize"] = current.Size
		// This is a metadata-only update: no replication or object-created
		// notification, payload reads or Intelligent-Tiering access signal.
		return out.prepare(c, &api.UpdateObjectEncryptionOutput{})
	})
	return out, wire
}

func sourceCiphertext(record ObjectRecord) []byte {
	if record.EncryptionAlgorithm == "aws:kms" {
		return record.EncryptionKey
	}
	return nil
}

func encryptionUpdateTransportError(operation string, header http.Header) *awswire.Error {
	if operation != "UpdateObjectEncryption" {
		return nil
	}
	for name := range header {
		name = strings.ToLower(name)
		if strings.HasPrefix(name, "x-amz-server-side-encryption") || strings.HasPrefix(name, "x-amz-copy-source") {
			return encryptionUpdateInvalid("UpdateObjectEncryption accepts encryption settings only in its SSE-KMS XML document.")
		}
	}
	return nil
}

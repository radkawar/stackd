package s3

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// Local IDs are opaque identifiers with a versioned local envelope. This is
// deliberately not a validator for AWS's private token encoding. An otherwise
// valid local token remains valid after deletion, producing NoSuchVersion on GET.
func issueVersion(state string) (string, error) {
	if state != "Enabled" {
		return "null", nil
	}
	var token [24]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return "sv1_" + base64.RawURLEncoding.EncodeToString(token[:]), nil
}

func validateVersion(version string) *awswire.Error {
	if version == "null" {
		return nil
	}
	if strings.HasPrefix(version, "sv1_") {
		raw := strings.TrimPrefix(version, "sv1_")
		token, err := base64.RawURLEncoding.Strict().DecodeString(raw)
		if err == nil && len(token) == 24 && base64.RawURLEncoding.EncodeToString(token) == raw {
			return nil
		}
	}
	return argumentError("versionId", version, "Invalid version id specified")
}

func selectObjectVersion(r Reader, key ObjectKey, version *api.ObjectVersionId) (ObjectRecord, error) {
	if version == nil {
		return r.Object(key)
	}
	if wire := validateVersion(value(version)); wire != nil {
		return ObjectRecord{}, wire
	}
	return r.ObjectVersion(ObjectVersionKey{ObjectKey: key, VersionID: value(version)})
}

func (s *Service) getBucketVersioning(ctx context.Context, in *api.GetBucketVersioningInput) (*api.GetBucketVersioningOutput, *awswire.Error) {
	c := call(ctx, "GetBucketVersioning", value(in.Bucket), "")
	c.params["versioning"] = ""
	out := &api.GetBucketVersioningOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketVersioning", "", nil); w != nil {
			return w
		}
		if b.Versioning != "" {
			out.Status = new(api.BucketVersioningStatus(b.Versioning))
		}
		if b.ObjectLockEnabled {
			out.MFADelete = new(api.MFADeleteStatus("Disabled"))
		}
		return nil
	})
	return out, wire
}

func (s *Service) putBucketVersioning(ctx context.Context, in *api.PutBucketVersioningInput) (*api.PutBucketVersioningOutput, *awswire.Error) {
	c := call(ctx, "PutBucketVersioning", value(in.Bucket), "")
	c.params["versioning"] = ""
	c.params["VersioningConfiguration"] = in.VersioningConfiguration
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutBucketVersioning", "", nil); w != nil {
			return w
		}
		if in.VersioningConfiguration == nil || in.VersioningConfiguration.Status == nil {
			return failure("IllegalVersioningConfigurationException", "The Versioning element must be specified", 400)
		}
		if in.MFA != nil || in.VersioningConfiguration.MFADelete != nil {
			return unsupported("MFA delete is not implemented.")
		}
		state := value(in.VersioningConfiguration.Status)
		if state != "Enabled" && state != "Suspended" {
			return failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema", 400)
		}
		if b.ObjectLockEnabled && state != "Enabled" {
			return failure("InvalidBucketState", "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.", 409)
		}
		if state == "Suspended" {
			replication, err := tx.BucketReplication(b.Key)
			if err != nil {
				return err
			}
			if replication != nil {
				return failure("InvalidBucketState", "A replication configuration is present on this bucket, so you cannot change the versioning state. To change the versioning state, first delete the replication configuration.", 409)
			}
		}
		b.Versioning = state
		return tx.PutBucket(b)
	})
	return &api.PutBucketVersioningOutput{}, wire
}

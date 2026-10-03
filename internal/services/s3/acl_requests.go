package s3

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func validOwnership(mode string) bool {
	return mode == "BucketOwnerEnforced" || mode == "BucketOwnerPreferred" || mode == "ObjectWriter"
}
func invalidBucketOwnershipACL() *awswire.Error {
	return failure("InvalidBucketAclWithObjectOwnership", "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting", 400)
}

// aclRequestError gives source-owned error semantics to generated decode failures.
func aclRequestError(name string, err error) *awswire.Error {
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) && validation.Path == "ACL" {
		return argumentError("x-amz-acl", validation.EnumValue, "")
	}
	if name == "PutBucketAcl" || name == "PutObjectAcl" {
		if errors.As(err, &validation) && (validation.Path == "Bucket" || validation.Path == "Key") {
			return nil
		}
		if validation != nil && validation.Reason == "expected XML scalar" {
			return malformedXML()
		}
		return malformedACL()
	}
	if name == "PutBucketOwnershipControls" {
		if errors.As(err, &validation) && validation.Path == "OwnershipControls" && validation.Constraint == "required" {
			return failure("MissingRequestBodyError", "Request Body is empty", 400)
		}
		return malformedXML()
	}
	return nil
}

func validateACLRequest(ctx context.Context, canned string, hasGrants bool) *awswire.Error {
	decoded, ok := awsapi.FromContext(ctx)
	if !ok || len(decoded.Body) == 0 {
		return nil
	}
	if canned != "" || hasGrants {
		return failure("UnexpectedContent", "This request does not support content", 400)
	}
	return nil
}

func (s *Service) putBucketOwnershipControls(ctx context.Context, in *api.PutBucketOwnershipControlsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketOwnershipControls", value(in.Bucket), "", "ownershipControls")
	ownershipParameters(c, in.OwnershipControls)
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutBucketOwnershipControls", "", nil); wire != nil {
			return wire
		}
		// Typed commands carry the admitted structure without a wire body.
		// An empty HTTP payload is bound as nil and is rejected here as well.
		if in.OwnershipControls == nil {
			return failure("MissingRequestBodyError", "Request Body is empty", 400)
		}
		if len(in.OwnershipControls.Rules) != 1 || !validOwnership(value(in.OwnershipControls.Rules[0].ObjectOwnership)) {
			return malformedXML()
		}
		mode := value(in.OwnershipControls.Rules[0].ObjectOwnership)
		if mode == "BucketOwnerEnforced" && !ownerFullControlOnly(originalACL(b, b.ACL), canonicalID(b.Key.Partition, b.AccountID)) {
			return invalidBucketOwnershipACL()
		}
		b.Ownership = mode
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketOwnershipControlsOutput{})
	})
	return out, wire
}

func (s *Service) deleteBucketOwnershipControls(ctx context.Context, in *api.DeleteBucketOwnershipControlsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketOwnershipControls", value(in.Bucket), "", "ownershipControls")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutBucketOwnershipControls", "", nil); wire != nil {
			return wire
		}
		b.Ownership = ""
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		return out.prepare(c, &api.DeleteBucketOwnershipControlsOutput{})
	})
	return out, wire
}

func (s *Service) putBucketACL(ctx context.Context, in *api.PutBucketAclInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketAcl", value(in.Bucket), "", "acl")
	aclParameters(c, value(in.ACL), in.AccessControlPolicy)
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutBucketAcl", "", nil); wire != nil {
			return wire
		}
		headers := aclHeaders{full: value(in.GrantFullControl), read: value(in.GrantRead), readACP: value(in.GrantReadACP), write: value(in.GrantWrite), writeACP: value(in.GrantWriteACP)}
		if wire := validateACLRequest(ctx, value(in.ACL), headers.supplied()); wire != nil {
			return wire
		}
		acl, wire := parseACL(b, originalACL(b, b.ACL), value(in.ACL), headers, in.AccessControlPolicy, true)
		if wire != nil {
			return wire
		}
		if b.Ownership == "BucketOwnerEnforced" {
			return aclDisabled()
		}
		if c.publicAccess.BlockPublicACLs && publicACL(acl) {
			return denied()
		}
		b.ACL = acl
		if err := tx.PutBucket(b); err != nil {
			return err
		}
		c.aclRequired = true
		return out.prepare(c, &api.PutBucketAclOutput{})
	})
	return out, wire
}

type objectACLResponse[O any] struct {
	response    O
	prepared    preparedResponse
	version     string
	marker      bool
	allowDelete bool
}

func (out *objectACLResponse[O]) responseWithHeaders(headers http.Header) any {
	if out.version != "" {
		headers.Set("x-amz-version-id", out.version)
	}
	if out.marker {
		headers.Set("x-amz-delete-marker", "true")
	}
	if out.allowDelete {
		headers.Set("Allow", "DELETE")
	}
	return &out.prepared
}

func (out *objectACLResponse[O]) modeledOutput() any { return &out.response }

func (s *Service) aclObject(r Reader, c *apiCall, expected string, version *api.ObjectVersionId) (BucketRecord, ObjectRecord, error) {
	b, err := s.bucket(r, c, expected)
	if err != nil {
		return b, ObjectRecord{}, err
	}
	if wire := validateKey(c.key); wire != nil {
		return b, ObjectRecord{}, wire
	}
	object, err := selectObjectVersion(r, ObjectKey{b.Key, c.key}, version)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return b, object, err
	}
	if err == nil && object.DeleteMarker {
		if version == nil && c.name == "GetObjectAcl" {
			return b, object, noSuchKey(c.key)
		}
		wire := failure("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
		wire.Method, wire.ResourceType = strings.ToUpper(strings.TrimSuffix(c.name, "ObjectAcl")), "DeleteMarker"
		return b, object, wire
	}
	if errors.Is(err, ErrNotFound) {
		object.Key = ObjectKey{b.Key, c.key}
	}
	action := c.name
	conditions := map[string][]string{}
	if version != nil {
		action = strings.Replace(action, "ObjectAcl", "ObjectVersionAcl", 1)
		conditions["s3:VersionId"] = []string{value(version)}
	}
	if wire := s.authorizeObject(r.Context(), c, b, object, action, conditions); wire != nil {
		return b, ObjectRecord{}, wire
	}
	if errors.Is(err, ErrNotFound) {
		if version != nil {
			return b, object, failure("NoSuchVersion", "The specified version does not exist.", 404)
		}
		if wire := s.authorize(r.Context(), c, b, "ListBucket", "", nil); wire != nil {
			return b, object, wire
		}
		return b, object, noSuchKey(c.key)
	}
	return b, object, nil
}

func (s *Service) getObjectACL(ctx context.Context, in *api.GetObjectAclInput) (*objectACLResponse[api.GetObjectAclOutput], *awswire.Error) {
	c := s.accessCall(ctx, "GetObjectAcl", value(in.Bucket), value(in.Key), "acl")
	if in.VersionId != nil {
		c.params["versionId"] = value(in.VersionId)
	}
	out := &objectACLResponse[api.GetObjectAclOutput]{}
	err := s.repository.View(ctx, func(r Reader) error {
		b, object, err := s.aclObject(r, c, value(in.ExpectedBucketOwner), in.VersionId)
		if object.DeleteMarker {
			out.version, out.marker = object.VersionID, true
			out.allowDelete = in.VersionId != nil
		}
		if err != nil {
			return err
		}
		out.version = object.VersionID
		out.response.Owner, out.response.Grants = aclOutput(effectiveACL(b, object.ACL, c.publicAccess.IgnorePublicACLs))
		return out.prepared.prepare(c, &out.response)
	})
	return out, s.complete(ctx, c, err)
}

func (s *Service) putObjectACL(ctx context.Context, in *api.PutObjectAclInput) (*objectACLResponse[api.PutObjectAclOutput], *awswire.Error) {
	c := s.accessCall(ctx, "PutObjectAcl", value(in.Bucket), value(in.Key), "acl")
	aclParameters(c, value(in.ACL), in.AccessControlPolicy)
	if in.VersionId != nil {
		c.params["versionId"] = value(in.VersionId)
	}
	out := &objectACLResponse[api.PutObjectAclOutput]{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, object, err := s.aclObject(tx, c, value(in.ExpectedBucketOwner), in.VersionId)
		if object.DeleteMarker {
			out.allowDelete = true
			if in.VersionId != nil {
				out.version, out.marker = object.VersionID, true
			}
		}
		if err != nil {
			return err
		}
		headers := aclHeaders{full: value(in.GrantFullControl), read: value(in.GrantRead), readACP: value(in.GrantReadACP), write: value(in.GrantWrite), writeACP: value(in.GrantWriteACP)}
		if wire := validateACLRequest(ctx, value(in.ACL), headers.supplied()); wire != nil {
			return wire
		}
		acl, wire := parseACL(b, effectiveACL(b, object.ACL, c.publicAccess.IgnorePublicACLs), value(in.ACL), headers, in.AccessControlPolicy, true)
		if wire != nil {
			return wire
		}
		if b.Ownership == "BucketOwnerEnforced" {
			return aclDisabled()
		}
		if c.publicAccess.BlockPublicACLs && publicACL(acl) {
			return denied()
		}
		if err := tx.ReplaceObjectACL(object.VersionKey(), *acl); err != nil {
			return err
		}
		changed := !equalACL(originalACL(b, object.ACL), acl)
		object.ACL = acl
		out.version = object.VersionID
		c.aclRequired = true
		if err := s.enqueueObjectReplication(tx, c, b, object, ReplicationACL); err != nil {
			return err
		}
		if changed {
			if err := s.notifyObject(tx, c, b, object, "ObjectAcl:Put"); err != nil {
				return err
			}
		}
		return out.prepared.prepare(c, &out.response)
	})
	return out, wire
}

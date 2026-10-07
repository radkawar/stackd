package s3

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var commercialRegions = awscatalog.CommercialRegions()

func validLocation(partition, region string) bool {
	switch partition {
	case "aws":
		return slices.ContainsFunc(commercialRegions, func(r awscatalog.CommercialRegion) bool { return r.Name == region })
	case "aws-cn":
		return region == "cn-north-1" || region == "cn-northwest-1"
	case "aws-us-gov":
		return region == "us-gov-east-1" || region == "us-gov-west-1"
	default:
		return false
	}
}
func createBucketRequestError(name string, err error) *awswire.Error {
	var validation *awsapi.ValidationError
	if name == "CreateBucket" && errors.As(err, &validation) &&
		validation.Path == "CreateBucketConfiguration.LocationConstraint" && validation.Constraint == "enum" {
		return failure("InvalidLocationConstraint", "The specified location constraint is not valid.", 400)
	}
	return nil
}

func (s *Service) createBucket(ctx context.Context, in *api.CreateBucketInput) (*api.CreateBucketOutput, *awswire.Error) {
	c := s.accessCall(ctx, "CreateBucket", value(in.Bucket), "", "")
	if s.events != nil {
		request, _ := awsapi.FromContext(ctx)
		xmlAuditParameters(c, request.Body)
		createBucketParameters(c, in)
	}
	out := &api.CreateBucketOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		if w := validateBucket(c.bucket); w != nil {
			return w
		}
		if in.BucketNamespace != nil {
			return unsupported("Bucket namespaces are not implemented.")
		}
		ownership := value(in.ObjectOwnership)
		if ownership == "" {
			ownership = "BucketOwnerEnforced"
		}
		if !validOwnership(ownership) {
			return invalid("Invalid object ownership setting.")
		}
		m := awsctx.FromContext(tx.Context())
		region := "us-east-1"
		var tags []Tag
		if conf := in.CreateBucketConfiguration; conf != nil {
			if conf.Bucket != nil || conf.Location != nil {
				return unsupported("Directory buckets are not implemented.")
			}
			if conf.LocationConstraint != nil {
				region = value(conf.LocationConstraint)
				if region == "EU" {
					region = "eu-west-1"
				}
				if region == "" || region == "us-east-1" {
					return failure("InvalidLocationConstraint", "The specified location constraint is not valid.", 400)
				}
			}
			if conf.Tags != nil {
				var wire *awswire.Error
				tags, wire = validateBucketTags(&api.Tagging{TagSet: conf.Tags}, true)
				if wire != nil {
					return wire
				}
			}
		}
		if !validLocation(m.Partition, region) {
			return failure("InvalidLocationConstraint", "The specified location constraint is not valid in this partition.", 400)
		}
		if m.Region != "" && m.Region != "us-east-1" && m.Region != region {
			return failure("IllegalLocationConstraintException", "The location constraint is incompatible with the regional endpoint.", 400)
		}
		b := BucketRecord{Key: BucketKey{m.Partition, c.bucket}, AccountID: m.AccountID, Region: region, Created: s.clock.Now().UTC(), Ownership: ownership, PublicAccess: &PublicAccessBlock{true, true, true, true}, EncryptionAlgorithm: "AES256", SSECustomerBlocked: true}
		if in.ObjectLockEnabledForBucket != nil {
			b.ObjectLockEnabled = bool(*in.ObjectLockEnabledForBucket)
			if b.ObjectLockEnabled {
				b.Versioning = "Enabled"
			}
		}
		c.publicAccess = *b.PublicAccess
		var aclWire *awswire.Error
		b.ACL, aclWire = parseACL(b, DefaultACL(m.Partition, m.AccountID), value(in.ACL), aclHeaders{full: value(in.GrantFullControl), read: value(in.GrantRead), readACP: value(in.GrantReadACP), write: value(in.GrantWrite), writeACP: value(in.GrantWriteACP)}, nil, false)
		if aclWire != nil {
			return aclWire
		}
		if ownership == "BucketOwnerEnforced" && !ownerFullControlOnly(b.ACL, b.ACL.OwnerID) {
			return invalidBucketOwnershipACL()
		}
		if b.PublicAccess.BlockPublicACLs && publicACL(b.ACL) {
			return failure("InvalidBucketAclWithBlockPublicAccessError", "Bucket cannot have public ACLs set with BlockPublicAccess enabled", 400)
		}
		existing, lookupErr := tx.Bucket(b.Key)
		if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
			return lookupErr
		}
		if lookupErr == nil && existing.AccountID == m.AccountID {
			// Creation evaluates the current policy, but not existing resource
			// tags or mutable settings as if they had been requested.
			b.Policy = existing.Policy
		}
		c.region = region
		conditions := map[string][]string{"s3:LocationConstraint": {region}}
		addRequestTagConditions(conditions, tags, nil)
		if w := s.authorize(tx.Context(), c, b, "CreateBucket", "", conditions); w != nil {
			return w
		}
		if len(tags) != 0 {
			if wire := s.authorize(tx.Context(), c, b, "TagResource", "", conditions); wire != nil {
				return wire
			}
		}
		if b.ObjectLockEnabled {
			if w := s.authorize(tx.Context(), c, b, "PutBucketObjectLockConfiguration", "", nil); w != nil {
				return w
			}
			if w := s.authorize(tx.Context(), c, b, "PutBucketVersioning", "", nil); w != nil {
				return w
			}
		}
		if !ownerFullControlOnly(b.ACL, b.ACL.OwnerID) {
			if w := s.authorize(tx.Context(), c, b, "PutBucketAcl", "", nil); w != nil {
				return w
			}
		}
		if in.ObjectOwnership != nil {
			if w := s.authorize(tx.Context(), c, b, "PutBucketOwnershipControls", "", map[string][]string{"s3:x-amz-object-ownership": {value(in.ObjectOwnership)}}); w != nil {
				return w
			}
		}
		claim, claimed := cloudFormationOwner(tx.Context(), cloudFormationBucket)
		if lookupErr == nil {
			c.account, c.region = existing.AccountID, existing.Region
			if existing.AccountID != m.AccountID {
				return failure("BucketAlreadyExists", "The requested bucket name is not available.", 409)
			}
			if claimed {
				// Only the exact incarnation that committed this bucket recovers
				// it, unchanged. Names, tags and settings never prove ownership.
				if existing.CloudFormationOwner != claim {
					return failure("BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it.", 409)
				}
				out.Location = new(api.Location("/" + c.bucket))
				if m.Partition == "aws" && existing.Region != "us-east-1" {
					out.Location = new(api.Location("http://" + c.bucket + ".s3.amazonaws.com/"))
				}
				out.BucketArn = new(api.S3RegionalOrS3ExpressBucketArnString(existing.Key.ARN()))
				return nil
			}
			if region != "us-east-1" || existing.Region != region ||
				(existing.Ownership != "" && existing.Ownership != ownership) ||
				existing.ObjectLockEnabled != b.ObjectLockEnabled || existing.ABACEnabled ||
				len(tags) != 0 || (existing.PublicAccess != nil && *existing.PublicAccess != *b.PublicAccess) {
				return failure("BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it.", 409)
			}
			// Legacy us-east-1 recreation replaces only the ACL. In particular,
			// absent ownership/public-access settings remain absent.
			existing.ACL = b.ACL
			if err := tx.PutBucket(existing); err != nil {
				return err
			}
		} else {
			id, err := uuid.NewRandom()
			if err != nil {
				return err
			}
			b.Incarnation = id.String()
			b.CloudFormationOwner = claim
			if err := tx.PutBucket(b); err != nil {
				return err
			}
		}
		if len(tags) != 0 {
			if err := tx.ReplaceBucketTags(b.Key, tags); err != nil {
				return err
			}
		}
		out.Location = new(api.Location("/" + c.bucket))
		if m.Partition == "aws" && region != "us-east-1" {
			out.Location = new(api.Location("http://" + c.bucket + ".s3.amazonaws.com/"))
		}
		out.BucketArn = new(api.S3RegionalOrS3ExpressBucketArnString(b.Key.ARN()))
		return nil
	})
	return out, wire
}
func (s *Service) deleteBucket(ctx context.Context, in *api.DeleteBucketInput) (*api.DeleteBucketOutput, *awswire.Error) {
	c := call(ctx, "DeleteBucket", value(in.Bucket), "")
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "DeleteBucket", "", nil); w != nil {
			return w
		}
		objects, err := tx.ObjectVersions(VersionQuery{Bucket: b.Key, Limit: 1})
		if err != nil {
			return err
		}
		if len(objects) > 0 {
			return failure("BucketNotEmpty", "The bucket you tried to delete is not empty.", 409)
		}
		points, err := tx.AccessPoints(AccessPointQuery{Partition: b.Key.Partition, AccountID: b.AccountID, Region: b.Region, Bucket: b.Key.Name, Limit: 1})
		if err != nil {
			return err
		}
		if len(points) != 0 {
			return failure("BucketHasAccessPointsAttached", "The bucket you tried to delete has access points attached.", 400)
		}
		return tx.DeleteBucket(b.Key)
	})
	return &api.DeleteBucketOutput{}, wire
}

// HeadBucket checks current bucket existence and ListBucket authority.
func (s *Service) HeadBucket(ctx context.Context, in *api.HeadBucketInput) (*api.HeadBucketOutput, *awswire.Error) {
	c := call(ctx, "HeadBucket", value(in.Bucket), "")
	out := &api.HeadBucketOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if b.Region != "" {
			out.BucketRegion = new(api.Region(b.Region))
		}
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "ListBucket", "", nil); w != nil {
			return w
		}
		out.AccessPointAlias = new(api.AccessPointAlias(strings.HasSuffix(c.accessPointReference, "-s3alias")))
		out.BucketArn = new(api.S3RegionalOrS3ExpressBucketArnString(b.Key.ARN()))
		return nil
	})
	return out, wire
}
func (s *Service) GetBucketLocation(ctx context.Context, in *api.GetBucketLocationInput) (*api.GetBucketLocationOutput, *awswire.Error) {
	out := &api.GetBucketLocationOutput{}
	_, wire := s.bucketLocationResponse(ctx, in, out)
	return out, wire
}

func (s *Service) getBucketLocation(ctx context.Context, in *api.GetBucketLocationInput) (*preparedResponse, *awswire.Error) {
	return s.bucketLocationResponse(ctx, in, &api.GetBucketLocationOutput{})
}

func (s *Service) bucketLocationResponse(ctx context.Context, in *api.GetBucketLocationInput, out *api.GetBucketLocationOutput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketLocation", value(in.Bucket), "", "location")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketLocation", "", nil); w != nil {
			return w
		}
		if b.Region != "us-east-1" {
			out.LocationConstraint = new(api.BucketLocationConstraint(b.Region))
		}
		return response.prepare(c, out)
	})
	return response, wire
}
func (s *Service) GetBucketACL(ctx context.Context, in *api.GetBucketAclInput) (*api.GetBucketAclOutput, *awswire.Error) {
	out := &api.GetBucketAclOutput{}
	_, wire := s.bucketACLResponse(ctx, in, out)
	return out, wire
}

func (s *Service) getBucketACL(ctx context.Context, in *api.GetBucketAclInput) (*preparedResponse, *awswire.Error) {
	return s.bucketACLResponse(ctx, in, &api.GetBucketAclOutput{})
}

func (s *Service) bucketACLResponse(ctx context.Context, in *api.GetBucketAclInput, out *api.GetBucketAclOutput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketAcl", value(in.Bucket), "", "acl")
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketAcl", "", nil); w != nil {
			return w
		}
		out.Owner, out.Grants = aclOutput(effectiveACL(b, b.ACL, c.publicAccess.IgnorePublicACLs))
		return response.prepare(c, out)
	})
	return response, wire
}
func (s *Service) getBucketOwnershipControls(ctx context.Context, in *api.GetBucketOwnershipControlsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketOwnershipControls", value(in.Bucket), "", "ownershipControls")
	out := &api.GetBucketOwnershipControlsOutput{}
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketOwnershipControls", "", nil); w != nil {
			return w
		}
		if b.Ownership == "" {
			return failure("OwnershipControlsNotFoundError", "The bucket ownership controls were not found.", 404)
		}
		out.OwnershipControls = &api.OwnershipControls{Rules: api.OwnershipControlsRules{{ObjectOwnership: new(api.ObjectOwnership(b.Ownership))}}}
		return response.prepare(c, out)
	})
	return response, wire
}
func (s *Service) getPublicAccessBlock(ctx context.Context, in *api.GetPublicAccessBlockInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetPublicAccessBlock", value(in.Bucket), "", "publicAccessBlock")
	out := &api.GetPublicAccessBlockOutput{}
	response := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetBucketPublicAccessBlock", "", nil); w != nil {
			return w
		}
		p := b.PublicAccess
		if p == nil {
			return failure("NoSuchPublicAccessBlockConfiguration", "The public access block configuration was not found.", 404)
		}
		out.PublicAccessBlockConfiguration = &api.PublicAccessBlockConfiguration{BlockPublicAcls: new(api.Setting(p.BlockPublicACLs)), IgnorePublicAcls: new(api.Setting(p.IgnorePublicACLs)), BlockPublicPolicy: new(api.Setting(p.BlockPublicPolicy)), RestrictPublicBuckets: new(api.Setting(p.RestrictPublicBuckets))}
		return response.prepare(c, out)
	})
	return response, wire
}
func (s *Service) listBuckets(ctx context.Context, in *api.ListBucketsInput) (*api.ListBucketsOutput, *awswire.Error) {
	c := call(ctx, "ListBuckets", "", "")
	out := &api.ListBucketsOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		m := awsctx.FromContext(tx.Context())
		if w := s.authorizer.Authorize(tx.Context(), authorization.Request{Action: "s3:ListAllMyBuckets", ResourceARN: "*", ResourceAccountID: m.AccountID}); w != nil {
			return w
		}
		limit := 10000
		if in.MaxBuckets != nil {
			limit = int(*in.MaxBuckets)
			if limit < 1 || limit > 10000 {
				return invalid("MaxBuckets must be between 1 and 10000.")
			}
		}
		after := ""
		if in.ContinuationToken != nil {
			decoded, err := base64.RawURLEncoding.DecodeString(value(in.ContinuationToken))
			if err != nil {
				return invalid("Invalid continuation token.")
			}
			after = string(decoded)
		}
		records, err := tx.Buckets(m.Partition, m.AccountID)
		if err != nil {
			return err
		}
		slices.SortFunc(records, func(a, b BucketRecord) int { return strings.Compare(a.Key.Name, b.Key.Name) })
		for _, b := range records {
			if b.Key.Name <= after || !strings.HasPrefix(b.Key.Name, value(in.Prefix)) || (in.BucketRegion != nil && b.Region != value(in.BucketRegion)) {
				continue
			}
			if len(out.Buckets) == limit {
				last := value(out.Buckets[len(out.Buckets)-1].Name)
				out.ContinuationToken = new(api.NextToken(base64.RawURLEncoding.EncodeToString([]byte(last))))
				break
			}
			out.Buckets = append(out.Buckets, api.Bucket{Name: new(api.BucketName(b.Key.Name)), CreationDate: new(b.Created), BucketRegion: new(api.BucketRegion(b.Region)), BucketArn: new(api.S3RegionalOrS3ExpressBucketArnString(b.Key.ARN()))})
		}
		out.Owner = &api.Owner{ID: new(api.ID(canonicalID(m.Partition, m.AccountID)))}
		out.Prefix = in.Prefix
		return nil
	})
	return out, wire
}

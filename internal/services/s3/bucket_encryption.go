package s3

import (
	"context"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) getBucketEncryption(ctx context.Context, in *api.GetBucketEncryptionInput) (*api.GetBucketEncryptionOutput, *awswire.Error) {
	c := call(ctx, "GetBucketEncryption", value(in.Bucket), "")
	c.params["encryption"] = ""
	out := &api.GetBucketEncryptionOutput{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "GetEncryptionConfiguration", "", nil); w != nil {
			return w
		}
		defaults := &api.ServerSideEncryptionByDefault{SSEAlgorithm: new(api.ServerSideEncryption(b.EncryptionAlgorithm))}
		if b.KMSKeyID != "" {
			defaults.KMSMasterKeyID = new(api.SSEKMSKeyId(b.KMSKeyID))
		}
		blocked := api.EncryptionTypeNONE
		if b.SSECustomerBlocked {
			blocked = api.EncryptionTypeSSE_C
		}
		out.ServerSideEncryptionConfiguration = &api.ServerSideEncryptionConfiguration{
			Rules: api.ServerSideEncryptionRules{{
				ApplyServerSideEncryptionByDefault: defaults,
				BucketKeyEnabled:                   new(api.BucketKeyEnabled(b.BucketKeyEnabled)),
				BlockedEncryptionTypes:             &api.BlockedEncryptionTypes{EncryptionType: api.EncryptionTypeList{blocked}},
			}},
		}
		return nil
	})
	return out, wire
}

func (s *Service) putBucketEncryption(ctx context.Context, in *api.PutBucketEncryptionInput) (*api.PutBucketEncryptionOutput, *awswire.Error) {
	c := call(ctx, "PutBucketEncryption", value(in.Bucket), "")
	bucketEncryptionParameters(c, in.ServerSideEncryptionConfiguration)
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		if w := s.authorize(tx.Context(), c, b, "PutEncryptionConfiguration", "", nil); w != nil {
			return w
		}
		conf := in.ServerSideEncryptionConfiguration
		if conf == nil || len(conf.Rules) != 1 {
			return failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema", 400)
		}
		rule := conf.Rules[0]
		defaults := rule.ApplyServerSideEncryptionByDefault
		algorithm, keyID := "AES256", ""
		if defaults != nil {
			algorithm, keyID = value(defaults.SSEAlgorithm), value(defaults.KMSMasterKeyID)
		}
		switch algorithm {
		case "AES256":
			if keyID != "" {
				return invalid("KMSMasterKeyID requires the aws:kms encryption algorithm.")
			}
		case "aws:kms":
		case "SSE-C":
			return invalid("SSE-C cannot be used as a bucket default encryption method.")
		case "aws:kms:dsse", "aws:fsx", "aws:backup":
			return unsupported("The requested bucket encryption algorithm is not implemented.")
		default:
			return invalid("The encryption algorithm is not valid.")
		}
		if algorithm == "aws:kms" && rule.BucketKeyEnabled != nil && bool(*rule.BucketKeyEnabled) {
			return unsupported("S3 Bucket Keys are not implemented.")
		}
		// Replacement resets omitted settings to the current native defaults.
		b.SSECustomerBlocked = true
		if blocked := rule.BlockedEncryptionTypes; blocked != nil {
			if len(blocked.EncryptionType) != 1 {
				return invalid("BlockedEncryptionTypes must contain exactly one encryption type.")
			}
			b.SSECustomerBlocked = blocked.EncryptionType[0] != api.EncryptionTypeNONE
		}
		b.EncryptionAlgorithm = algorithm
		// S3 retains this setting for AES256 even though SSE-S3 has no KMS
		// bucket key. KMS bucket-key execution remains explicitly unsupported.
		b.BucketKeyEnabled = rule.BucketKeyEnabled != nil && bool(*rule.BucketKeyEnabled)
		// Bucket configuration retains the supplied identifier literally. KMS
		// resolves it only when an object is written, including alias targets.
		b.KMSKeyID = keyID
		return tx.PutBucket(b)
	})
	return &api.PutBucketEncryptionOutput{}, wire
}

func (s *Service) deleteBucketEncryption(ctx context.Context, in *api.DeleteBucketEncryptionInput) (*api.DeleteBucketEncryptionOutput, *awswire.Error) {
	c := call(ctx, "DeleteBucketEncryption", value(in.Bucket), "")
	c.params["encryption"] = ""
	c.additional = map[string]any{"httpStatusCode": 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.bucket(tx, c, value(in.ExpectedBucketOwner))
		if err != nil {
			return err
		}
		// Deleting the override uses the same IAM action as configuring it.
		if w := s.authorize(tx.Context(), c, b, "PutEncryptionConfiguration", "", nil); w != nil {
			return w
		}
		b.EncryptionAlgorithm, b.KMSKeyID = "AES256", ""
		b.BucketKeyEnabled = false
		b.SSECustomerBlocked = true
		return tx.PutBucket(b)
	})
	return &api.DeleteBucketEncryptionOutput{}, wire
}

// Native management events retain the XML Rule shape rather than SDK Rules.
func bucketEncryptionParameters(c *apiCall, conf *api.ServerSideEncryptionConfiguration) {
	c.params["encryption"] = ""
	if conf == nil {
		return
	}
	var rules any = conf.Rules
	if len(conf.Rules) == 1 {
		rules = conf.Rules[0]
	}
	c.params["ServerSideEncryptionConfiguration"] = map[string]any{
		"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
		"Rule":  rules,
	}
}

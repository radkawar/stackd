package s3

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) putBucketIntelligentTieringConfiguration(ctx context.Context, in *api.PutBucketIntelligentTieringConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketIntelligentTieringConfiguration", value(in.Bucket), "", "intelligent-tiering")
	c.params["id"] = value(in.Id)
	c.params["IntelligentTieringConfiguration"] = in.IntelligentTieringConfiguration
	out := &preparedResponse{statusCode: 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutIntelligentTieringConfiguration", "", nil); wire != nil {
			return wire
		}
		if value(in.Id) == "" {
			return invalidConfigurationID()
		}
		configuration, wire := parseTieringConfiguration(value(in.Id), in.IntelligentTieringConfiguration)
		if wire != nil {
			return wire
		}
		existing, err := tx.BucketTieringConfiguration(b.Key, configuration.ID)
		if err != nil {
			return err
		}
		if existing == nil {
			count, err := tx.BucketTieringConfigurationCount(b.Key)
			if err != nil {
				return err
			}
			if count >= 1000 {
				return failure("TooManyConfigurations", "You have attempted to create more configurations than the 1000 allowed.", 400)
			}
		}
		if c.eventID == "" {
			c.eventID = uuid.NewString()
		}
		configuration.ParentEventID = c.eventID
		if err := tx.PutBucketTieringConfiguration(b.Key, *configuration); err != nil {
			return err
		}
		if err := s.scheduleBucketTiering(tx, b.Key); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketIntelligentTieringConfigurationOutput{})
	})
	return out, wire
}

func (s *Service) getBucketIntelligentTieringConfiguration(ctx context.Context, in *api.GetBucketIntelligentTieringConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketIntelligentTieringConfiguration", value(in.Bucket), "", "intelligent-tiering")
	c.params["id"] = value(in.Id)
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetIntelligentTieringConfiguration", "", nil); wire != nil {
			return wire
		}
		configuration, err := tx.BucketTieringConfiguration(b.Key, value(in.Id))
		if err != nil {
			return err
		}
		if configuration == nil {
			return noSuchConfiguration()
		}
		return out.prepare(c, &api.GetBucketIntelligentTieringConfigurationOutput{IntelligentTieringConfiguration: outputTieringConfiguration(*configuration)})
	})
	return out, wire
}

func (s *Service) deleteBucketIntelligentTieringConfiguration(ctx context.Context, in *api.DeleteBucketIntelligentTieringConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketIntelligentTieringConfiguration", value(in.Bucket), "", "intelligent-tiering")
	c.params["id"] = value(in.Id)
	out := &preparedResponse{statusCode: 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutIntelligentTieringConfiguration", "", nil); wire != nil {
			return wire
		}
		if value(in.Id) == "" {
			return invalidConfigurationID()
		}
		configuration, err := tx.BucketTieringConfiguration(b.Key, value(in.Id))
		if err != nil {
			return err
		}
		if configuration == nil {
			return noSuchConfiguration()
		}
		if err := tx.DeleteBucketTieringConfiguration(b.Key, value(in.Id)); err != nil {
			return err
		}
		if err := s.scheduleBucketTiering(tx, b.Key); err != nil {
			return err
		}
		return out.prepare(c, &api.DeleteBucketIntelligentTieringConfigurationOutput{})
	})
	return out, wire
}

func (s *Service) listBucketIntelligentTieringConfigurations(ctx context.Context, in *api.ListBucketIntelligentTieringConfigurationsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "ListBucketIntelligentTieringConfigurations", value(in.Bucket), "", "intelligent-tiering")
	if in.ContinuationToken != nil {
		c.params["continuation-token"] = value(in.ContinuationToken)
	}
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetIntelligentTieringConfiguration", "", nil); wire != nil {
			return wire
		}
		after := ""
		if token := value(in.ContinuationToken); token != "" {
			var wire *awswire.Error
			after, wire = decodeCursor(token, b.Key.Name, "intelligent-tiering", "")
			if wire != nil {
				return failure("MalformedContinuationToken", "The continuation-token you provided invalid.", 400)
			}
		}
		configurations, err := tx.BucketTieringConfigurations(BucketConfigurationQuery{Bucket: b.Key, After: after, Limit: 101})
		if err != nil {
			return err
		}
		truncated := len(configurations) > 100
		if truncated {
			configurations = configurations[:100]
		}
		result := &api.ListBucketIntelligentTieringConfigurationsOutput{
			ContinuationToken:                   in.ContinuationToken,
			IsTruncated:                         new(api.IsTruncated(truncated)),
			IntelligentTieringConfigurationList: make(api.IntelligentTieringConfigurationList, 0, len(configurations)),
		}
		for _, configuration := range configurations {
			result.IntelligentTieringConfigurationList = append(result.IntelligentTieringConfigurationList, *outputTieringConfiguration(configuration))
		}
		if truncated {
			result.NextContinuationToken = new(api.NextToken(encodeCursor(listCursor{Bucket: b.Key.Name, Prefix: "intelligent-tiering", After: configurations[len(configurations)-1].ID})))
		}
		return out.prepare(c, result)
	})
	return out, wire
}

func (s *Service) scheduleBucketTiering(tx Transaction, bucket BucketKey) error {
	enabled, err := tx.BucketHasEnabledTiering(bucket)
	if err != nil {
		return err
	}
	if enabled {
		return tx.SetTieringScan(bucket, new(objectDayDeadline(s.clock.Now(), 0)))
	}
	return tx.SetTieringScan(bucket, nil)
}

// Generated decoding owns XML syntax and required-member checks; these controls
// use native error codes rather than generic model validation errors.
func tieringRequestError(name string, err error) *awswire.Error {
	switch name {
	case "PutBucketIntelligentTieringConfiguration", "GetBucketIntelligentTieringConfiguration", "DeleteBucketIntelligentTieringConfiguration", "ListBucketIntelligentTieringConfigurations":
	default:
		return nil
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		if validation.Path == "Id" {
			return invalidConfigurationID()
		}
		if strings.HasPrefix(validation.Path, "IntelligentTieringConfiguration") {
			if strings.HasSuffix(validation.Path, ".Key") && validation.Constraint == "length.min" {
				return failure("InvalidTag", "Tag Key cannot be null or empty.", 400)
			}
			return malformedXML()
		}
		return nil
	}
	if name == "PutBucketIntelligentTieringConfiguration" {
		return malformedXML()
	}
	return nil
}

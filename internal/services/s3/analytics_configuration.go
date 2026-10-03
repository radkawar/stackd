package s3

import (
	"context"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) putBucketAnalyticsConfiguration(ctx context.Context, in *api.PutBucketAnalyticsConfigurationInput) (*preparedResponse, *awswire.Error) {
	// TODO: Comeback implement actual analytics measurement and daily CSV export; retained configuration alone does not provide report behavior.
	c := s.accessCall(ctx, "PutBucketAnalyticsConfiguration", value(in.Bucket), "", "analytics")
	c.params["id"] = value(in.Id)
	analyticsParameters(c, observedRequestQuery(ctx))
	out := &preparedResponse{statusCode: 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutAnalyticsConfiguration", "", nil); wire != nil {
			return wire
		}
		if value(in.Id) == "" {
			return invalidConfigurationID()
		}
		configuration, wire := parseAnalyticsConfiguration(value(in.Id), in.AnalyticsConfiguration)
		if wire != nil {
			return wire
		}
		existing, err := tx.BucketAnalyticsConfiguration(b.Key, configuration.ID)
		if err != nil {
			return err
		}
		if existing == nil {
			count, err := tx.BucketAnalyticsConfigurationCount(b.Key)
			if err != nil {
				return err
			}
			if count >= 1000 {
				return failure("TooManyConfigurations", "You have attempted to create more configurations than the 1000 allowed.", 400)
			}
		}
		if err := tx.PutBucketAnalyticsConfiguration(b.Key, *configuration); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketAnalyticsConfigurationOutput{})
	})
	return out, wire
}

func (s *Service) getBucketAnalyticsConfiguration(ctx context.Context, in *api.GetBucketAnalyticsConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketAnalyticsConfiguration", value(in.Bucket), "", "analytics")
	c.params["id"] = value(in.Id)
	analyticsParameters(c, observedRequestQuery(ctx))
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetAnalyticsConfiguration", "", nil); wire != nil {
			return wire
		}
		configuration, err := tx.BucketAnalyticsConfiguration(b.Key, value(in.Id))
		if err != nil {
			return err
		}
		if configuration == nil {
			return noSuchConfiguration()
		}
		return out.prepare(c, &api.GetBucketAnalyticsConfigurationOutput{AnalyticsConfiguration: new(outputAnalyticsConfiguration(*configuration))})
	})
	return out, wire
}

func (s *Service) deleteBucketAnalyticsConfiguration(ctx context.Context, in *api.DeleteBucketAnalyticsConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketAnalyticsConfiguration", value(in.Bucket), "", "analytics")
	c.params["id"] = value(in.Id)
	analyticsParameters(c, observedRequestQuery(ctx))
	out := &preparedResponse{statusCode: 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutAnalyticsConfiguration", "", nil); wire != nil {
			return wire
		}
		if value(in.Id) == "" {
			return invalidConfigurationID()
		}
		configuration, err := tx.BucketAnalyticsConfiguration(b.Key, value(in.Id))
		if err != nil {
			return err
		}
		if configuration == nil {
			return noSuchConfiguration()
		}
		if err := tx.DeleteBucketAnalyticsConfiguration(b.Key, value(in.Id)); err != nil {
			return err
		}
		return out.prepare(c, &api.DeleteBucketAnalyticsConfigurationOutput{})
	})
	return out, wire
}

func (s *Service) listBucketAnalyticsConfigurations(ctx context.Context, in *api.ListBucketAnalyticsConfigurationsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "ListBucketAnalyticsConfigurations", value(in.Bucket), "", "analytics")
	if in.ContinuationToken != nil {
		c.params["continuation-token"] = value(in.ContinuationToken)
	}
	analyticsParameters(c, observedRequestQuery(ctx))
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetAnalyticsConfiguration", "", nil); wire != nil {
			return wire
		}
		after := ""
		if token := value(in.ContinuationToken); token != "" {
			var wire *awswire.Error
			after, wire = decodeCursor(token, b.Key.Name, "analytics", "")
			if wire != nil {
				return failure("MalformedContinuationToken", "The continuation-token you provided invalid.", 400)
			}
		}
		configurations, err := tx.BucketAnalyticsConfigurations(BucketConfigurationQuery{Bucket: b.Key, After: after, Limit: 101})
		if err != nil {
			return err
		}
		truncated := len(configurations) > 100
		if truncated {
			configurations = configurations[:100]
		}
		result := &api.ListBucketAnalyticsConfigurationsOutput{
			ContinuationToken:          in.ContinuationToken,
			IsTruncated:                new(api.IsTruncated(truncated)),
			AnalyticsConfigurationList: make(api.AnalyticsConfigurationList, len(configurations)),
		}
		for i, configuration := range configurations {
			result.AnalyticsConfigurationList[i] = outputAnalyticsConfiguration(configuration)
		}
		if truncated {
			result.NextContinuationToken = new(api.NextToken(encodeCursor(listCursor{Bucket: b.Key.Name, Prefix: "analytics", After: configurations[len(configurations)-1].ID})))
		}
		return out.prepare(c, result)
	})
	return out, wire
}

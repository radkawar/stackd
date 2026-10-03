package s3

import (
	"context"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) putBucketMetricsConfiguration(ctx context.Context, in *api.PutBucketMetricsConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.transferCall(ctx, "PutBucketMetricsConfiguration", value(in.Bucket), "")
	c.params["metrics"] = ""
	c.params["id"] = value(in.Id)
	out := &preparedResponse{statusCode: 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutMetricsConfiguration", "", nil); wire != nil {
			return wire
		}
		request, _ := awsapi.FromContext(ctx)
		c.additional["bytesTransferredIn"] = len(request.Body)
		if value(in.Id) == "" {
			return invalidConfigurationID()
		}
		configuration, wire := parseMetricsConfiguration(value(in.Id), in.MetricsConfiguration)
		if wire != nil {
			return wire
		}
		if s.metrics == nil {
			return unsupported("Native request metrics are not configured.")
		}
		existing, err := tx.BucketMetricsConfiguration(b.Key, configuration.ID)
		if err != nil {
			return err
		}
		if existing == nil {
			count, err := tx.BucketMetricsConfigurationCount(b.Key)
			if err != nil {
				return err
			}
			if count >= maxMetricsConfigurations {
				return failure("TooManyConfigurations", "You have attempted to create more configurations than the 1000 allowed.", 400)
			}
		}
		if err := tx.PutBucketMetricsConfiguration(b.Key, *configuration); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketMetricsConfigurationOutput{})
	})
	return out, wire
}

func (s *Service) getBucketMetricsConfiguration(ctx context.Context, in *api.GetBucketMetricsConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketMetricsConfiguration", value(in.Bucket), "", "metrics")
	c.params["id"] = value(in.Id)
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetMetricsConfiguration", "", nil); wire != nil {
			return wire
		}
		configuration, err := tx.BucketMetricsConfiguration(b.Key, value(in.Id))
		if err != nil {
			return err
		}
		if configuration == nil {
			return noSuchConfiguration()
		}
		return out.prepare(c, &api.GetBucketMetricsConfigurationOutput{MetricsConfiguration: new(outputMetricsConfiguration(*configuration))})
	})
	return out, wire
}

func (s *Service) deleteBucketMetricsConfiguration(ctx context.Context, in *api.DeleteBucketMetricsConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketMetricsConfiguration", value(in.Bucket), "", "metrics")
	c.params["id"] = value(in.Id)
	out := &preparedResponse{statusCode: 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutMetricsConfiguration", "", nil); wire != nil {
			return wire
		}
		if value(in.Id) == "" {
			return invalidConfigurationID()
		}
		configuration, err := tx.BucketMetricsConfiguration(b.Key, value(in.Id))
		if err != nil {
			return err
		}
		if configuration == nil {
			return noSuchConfiguration()
		}
		if err := tx.DeleteBucketMetricsConfiguration(b.Key, value(in.Id)); err != nil {
			return err
		}
		return out.prepare(c, &api.DeleteBucketMetricsConfigurationOutput{})
	})
	return out, wire
}

func (s *Service) listBucketMetricsConfigurations(ctx context.Context, in *api.ListBucketMetricsConfigurationsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "ListBucketMetricsConfigurations", value(in.Bucket), "", "metrics")
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetMetricsConfiguration", "", nil); wire != nil {
			return wire
		}
		after := ""
		if token := value(in.ContinuationToken); token != "" {
			var wire *awswire.Error
			after, wire = decodeCursor(token, b.Key.Name, "metrics", "")
			if wire != nil {
				return failure("MalformedContinuationToken", "The continuation-token you provided invalid.", 400)
			}
		}
		configurations, err := tx.BucketMetricsConfigurations(BucketConfigurationQuery{Bucket: b.Key, After: after, Limit: 101})
		if err != nil {
			return err
		}
		truncated := len(configurations) > 100
		if truncated {
			configurations = configurations[:100]
		}
		result := &api.ListBucketMetricsConfigurationsOutput{
			ContinuationToken:        in.ContinuationToken,
			IsTruncated:              new(api.IsTruncated(truncated)),
			MetricsConfigurationList: make(api.MetricsConfigurationList, len(configurations)),
		}
		for i, configuration := range configurations {
			result.MetricsConfigurationList[i] = outputMetricsConfiguration(configuration)
		}
		if truncated {
			result.NextContinuationToken = new(api.NextToken(encodeCursor(listCursor{Bucket: b.Key.Name, Prefix: "metrics", After: configurations[len(configurations)-1].ID})))
		}
		return out.prepare(c, result)
	})
	return out, wire
}

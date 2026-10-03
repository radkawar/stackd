package s3

import (
	"context"
	"time"

	"github.com/google/uuid"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func (s *Service) putBucketInventoryConfiguration(ctx context.Context, in *api.PutBucketInventoryConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "PutBucketInventoryConfiguration", value(in.Bucket), "", "inventory")
	c.params["id"] = value(in.Id)
	request, _ := awsapi.FromContext(ctx)
	xmlAuditParameters(c, request.Body)
	out := &preparedResponse{statusCode: 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		configuration, wire := parseInventoryConfiguration(value(in.Id), in.InventoryConfiguration)
		if wire != nil {
			return wire
		}
		conditions := map[string][]string{}
		if len(configuration.OptionalFields) != 0 {
			conditions["s3:InventoryAccessibleOptionalFields"] = configuration.OptionalFields
		}
		if wire := s.authorize(tx.Context(), c, b, "PutInventoryConfiguration", "", conditions); wire != nil {
			return wire
		}
		existing, err := tx.BucketInventoryConfiguration(b.Key, configuration.ID)
		if err != nil {
			return err
		}
		if existing == nil {
			count, err := tx.BucketInventoryConfigurationCount(b.Key)
			if err != nil {
				return err
			}
			if count >= 1000 {
				return failure("TooManyConfigurations", "You have attempted to create more configurations than the 1000 allowed.", 400)
			}
		}
		// The event identity also fences report completion in embedded instances
		// without an API recorder; replacement must still have its own revision.
		if c.eventID == "" {
			c.eventID = uuid.NewString()
		}
		configuration.ParentEventID = c.eventID
		if configuration.Enabled {
			// A deterministic local first report at the next UTC midnight is
			// within AWS's documented up-to-48-hour initial delivery window.
			configuration.NextReport = s.clock.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
		}
		if err := tx.PutBucketInventoryConfiguration(b.Key, *configuration); err != nil {
			return err
		}
		return out.prepare(c, &api.PutBucketInventoryConfigurationOutput{})
	})
	if wire == nil {
		s.jobs.Wake()
	}
	return out, wire
}

func (s *Service) getBucketInventoryConfiguration(ctx context.Context, in *api.GetBucketInventoryConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "GetBucketInventoryConfiguration", value(in.Bucket), "", "inventory")
	c.params["id"] = value(in.Id)
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetInventoryConfiguration", "", nil); wire != nil {
			return wire
		}
		configuration, err := tx.BucketInventoryConfiguration(b.Key, value(in.Id))
		if err != nil {
			return err
		}
		if configuration == nil {
			return noSuchConfiguration()
		}
		return out.prepare(c, &api.GetBucketInventoryConfigurationOutput{InventoryConfiguration: new(outputInventoryConfiguration(*configuration))})
	})
	return out, wire
}

func (s *Service) deleteBucketInventoryConfiguration(ctx context.Context, in *api.DeleteBucketInventoryConfigurationInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "DeleteBucketInventoryConfiguration", value(in.Bucket), "", "inventory")
	c.params["id"] = value(in.Id)
	out := &preparedResponse{statusCode: 204}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "PutInventoryConfiguration", "", nil); wire != nil {
			return wire
		}
		if value(in.Id) == "" {
			return invalidConfigurationID()
		}
		configuration, err := tx.BucketInventoryConfiguration(b.Key, value(in.Id))
		if err != nil {
			return err
		}
		if configuration == nil {
			return noSuchConfiguration()
		}
		if err := tx.DeleteBucketInventoryConfiguration(b.Key, value(in.Id)); err != nil {
			return err
		}
		return out.prepare(c, &api.DeleteBucketInventoryConfigurationOutput{})
	})
	return out, wire
}

func (s *Service) listBucketInventoryConfigurations(ctx context.Context, in *api.ListBucketInventoryConfigurationsInput) (*preparedResponse, *awswire.Error) {
	c := s.accessCall(ctx, "ListBucketInventoryConfigurations", value(in.Bucket), "", "inventory")
	if in.ContinuationToken != nil {
		c.params["continuation-token"] = value(in.ContinuationToken)
	}
	// The generated route treats an empty id as LIST, while native audit
	// preserves the submitted query member.
	if query := observedRequestQuery(ctx); query.Has("id") {
		c.params["id"] = query.Get("id")
	}
	out := &preparedResponse{}
	wire := s.execute(ctx, c, func(tx Transaction) error {
		b, err := s.configurationBucket(tx, c, in.ExpectedBucketOwner)
		if err != nil {
			return err
		}
		if wire := s.authorize(tx.Context(), c, b, "GetInventoryConfiguration", "", nil); wire != nil {
			return wire
		}
		after := ""
		if token := value(in.ContinuationToken); token != "" {
			var wire *awswire.Error
			after, wire = decodeCursor(token, b.Key.Name, "inventory", "")
			if wire != nil {
				return failure("MalformedContinuationToken", "The continuation-token you provided invalid.", 400)
			}
		}
		configurations, err := tx.BucketInventoryConfigurations(BucketConfigurationQuery{Bucket: b.Key, After: after, Limit: 101})
		if err != nil {
			return err
		}
		truncated := len(configurations) > 100
		if truncated {
			configurations = configurations[:100]
		}
		result := &api.ListBucketInventoryConfigurationsOutput{
			ContinuationToken:          in.ContinuationToken,
			IsTruncated:                new(api.IsTruncated(truncated)),
			InventoryConfigurationList: make(api.InventoryConfigurationList, len(configurations)),
		}
		for i, configuration := range configurations {
			result.InventoryConfigurationList[i] = outputInventoryConfiguration(configuration)
		}
		if truncated {
			result.NextContinuationToken = new(api.NextToken(encodeCursor(listCursor{Bucket: b.Key.Name, Prefix: "inventory", After: configurations[len(configurations)-1].ID})))
		}
		return out.prepare(c, result)
	})
	return out, wire
}

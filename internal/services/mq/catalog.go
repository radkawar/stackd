package mq

import (
	"context"
	api "stackd/internal/awsapi/mq"
)

// Catalogs advertise only installed-runtime capabilities, not fictitious fleet
// capacity or physical AZ/storage integrations.
func registerCatalog(s *Service) {
	register(s, "DescribeBrokerEngineTypes", func(ctx context.Context, t Transaction, in *api.DescribeBrokerEngineTypesInput) (*api.DescribeBrokerEngineTypesOutput, error) {
		if e := s.authorize(ctx, BrokerRecord{}, "DescribeBrokerEngineTypes", nil); e != nil {
			return nil, e
		}
		limit, after, e := page(ctx, "engines:"+value(in.EngineType), in.MaxResults, value(in.NextToken))
		if e != nil {
			return nil, e
		}
		if after != "" {
			return nil, invalid("Invalid NextToken")
		}
		filter := value(in.EngineType)
		if filter != "" && filter != "ACTIVEMQ" && filter != "RABBITMQ" {
			return nil, invalid("Invalid EngineType")
		}
		o := &api.DescribeBrokerEngineTypesOutput{}
		number(&o.MaxResults, limit)
		for _, kind := range []string{"ACTIVEMQ", "RABBITMQ"} {
			if filter != "" && filter != kind {
				continue
			}
			v, _ := engineVersion(kind, "")
			engine := api.BrokerEngineType{}
			text(&engine.EngineType, kind)
			version := api.EngineVersion{}
			text(&version.Name, v)
			engine.EngineVersions = append(engine.EngineVersions, version)
			o.BrokerEngineTypes = append(o.BrokerEngineTypes, engine)
		}
		return o, nil
	})
	register(s, "DescribeBrokerInstanceOptions", func(ctx context.Context, t Transaction, in *api.DescribeBrokerInstanceOptionsInput) (*api.DescribeBrokerInstanceOptionsOutput, error) {
		if e := s.authorize(ctx, BrokerRecord{}, "DescribeBrokerInstanceOptions", nil); e != nil {
			return nil, e
		}
		limit, after, e := page(ctx, "instances:"+value(in.EngineType)+":"+value(in.HostInstanceType)+":"+value(in.StorageType), in.MaxResults, value(in.NextToken))
		if e != nil {
			return nil, e
		}
		if after != "" {
			return nil, invalid("Invalid NextToken")
		}
		filter := value(in.EngineType)
		if filter != "" && filter != "ACTIVEMQ" && filter != "RABBITMQ" {
			return nil, invalid("Invalid EngineType")
		}
		o := &api.DescribeBrokerInstanceOptionsOutput{}
		number(&o.MaxResults, limit)
		if value(in.HostInstanceType) != "" && value(in.HostInstanceType) != "mq.t3.micro" || value(in.StorageType) != "" {
			return o, nil
		}
		for _, kind := range []string{"ACTIVEMQ", "RABBITMQ"} {
			if filter != "" && filter != kind {
				continue
			}
			v, _ := engineVersion(kind, "")
			option := api.BrokerInstanceOption{}
			text(&option.EngineType, kind)
			text(&option.HostInstanceType, "mq.t3.micro")
			stringList(&option.SupportedEngineVersions, []string{v})
			stringList(&option.SupportedDeploymentModes, []string{"SINGLE_INSTANCE"})
			o.BrokerInstanceOptions = append(o.BrokerInstanceOptions, option)
		}
		return o, nil
	})
}

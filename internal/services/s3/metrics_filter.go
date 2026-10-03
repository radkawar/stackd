package s3

import (
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func parseMetricsConfiguration(id string, in *api.MetricsConfiguration) (*RequestMetricsConfiguration, *awswire.Error) {
	if validateConfigurationID(value(in.Id)) != nil || id != value(in.Id) {
		return nil, malformedXML()
	}
	out := &RequestMetricsConfiguration{ID: id}
	if in.Filter == nil {
		return out, nil
	}
	filter := in.Filter
	members := 0
	for _, present := range []bool{filter.Prefix != nil, filter.Tag != nil, filter.And != nil, filter.AccessPointArn != nil} {
		if present {
			members++
		}
	}
	if members != 1 {
		return nil, malformedXML()
	}
	f := &RequestMetricsFilter{}
	var tags api.TagSet
	var point *api.AccessPointArn
	switch {
	case filter.Prefix != nil:
		f.Kind, f.Prefix = "prefix", new(value(filter.Prefix))
	case filter.Tag != nil:
		f.Kind, tags = "tag", api.TagSet{*filter.Tag}
	case filter.AccessPointArn != nil:
		f.Kind, point = "access-point", filter.AccessPointArn
	case filter.And != nil:
		f.Kind, tags, point = "and", filter.And.Tags, filter.And.AccessPointArn
		predicates := len(tags)
		if filter.And.Prefix != nil {
			f.Prefix = new(value(filter.And.Prefix))
			predicates++
		}
		if point != nil {
			predicates++
		}
		if predicates < 2 {
			return nil, malformedXML()
		}
	}
	if f.Prefix != nil && *f.Prefix == "" {
		return nil, malformedXML()
	}
	if point != nil {
		if _, wire := parseAccessPointARN(value(point)); wire != nil {
			return nil, malformedXML()
		}
		f.AccessPointARN = value(point)
	}
	// Duplicate keys are native-valid here, unlike Intelligent-Tiering. Their
	// conjunction is retained without collapsing or rewriting the predicates.
	f.Tags = make([]Tag, len(tags))
	for i, tag := range tags {
		f.Tags[i] = Tag{Key: value(tag.Key), Value: value(tag.Value)}
	}
	out.Filter = f
	return out, nil
}

func outputMetricsConfiguration(config RequestMetricsConfiguration) api.MetricsConfiguration {
	out := api.MetricsConfiguration{Id: new(api.MetricsId(config.ID))}
	if config.Filter == nil {
		return out
	}
	f := config.Filter
	out.Filter = &api.MetricsFilter{}
	switch f.Kind {
	case "prefix":
		out.Filter.Prefix = new(api.Prefix(*f.Prefix))
	case "tag":
		out.Filter.Tag = &api.Tag{Key: new(api.ObjectKey(f.Tags[0].Key)), Value: new(api.Value(f.Tags[0].Value))}
	case "access-point":
		out.Filter.AccessPointArn = new(api.AccessPointArn(f.AccessPointARN))
	case "and":
		and := &api.MetricsAndOperator{Tags: outputTags(f.Tags)}
		if f.Prefix != nil {
			and.Prefix = new(api.Prefix(*f.Prefix))
		}
		if f.AccessPointARN != "" {
			and.AccessPointArn = new(api.AccessPointArn(f.AccessPointARN))
		}
		out.Filter.And = and
	}
	return out
}

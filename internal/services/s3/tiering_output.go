package s3

import api "stackd/internal/awsapi/s3"

func outputTieringConfiguration(in TieringConfiguration) *api.IntelligentTieringConfiguration {
	status := api.IntelligentTieringStatus("Disabled")
	if in.Enabled {
		status = "Enabled"
	}
	out := &api.IntelligentTieringConfiguration{
		Id:       new(api.IntelligentTieringId(in.ID)),
		Status:   &status,
		Tierings: make(api.TieringList, 0, len(in.Tierings)),
	}
	for _, tier := range in.Tierings {
		out.Tierings = append(out.Tierings, api.Tiering{AccessTier: new(api.IntelligentTieringAccessTier(tier.AccessTier)), Days: new(api.IntelligentTieringDays(tier.Days))})
	}
	if in.Filter != nil {
		out.Filter = outputTieringFilter(*in.Filter)
	}
	return out
}

func outputTieringFilter(in ObjectFilter) *api.IntelligentTieringFilter {
	out := &api.IntelligentTieringFilter{}
	if in.Kind == "and" {
		out.And = &api.IntelligentTieringAndOperator{Tags: outputTags(in.Tags)}
		if in.Prefix != nil {
			out.And.Prefix = new(api.Prefix(*in.Prefix))
		}
		return out
	}
	if in.Prefix != nil {
		out.Prefix = new(api.Prefix(*in.Prefix))
	}
	if in.Kind == "tag" {
		out.Tag = &api.Tag{Key: new(api.ObjectKey(in.Tags[0].Key)), Value: new(api.Value(in.Tags[0].Value))}
	}
	return out
}

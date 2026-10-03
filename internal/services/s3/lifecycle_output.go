package s3

import api "stackd/internal/awsapi/s3"

func outputLifecycleConfiguration(in *LifecycleConfiguration) *api.GetBucketLifecycleConfigurationOutput {
	out := &api.GetBucketLifecycleConfigurationOutput{
		Rules:                              make(api.LifecycleRules, 0, len(in.Rules)),
		TransitionDefaultMinimumObjectSize: new(api.TransitionDefaultMinimumObjectSize(in.MinimumObjectSize)),
	}
	for _, rule := range in.Rules {
		status := api.ExpirationStatus("Disabled")
		if rule.Enabled {
			status = "Enabled"
		}
		item := api.LifecycleRule{ID: new(api.ID(rule.ID)), Status: &status}
		if rule.Filter.Kind == "legacy" {
			item.Prefix = new(api.Prefix(*rule.Filter.Prefix))
		} else {
			item.Filter = outputLifecycleFilter(rule.Filter)
		}
		if expiration := rule.Expiration; expiration != nil {
			item.Expiration = &api.LifecycleExpiration{Date: expiration.Date}
			if expiration.Days != nil {
				item.Expiration.Days = new(api.Days(*expiration.Days))
			}
			if expiration.ExpiredObjectDeleteMarker != nil {
				item.Expiration.ExpiredObjectDeleteMarker = new(api.ExpiredObjectDeleteMarker(*expiration.ExpiredObjectDeleteMarker))
			}
		}
		if len(rule.Transitions) != 0 {
			item.Transitions = make(api.TransitionList, 0, len(rule.Transitions))
		}
		for _, transition := range rule.Transitions {
			output := api.Transition{Date: transition.Date, StorageClass: new(api.TransitionStorageClass(transition.StorageClass))}
			if transition.Days != nil {
				output.Days = new(api.Days(*transition.Days))
			}
			item.Transitions = append(item.Transitions, output)
		}
		if expiration := rule.NoncurrentExpiration; expiration != nil {
			item.NoncurrentVersionExpiration = &api.NoncurrentVersionExpiration{NoncurrentDays: new(api.Days(expiration.Days))}
			if expiration.NewerNoncurrentVersions != nil {
				item.NoncurrentVersionExpiration.NewerNoncurrentVersions = new(api.VersionCount(*expiration.NewerNoncurrentVersions))
			}
		}
		if len(rule.NoncurrentTransitions) != 0 {
			item.NoncurrentVersionTransitions = make(api.NoncurrentVersionTransitionList, 0, len(rule.NoncurrentTransitions))
		}
		for _, transition := range rule.NoncurrentTransitions {
			output := api.NoncurrentVersionTransition{NoncurrentDays: new(api.Days(transition.Days)), StorageClass: new(api.TransitionStorageClass(transition.StorageClass))}
			if transition.NewerNoncurrentVersions != nil {
				output.NewerNoncurrentVersions = new(api.VersionCount(*transition.NewerNoncurrentVersions))
			}
			item.NoncurrentVersionTransitions = append(item.NoncurrentVersionTransitions, output)
		}
		if rule.AbortIncompleteDays != nil {
			item.AbortIncompleteMultipartUpload = &api.AbortIncompleteMultipartUpload{DaysAfterInitiation: new(api.DaysAfterInitiation(*rule.AbortIncompleteDays))}
		}
		out.Rules = append(out.Rules, item)
	}
	return out
}

func outputLifecycleFilter(in ObjectFilter) *api.LifecycleRuleFilter {
	out := &api.LifecycleRuleFilter{}
	if in.Kind == "and" {
		out.And = &api.LifecycleRuleAndOperator{Tags: outputTags(in.Tags)}
		if in.Prefix != nil {
			out.And.Prefix = new(api.Prefix(*in.Prefix))
		}
		if in.ObjectSizeGreaterThan != nil {
			out.And.ObjectSizeGreaterThan = new(api.ObjectSizeGreaterThanBytes(*in.ObjectSizeGreaterThan))
		}
		if in.ObjectSizeLessThan != nil {
			out.And.ObjectSizeLessThan = new(api.ObjectSizeLessThanBytes(*in.ObjectSizeLessThan))
		}
		return out
	}
	if in.Prefix != nil {
		out.Prefix = new(api.Prefix(*in.Prefix))
	}
	if in.Kind == "tag" {
		out.Tag = &api.Tag{Key: new(api.ObjectKey(in.Tags[0].Key)), Value: new(api.Value(in.Tags[0].Value))}
	}
	if in.ObjectSizeGreaterThan != nil {
		out.ObjectSizeGreaterThan = new(api.ObjectSizeGreaterThanBytes(*in.ObjectSizeGreaterThan))
	}
	if in.ObjectSizeLessThan != nil {
		out.ObjectSizeLessThan = new(api.ObjectSizeLessThanBytes(*in.ObjectSizeLessThan))
	}
	return out
}

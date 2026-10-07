package integrations

import (
	"fmt"
	"time"

	api "stackd/internal/awsapi/s3"
)

// CloudFormation lifecycle properties follow the AWS::S3::Bucket Rule registry
// schema. The S3 owner remains authoritative for action, filter and ordering
// semantics; this adapter only translates between the two representations.
type cfnS3Lifecycle struct {
	Rules                              []cfnS3LifecycleRule
	TransitionDefaultMinimumObjectSize string
}
type cfnS3LifecycleRule struct {
	ID                                string `json:"Id"`
	Status                            string
	Prefix                            *string
	TagFilters                        []cfnMessagingTag
	ObjectSizeGreaterThan             *cfnMessagingInt
	ObjectSizeLessThan                *cfnMessagingInt
	ExpirationDate                    string
	ExpirationInDays                  *cfnMessagingInt
	ExpiredObjectDeleteMarker         *cfnMessagingBool
	NoncurrentVersionExpiration       *cfnS3NoncurrentExpiration
	NoncurrentVersionExpirationInDays *cfnMessagingInt
	NoncurrentVersionTransition       *cfnS3NoncurrentTransition
	NoncurrentVersionTransitions      []cfnS3NoncurrentTransition
	Transition                        *cfnS3Transition
	Transitions                       []cfnS3Transition
	AbortIncompleteMultipartUpload    *struct{ DaysAfterInitiation cfnMessagingInt }
}
type cfnS3NoncurrentExpiration struct {
	NoncurrentDays          cfnMessagingInt
	NewerNoncurrentVersions *cfnMessagingInt
}
type cfnS3NoncurrentTransition struct {
	StorageClass            string
	TransitionInDays        cfnMessagingInt
	NewerNoncurrentVersions *cfnMessagingInt
}
type cfnS3Transition struct {
	StorageClass     string
	TransitionDate   string
	TransitionInDays *cfnMessagingInt
}

const cfnS3LifecycleDate = "2006-01-02T15:04:05Z"

func cfnS3Int32(name string, value cfnMessagingInt) (int32, error) {
	if value < -2147483648 || value > 2147483647 {
		return 0, fmt.Errorf("%s must be a 32-bit integer", name)
	}
	return int32(value), nil
}

func cfnS3LifecycleTime(name, value string) (*api.Date, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("%s must be an ISO 8601 UTC timestamp: %w", name, err)
	}
	return new(api.Date(parsed.UTC())), nil
}

// CloudFormation retains the legacy mixed-case Glacier enum value.
func cfnS3StorageClass(value string) (*api.TransitionStorageClass, error) {
	if value == "" {
		return nil, fmt.Errorf("lifecycle transitions require StorageClass")
	}
	if value == "Glacier" {
		value = "GLACIER"
	}
	return new(api.TransitionStorageClass(value)), nil
}

func (t cfnS3Transition) native() (api.Transition, error) {
	class, err := cfnS3StorageClass(t.StorageClass)
	if err != nil {
		return api.Transition{}, err
	}
	out := api.Transition{StorageClass: class}
	if t.TransitionDate != "" {
		if out.Date, err = cfnS3LifecycleTime("TransitionDate", t.TransitionDate); err != nil {
			return api.Transition{}, err
		}
	}
	if t.TransitionInDays != nil {
		days, err := cfnS3Int32("TransitionInDays", *t.TransitionInDays)
		if err != nil {
			return api.Transition{}, err
		}
		out.Days = new(api.Days(days))
	}
	return out, nil
}

func (t cfnS3NoncurrentTransition) native() (api.NoncurrentVersionTransition, error) {
	class, err := cfnS3StorageClass(t.StorageClass)
	if err != nil {
		return api.NoncurrentVersionTransition{}, err
	}
	days, err := cfnS3Int32("TransitionInDays", t.TransitionInDays)
	if err != nil {
		return api.NoncurrentVersionTransition{}, err
	}
	out := api.NoncurrentVersionTransition{StorageClass: class, NoncurrentDays: new(api.Days(days))}
	if t.NewerNoncurrentVersions != nil {
		newer, err := cfnS3Int32("NewerNoncurrentVersions", *t.NewerNoncurrentVersions)
		if err != nil {
			return api.NoncurrentVersionTransition{}, err
		}
		out.NewerNoncurrentVersions = new(api.VersionCount(newer))
	}
	return out, nil
}

// filter expresses CloudFormation's flattened predicates as the Lifecycle V2
// filter. Two or more predicates require the And operator.
func (rule cfnS3LifecycleRule) filter() (*api.LifecycleRuleFilter, error) {
	prefix := ""
	if rule.Prefix != nil {
		prefix = *rule.Prefix
	}
	tags := make(api.TagSet, 0, len(rule.TagFilters))
	for _, tag := range rule.TagFilters {
		if tag.Key == "" {
			return nil, fmt.Errorf("lifecycle TagFilters require Key")
		}
		tags = append(tags, api.Tag{Key: new(api.ObjectKey(tag.Key)), Value: new(api.Value(tag.Value))})
	}
	var greater *api.ObjectSizeGreaterThanBytes
	var less *api.ObjectSizeLessThanBytes
	if rule.ObjectSizeGreaterThan != nil {
		greater = new(api.ObjectSizeGreaterThanBytes(*rule.ObjectSizeGreaterThan))
	}
	if rule.ObjectSizeLessThan != nil {
		less = new(api.ObjectSizeLessThanBytes(*rule.ObjectSizeLessThan))
	}
	predicates := len(tags)
	if prefix != "" {
		predicates++
	}
	if greater != nil {
		predicates++
	}
	if less != nil {
		predicates++
	}
	switch {
	case predicates >= 2:
		and := &api.LifecycleRuleAndOperator{Tags: tags, ObjectSizeGreaterThan: greater, ObjectSizeLessThan: less}
		if prefix != "" {
			and.Prefix = new(api.Prefix(prefix))
		}
		return &api.LifecycleRuleFilter{And: and}, nil
	case len(tags) == 1:
		return &api.LifecycleRuleFilter{Tag: &tags[0]}, nil
	case greater != nil:
		return &api.LifecycleRuleFilter{ObjectSizeGreaterThan: greater}, nil
	case less != nil:
		return &api.LifecycleRuleFilter{ObjectSizeLessThan: less}, nil
	default:
		return &api.LifecycleRuleFilter{Prefix: new(api.Prefix(prefix))}, nil
	}
}

func (rule cfnS3LifecycleRule) expiration() (*api.LifecycleExpiration, error) {
	marker := rule.ExpiredObjectDeleteMarker
	if rule.ExpirationDate == "" && rule.ExpirationInDays == nil && marker == nil {
		return nil, nil
	}
	out := &api.LifecycleExpiration{}
	if rule.ExpirationDate != "" {
		date, err := cfnS3LifecycleTime("ExpirationDate", rule.ExpirationDate)
		if err != nil {
			return nil, err
		}
		out.Date = date
	}
	if rule.ExpirationInDays != nil {
		days, err := cfnS3Int32("ExpirationInDays", *rule.ExpirationInDays)
		if err != nil {
			return nil, err
		}
		out.Days = new(api.Days(days))
	}
	// A false marker is the S3 default. Combining a true marker with a date,
	// day count or tag filter remains an owner validation error.
	if marker != nil && (bool(*marker) || out.Date == nil && out.Days == nil) {
		out.ExpiredObjectDeleteMarker = new(api.ExpiredObjectDeleteMarker(bool(*marker)))
	}
	return out, nil
}

func (rule cfnS3LifecycleRule) native() (api.LifecycleRule, error) {
	if rule.Status != "Enabled" && rule.Status != "Disabled" {
		return api.LifecycleRule{}, fmt.Errorf("lifecycle rule Status must be Enabled or Disabled")
	}
	if rule.Transition != nil && len(rule.Transitions) != 0 {
		return api.LifecycleRule{}, fmt.Errorf("lifecycle rule cannot specify both Transition and Transitions")
	}
	if rule.NoncurrentVersionTransition != nil && len(rule.NoncurrentVersionTransitions) != 0 {
		return api.LifecycleRule{}, fmt.Errorf("lifecycle rule cannot specify both NoncurrentVersionTransition and NoncurrentVersionTransitions")
	}
	if rule.NoncurrentVersionExpiration != nil && rule.NoncurrentVersionExpirationInDays != nil {
		return api.LifecycleRule{}, fmt.Errorf("lifecycle rule cannot specify both NoncurrentVersionExpiration and NoncurrentVersionExpirationInDays")
	}
	out := api.LifecycleRule{Status: new(api.ExpirationStatus(rule.Status))}
	if rule.ID != "" {
		out.ID = new(api.ID(rule.ID))
	}
	var err error
	if out.Filter, err = rule.filter(); err != nil {
		return api.LifecycleRule{}, err
	}
	if out.Expiration, err = rule.expiration(); err != nil {
		return api.LifecycleRule{}, err
	}
	transitions := rule.Transitions
	if rule.Transition != nil {
		transitions = []cfnS3Transition{*rule.Transition}
	}
	for _, transition := range transitions {
		native, err := transition.native()
		if err != nil {
			return api.LifecycleRule{}, err
		}
		out.Transitions = append(out.Transitions, native)
	}
	noncurrent := rule.NoncurrentVersionTransitions
	if rule.NoncurrentVersionTransition != nil {
		noncurrent = []cfnS3NoncurrentTransition{*rule.NoncurrentVersionTransition}
	}
	for _, transition := range noncurrent {
		native, err := transition.native()
		if err != nil {
			return api.LifecycleRule{}, err
		}
		out.NoncurrentVersionTransitions = append(out.NoncurrentVersionTransitions, native)
	}
	expiration := rule.NoncurrentVersionExpiration
	if rule.NoncurrentVersionExpirationInDays != nil {
		expiration = &cfnS3NoncurrentExpiration{NoncurrentDays: *rule.NoncurrentVersionExpirationInDays}
	}
	if expiration != nil {
		days, err := cfnS3Int32("NoncurrentDays", expiration.NoncurrentDays)
		if err != nil {
			return api.LifecycleRule{}, err
		}
		out.NoncurrentVersionExpiration = &api.NoncurrentVersionExpiration{NoncurrentDays: new(api.Days(days))}
		if expiration.NewerNoncurrentVersions != nil {
			newer, err := cfnS3Int32("NewerNoncurrentVersions", *expiration.NewerNoncurrentVersions)
			if err != nil {
				return api.LifecycleRule{}, err
			}
			out.NoncurrentVersionExpiration.NewerNoncurrentVersions = new(api.VersionCount(newer))
		}
	}
	if abort := rule.AbortIncompleteMultipartUpload; abort != nil {
		days, err := cfnS3Int32("DaysAfterInitiation", abort.DaysAfterInitiation)
		if err != nil {
			return api.LifecycleRule{}, err
		}
		out.AbortIncompleteMultipartUpload = &api.AbortIncompleteMultipartUpload{DaysAfterInitiation: new(api.DaysAfterInitiation(days))}
	}
	if out.Expiration == nil && len(out.Transitions) == 0 && out.NoncurrentVersionExpiration == nil && len(out.NoncurrentVersionTransitions) == 0 && out.AbortIncompleteMultipartUpload == nil {
		return api.LifecycleRule{}, fmt.Errorf("lifecycle rule requires an expiration, transition or abort action")
	}
	return out, nil
}

func (p *cfnS3Lifecycle) native() (*api.PutBucketLifecycleConfigurationInput, error) {
	if p == nil {
		return nil, nil
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("LifecycleConfiguration requires Rules")
	}
	out := &api.PutBucketLifecycleConfigurationInput{LifecycleConfiguration: &api.BucketLifecycleConfiguration{Rules: make(api.LifecycleRules, 0, len(p.Rules))}}
	if p.TransitionDefaultMinimumObjectSize != "" {
		out.TransitionDefaultMinimumObjectSize = new(api.TransitionDefaultMinimumObjectSize(p.TransitionDefaultMinimumObjectSize))
	}
	for _, rule := range p.Rules {
		native, err := rule.native()
		if err != nil {
			return nil, err
		}
		out.LifecycleConfiguration.Rules = append(out.LifecycleConfiguration.Rules, native)
	}
	return out, nil
}

func cfnS3ReadLifecycleTags(tags api.TagSet) []any {
	out := make([]any, 0, len(tags))
	for _, tag := range tags {
		out = append(out, map[string]any{"Key": cfnComputeValue(tag.Key), "Value": cfnComputeValue(tag.Value)})
	}
	return out
}

// cfnS3ReadLifecycle projects every owner-admitted lifecycle rule. Each owner
// predicate and action has a CloudFormation property, so updates never discard
// a rule that Read could not represent.
func cfnS3ReadLifecycle(out *api.GetBucketLifecycleConfigurationOutput) map[string]any {
	rules := make([]any, 0, len(out.Rules))
	for _, rule := range out.Rules {
		p := map[string]any{"Status": cfnComputeValue(rule.Status)}
		if rule.ID != nil {
			p["Id"] = string(*rule.ID)
		}
		if rule.Prefix != nil {
			p["Prefix"] = string(*rule.Prefix)
		}
		if filter := rule.Filter; filter != nil {
			greater, less := filter.ObjectSizeGreaterThan, filter.ObjectSizeLessThan
			if filter.Prefix != nil {
				p["Prefix"] = string(*filter.Prefix)
			}
			if filter.Tag != nil {
				p["TagFilters"] = cfnS3ReadLifecycleTags(api.TagSet{*filter.Tag})
			}
			if and := filter.And; and != nil {
				if and.Prefix != nil {
					p["Prefix"] = string(*and.Prefix)
				}
				if len(and.Tags) != 0 {
					p["TagFilters"] = cfnS3ReadLifecycleTags(and.Tags)
				}
				greater, less = and.ObjectSizeGreaterThan, and.ObjectSizeLessThan
			}
			if greater != nil {
				p["ObjectSizeGreaterThan"] = fmt.Sprint(int64(*greater))
			}
			if less != nil {
				p["ObjectSizeLessThan"] = fmt.Sprint(int64(*less))
			}
		}
		if value := rule.Expiration; value != nil {
			if value.Days != nil {
				p["ExpirationInDays"] = int32(*value.Days)
			}
			if value.Date != nil {
				p["ExpirationDate"] = value.Date.UTC().Format(cfnS3LifecycleDate)
			}
			if value.ExpiredObjectDeleteMarker != nil {
				p["ExpiredObjectDeleteMarker"] = bool(*value.ExpiredObjectDeleteMarker)
			}
		}
		if len(rule.Transitions) != 0 {
			transitions := make([]any, 0, len(rule.Transitions))
			for _, transition := range rule.Transitions {
				item := map[string]any{"StorageClass": cfnComputeValue(transition.StorageClass)}
				if transition.Days != nil {
					item["TransitionInDays"] = int32(*transition.Days)
				}
				if transition.Date != nil {
					item["TransitionDate"] = transition.Date.UTC().Format(cfnS3LifecycleDate)
				}
				transitions = append(transitions, item)
			}
			p["Transitions"] = transitions
		}
		if len(rule.NoncurrentVersionTransitions) != 0 {
			transitions := make([]any, 0, len(rule.NoncurrentVersionTransitions))
			for _, transition := range rule.NoncurrentVersionTransitions {
				item := map[string]any{"StorageClass": cfnComputeValue(transition.StorageClass)}
				if transition.NoncurrentDays != nil {
					item["TransitionInDays"] = int32(*transition.NoncurrentDays)
				}
				if transition.NewerNoncurrentVersions != nil {
					item["NewerNoncurrentVersions"] = int32(*transition.NewerNoncurrentVersions)
				}
				transitions = append(transitions, item)
			}
			p["NoncurrentVersionTransitions"] = transitions
		}
		if value := rule.NoncurrentVersionExpiration; value != nil {
			expiration := map[string]any{}
			if value.NoncurrentDays != nil {
				expiration["NoncurrentDays"] = int32(*value.NoncurrentDays)
			}
			if value.NewerNoncurrentVersions != nil {
				expiration["NewerNoncurrentVersions"] = int32(*value.NewerNoncurrentVersions)
			}
			p["NoncurrentVersionExpiration"] = expiration
		}
		if value := rule.AbortIncompleteMultipartUpload; value != nil && value.DaysAfterInitiation != nil {
			p["AbortIncompleteMultipartUpload"] = map[string]any{"DaysAfterInitiation": int32(*value.DaysAfterInitiation)}
		}
		rules = append(rules, p)
	}
	result := map[string]any{"Rules": rules}
	if out.TransitionDefaultMinimumObjectSize != nil {
		result["TransitionDefaultMinimumObjectSize"] = string(*out.TransitionDefaultMinimumObjectSize)
	}
	return result
}

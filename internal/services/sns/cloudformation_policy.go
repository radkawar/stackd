package sns

import "context"

// PolicyOwnership is private native metadata for the bound topic policy.
// Native policy writes relinquish ownership, including equal-document writes.
type PolicyOwnership struct {
	Owner, Identifier, Type string
}
type CloudFormationPolicyClaim struct {
	Owner, Identifier, Type      string
	Remove, RequireOwned, Direct bool
	Incarnation                  string
}
type cloudFormationPolicyContextKey struct{}

func WithCloudFormationPolicyClaim(ctx context.Context, claim CloudFormationPolicyClaim) context.Context {
	return context.WithValue(ctx, cloudFormationPolicyContextKey{}, claim)
}

func clearCloudFormationPolicyClaim(topic *TopicRecord) {
	topic.PolicyOwnership = PolicyOwnership{}
}

func (s *Service) setClaimedTopicPolicy(ctx context.Context, topic *TopicRecord, document string) error {
	claim, managed := ctx.Value(cloudFormationPolicyContextKey{}).(CloudFormationPolicyClaim)
	if managed && !claim.Direct {
		if claim.Incarnation != "" && topic.ID != claim.Incarnation {
			return failure("InvalidParameter", "Topic policy belongs to another native incarnation")
		}
		owner := topic.PolicyOwnership.Owner
		if claim.Remove && owner == "" {
			return nil
		}
		if claim.Owner == "" || (owner != "" && owner != claim.Owner) || (claim.RequireOwned && owner != claim.Owner) {
			return failure("InvalidParameter", "Topic policy is not owned by this resource incarnation")
		}
		if owner == "" {
			defaultDocument, err := validateTopicPolicy(defaultTopicPolicy(topic.Key), topic.Key)
			if err != nil {
				return err
			}
			if topic.Policy.Document != defaultDocument {
				return failure("InvalidParameter", "Topic already has an unrelated policy")
			}
		}
	}
	if err := s.setTopicAttribute(ctx, topic, "Policy", document); err != nil {
		return err
	}
	clearCloudFormationPolicyClaim(topic)
	if managed && !claim.Remove {
		topic.PolicyOwnership = PolicyOwnership{Identifier: claim.Identifier, Type: claim.Type}
		if !claim.Direct {
			topic.PolicyOwnership.Owner = claim.Owner
		}
	}
	return nil
}

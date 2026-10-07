package sns

import "context"

// TopicCreationOwner is private authority committed with the native incarnation.
// Customer tags and public topic attributes never populate this claim.
type TopicCreationOwner struct {
	Owner, Token string
}

type CloudFormationTopicClaim struct {
	TopicCreationOwner
	Incarnation string
}
type cloudFormationTopicContextKey struct{}

func WithCloudFormationTopicClaim(ctx context.Context, claim CloudFormationTopicClaim) context.Context {
	return context.WithValue(ctx, cloudFormationTopicContextKey{}, claim)
}

func checkCloudFormationTopicClaim(ctx context.Context, topic TopicRecord) error {
	claim, managed := ctx.Value(cloudFormationTopicContextKey{}).(CloudFormationTopicClaim)
	if !managed {
		return nil
	}
	if claim.Owner == "" || claim.Token == "" || topic.CreationOwner != claim.TopicCreationOwner || (claim.Incarnation != "" && topic.ID != claim.Incarnation) {
		return failure("InvalidParameter", "Topic is not owned by this resource incarnation")
	}
	return nil
}

// TopicOwnershipObservation is supplied only by trusted adapters and filled by
// an authorized native read. It is not part of the public SNS response.
type TopicOwnershipObservation struct {
	Incarnation     string
	CreationOwner   TopicCreationOwner
	PolicyOwnership PolicyOwnership
}
type topicOwnershipObservationContextKey struct{}

func WithTopicOwnershipObservation(ctx context.Context, observation *TopicOwnershipObservation) context.Context {
	return context.WithValue(ctx, topicOwnershipObservationContextKey{}, observation)
}
func observeTopicOwnership(ctx context.Context, topic TopicRecord) {
	if out, ok := ctx.Value(topicOwnershipObservationContextKey{}).(*TopicOwnershipObservation); ok && out != nil {
		*out = TopicOwnershipObservation{Incarnation: topic.ID, CreationOwner: topic.CreationOwner, PolicyOwnership: topic.PolicyOwnership}
	}
}

package integrations

import (
	"context"

	api "stackd/internal/awsapi/sns"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/sns"
)

func cfnSNSTopicClaim(r cloudformation.ResourceRequest) sns.CloudFormationTopicClaim {
	return sns.CloudFormationTopicClaim{TopicCreationOwner: sns.TopicCreationOwner{Owner: cfnMessagingOwner(r), Token: cfnMessagingHash(r.Token)}}
}
func cfnSNSTopicTags(r cloudformation.ResourceRequest, customer []cfnMessagingTag) (map[string]string, error) {
	tags, err := cfnMessagingTags(r, customer)
	delete(tags, cfnMessagingOwnerTag)
	delete(tags, cfnMessagingTokenTag)
	return tags, err
}
func (h cfnSNSTopic) observe(ctx context.Context, arn string) (*api.GetTopicAttributesOutput, sns.TopicOwnershipObservation, error) {
	var observation sns.TopicOwnershipObservation
	ctx = sns.WithTopicOwnershipObservation(ctx, &observation)
	out, err := cfnMessagingCall[api.GetTopicAttributesOutput](ctx, h.commands, "sns", "GetTopicAttributes", &api.GetTopicAttributesInput{TopicArn: new(api.TopicARN(arn))})
	return out, observation, err
}
func (h cfnSNSTopic) ownedContext(ctx context.Context, r cloudformation.ResourceRequest) (context.Context, error) {
	if r.CloudControl {
		return ctx, nil
	}
	claim := cfnSNSTopicClaim(r)
	ctx = sns.WithCloudFormationTopicClaim(ctx, claim)
	_, observed, err := h.observe(ctx, r.PhysicalID)
	if err != nil {
		return ctx, err
	}
	claim.Incarnation = observed.Incarnation
	return sns.WithCloudFormationTopicClaim(ctx, claim), nil
}
func (h cfnSNSTopic) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	var p cfnSNSTopicProperties
	if err := cfnMessagingDecode(r.Properties, &p); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := p.TopicName
	if name == "" {
		name = cfnMessagingName(r, 256, p.fifo())
	}
	arn := "arn:" + r.Scope.Partition + ":sns:" + r.Scope.Region + ":" + r.Scope.Account + ":" + name
	ctx = sns.WithCloudFormationTopicClaim(ctx, cfnSNSTopicClaim(r))
	if _, _, err := h.observe(ctx, arn); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.result(arn), nil
}

var _ cloudformation.ResourceCreationRecoverer = cfnSNSTopic{}

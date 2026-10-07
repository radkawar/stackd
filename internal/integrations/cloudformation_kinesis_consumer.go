package integrations

import (
	"context"
	"fmt"

	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/services/cloudformation"
)

// cfnKinesisConsumer registers enhanced fan-out consumers through the Kinesis
// owner. Every property is create-only; the physical identity is the ARN.
type cfnKinesisConsumer struct{ commands StepFunctionsCommands }

type cfnKinesisConsumerProperties struct {
	ConsumerName string
	StreamARN    string
	Tags         []cfnMessagingTag
}

func cfnKinesisConsumerDecode(raw cloudformation.Properties) (cfnKinesisConsumerProperties, error) {
	var p cfnKinesisConsumerProperties
	if err := cfnMessagingDecode(raw, &p); err != nil {
		return p, err
	}
	if p.ConsumerName == "" || p.StreamARN == "" {
		return p, fmt.Errorf("ConsumerName and StreamARN are required")
	}
	_, err := cfnComputeTags(raw)
	return p, err
}

func (h cfnKinesisConsumer) Validate(p cloudformation.Properties) error {
	_, err := cfnKinesisConsumerDecode(p)
	return err
}

// ConsumerName, StreamARN and Tags are create-only in the pinned schema.
func (h cfnKinesisConsumer) Replacement(a, b cloudformation.Properties) (bool, error) {
	if _, err := cfnKinesisConsumerDecode(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "ConsumerName", "StreamARN", "Tags"), nil
}

func (h cfnKinesisConsumer) describe(ctx context.Context, in map[string]any) (*kinesisapi.ConsumerDescription, error) {
	out, err := cfnComputeCall[kinesisapi.DescribeStreamConsumerOutput](ctx, h.commands, "kinesis", "DescribeStreamConsumer", in)
	if err != nil {
		return nil, err
	}
	if out.ConsumerDescription == nil {
		return nil, fmt.Errorf("Kinesis returned no consumer description")
	}
	return out.ConsumerDescription, nil
}

func cfnKinesisConsumerResult(c *kinesisapi.ConsumerDescription) cloudformation.ResourceResult {
	arn := cfnComputeValue(c.ConsumerARN)
	return cloudformation.ResourceResult{PhysicalID: arn, Ref: arn, Attributes: map[string]any{
		"ConsumerARN":               arn,
		"ConsumerName":              cfnComputeValue(c.ConsumerName),
		"ConsumerStatus":            cfnComputeValue(c.ConsumerStatus),
		"ConsumerCreationTimestamp": cfnDataTimestamp(c.ConsumerCreationTimestamp),
		"StreamARN":                 cfnComputeValue(c.StreamARN),
	}}
}

func (h cfnKinesisConsumer) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "consumer", true)
	p, err := cfnKinesisConsumerDecode(r.Properties)
	if err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	existing, err := h.describe(ctx, map[string]any{"StreamARN": p.StreamARN, "ConsumerName": p.ConsumerName})
	if err == nil {
		return cfnKinesisConsumerResult(existing), nil
	}
	if !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnComputeCall[kinesisapi.RegisterStreamConsumerOutput](ctx, h.commands, "kinesis", "RegisterStreamConsumer", map[string]any{"StreamARN": p.StreamARN, "ConsumerName": p.ConsumerName, "Tags": cfnDataCreateTags(r)})
	if err != nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, err
	}
	if out.Consumer == nil {
		result, _ := h.RecoverCreation(ctx, r)
		return result, fmt.Errorf("RegisterStreamConsumer returned no consumer")
	}
	c := out.Consumer
	return cfnKinesisConsumerResult(&kinesisapi.ConsumerDescription{ConsumerARN: c.ConsumerARN, ConsumerName: c.ConsumerName, ConsumerStatus: c.ConsumerStatus, ConsumerCreationTimestamp: c.ConsumerCreationTimestamp, StreamARN: new(kinesisapi.StreamARN(p.StreamARN))}), nil
}

// Update has no mutable consumer properties; it verifies the incarnation and
// reports the current owner state.
func (h cfnKinesisConsumer) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "consumer", false)
	if _, err := cfnKinesisConsumerDecode(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	c, err := h.describe(ctx, map[string]any{"ConsumerARN": r.PhysicalID})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnKinesisConsumerResult(c), nil
}

// Stabilize waits until the consumer can subscribe; CREATING consumers
// cannot read data.
func (h cfnKinesisConsumer) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "consumer", false)
	c, err := h.describe(ctx, map[string]any{"ConsumerARN": r.PhysicalID})
	if err != nil {
		return false, err
	}
	switch status := cfnComputeValue(c.ConsumerStatus); status {
	case "ACTIVE":
		return true, nil
	case "CREATING":
		return false, nil
	default:
		return false, fmt.Errorf("Kinesis consumer %s is %s", r.PhysicalID, status)
	}
}

func (h cfnKinesisConsumer) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "consumer", false)
	c, err := h.describe(ctx, map[string]any{"ConsumerARN": r.PhysicalID})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnKinesisConsumerResult(c), nil
}

func (h cfnKinesisConsumer) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ctx = cfnKinesisOwnerContext(ctx, r, "consumer", false)
	if r.PhysicalID == "" {
		return nil
	}
	c, err := h.describe(ctx, map[string]any{"ConsumerARN": r.PhysicalID})
	if cfnComputeMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfnComputeValue(c.ConsumerStatus) == "DELETING" {
		return nil
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "kinesis", "DeregisterStreamConsumer", map[string]any{"ConsumerARN": r.PhysicalID}))
}

func (h cfnKinesisConsumer) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnKinesisOwnerContext(ctx, r, "consumer", false)
	if r.PhysicalID == "" {
		return true, nil
	}
	_, err := h.describe(ctx, map[string]any{"ConsumerARN": r.PhysicalID})
	if cfnComputeMissing(err) {
		return true, nil
	}
	return false, err
}

func (h cfnKinesisConsumer) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	c, err := h.describe(ctx, map[string]any{"ConsumerARN": r.PhysicalID})
	if err != nil {
		return nil, err
	}
	tags, err := cfnKinesisTags(ctx, h.commands, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	p := cloudformation.Properties{}
	for key, value := range cfnKinesisConsumerResult(c).Attributes {
		p[key] = value
	}
	p["Tags"] = cfnDataUserTags(tags)
	return p, nil
}

// List enumerates consumers of the requested stream, or of every stream when
// the Cloud Control request does not scope the listing.
func (h cfnKinesisConsumer) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var streams []string
	if arn := cfnComputeString(r.Properties, "StreamARN"); arn != "" {
		streams = []string{arn}
	} else {
		all, err := (cfnKinesisStream(h)).List(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, stream := range all {
			if arn := cfnComputeString(stream.Properties, "Arn"); arn != "" {
				streams = append(streams, arn)
			}
		}
	}
	result := []cloudformation.ResourceDescription{}
	for _, stream := range streams {
		in := map[string]any{"StreamARN": stream}
		for {
			out, err := cfnComputeCall[kinesisapi.ListStreamConsumersOutput](ctx, h.commands, "kinesis", "ListStreamConsumers", in)
			if err != nil {
				return nil, err
			}
			for _, c := range out.Consumers {
				arn := cfnComputeValue(c.ConsumerARN)
				result = append(result, cloudformation.ResourceDescription{Identifier: arn, Properties: cloudformation.Properties{"ConsumerARN": arn, "ConsumerName": cfnComputeValue(c.ConsumerName), "StreamARN": stream}})
			}
			if cfnComputeValue(out.NextToken) == "" {
				break
			}
			in = map[string]any{"StreamARN": stream, "NextToken": cfnComputeValue(out.NextToken)}
		}
	}
	return result, nil
}

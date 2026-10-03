package integrations

import (
	"context"
	"errors"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awscommands"
)

// SSMImages invokes the normal EC2 DescribeImages authority and visibility rules.
type SSMImages struct{ EC2 awscommands.CommandExecutor }

func (a SSMImages) ValidateParameterImage(ctx context.Context, id string) error {
	model, _ := awscatalog.LookupService("ec2")
	operation, _ := model.Operation("DescribeImages")
	result, rejected := a.EC2.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: &api.DescribeImagesRequest{ImageIds: api.ImageIdStringList{api.ImageId(id)}}})
	if rejected != nil {
		return rejected
	}
	images, ok := result.(*api.DescribeImagesResult)
	if !ok {
		return errors.New("invalid image authority result")
	}
	for _, image := range images.Images {
		if image.ImageId != nil && string(*image.ImageId) == id && image.State != nil && string(*image.State) == "available" {
			return nil
		}
	}
	return errors.New("image is not available")
}

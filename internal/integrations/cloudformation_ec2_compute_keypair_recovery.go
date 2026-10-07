package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/ssm"
	"stackd/internal/services/cloudformation"
)

// Private material is addressed only by the exact currently authorized native
// key identity. Public SSM metadata never grants deletion authority, and a
// missing native key cannot authorize cleanup of any parameter.
func (h cfnEC2KeyPair) privateReceipt(ctx context.Context, id string) (bool, error) {
	owner, err := cfnEC2NativeOwner(h.commands)
	if err != nil {
		return false, err
	}
	receipts, ok := owner.(interface {
		CloudFormationKeyPairPrivateKey(context.Context, string) (bool, error)
	})
	if !ok {
		return false, fmt.Errorf("EC2 owner does not support private key material receipts")
	}
	return receipts.CloudFormationKeyPairPrivateKey(ctx, id)
}

func (h cfnEC2KeyPair) deletePrivateParameter(ctx context.Context, r cloudformation.ResourceRequest, id string) error {
	generated, err := h.privateReceipt(ctx, id)
	if err != nil {
		return err
	}
	if !generated {
		return nil
	}
	if err := cfnEC2NativeOwned(ctx, h.commands, r, id); err != nil {
		return err
	}
	err = cfnComputeRun(ctx, h.commands, "ssm", "DeleteParameter", map[string]any{"Name": "/ec2/keypair/" + id})
	if err != nil && !cfnMessagingMissing(err, "ParameterNotFound") {
		return err
	}
	return nil
}

func (h cfnEC2KeyPair) privateAvailable(ctx context.Context, id string) error {
	generated, err := h.privateReceipt(ctx, id)
	if err != nil {
		return err
	}
	if !generated {
		return nil
	}
	name := "/ec2/keypair/" + id
	out, err := cfnComputeCall[api.DescribeParametersResult](ctx, h.commands, "ssm", "DescribeParameters", map[string]any{"ParameterFilters": []any{map[string]any{"Key": "Name", "Option": "Equals", "Values": []string{name}}}})
	if err != nil {
		return err
	}
	if len(out.Parameters) != 1 || cfnComputeValue(out.Parameters[0].Name) != name || cfnComputeValue(out.Parameters[0].Type) != "SecureString" {
		return fmt.Errorf("generated key pair has no durable encrypted private parameter")
	}
	return nil
}

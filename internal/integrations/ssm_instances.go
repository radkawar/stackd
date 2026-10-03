package integrations

import (
	"context"
	"errors"

	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/internal/services/ssmcommands"
)

// SSMInstances reads EC2's current identity, tags, profile and primary ENI.
// SSM retains agent observations, not a second instance/network catalog.
type SSMInstances struct{ EC2 ec2.Repository }

func (a SSMInstances) Instance(ctx context.Context, id string) (ssmcommands.Instance, error) {
	m := awsctx.FromContext(ctx)
	k := ec2.ResourceKey{Scope: ec2.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, ID: id}
	var out ssmcommands.Instance
	err := a.EC2.View(ctx, func(r ec2.Reader) error {
		row, err := r.Instance(k)
		if err != nil {
			return err
		}
		out.ID = id
		out.Tags = map[string]string{}
		if row.Data.State != nil && row.Data.State.Name != nil {
			out.State = string(*row.Data.State.Name)
		}
		for _, tag := range row.Data.Tags {
			if tag.Key != nil && tag.Value != nil {
				out.Tags[string(*tag.Key)] = string(*tag.Value)
			}
		}
		for _, attachment := range row.Data.NetworkInterfaces {
			if attachment.NetworkInterfaceId == nil {
				continue
			}
			eni, err := r.NetworkInterface(ec2.ResourceKey{Scope: k.Scope, ID: string(*attachment.NetworkInterfaceId)})
			if err != nil {
				return err
			}
			if eni.Data.Attachment == nil || eni.Data.Attachment.InstanceId == nil || string(*eni.Data.Attachment.InstanceId) != id || eni.Data.Attachment.DeviceIndex == nil || *eni.Data.Attachment.DeviceIndex != 0 {
				continue
			}
			if eni.Data.PrivateIpAddress != nil {
				out.PrivateIP = string(*eni.Data.PrivateIpAddress)
			}
		}
		return nil
	})
	if errors.Is(err, ec2.ErrNotFound) {
		return out, ssmcommands.ErrNotFound
	}
	return out, err
}

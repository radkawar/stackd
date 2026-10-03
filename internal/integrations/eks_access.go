package integrations

import (
	"context"
	"errors"
	"regexp"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
)

// EKSNodeNames reads EC2's retained real instance identity for the private
// authenticator's EC2PrivateDNSName template. It never derives a DNS name from a
// session string and does not expose EC2 read authority to the public caller.
type EKSNodeNames struct{ EC2 ec2.Repository }

var eksNodeInstanceID = regexp.MustCompile(`^i-([0-9a-f]{8}|[0-9a-f]{17})$`)

func (a EKSNodeNames) ResolveNodePrivateDNS(ctx context.Context, account, region, instanceID string) (string, error) {
	m := awsctx.FromContext(ctx)
	if a.EC2 == nil || !eksNodeInstanceID.MatchString(instanceID) || m.AccountID != account || awscatalog.RegionPartition(region) != m.Partition {
		return "", errors.New("invalid EKS EC2 node scope")
	}
	key := ec2.ResourceKey{Scope: ec2.Scope{Partition: m.Partition, AccountID: account, Region: region}, ID: instanceID}
	var dns string
	err := a.EC2.View(ctx, func(tx ec2.Reader) error {
		instance, err := tx.Instance(key)
		if err != nil {
			return err
		}
		if instance.Data.PrivateDnsName == nil || string(*instance.Data.PrivateDnsName) == "" || instance.Data.State == nil || instance.Data.State.Name == nil || string(*instance.Data.State.Name) == "terminated" {
			return errors.New("EC2 node private DNS unavailable")
		}
		dns = string(*instance.Data.PrivateDnsName)
		return nil
	})
	return dns, err
}

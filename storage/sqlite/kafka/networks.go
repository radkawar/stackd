package kafka

import (
	"database/sql"
	"errors"
	domain "stackd/storage/kafka"
	"stackd/storage/sqlite/kafka/internal/sqlcgen"
)

func (r reader) clusterNetworkOptions(arn string) (bool, error) {
	value, err := r.q.GetClusterNetworkOptions(r.ctx, arn)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return value != 0, err
}

func (w writer) putClusterNetworks(v domain.ClusterRecord) error {
	var enabled int64
	if v.DefaultMetrics {
		enabled = 1
	}
	if err := w.q.PutClusterNetworkOptions(w.ctx, sqlcgen.PutClusterNetworkOptionsParams{Arn: v.ARN, DefaultMetrics: enabled}); err != nil {
		return err
	}
	if err := w.q.DeleteClusterSubnets(w.ctx, v.ARN); err != nil {
		return err
	}
	for index, subnet := range v.ClientSubnets {
		if err := w.q.PutClusterSubnet(w.ctx, sqlcgen.PutClusterSubnetParams{Arn: v.ARN, Ordinal: int64(index), SubnetID: subnet}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteClusterSecurityGroups(w.ctx, v.ARN); err != nil {
		return err
	}
	for _, group := range v.SecurityGroups {
		if err := w.q.PutClusterSecurityGroup(w.ctx, sqlcgen.PutClusterSecurityGroupParams{Arn: v.ARN, SecurityGroupID: group}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteBrokerNetworks(w.ctx, v.ARN); err != nil {
		return err
	}
	for _, attachment := range v.BrokerNetworks {
		if err := w.q.PutBrokerNetwork(w.ctx, sqlcgen.PutBrokerNetworkParams{Arn: v.ARN, BrokerID: int64(attachment.BrokerID), InterfaceID: attachment.InterfaceID, SubnetID: attachment.SubnetID, AvailabilityZone: attachment.AvailabilityZone, NetworkID: attachment.NetworkID}); err != nil {
			return err
		}
	}
	return nil
}

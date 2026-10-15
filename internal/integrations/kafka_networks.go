package integrations

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/internal/services/kafka"
)

// KafkaNetworks uses the current Kafka service-linked role for native broker
// reservations. EC2 owns placement, addresses, identity fences and packet policy.
type KafkaNetworks struct {
	EC2      *ec2.Service
	Roles    ServiceRoles
	sessions serviceRoleSessions
}

var _ kafka.NetworkControl = (*KafkaNetworks)(nil)

func (a *KafkaNetworks) serviceContext(ctx context.Context, clusterARN string) (context.Context, error) {
	if a.EC2 == nil {
		return nil, errors.New("native Kafka EC2 network owner is unavailable")
	}
	metadata := awsctx.FromContext(ctx)
	cluster, err := arn.Parse(clusterARN)
	if err != nil || cluster.Service != "kafka" || cluster.Partition != metadata.Partition || cluster.AccountID != metadata.AccountID || cluster.Region != metadata.Region {
		return nil, errors.New("native Kafka network owner and request scopes differ")
	}
	if parent := apievents.EventID(ctx); parent != "" {
		metadata.ParentEventID = parent
		ctx = awsctx.WithMetadata(ctx, metadata)
	}
	role := "arn:" + metadata.Partition + ":iam::" + metadata.AccountID + ":role/aws-service-role/kafka.amazonaws.com/AWSServiceRoleForKafka"
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: "kafka.amazonaws.com", SourceARN: clusterARN, Type: "AWSService"}, role, "kafka-eni-provisioning", "")
}

func (a *KafkaNetworks) AllocateBrokerNetwork(ctx context.Context, request kafka.BrokerNetworkRequest) (kafka.BrokerNetwork, error) {
	service, err := a.serviceContext(ctx, request.Identity.ClusterARN)
	if err != nil {
		return kafka.BrokerNetwork{}, err
	}
	result, err := a.EC2.AllocateBrokerNetwork(service, ec2.BrokerNetworkRequest{
		Identity: ec2BrokerIdentity(request.Identity), SubnetIDs: request.SubnetIDs, SecurityGroups: request.SecurityGroups,
	})
	if err != nil {
		return kafka.BrokerNetwork{}, err
	}
	return kafkaBrokerNetwork(result), nil
}

func (a *KafkaNetworks) ObserveBrokerNetwork(ctx context.Context, identity kafka.BrokerNetworkIdentity, interfaceID string) (kafka.BrokerNetwork, error) {
	service, err := a.serviceContext(ctx, identity.ClusterARN)
	if err != nil {
		return kafka.BrokerNetwork{}, err
	}
	result, err := a.EC2.ObserveBrokerNetwork(service, ec2BrokerIdentity(identity), interfaceID)
	if err != nil {
		return kafka.BrokerNetwork{}, err
	}
	return kafkaBrokerNetwork(result), nil
}

func (a *KafkaNetworks) ReleaseBrokerNetwork(ctx context.Context, identity kafka.BrokerNetworkIdentity, interfaceID string) error {
	service, err := a.serviceContext(ctx, identity.ClusterARN)
	if err != nil {
		return err
	}
	return a.EC2.ReleaseBrokerNetwork(service, ec2BrokerIdentity(identity), interfaceID)
}

func ec2BrokerIdentity(identity kafka.BrokerNetworkIdentity) ec2.BrokerNetworkIdentity {
	return ec2.BrokerNetworkIdentity{ClusterARN: identity.ClusterARN, Incarnation: identity.Incarnation, BrokerID: identity.BrokerID}
}

func kafkaBrokerNetwork(result ec2.BrokerNetwork) kafka.BrokerNetwork {
	return kafka.BrokerNetwork{
		InterfaceID:      ecsNetworkString(result.Interface.NetworkInterfaceId),
		SubnetID:         ecsNetworkString(result.Interface.SubnetId),
		AvailabilityZone: ecsNetworkString(result.Interface.AvailabilityZone),
		Network:          result.Network,
	}
}

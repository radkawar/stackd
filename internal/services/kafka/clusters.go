package kafka

import (
	"context"
	"github.com/google/uuid"
	"slices"
	api "stackd/internal/awsapi/kafka"
	"strconv"
	"strings"
)

func registerClusters(s *Service) {
	register(s, "CreateCluster", s.createCluster)
	register(s, "CreateClusterV2", s.createClusterV2)
	register(s, "DescribeCluster", s.describeCluster)
	register(s, "DescribeClusterV2", s.describeClusterV2)
	register(s, "ListClusters", s.listClusters)
	register(s, "ListClustersV2", s.listClustersV2)
	register(s, "DeleteCluster", s.deleteCluster)
	register(s, "GetBootstrapBrokers", s.bootstrap)
	register(s, "UpdateClusterConfiguration", s.updateClusterConfiguration)
	register(s, "RebootBroker", s.reboot)
	register(s, "ListNodes", s.listNodes)
	register(s, "DescribeClusterOperation", s.describeOperation)
	register(s, "ListClusterOperations", s.listOperations)
}
func (s *Service) createCluster(ctx context.Context, t Transaction, in *api.CreateClusterInput) (*api.CreateClusterOutput, error) {
	p := &api.ProvisionedRequest{BrokerNodeGroupInfo: in.BrokerNodeGroupInfo, ClientAuthentication: in.ClientAuthentication, ConfigurationInfo: in.ConfigurationInfo, EncryptionInfo: in.EncryptionInfo, EnhancedMonitoring: in.EnhancedMonitoring, KafkaVersion: in.KafkaVersion, LoggingInfo: in.LoggingInfo, NumberOfBrokerNodes: in.NumberOfBrokerNodes, OpenMonitoring: in.OpenMonitoring, Rebalancing: in.Rebalancing, StorageMode: in.StorageMode}
	v, e := s.create(ctx, t, value(in.ClusterName), p, plainTags(in.Tags), "CreateCluster")
	if e != nil {
		return nil, e
	}
	out := &api.CreateClusterOutput{State: new(api.ClusterState(v.State))}
	text(&out.ClusterArn, v.ARN)
	text(&out.ClusterName, v.Name)
	return out, nil
}
func (s *Service) createClusterV2(ctx context.Context, t Transaction, in *api.CreateClusterV2Input) (*api.CreateClusterV2Output, error) {
	if in.Serverless != nil || in.Provisioned == nil {
		return nil, unsupported("Only provisioned native Kafka clusters are supported")
	}
	v, e := s.create(ctx, t, value(in.ClusterName), in.Provisioned, plainTags(in.Tags), "CreateClusterV2")
	if e != nil {
		return nil, e
	}
	out := &api.CreateClusterV2Output{State: new(api.ClusterState(v.State)), ClusterType: new(api.ClusterType("PROVISIONED"))}
	text(&out.ClusterArn, v.ARN)
	text(&out.ClusterName, v.Name)
	return out, nil
}
func (s *Service) create(ctx context.Context, t Transaction, name string, p *api.ProvisionedRequest, tags map[string]string, action string) (ClusterRecord, error) {
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "/: \t\n") {
		return ClusterRecord{}, invalid("Invalid cluster name")
	}
	sc := scopeFor(ctx)
	id := uuid.NewString()
	v := ClusterRecord{Scope: sc, ARN: "arn:" + sc.Partition + ":kafka:" + sc.Region + ":" + sc.AccountID + ":cluster/" + name + "/" + id, Name: name, Incarnation: id, KafkaVersion: value(p.KafkaVersion), Tags: tags, State: "CREATING", Version: 1, Created: s.clock.Now(), Due: s.clock.Now(), Operation: "create"}
	if p.NumberOfBrokerNodes != nil {
		v.Brokers = int32(*p.NumberOfBrokerNodes)
	}
	if owner, ok := cloudFormationOwnerFor(ctx, cloudFormationCluster); ok {
		v.OwnerStackID, v.OwnerLogicalID, v.OwnerToken = owner.StackID, owner.LogicalID, owner.Token
	}
	if e := s.authorize(ctx, v, action, requestTags(tags)); e != nil {
		return v, e
	}
	if e := validateTags(tags); e != nil {
		return v, e
	}
	all, e := t.Clusters(sc)
	if e != nil {
		return v, e
	}
	for _, x := range all {
		if x.Name == name {
			return v, conflict("A cluster with this name already exists")
		}
	}
	if s.runtime == nil {
		return v, unsupported("No native Kafka runtime is configured")
	}
	if e = admitProvisioned(p, &v); e != nil {
		return v, e
	}
	if p.ConfigurationInfo != nil {
		if e = s.applyConfiguration(ctx, t, &v, p.ConfigurationInfo, false); e != nil {
			return v, e
		}
	}
	if e = ValidateSpecification(baseSpecification(v)); e != nil {
		return v, invalid(e.Error())
	}
	if v.DefaultMetrics {
		if _, ok := s.runtime.(MetricsRuntime); !ok || s.metrics == nil {
			return v, unsupported("DEFAULT monitoring requires native broker measurements and the CloudWatch owner")
		}
	}
	if len(v.ClientSubnets) > 0 && s.networks == nil {
		return v, unsupported("Broker subnet allocation requires the EC2 network owner")
	}
	if len(v.ClientSubnets) > 0 {
		if _, ok := s.runtime.(QuarantineRuntime); !ok {
			return v, unsupported("Managed broker networks require an exact-owned quarantine runtime")
		}
	}
	if len(v.ClientSubnets) > 0 || v.DefaultMetrics {
		if s.serviceLinkedRoles == nil {
			return v, unsupported("Managed broker networks and monitoring require the IAM service-linked-role owner")
		}
		if e = s.serviceLinkedRoles.EnsureServiceLinkedRole(ctx, "kafka.amazonaws.com"); e != nil {
			return v, e
		}
	}
	if len(v.ClientSubnets) > 0 {
		for broker := 1; broker <= int(v.Brokers); broker++ {
			attachment, err := s.networks.AllocateBrokerNetwork(runtimeContext(ctx, v), BrokerNetworkRequest{Identity: BrokerNetworkIdentity{ClusterARN: v.ARN, Incarnation: v.Incarnation, BrokerID: broker}, SubnetIDs: v.ClientSubnets, SecurityGroups: v.SecurityGroups})
			if err != nil {
				return v, err
			}
			if attachment.InterfaceID == "" || attachment.SubnetID == "" || attachment.AvailabilityZone == "" || attachment.Network.NetworkID == "" {
				return v, invalid("EC2 returned an incomplete broker attachment")
			}
			v.BrokerNetworks = append(v.BrokerNetworks, BrokerNetworkRecord{BrokerID: broker, InterfaceID: attachment.InterfaceID, SubnetID: attachment.SubnetID, AvailabilityZone: attachment.AvailabilityZone, NetworkID: attachment.Network.NetworkID})
		}
	}
	return v, t.PutCluster(v)
}

// EC2 owns requested subnet placement and packet policy. Empty network fields
// retain the explicit local-only workflow, not an invented managed placement.
func admitProvisioned(p *api.ProvisionedRequest, v *ClusterRecord) error {
	if p.BrokerNodeGroupInfo == nil {
		return invalid("BrokerNodeGroupInfo is required")
	}
	b := p.BrokerNodeGroupInfo
	if len(b.ZoneIds) > 0 || b.ConnectivityInfo != nil {
		return unsupported("Explicit zone IDs and multi-VPC/public connectivity are not implemented")
	}
	if len(b.ClientSubnets) == 0 {
		if len(b.SecurityGroups) > 0 || b.BrokerAZDistribution != nil {
			return unsupported("Broker AZ distribution and security groups require EC2-owned subnets")
		}
	} else {
		if len(b.ClientSubnets) != 2 && len(b.ClientSubnets) != 3 {
			return invalid("DEFAULT broker placement requires two or three subnets in distinct Availability Zones")
		}
		if value(b.BrokerAZDistribution) != "" && value(b.BrokerAZDistribution) != "DEFAULT" {
			return unsupported("Only DEFAULT broker AZ distribution is supported")
		}
		if v.Brokers < 1 || int(v.Brokers)%len(b.ClientSubnets) != 0 {
			return invalid("The broker count must be a positive multiple of the subnet count")
		}
		for _, subnet := range b.ClientSubnets {
			v.ClientSubnets = append(v.ClientSubnets, string(subnet))
		}
		for _, group := range b.SecurityGroups {
			v.SecurityGroups = append(v.SecurityGroups, string(group))
		}
		slices.Sort(v.ClientSubnets)
		slices.Sort(v.SecurityGroups)
	}
	if value(b.InstanceType) != "kafka.local" {
		return unsupported("Only kafka.local native broker allocation is supported")
	}
	if b.StorageInfo != nil {
		return unsupported("Managed EBS storage settings are not implemented")
	}
	if p.LoggingInfo != nil || p.OpenMonitoring != nil || p.Rebalancing != nil || p.StorageMode != nil {
		return unsupported("Managed logging, open monitoring, rebalancing and storage modes are not implemented")
	}
	// AWS enables DEFAULT monitoring when the managed placement omits this
	// field. The explicit subnet-free local API remains a separate boundary.
	v.DefaultMetrics = len(v.ClientSubnets) > 0
	if p.EnhancedMonitoring != nil {
		if value(p.EnhancedMonitoring) != "DEFAULT" {
			return unsupported("Only DEFAULT native broker monitoring is implemented")
		}
		v.DefaultMetrics = true
	}
	v.SecurityMode = "TLS"
	if p.EncryptionInfo != nil {
		if p.EncryptionInfo.EncryptionAtRest != nil {
			return unsupported("Managed KMS data-volume encryption is not implemented")
		}
		if x := p.EncryptionInfo.EncryptionInTransit; x != nil {
			if x.InCluster != nil && !bool(*x.InCluster) {
				return unsupported("Native broker/controller traffic always uses TLS")
			}
			switch value(x.ClientBroker) {
			case "", "TLS":
			case "PLAINTEXT":
				v.SecurityMode = "PLAINTEXT"
			default:
				return unsupported("Select one native client transport: TLS or PLAINTEXT")
			}
		}
	}
	if a := p.ClientAuthentication; a != nil {
		if a.Tls != nil {
			return unsupported("Mutual TLS certificate authentication is not implemented")
		}
		scram := false
		if a.Sasl != nil {
			if a.Sasl.Iam != nil && a.Sasl.Iam.Enabled != nil && bool(*a.Sasl.Iam.Enabled) {
				return unsupported("IAM Kafka data authentication is not implemented")
			}
			scram = a.Sasl.Scram != nil && a.Sasl.Scram.Enabled != nil && bool(*a.Sasl.Scram.Enabled)
		}
		unauth := a.Unauthenticated == nil || a.Unauthenticated.Enabled == nil || bool(*a.Unauthenticated.Enabled)
		if scram {
			if v.SecurityMode != "TLS" {
				return invalid("SCRAM requires TLS")
			}
			if a.Unauthenticated != nil && a.Unauthenticated.Enabled != nil && bool(*a.Unauthenticated.Enabled) {
				return unsupported("Mixed authenticated and unauthenticated listeners are not implemented")
			}
			v.SecurityMode = "SASL_SCRAM"
		} else if !unauth {
			return invalid("No supported client authentication mode is enabled")
		}
	}
	return nil
}
func (s *Service) deleteCluster(ctx context.Context, t Transaction, in *api.DeleteClusterInput) (*api.DeleteClusterOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "DeleteCluster")
	if e != nil {
		return nil, e
	}
	if e = checkPrepared(ctx, v); e != nil {
		return nil, e
	}
	if x := value(in.CurrentVersion); x != "" && x != strconv.FormatInt(v.Version, 10) {
		return nil, invalid("The current cluster version does not match")
	}
	for _, ref := range v.Secrets {
		if e = s.secrets.ReleaseSCRAM(ctx, v.ARN, v.Incarnation, ref); e != nil {
			return nil, e
		}
	}
	v.Secrets = nil
	v.Version++
	v.State = "DELETING"
	v.Operation = "delete"
	v.Due = s.clock.Now()
	v.Endpoint = Endpoint{}
	v.Failure = ""
	if e = t.PutCluster(v); e != nil {
		return nil, e
	}
	out := &api.DeleteClusterOutput{State: new(api.ClusterState(v.State))}
	text(&out.ClusterArn, v.ARN)
	return out, nil
}
func (s *Service) applyConfiguration(ctx context.Context, t Transaction, v *ClusterRecord, in *api.ConfigurationInfo, pending bool) error {
	if in == nil || in.Revision == nil {
		return invalid("Configuration ARN and revision are required")
	}
	c, e := s.configuration(ctx, t, value(in.Arn), "DescribeConfiguration")
	if e != nil {
		return e
	}
	if len(c.KafkaVersions) > 0 {
		found := false
		for _, x := range c.KafkaVersions {
			if x == v.KafkaVersion {
				found = true
			}
		}
		if !found {
			return invalid("Configuration does not support the cluster Kafka version")
		}
	}
	r, e := t.Revision(c.ARN, int64(*in.Revision))
	if e != nil {
		return invalid("Configuration revision does not exist")
	}
	spec := baseSpecification(*v)
	spec.ServerProperties = r.ServerProperties
	if e = ValidateSpecification(spec); e != nil {
		return invalid(e.Error())
	}
	if pending {
		v.PendingConfigurationARN = c.ARN
		v.PendingConfigurationRevision = r.Revision
		v.PendingServerProperties = r.ServerProperties
	} else {
		v.ConfigurationARN = c.ARN
		v.ConfigurationRevision = r.Revision
		v.ServerProperties = r.ServerProperties
	}
	return nil
}
func (s *Service) beginOperation(t Transaction, v *ClusterRecord, kind string) error {
	v.Version++
	v.State = "UPDATING"
	if kind == "REBOOT_BROKER" {
		v.State = "HEALING"
	} else {
		v.RebootBrokerID = 0
	}
	v.Operation = kind
	v.Due = s.clock.Now()
	v.Endpoint = Endpoint{}
	v.Failure = ""
	v.OperationARN = "arn:" + v.Partition + ":kafka:" + v.Region + ":" + v.AccountID + ":cluster-operation/" + v.Name + "/" + v.Incarnation + "/" + uuid.NewString()
	op := OperationRecord{Scope: v.Scope, ARN: v.OperationARN, ClusterARN: v.ARN, Type: kind, State: "PENDING", Created: s.clock.Now(), SourceConfigurationARN: v.ConfigurationARN, SourceRevision: v.ConfigurationRevision, TargetConfigurationARN: v.PendingConfigurationARN, TargetRevision: v.PendingConfigurationRevision}
	if e := t.PutOperation(op); e != nil {
		return e
	}
	return t.PutCluster(*v)
}
func (s *Service) updateClusterConfiguration(ctx context.Context, t Transaction, in *api.UpdateClusterConfigurationInput) (*api.UpdateClusterConfigurationOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "UpdateClusterConfiguration")
	if e != nil {
		return nil, e
	}
	if e = writable(v); e != nil {
		return nil, e
	}
	if value(in.CurrentVersion) != strconv.FormatInt(v.Version, 10) {
		return nil, invalid("The current cluster version does not match")
	}
	if e = s.applyConfiguration(ctx, t, &v, in.ConfigurationInfo, true); e != nil {
		return nil, e
	}
	if e = s.beginOperation(t, &v, "UPDATE_CLUSTER_CONFIGURATION"); e != nil {
		return nil, e
	}
	out := &api.UpdateClusterConfigurationOutput{}
	text(&out.ClusterArn, v.ARN)
	text(&out.ClusterOperationArn, v.OperationARN)
	return out, nil
}
func (s *Service) reboot(ctx context.Context, t Transaction, in *api.RebootBrokerInput) (*api.RebootBrokerOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "RebootBroker")
	if e != nil {
		return nil, e
	}
	if v.State != "ACTIVE" {
		return nil, invalid("The cluster must be ACTIVE before rebooting a broker")
	}
	if len(in.BrokerIds) != 1 {
		return nil, parameterError(invalid("Specify exactly one broker ID"), "brokerIds")
	}
	id, e := strconv.Atoi(string(in.BrokerIds[0]))
	if e != nil || id < 1 || id > int(v.Brokers) {
		return nil, parameterError(invalid("Invalid broker ID"), "brokerIds")
	}
	v.RebootBrokerID = int32(id)
	if e = s.beginOperation(t, &v, "REBOOT_BROKER"); e != nil {
		return nil, e
	}
	out := &api.RebootBrokerOutput{}
	text(&out.ClusterArn, v.ARN)
	text(&out.ClusterOperationArn, v.OperationARN)
	return out, nil
}

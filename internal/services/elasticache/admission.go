package elasticache

import api "stackd/internal/awsapi/elasticache"

// Explicit DTO admission prevents unsupported effects from becoming inert state.
func validateCreateCacheClusterMessage(in *api.CreateCacheClusterMessage) error {
	if in.AZMode != nil {
		return unsupported("AZMode is not supported by the native cache runtime.")
	}
	if len(in.CacheSecurityGroupNames) != 0 {
		return unsupported("CacheSecurityGroupNames is not supported by the native cache runtime.")
	}
	if in.CacheSubnetGroupName != nil {
		return unsupported("CacheSubnetGroupName is not supported by the native cache runtime.")
	}
	if in.IpDiscovery != nil {
		return unsupported("IpDiscovery is not supported by the native cache runtime.")
	}
	if len(in.LogDeliveryConfigurations) != 0 {
		return unsupported("LogDeliveryConfigurations is not supported by the native cache runtime.")
	}
	if in.NetworkType != nil {
		return unsupported("NetworkType is not supported by the native cache runtime.")
	}
	if in.NotificationTopicArn != nil {
		return unsupported("NotificationTopicArn is not supported by the native cache runtime.")
	}
	if in.OutpostMode != nil {
		return unsupported("OutpostMode is not supported by the native cache runtime.")
	}
	if in.Port != nil {
		return unsupported("Port is not supported by the native cache runtime.")
	}
	if in.PreferredAvailabilityZone != nil {
		return unsupported("PreferredAvailabilityZone is not supported by the native cache runtime.")
	}
	if len(in.PreferredAvailabilityZones) != 0 {
		return unsupported("PreferredAvailabilityZones is not supported by the native cache runtime.")
	}
	if in.PreferredMaintenanceWindow != nil {
		return unsupported("PreferredMaintenanceWindow is not supported by the native cache runtime.")
	}
	if in.PreferredOutpostArn != nil {
		return unsupported("PreferredOutpostArn is not supported by the native cache runtime.")
	}
	if len(in.PreferredOutpostArns) != 0 {
		return unsupported("PreferredOutpostArns is not supported by the native cache runtime.")
	}
	if in.ReplicationGroupId != nil {
		return unsupported("ReplicationGroupId is not supported by the native cache runtime.")
	}
	if len(in.SecurityGroupIds) != 0 {
		return unsupported("SecurityGroupIds is not supported by the native cache runtime.")
	}
	if len(in.SnapshotArns) != 0 {
		return unsupported("SnapshotArns is not supported by the native cache runtime.")
	}
	if in.SnapshotWindow != nil {
		return unsupported("SnapshotWindow is not supported by the native cache runtime.")
	}
	if boolean(in.AutoMinorVersionUpgrade) {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native cache runtime.")
	}
	if in.SnapshotRetentionLimit != nil && *in.SnapshotRetentionLimit != 0 {
		return unsupported("SnapshotRetentionLimit is not supported by the native cache runtime.")
	}
	return nil
}
func validateCreateReplicationGroupMessage(in *api.CreateReplicationGroupMessage) error {
	if len(in.CacheSecurityGroupNames) != 0 {
		return unsupported("CacheSecurityGroupNames is not supported by the native cache runtime.")
	}
	if in.CacheSubnetGroupName != nil {
		return unsupported("CacheSubnetGroupName is not supported by the native cache runtime.")
	}
	if in.DataTieringEnabled != nil {
		return unsupported("DataTieringEnabled is not supported by the native cache runtime.")
	}
	if in.Durability != nil {
		return unsupported("Durability is not supported by the native cache runtime.")
	}
	if in.GlobalReplicationGroupId != nil {
		return unsupported("GlobalReplicationGroupId is not supported by the native cache runtime.")
	}
	if in.IpDiscovery != nil {
		return unsupported("IpDiscovery is not supported by the native cache runtime.")
	}
	if in.KmsKeyId != nil {
		return unsupported("KmsKeyId is not supported by the native cache runtime.")
	}
	if len(in.LogDeliveryConfigurations) != 0 {
		return unsupported("LogDeliveryConfigurations is not supported by the native cache runtime.")
	}
	if in.NetworkType != nil {
		return unsupported("NetworkType is not supported by the native cache runtime.")
	}
	if len(in.NodeGroupConfiguration) != 0 {
		return unsupported("NodeGroupConfiguration is not supported by the native cache runtime.")
	}
	if in.NotificationTopicArn != nil {
		return unsupported("NotificationTopicArn is not supported by the native cache runtime.")
	}
	if in.Port != nil {
		return unsupported("Port is not supported by the native cache runtime.")
	}
	if len(in.PreferredCacheClusterAZs) != 0 {
		return unsupported("PreferredCacheClusterAZs is not supported by the native cache runtime.")
	}
	if in.PreferredMaintenanceWindow != nil {
		return unsupported("PreferredMaintenanceWindow is not supported by the native cache runtime.")
	}
	if in.PrimaryClusterId != nil {
		return unsupported("PrimaryClusterId is not supported by the native cache runtime.")
	}
	if len(in.SecurityGroupIds) != 0 {
		return unsupported("SecurityGroupIds is not supported by the native cache runtime.")
	}
	if in.ServerlessCacheSnapshotName != nil {
		return unsupported("ServerlessCacheSnapshotName is not supported by the native cache runtime.")
	}
	if len(in.SnapshotArns) != 0 {
		return unsupported("SnapshotArns is not supported by the native cache runtime.")
	}
	if in.SnapshotWindow != nil {
		return unsupported("SnapshotWindow is not supported by the native cache runtime.")
	}
	// TODO: Comeback implement managed at-rest/KMS encryption through a real
	// storage owner. Local durable engine files are sensitive plaintext bytes;
	// AWS physical-storage defaults are not claims about this host filesystem.
	if boolean(in.AtRestEncryptionEnabled) {
		return unsupported("AtRestEncryptionEnabled is not supported by the native cache runtime.")
	}
	if boolean(in.AutoMinorVersionUpgrade) {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native cache runtime.")
	}
	if boolean(in.MultiAZEnabled) {
		return unsupported("MultiAZEnabled is not supported by the native cache runtime.")
	}
	if in.SnapshotRetentionLimit != nil && *in.SnapshotRetentionLimit != 0 {
		return unsupported("SnapshotRetentionLimit is not supported by the native cache runtime.")
	}
	return nil
}
func validateModifyCacheClusterMessage(in *api.ModifyCacheClusterMessage) error {
	if in.AZMode != nil {
		return unsupported("AZMode is not supported by the native cache runtime.")
	}
	if in.AutoMinorVersionUpgrade != nil {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native cache runtime.")
	}
	if len(in.CacheNodeIdsToRemove) != 0 {
		return unsupported("CacheNodeIdsToRemove is not supported by the native cache runtime.")
	}
	if in.CacheNodeType != nil {
		return unsupported("CacheNodeType is not supported by the native cache runtime.")
	}
	if len(in.CacheSecurityGroupNames) != 0 {
		return unsupported("CacheSecurityGroupNames is not supported by the native cache runtime.")
	}
	if in.Engine != nil {
		return unsupported("Engine is not supported by the native cache runtime.")
	}
	if in.EngineVersion != nil {
		return unsupported("EngineVersion is not supported by the native cache runtime.")
	}
	if in.IpDiscovery != nil {
		return unsupported("IpDiscovery is not supported by the native cache runtime.")
	}
	if len(in.LogDeliveryConfigurations) != 0 {
		return unsupported("LogDeliveryConfigurations is not supported by the native cache runtime.")
	}
	if len(in.NewAvailabilityZones) != 0 {
		return unsupported("NewAvailabilityZones is not supported by the native cache runtime.")
	}
	if in.NotificationTopicArn != nil {
		return unsupported("NotificationTopicArn is not supported by the native cache runtime.")
	}
	if in.NotificationTopicStatus != nil {
		return unsupported("NotificationTopicStatus is not supported by the native cache runtime.")
	}
	if in.NumCacheNodes != nil {
		return unsupported("NumCacheNodes is not supported by the native cache runtime.")
	}
	if in.PreferredMaintenanceWindow != nil {
		return unsupported("PreferredMaintenanceWindow is not supported by the native cache runtime.")
	}
	if in.ScaleConfig != nil {
		return unsupported("ScaleConfig is not supported by the native cache runtime.")
	}
	if len(in.SecurityGroupIds) != 0 {
		return unsupported("SecurityGroupIds is not supported by the native cache runtime.")
	}
	if in.SnapshotRetentionLimit != nil && *in.SnapshotRetentionLimit != 0 {
		return unsupported("SnapshotRetentionLimit is not supported by the native cache runtime.")
	}
	if in.SnapshotWindow != nil {
		return unsupported("SnapshotWindow is not supported by the native cache runtime.")
	}
	return nil
}
func validateModifyReplicationGroupMessage(in *api.ModifyReplicationGroupMessage) error {
	if in.AutoMinorVersionUpgrade != nil {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native cache runtime.")
	}
	if in.AutomaticFailoverEnabled != nil {
		return unsupported("AutomaticFailoverEnabled is not supported by the native cache runtime.")
	}
	if in.CacheNodeType != nil {
		return unsupported("CacheNodeType is not supported by the native cache runtime.")
	}
	if len(in.CacheSecurityGroupNames) != 0 {
		return unsupported("CacheSecurityGroupNames is not supported by the native cache runtime.")
	}
	if in.ClusterMode != nil {
		return unsupported("ClusterMode is not supported by the native cache runtime.")
	}
	if in.Durability != nil {
		return unsupported("Durability is not supported by the native cache runtime.")
	}
	if in.Engine != nil {
		return unsupported("Engine is not supported by the native cache runtime.")
	}
	if in.EngineVersion != nil {
		return unsupported("EngineVersion is not supported by the native cache runtime.")
	}
	if in.IpDiscovery != nil {
		return unsupported("IpDiscovery is not supported by the native cache runtime.")
	}
	if len(in.LogDeliveryConfigurations) != 0 {
		return unsupported("LogDeliveryConfigurations is not supported by the native cache runtime.")
	}
	if in.MultiAZEnabled != nil {
		return unsupported("MultiAZEnabled is not supported by the native cache runtime.")
	}
	if in.NodeGroupId != nil {
		return unsupported("NodeGroupId is not supported by the native cache runtime.")
	}
	if in.NotificationTopicArn != nil {
		return unsupported("NotificationTopicArn is not supported by the native cache runtime.")
	}
	if in.NotificationTopicStatus != nil {
		return unsupported("NotificationTopicStatus is not supported by the native cache runtime.")
	}
	if in.PreferredMaintenanceWindow != nil {
		return unsupported("PreferredMaintenanceWindow is not supported by the native cache runtime.")
	}
	if in.PrimaryClusterId != nil {
		return unsupported("PrimaryClusterId is not supported by the native cache runtime.")
	}
	if len(in.SecurityGroupIds) != 0 {
		return unsupported("SecurityGroupIds is not supported by the native cache runtime.")
	}
	if in.SnapshotRetentionLimit != nil && *in.SnapshotRetentionLimit != 0 {
		return unsupported("SnapshotRetentionLimit is not supported by the native cache runtime.")
	}
	if in.SnapshotWindow != nil {
		return unsupported("SnapshotWindow is not supported by the native cache runtime.")
	}
	if in.SnapshottingClusterId != nil {
		return unsupported("SnapshottingClusterId is not supported by the native cache runtime.")
	}
	if in.TransitEncryptionEnabled != nil {
		return unsupported("TransitEncryptionEnabled is not supported by the native cache runtime.")
	}
	if in.TransitEncryptionMode != nil {
		return unsupported("TransitEncryptionMode is not supported by the native cache runtime.")
	}
	return nil
}

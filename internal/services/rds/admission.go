package rds

import api "stackd/internal/awsapi/rds"

// Explicit generated-DTO admission prevents silently discarding unsupported
// fields. Disabled feature switches are accepted only when actually disabled.
func validateCreateDBInstanceMessage(in *api.CreateDBInstanceMessage) error {
	if len(in.AdditionalStorageVolumes) != 0 {
		return unsupported("AdditionalStorageVolumes is not supported by the native RDS runtime.")
	}
	if in.AllocatedStorage != nil {
		return unsupported("AllocatedStorage is not supported by the native RDS runtime.")
	}
	if boolean(in.AutoMinorVersionUpgrade) {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native RDS runtime.")
	}
	if in.AvailabilityZone != nil {
		return unsupported("AvailabilityZone is not supported by the native RDS runtime.")
	}
	if in.BackupRetentionPeriod != nil && *in.BackupRetentionPeriod != 0 {
		return unsupported("BackupRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.BackupTarget != nil {
		return unsupported("BackupTarget is not supported by the native RDS runtime.")
	}
	if in.CACertificateIdentifier != nil {
		return unsupported("CACertificateIdentifier is not supported by the native RDS runtime.")
	}
	if in.CharacterSetName != nil {
		return unsupported("CharacterSetName is not supported by the native RDS runtime.")
	}
	if in.CustomIamInstanceProfile != nil {
		return unsupported("CustomIamInstanceProfile is not supported by the native RDS runtime.")
	}
	if len(in.DBSecurityGroups) != 0 {
		return unsupported("DBSecurityGroups is not supported by the native RDS runtime.")
	}
	if in.DBSubnetGroupName != nil {
		return unsupported("DBSubnetGroupName is not supported by the native RDS runtime.")
	}
	if in.DBSystemId != nil {
		return unsupported("DBSystemId is not supported by the native RDS runtime.")
	}
	if in.DatabaseInsightsMode != nil {
		return unsupported("DatabaseInsightsMode is not supported by the native RDS runtime.")
	}
	if boolean(in.DedicatedLogVolume) {
		return unsupported("DedicatedLogVolume is not supported by the native RDS runtime.")
	}
	if in.Domain != nil {
		return unsupported("Domain is not supported by the native RDS runtime.")
	}
	if in.DomainAuthSecretArn != nil {
		return unsupported("DomainAuthSecretArn is not supported by the native RDS runtime.")
	}
	if len(in.DomainDnsIps) != 0 {
		return unsupported("DomainDnsIps is not supported by the native RDS runtime.")
	}
	if in.DomainFqdn != nil {
		return unsupported("DomainFqdn is not supported by the native RDS runtime.")
	}
	if in.DomainIAMRoleName != nil {
		return unsupported("DomainIAMRoleName is not supported by the native RDS runtime.")
	}
	if in.DomainOu != nil {
		return unsupported("DomainOu is not supported by the native RDS runtime.")
	}
	if len(in.EnableCloudwatchLogsExports) != 0 {
		return unsupported("EnableCloudwatchLogsExports is not supported by the native RDS runtime.")
	}
	if in.EnableCustomerOwnedIp != nil {
		return unsupported("EnableCustomerOwnedIp is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableIAMDatabaseAuthentication) {
		return unsupported("EnableIAMDatabaseAuthentication is not supported by the native RDS runtime.")
	}
	if boolean(in.EnablePerformanceInsights) {
		return unsupported("EnablePerformanceInsights is not supported by the native RDS runtime.")
	}
	if in.EngineLifecycleSupport != nil {
		return unsupported("EngineLifecycleSupport is not supported by the native RDS runtime.")
	}
	if in.Iops != nil {
		return unsupported("Iops is not supported by the native RDS runtime.")
	}
	if in.KmsKeyId != nil {
		return unsupported("KmsKeyId is not supported by the native RDS runtime.")
	}
	if in.LicenseModel != nil {
		return unsupported("LicenseModel is not supported by the native RDS runtime.")
	}
	if boolean(in.ManageMasterUserPassword) {
		return unsupported("ManageMasterUserPassword is not supported by the native RDS runtime.")
	}
	if in.MasterUserAuthenticationType != nil {
		return unsupported("MasterUserAuthenticationType is not supported by the native RDS runtime.")
	}
	if in.MasterUserSecretKmsKeyId != nil {
		return unsupported("MasterUserSecretKmsKeyId is not supported by the native RDS runtime.")
	}
	if in.MaxAllocatedStorage != nil {
		return unsupported("MaxAllocatedStorage is not supported by the native RDS runtime.")
	}
	if in.MonitoringInterval != nil && *in.MonitoringInterval != 0 {
		return unsupported("MonitoringInterval is not supported by the native RDS runtime.")
	}
	if in.MonitoringRoleArn != nil {
		return unsupported("MonitoringRoleArn is not supported by the native RDS runtime.")
	}
	if boolean(in.MultiAZ) {
		return unsupported("MultiAZ is not supported by the native RDS runtime.")
	}
	if boolean(in.MultiTenant) {
		return unsupported("MultiTenant is not supported by the native RDS runtime.")
	}
	if in.NcharCharacterSetName != nil {
		return unsupported("NcharCharacterSetName is not supported by the native RDS runtime.")
	}
	if in.NetworkType != nil {
		return unsupported("NetworkType is not supported by the native RDS runtime.")
	}
	if in.OptionGroupName != nil {
		return unsupported("OptionGroupName is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsKMSKeyId != nil {
		return unsupported("PerformanceInsightsKMSKeyId is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsRetentionPeriod != nil {
		return unsupported("PerformanceInsightsRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.PreferredBackupWindow != nil {
		return unsupported("PreferredBackupWindow is not supported by the native RDS runtime.")
	}
	if in.PreferredMaintenanceWindow != nil {
		return unsupported("PreferredMaintenanceWindow is not supported by the native RDS runtime.")
	}
	if len(in.ProcessorFeatures) != 0 {
		return unsupported("ProcessorFeatures is not supported by the native RDS runtime.")
	}
	if in.PromotionTier != nil {
		return unsupported("PromotionTier is not supported by the native RDS runtime.")
	}
	if boolean(in.PubliclyAccessible) {
		return unsupported("PubliclyAccessible is not supported by the native RDS runtime.")
	}
	if boolean(in.StorageEncrypted) {
		return unsupported("StorageEncrypted is not supported by the native RDS runtime.")
	}
	if in.StorageThroughput != nil {
		return unsupported("StorageThroughput is not supported by the native RDS runtime.")
	}
	if in.StorageType != nil {
		return unsupported("StorageType is not supported by the native RDS runtime.")
	}
	if len(in.TagSpecifications) != 0 {
		return unsupported("TagSpecifications is not supported by the native RDS runtime.")
	}
	if in.TdeCredentialArn != nil {
		return unsupported("TdeCredentialArn is not supported by the native RDS runtime.")
	}
	if in.TdeCredentialPassword != nil {
		return unsupported("TdeCredentialPassword is not supported by the native RDS runtime.")
	}
	if in.Timezone != nil {
		return unsupported("Timezone is not supported by the native RDS runtime.")
	}
	if len(in.VpcSecurityGroupIds) != 0 {
		return unsupported("VpcSecurityGroupIds is not supported by the native RDS runtime.")
	}
	return nil
}

func validateCreateDBClusterMessage(in *api.CreateDBClusterMessage) error {
	if in.AllocatedStorage != nil {
		return unsupported("AllocatedStorage is not supported by the native RDS runtime.")
	}
	if len(in.AssociatedRoles) != 0 {
		return unsupported("AssociatedRoles is not supported by the native RDS runtime.")
	}
	if boolean(in.AutoMinorVersionUpgrade) {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native RDS runtime.")
	}
	if len(in.AvailabilityZones) != 0 {
		return unsupported("AvailabilityZones is not supported by the native RDS runtime.")
	}
	if in.BacktrackWindow != nil && *in.BacktrackWindow != 0 {
		return unsupported("BacktrackWindow is not supported by the native RDS runtime.")
	}
	if in.BackupRetentionPeriod != nil && *in.BackupRetentionPeriod != 0 {
		return unsupported("BackupRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.CACertificateIdentifier != nil {
		return unsupported("CACertificateIdentifier is not supported by the native RDS runtime.")
	}
	if in.CharacterSetName != nil {
		return unsupported("CharacterSetName is not supported by the native RDS runtime.")
	}
	if in.ClusterScalabilityType != nil {
		return unsupported("ClusterScalabilityType is not supported by the native RDS runtime.")
	}
	if in.DBClusterInstanceClass != nil {
		return unsupported("DBClusterInstanceClass is not supported by the native RDS runtime.")
	}
	if in.DBSubnetGroupName != nil {
		return unsupported("DBSubnetGroupName is not supported by the native RDS runtime.")
	}
	if in.DBSystemId != nil {
		return unsupported("DBSystemId is not supported by the native RDS runtime.")
	}
	if in.DatabaseInsightsMode != nil {
		return unsupported("DatabaseInsightsMode is not supported by the native RDS runtime.")
	}
	if in.Domain != nil {
		return unsupported("Domain is not supported by the native RDS runtime.")
	}
	if in.DomainIAMRoleName != nil {
		return unsupported("DomainIAMRoleName is not supported by the native RDS runtime.")
	}
	if len(in.EnableCloudwatchLogsExports) != 0 {
		return unsupported("EnableCloudwatchLogsExports is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableGlobalWriteForwarding) {
		return unsupported("EnableGlobalWriteForwarding is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableIAMDatabaseAuthentication) {
		return unsupported("EnableIAMDatabaseAuthentication is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableLimitlessDatabase) {
		return unsupported("EnableLimitlessDatabase is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableLocalWriteForwarding) {
		return unsupported("EnableLocalWriteForwarding is not supported by the native RDS runtime.")
	}
	if boolean(in.EnablePerformanceInsights) {
		return unsupported("EnablePerformanceInsights is not supported by the native RDS runtime.")
	}
	if in.EngineLifecycleSupport != nil {
		return unsupported("EngineLifecycleSupport is not supported by the native RDS runtime.")
	}
	if in.GlobalClusterIdentifier != nil {
		return unsupported("GlobalClusterIdentifier is not supported by the native RDS runtime.")
	}
	if in.Iops != nil {
		return unsupported("Iops is not supported by the native RDS runtime.")
	}
	if in.KmsKeyId != nil {
		return unsupported("KmsKeyId is not supported by the native RDS runtime.")
	}
	if boolean(in.ManageMasterUserPassword) {
		return unsupported("ManageMasterUserPassword is not supported by the native RDS runtime.")
	}
	if in.MasterUserAuthenticationType != nil {
		return unsupported("MasterUserAuthenticationType is not supported by the native RDS runtime.")
	}
	if in.MasterUserSecretKmsKeyId != nil {
		return unsupported("MasterUserSecretKmsKeyId is not supported by the native RDS runtime.")
	}
	if in.MonitoringInterval != nil && *in.MonitoringInterval != 0 {
		return unsupported("MonitoringInterval is not supported by the native RDS runtime.")
	}
	if in.MonitoringRoleArn != nil {
		return unsupported("MonitoringRoleArn is not supported by the native RDS runtime.")
	}
	if in.NetworkType != nil {
		return unsupported("NetworkType is not supported by the native RDS runtime.")
	}
	if in.OptionGroupName != nil {
		return unsupported("OptionGroupName is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsKMSKeyId != nil {
		return unsupported("PerformanceInsightsKMSKeyId is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsRetentionPeriod != nil {
		return unsupported("PerformanceInsightsRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.PreSignedUrl != nil {
		return unsupported("PreSignedUrl is not supported by the native RDS runtime.")
	}
	if in.PreferredBackupWindow != nil {
		return unsupported("PreferredBackupWindow is not supported by the native RDS runtime.")
	}
	if in.PreferredMaintenanceWindow != nil {
		return unsupported("PreferredMaintenanceWindow is not supported by the native RDS runtime.")
	}
	if boolean(in.PubliclyAccessible) {
		return unsupported("PubliclyAccessible is not supported by the native RDS runtime.")
	}
	if in.RdsCustomClusterConfiguration != nil {
		return unsupported("RdsCustomClusterConfiguration is not supported by the native RDS runtime.")
	}
	if in.ReplicationSourceIdentifier != nil {
		return unsupported("ReplicationSourceIdentifier is not supported by the native RDS runtime.")
	}
	if in.ScalingConfiguration != nil {
		return unsupported("ScalingConfiguration is not supported by the native RDS runtime.")
	}
	if in.ServerlessV2ScalingConfiguration != nil {
		return unsupported("ServerlessV2ScalingConfiguration is not supported by the native RDS runtime.")
	}
	if boolean(in.StorageEncrypted) {
		return unsupported("StorageEncrypted is not supported by the native RDS runtime.")
	}
	if in.StorageType != nil {
		return unsupported("StorageType is not supported by the native RDS runtime.")
	}
	if len(in.TagSpecifications) != 0 {
		return unsupported("TagSpecifications is not supported by the native RDS runtime.")
	}
	if len(in.VpcSecurityGroupIds) != 0 {
		return unsupported("VpcSecurityGroupIds is not supported by the native RDS runtime.")
	}
	if in.WithExpressConfiguration != nil {
		return unsupported("WithExpressConfiguration is not supported by the native RDS runtime.")
	}
	return nil
}

func validateModifyDBInstanceMessage(in *api.ModifyDBInstanceMessage) error {
	if len(in.AdditionalStorageVolumes) != 0 {
		return unsupported("AdditionalStorageVolumes is not supported by the native RDS runtime.")
	}
	if in.AllocatedStorage != nil {
		return unsupported("AllocatedStorage is not supported by the native RDS runtime.")
	}
	if in.AllowMajorVersionUpgrade != nil {
		return unsupported("AllowMajorVersionUpgrade is not supported by the native RDS runtime.")
	}
	if boolean(in.AutoMinorVersionUpgrade) {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native RDS runtime.")
	}
	if in.AutomationMode != nil {
		return unsupported("AutomationMode is not supported by the native RDS runtime.")
	}
	if in.AwsBackupRecoveryPointArn != nil {
		return unsupported("AwsBackupRecoveryPointArn is not supported by the native RDS runtime.")
	}
	if in.BackupRetentionPeriod != nil && *in.BackupRetentionPeriod != 0 {
		return unsupported("BackupRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.CACertificateIdentifier != nil {
		return unsupported("CACertificateIdentifier is not supported by the native RDS runtime.")
	}
	if in.CertificateRotationRestart != nil {
		return unsupported("CertificateRotationRestart is not supported by the native RDS runtime.")
	}
	if in.CloudwatchLogsExportConfiguration != nil {
		return unsupported("CloudwatchLogsExportConfiguration is not supported by the native RDS runtime.")
	}
	if in.DBInstanceClass != nil {
		return unsupported("DBInstanceClass is not supported by the native RDS runtime.")
	}
	if in.DBPortNumber != nil {
		return unsupported("DBPortNumber is not supported by the native RDS runtime.")
	}
	if len(in.DBSecurityGroups) != 0 {
		return unsupported("DBSecurityGroups is not supported by the native RDS runtime.")
	}
	if in.DBSubnetGroupName != nil {
		return unsupported("DBSubnetGroupName is not supported by the native RDS runtime.")
	}
	if in.DatabaseInsightsMode != nil {
		return unsupported("DatabaseInsightsMode is not supported by the native RDS runtime.")
	}
	if boolean(in.DedicatedLogVolume) {
		return unsupported("DedicatedLogVolume is not supported by the native RDS runtime.")
	}
	if in.DisableDomain != nil {
		return unsupported("DisableDomain is not supported by the native RDS runtime.")
	}
	if in.Domain != nil {
		return unsupported("Domain is not supported by the native RDS runtime.")
	}
	if in.DomainAuthSecretArn != nil {
		return unsupported("DomainAuthSecretArn is not supported by the native RDS runtime.")
	}
	if len(in.DomainDnsIps) != 0 {
		return unsupported("DomainDnsIps is not supported by the native RDS runtime.")
	}
	if in.DomainFqdn != nil {
		return unsupported("DomainFqdn is not supported by the native RDS runtime.")
	}
	if in.DomainIAMRoleName != nil {
		return unsupported("DomainIAMRoleName is not supported by the native RDS runtime.")
	}
	if in.DomainOu != nil {
		return unsupported("DomainOu is not supported by the native RDS runtime.")
	}
	if in.EnableCustomerOwnedIp != nil {
		return unsupported("EnableCustomerOwnedIp is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableIAMDatabaseAuthentication) {
		return unsupported("EnableIAMDatabaseAuthentication is not supported by the native RDS runtime.")
	}
	if boolean(in.EnablePerformanceInsights) {
		return unsupported("EnablePerformanceInsights is not supported by the native RDS runtime.")
	}
	if in.Engine != nil {
		return unsupported("Engine is not supported by the native RDS runtime.")
	}
	if in.EngineLifecycleSupport != nil {
		return unsupported("EngineLifecycleSupport is not supported by the native RDS runtime.")
	}
	if in.EngineVersion != nil {
		return unsupported("EngineVersion is not supported by the native RDS runtime.")
	}
	if in.Iops != nil {
		return unsupported("Iops is not supported by the native RDS runtime.")
	}
	if in.LicenseModel != nil {
		return unsupported("LicenseModel is not supported by the native RDS runtime.")
	}
	if boolean(in.ManageMasterUserPassword) {
		return unsupported("ManageMasterUserPassword is not supported by the native RDS runtime.")
	}
	if in.MasterUserAuthenticationType != nil {
		return unsupported("MasterUserAuthenticationType is not supported by the native RDS runtime.")
	}
	if in.MasterUserSecretKmsKeyId != nil {
		return unsupported("MasterUserSecretKmsKeyId is not supported by the native RDS runtime.")
	}
	if in.MaxAllocatedStorage != nil {
		return unsupported("MaxAllocatedStorage is not supported by the native RDS runtime.")
	}
	if in.MonitoringInterval != nil && *in.MonitoringInterval != 0 {
		return unsupported("MonitoringInterval is not supported by the native RDS runtime.")
	}
	if in.MonitoringRoleArn != nil {
		return unsupported("MonitoringRoleArn is not supported by the native RDS runtime.")
	}
	if boolean(in.MultiAZ) {
		return unsupported("MultiAZ is not supported by the native RDS runtime.")
	}
	if boolean(in.MultiTenant) {
		return unsupported("MultiTenant is not supported by the native RDS runtime.")
	}
	if in.NetworkType != nil {
		return unsupported("NetworkType is not supported by the native RDS runtime.")
	}
	if in.NewDBInstanceIdentifier != nil {
		return unsupported("NewDBInstanceIdentifier is not supported by the native RDS runtime.")
	}
	if in.OptionGroupName != nil {
		return unsupported("OptionGroupName is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsKMSKeyId != nil {
		return unsupported("PerformanceInsightsKMSKeyId is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsRetentionPeriod != nil {
		return unsupported("PerformanceInsightsRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.PreferredBackupWindow != nil {
		return unsupported("PreferredBackupWindow is not supported by the native RDS runtime.")
	}
	if in.PreferredMaintenanceWindow != nil {
		return unsupported("PreferredMaintenanceWindow is not supported by the native RDS runtime.")
	}
	if len(in.ProcessorFeatures) != 0 {
		return unsupported("ProcessorFeatures is not supported by the native RDS runtime.")
	}
	if in.PromotionTier != nil {
		return unsupported("PromotionTier is not supported by the native RDS runtime.")
	}
	if boolean(in.PubliclyAccessible) {
		return unsupported("PubliclyAccessible is not supported by the native RDS runtime.")
	}
	if in.ReplicaMode != nil {
		return unsupported("ReplicaMode is not supported by the native RDS runtime.")
	}
	if in.ResumeFullAutomationModeMinutes != nil {
		return unsupported("ResumeFullAutomationModeMinutes is not supported by the native RDS runtime.")
	}
	if in.RotateMasterUserPassword != nil {
		return unsupported("RotateMasterUserPassword is not supported by the native RDS runtime.")
	}
	if in.StorageThroughput != nil {
		return unsupported("StorageThroughput is not supported by the native RDS runtime.")
	}
	if in.StorageType != nil {
		return unsupported("StorageType is not supported by the native RDS runtime.")
	}
	if len(in.TagSpecifications) != 0 {
		return unsupported("TagSpecifications is not supported by the native RDS runtime.")
	}
	if in.TdeCredentialArn != nil {
		return unsupported("TdeCredentialArn is not supported by the native RDS runtime.")
	}
	if in.TdeCredentialPassword != nil {
		return unsupported("TdeCredentialPassword is not supported by the native RDS runtime.")
	}
	if in.UseDefaultProcessorFeatures != nil {
		return unsupported("UseDefaultProcessorFeatures is not supported by the native RDS runtime.")
	}
	if len(in.VpcSecurityGroupIds) != 0 {
		return unsupported("VpcSecurityGroupIds is not supported by the native RDS runtime.")
	}
	return nil
}

func validateModifyDBClusterMessage(in *api.ModifyDBClusterMessage) error {
	if in.AllocatedStorage != nil {
		return unsupported("AllocatedStorage is not supported by the native RDS runtime.")
	}
	if in.AllowEngineModeChange != nil {
		return unsupported("AllowEngineModeChange is not supported by the native RDS runtime.")
	}
	if in.AllowMajorVersionUpgrade != nil {
		return unsupported("AllowMajorVersionUpgrade is not supported by the native RDS runtime.")
	}
	if boolean(in.AutoMinorVersionUpgrade) {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native RDS runtime.")
	}
	if in.AwsBackupRecoveryPointArn != nil {
		return unsupported("AwsBackupRecoveryPointArn is not supported by the native RDS runtime.")
	}
	if in.BacktrackWindow != nil && *in.BacktrackWindow != 0 {
		return unsupported("BacktrackWindow is not supported by the native RDS runtime.")
	}
	if in.BackupRetentionPeriod != nil && *in.BackupRetentionPeriod != 0 {
		return unsupported("BackupRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.CACertificateIdentifier != nil {
		return unsupported("CACertificateIdentifier is not supported by the native RDS runtime.")
	}
	if in.CloudwatchLogsExportConfiguration != nil {
		return unsupported("CloudwatchLogsExportConfiguration is not supported by the native RDS runtime.")
	}
	if in.DBClusterInstanceClass != nil {
		return unsupported("DBClusterInstanceClass is not supported by the native RDS runtime.")
	}
	if in.DBInstanceParameterGroupName != nil {
		return unsupported("DBInstanceParameterGroupName is not supported by the native RDS runtime.")
	}
	if in.DatabaseInsightsMode != nil {
		return unsupported("DatabaseInsightsMode is not supported by the native RDS runtime.")
	}
	if in.Domain != nil {
		return unsupported("Domain is not supported by the native RDS runtime.")
	}
	if in.DomainIAMRoleName != nil {
		return unsupported("DomainIAMRoleName is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableGlobalWriteForwarding) {
		return unsupported("EnableGlobalWriteForwarding is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableIAMDatabaseAuthentication) {
		return unsupported("EnableIAMDatabaseAuthentication is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableLimitlessDatabase) {
		return unsupported("EnableLimitlessDatabase is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableLocalWriteForwarding) {
		return unsupported("EnableLocalWriteForwarding is not supported by the native RDS runtime.")
	}
	if boolean(in.EnablePerformanceInsights) {
		return unsupported("EnablePerformanceInsights is not supported by the native RDS runtime.")
	}
	if in.EngineLifecycleSupport != nil {
		return unsupported("EngineLifecycleSupport is not supported by the native RDS runtime.")
	}
	if in.EngineMode != nil {
		return unsupported("EngineMode is not supported by the native RDS runtime.")
	}
	if in.EngineVersion != nil {
		return unsupported("EngineVersion is not supported by the native RDS runtime.")
	}
	if in.Iops != nil {
		return unsupported("Iops is not supported by the native RDS runtime.")
	}
	if boolean(in.ManageMasterUserPassword) {
		return unsupported("ManageMasterUserPassword is not supported by the native RDS runtime.")
	}
	if in.MasterUserAuthenticationType != nil {
		return unsupported("MasterUserAuthenticationType is not supported by the native RDS runtime.")
	}
	if in.MasterUserSecretKmsKeyId != nil {
		return unsupported("MasterUserSecretKmsKeyId is not supported by the native RDS runtime.")
	}
	if in.MonitoringInterval != nil && *in.MonitoringInterval != 0 {
		return unsupported("MonitoringInterval is not supported by the native RDS runtime.")
	}
	if in.MonitoringRoleArn != nil {
		return unsupported("MonitoringRoleArn is not supported by the native RDS runtime.")
	}
	if in.NetworkType != nil {
		return unsupported("NetworkType is not supported by the native RDS runtime.")
	}
	if in.NewDBClusterIdentifier != nil {
		return unsupported("NewDBClusterIdentifier is not supported by the native RDS runtime.")
	}
	if in.OptionGroupName != nil {
		return unsupported("OptionGroupName is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsKMSKeyId != nil {
		return unsupported("PerformanceInsightsKMSKeyId is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsRetentionPeriod != nil {
		return unsupported("PerformanceInsightsRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.Port != nil {
		return unsupported("Port is not supported by the native RDS runtime.")
	}
	if in.PreferredBackupWindow != nil {
		return unsupported("PreferredBackupWindow is not supported by the native RDS runtime.")
	}
	if in.PreferredMaintenanceWindow != nil {
		return unsupported("PreferredMaintenanceWindow is not supported by the native RDS runtime.")
	}
	if in.RotateMasterUserPassword != nil {
		return unsupported("RotateMasterUserPassword is not supported by the native RDS runtime.")
	}
	if in.ScalingConfiguration != nil {
		return unsupported("ScalingConfiguration is not supported by the native RDS runtime.")
	}
	if in.ServerlessV2ScalingConfiguration != nil {
		return unsupported("ServerlessV2ScalingConfiguration is not supported by the native RDS runtime.")
	}
	if in.StorageType != nil {
		return unsupported("StorageType is not supported by the native RDS runtime.")
	}
	if len(in.VpcSecurityGroupIds) != 0 {
		return unsupported("VpcSecurityGroupIds is not supported by the native RDS runtime.")
	}
	return nil
}

func validateRestoreDBInstanceFromDBSnapshotMessage(in *api.RestoreDBInstanceFromDBSnapshotMessage) error {
	if len(in.AdditionalStorageVolumes) != 0 {
		return unsupported("AdditionalStorageVolumes is not supported by the native RDS runtime.")
	}
	if in.AllocatedStorage != nil {
		return unsupported("AllocatedStorage is not supported by the native RDS runtime.")
	}
	if boolean(in.AutoMinorVersionUpgrade) {
		return unsupported("AutoMinorVersionUpgrade is not supported by the native RDS runtime.")
	}
	if in.AvailabilityZone != nil {
		return unsupported("AvailabilityZone is not supported by the native RDS runtime.")
	}
	if in.BackupRetentionPeriod != nil && *in.BackupRetentionPeriod != 0 {
		return unsupported("BackupRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.BackupTarget != nil {
		return unsupported("BackupTarget is not supported by the native RDS runtime.")
	}
	if in.CACertificateIdentifier != nil {
		return unsupported("CACertificateIdentifier is not supported by the native RDS runtime.")
	}
	if in.CustomIamInstanceProfile != nil {
		return unsupported("CustomIamInstanceProfile is not supported by the native RDS runtime.")
	}
	if in.DBClusterSnapshotIdentifier != nil {
		return unsupported("DBClusterSnapshotIdentifier is not supported by the native RDS runtime.")
	}
	if in.DBSubnetGroupName != nil {
		return unsupported("DBSubnetGroupName is not supported by the native RDS runtime.")
	}
	if boolean(in.DedicatedLogVolume) {
		return unsupported("DedicatedLogVolume is not supported by the native RDS runtime.")
	}
	if in.Domain != nil {
		return unsupported("Domain is not supported by the native RDS runtime.")
	}
	if in.DomainAuthSecretArn != nil {
		return unsupported("DomainAuthSecretArn is not supported by the native RDS runtime.")
	}
	if len(in.DomainDnsIps) != 0 {
		return unsupported("DomainDnsIps is not supported by the native RDS runtime.")
	}
	if in.DomainFqdn != nil {
		return unsupported("DomainFqdn is not supported by the native RDS runtime.")
	}
	if in.DomainIAMRoleName != nil {
		return unsupported("DomainIAMRoleName is not supported by the native RDS runtime.")
	}
	if in.DomainOu != nil {
		return unsupported("DomainOu is not supported by the native RDS runtime.")
	}
	if len(in.EnableCloudwatchLogsExports) != 0 {
		return unsupported("EnableCloudwatchLogsExports is not supported by the native RDS runtime.")
	}
	if in.EnableCustomerOwnedIp != nil {
		return unsupported("EnableCustomerOwnedIp is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableIAMDatabaseAuthentication) {
		return unsupported("EnableIAMDatabaseAuthentication is not supported by the native RDS runtime.")
	}
	if in.EngineLifecycleSupport != nil {
		return unsupported("EngineLifecycleSupport is not supported by the native RDS runtime.")
	}
	if in.Iops != nil {
		return unsupported("Iops is not supported by the native RDS runtime.")
	}
	if in.LicenseModel != nil {
		return unsupported("LicenseModel is not supported by the native RDS runtime.")
	}
	if boolean(in.ManageMasterUserPassword) {
		return unsupported("ManageMasterUserPassword is not supported by the native RDS runtime.")
	}
	if in.MasterUserSecretKmsKeyId != nil {
		return unsupported("MasterUserSecretKmsKeyId is not supported by the native RDS runtime.")
	}
	if boolean(in.MultiAZ) {
		return unsupported("MultiAZ is not supported by the native RDS runtime.")
	}
	if in.NetworkType != nil {
		return unsupported("NetworkType is not supported by the native RDS runtime.")
	}
	if in.OptionGroupName != nil {
		return unsupported("OptionGroupName is not supported by the native RDS runtime.")
	}
	if in.PreferredBackupWindow != nil {
		return unsupported("PreferredBackupWindow is not supported by the native RDS runtime.")
	}
	if len(in.ProcessorFeatures) != 0 {
		return unsupported("ProcessorFeatures is not supported by the native RDS runtime.")
	}
	if boolean(in.PubliclyAccessible) {
		return unsupported("PubliclyAccessible is not supported by the native RDS runtime.")
	}
	if in.StorageThroughput != nil {
		return unsupported("StorageThroughput is not supported by the native RDS runtime.")
	}
	if in.StorageType != nil {
		return unsupported("StorageType is not supported by the native RDS runtime.")
	}
	if len(in.TagSpecifications) != 0 {
		return unsupported("TagSpecifications is not supported by the native RDS runtime.")
	}
	if in.TdeCredentialArn != nil {
		return unsupported("TdeCredentialArn is not supported by the native RDS runtime.")
	}
	if in.TdeCredentialPassword != nil {
		return unsupported("TdeCredentialPassword is not supported by the native RDS runtime.")
	}
	if in.UseDefaultProcessorFeatures != nil {
		return unsupported("UseDefaultProcessorFeatures is not supported by the native RDS runtime.")
	}
	if len(in.VpcSecurityGroupIds) != 0 {
		return unsupported("VpcSecurityGroupIds is not supported by the native RDS runtime.")
	}
	return nil
}

func validateRestoreDBClusterFromSnapshotMessage(in *api.RestoreDBClusterFromSnapshotMessage) error {
	if len(in.AssociatedRoles) != 0 {
		return unsupported("AssociatedRoles is not supported by the native RDS runtime.")
	}
	if len(in.AvailabilityZones) != 0 {
		return unsupported("AvailabilityZones is not supported by the native RDS runtime.")
	}
	if in.BacktrackWindow != nil && *in.BacktrackWindow != 0 {
		return unsupported("BacktrackWindow is not supported by the native RDS runtime.")
	}
	if in.BackupRetentionPeriod != nil && *in.BackupRetentionPeriod != 0 {
		return unsupported("BackupRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.DBClusterInstanceClass != nil {
		return unsupported("DBClusterInstanceClass is not supported by the native RDS runtime.")
	}
	if in.DBSubnetGroupName != nil {
		return unsupported("DBSubnetGroupName is not supported by the native RDS runtime.")
	}
	if in.Domain != nil {
		return unsupported("Domain is not supported by the native RDS runtime.")
	}
	if in.DomainIAMRoleName != nil {
		return unsupported("DomainIAMRoleName is not supported by the native RDS runtime.")
	}
	if len(in.EnableCloudwatchLogsExports) != 0 {
		return unsupported("EnableCloudwatchLogsExports is not supported by the native RDS runtime.")
	}
	if boolean(in.EnableIAMDatabaseAuthentication) {
		return unsupported("EnableIAMDatabaseAuthentication is not supported by the native RDS runtime.")
	}
	if in.EnableInternetAccessGateway != nil {
		return unsupported("EnableInternetAccessGateway is not supported by the native RDS runtime.")
	}
	if boolean(in.EnablePerformanceInsights) {
		return unsupported("EnablePerformanceInsights is not supported by the native RDS runtime.")
	}
	if in.EnableVPCNetworking != nil {
		return unsupported("EnableVPCNetworking is not supported by the native RDS runtime.")
	}
	if in.EngineLifecycleSupport != nil {
		return unsupported("EngineLifecycleSupport is not supported by the native RDS runtime.")
	}
	if in.Iops != nil {
		return unsupported("Iops is not supported by the native RDS runtime.")
	}
	if in.KmsKeyId != nil {
		return unsupported("KmsKeyId is not supported by the native RDS runtime.")
	}
	if in.MonitoringInterval != nil && *in.MonitoringInterval != 0 {
		return unsupported("MonitoringInterval is not supported by the native RDS runtime.")
	}
	if in.MonitoringRoleArn != nil {
		return unsupported("MonitoringRoleArn is not supported by the native RDS runtime.")
	}
	if in.NetworkType != nil {
		return unsupported("NetworkType is not supported by the native RDS runtime.")
	}
	if in.OptionGroupName != nil {
		return unsupported("OptionGroupName is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsKMSKeyId != nil {
		return unsupported("PerformanceInsightsKMSKeyId is not supported by the native RDS runtime.")
	}
	if in.PerformanceInsightsRetentionPeriod != nil {
		return unsupported("PerformanceInsightsRetentionPeriod is not supported by the native RDS runtime.")
	}
	if in.PreferredBackupWindow != nil {
		return unsupported("PreferredBackupWindow is not supported by the native RDS runtime.")
	}
	if boolean(in.PubliclyAccessible) {
		return unsupported("PubliclyAccessible is not supported by the native RDS runtime.")
	}
	if in.RdsCustomClusterConfiguration != nil {
		return unsupported("RdsCustomClusterConfiguration is not supported by the native RDS runtime.")
	}
	if in.ScalingConfiguration != nil {
		return unsupported("ScalingConfiguration is not supported by the native RDS runtime.")
	}
	if in.ServerlessV2ScalingConfiguration != nil {
		return unsupported("ServerlessV2ScalingConfiguration is not supported by the native RDS runtime.")
	}
	if in.StorageType != nil {
		return unsupported("StorageType is not supported by the native RDS runtime.")
	}
	if len(in.TagSpecifications) != 0 {
		return unsupported("TagSpecifications is not supported by the native RDS runtime.")
	}
	if len(in.VpcSecurityGroupIds) != 0 {
		return unsupported("VpcSecurityGroupIds is not supported by the native RDS runtime.")
	}
	return nil
}

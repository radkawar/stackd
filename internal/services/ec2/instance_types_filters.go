package ec2

import (
	"fmt"
	api "stackd/internal/awsapi/ec2"
)

// Documented DescribeInstanceTypes selectors. The spelling is an API contract,
// not mechanically derived from Go names (for example disk and architecture
// are singular here although their response members are plural).
const instanceTypeFilterNames = `auto-recovery-supported bare-metal burstable-performance-supported current-generation dedicated-hosts-supported
 ebs-info.attachment-limit-type ebs-info.maximum-ebs-attachments
 ebs-info.ebs-optimized-info.baseline-bandwidth-in-mbps ebs-info.ebs-optimized-info.baseline-iops ebs-info.ebs-optimized-info.baseline-throughput-in-mbps
 ebs-info.ebs-optimized-info.maximum-bandwidth-in-mbps ebs-info.ebs-optimized-info.maximum-iops ebs-info.ebs-optimized-info.maximum-throughput-in-mbps
 ebs-info.ebs-optimized-support ebs-info.encryption-support ebs-info.nvme-support free-tier-eligible hibernation-supported hypervisor
 instance-storage-info.disk.count instance-storage-info.disk.size-in-gb instance-storage-info.disk.type
 instance-storage-info.encryption-support instance-storage-info.nvme-support instance-storage-info.total-size-in-gb instance-storage-supported instance-type memory-info.size-in-mib
 network-info.bandwidth-weightings network-info.efa-info.maximum-efa-interfaces network-info.efa-supported network-info.ena-support network-info.flexible-ena-queues-support
 network-info.encryption-in-transit-supported network-info.ipv4-addresses-per-interface network-info.ipv6-addresses-per-interface network-info.ipv6-supported
 network-info.maximum-network-cards network-info.maximum-network-interfaces network-info.network-performance
 nitro-enclaves-support nitro-tpm-support nitro-tpm-info.supported-versions processor-info.supported-architecture processor-info.sustained-clock-speed-in-ghz processor-info.supported-features
 reboot-migration-support supported-boot-mode supported-root-device-type supported-usage-class supported-virtualization-type
 vcpu-info.default-cores vcpu-info.default-threads-per-core vcpu-info.default-vcpus vcpu-info.valid-cores vcpu-info.valid-threads-per-core`

// Index values are built once, preserving absent scalar fields rather than
// manufacturing false/zero. Public wildcard matching remains in selection.go.
func instanceTypeScalar[T ~string | ~bool | ~int32 | ~int64 | ~float32 | ~float64](fields map[string][]string, name string, value *T) {
	if value != nil {
		fields[name] = append(fields[name], fmt.Sprint(*value))
	}
}

func instanceTypePageItem(info api.InstanceTypeInfo) pageItem {
	fields := map[string][]string{
		"supported-boot-mode":           stringsOf(info.SupportedBootModes),
		"supported-root-device-type":    stringsOf(info.SupportedRootDeviceTypes),
		"supported-usage-class":         stringsOf(info.SupportedUsageClasses),
		"supported-virtualization-type": stringsOf(info.SupportedVirtualizationTypes),
	}
	instanceTypeScalar(fields, "instance-type", info.InstanceType)
	instanceTypeScalar(fields, "auto-recovery-supported", info.AutoRecoverySupported)
	instanceTypeScalar(fields, "bare-metal", info.BareMetal)
	instanceTypeScalar(fields, "burstable-performance-supported", info.BurstablePerformanceSupported)
	instanceTypeScalar(fields, "current-generation", info.CurrentGeneration)
	instanceTypeScalar(fields, "dedicated-hosts-supported", info.DedicatedHostsSupported)
	instanceTypeScalar(fields, "free-tier-eligible", info.FreeTierEligible)
	instanceTypeScalar(fields, "hibernation-supported", info.HibernationSupported)
	instanceTypeScalar(fields, "hypervisor", info.Hypervisor)
	instanceTypeScalar(fields, "instance-storage-supported", info.InstanceStorageSupported)
	instanceTypeScalar(fields, "nitro-enclaves-support", info.NitroEnclavesSupport)
	instanceTypeScalar(fields, "nitro-tpm-support", info.NitroTpmSupport)
	instanceTypeScalar(fields, "reboot-migration-support", info.RebootMigrationSupport)
	if memory := info.MemoryInfo; memory != nil {
		instanceTypeScalar(fields, "memory-info.size-in-mib", memory.SizeInMiB)
	}
	if tpm := info.NitroTpmInfo; tpm != nil {
		fields["nitro-tpm-info.supported-versions"] = stringsOf(tpm.SupportedVersions)
	}
	if cpu := info.VCpuInfo; cpu != nil {
		instanceTypeScalar(fields, "vcpu-info.default-cores", cpu.DefaultCores)
		instanceTypeScalar(fields, "vcpu-info.default-threads-per-core", cpu.DefaultThreadsPerCore)
		instanceTypeScalar(fields, "vcpu-info.default-vcpus", cpu.DefaultVCpus)
		for _, value := range cpu.ValidCores {
			instanceTypeScalar(fields, "vcpu-info.valid-cores", &value)
		}
		for _, value := range cpu.ValidThreadsPerCore {
			instanceTypeScalar(fields, "vcpu-info.valid-threads-per-core", &value)
		}
	}
	if processor := info.ProcessorInfo; processor != nil {
		fields["processor-info.supported-architecture"] = stringsOf(processor.SupportedArchitectures)
		fields["processor-info.supported-features"] = stringsOf(processor.SupportedFeatures)
		instanceTypeScalar(fields, "processor-info.sustained-clock-speed-in-ghz", processor.SustainedClockSpeedInGhz)
	}
	if ebs := info.EbsInfo; ebs != nil {
		instanceTypeScalar(fields, "ebs-info.attachment-limit-type", ebs.AttachmentLimitType)
		instanceTypeScalar(fields, "ebs-info.maximum-ebs-attachments", ebs.MaximumEbsAttachments)
		instanceTypeScalar(fields, "ebs-info.ebs-optimized-support", ebs.EbsOptimizedSupport)
		instanceTypeScalar(fields, "ebs-info.encryption-support", ebs.EncryptionSupport)
		instanceTypeScalar(fields, "ebs-info.nvme-support", ebs.NvmeSupport)
		if optimized := ebs.EbsOptimizedInfo; optimized != nil {
			instanceTypeScalar(fields, "ebs-info.ebs-optimized-info.baseline-bandwidth-in-mbps", optimized.BaselineBandwidthInMbps)
			instanceTypeScalar(fields, "ebs-info.ebs-optimized-info.baseline-iops", optimized.BaselineIops)
			instanceTypeScalar(fields, "ebs-info.ebs-optimized-info.baseline-throughput-in-mbps", optimized.BaselineThroughputInMBps)
			instanceTypeScalar(fields, "ebs-info.ebs-optimized-info.maximum-bandwidth-in-mbps", optimized.MaximumBandwidthInMbps)
			instanceTypeScalar(fields, "ebs-info.ebs-optimized-info.maximum-iops", optimized.MaximumIops)
			instanceTypeScalar(fields, "ebs-info.ebs-optimized-info.maximum-throughput-in-mbps", optimized.MaximumThroughputInMBps)
		}
	}
	if storage := info.InstanceStorageInfo; storage != nil {
		instanceTypeScalar(fields, "instance-storage-info.encryption-support", storage.EncryptionSupport)
		instanceTypeScalar(fields, "instance-storage-info.nvme-support", storage.NvmeSupport)
		instanceTypeScalar(fields, "instance-storage-info.total-size-in-gb", storage.TotalSizeInGB)
		for _, disk := range storage.Disks {
			instanceTypeScalar(fields, "instance-storage-info.disk.count", disk.Count)
			instanceTypeScalar(fields, "instance-storage-info.disk.size-in-gb", disk.SizeInGB)
			instanceTypeScalar(fields, "instance-storage-info.disk.type", disk.Type)
		}
	}
	if network := info.NetworkInfo; network != nil {
		fields["network-info.bandwidth-weightings"] = stringsOf(network.BandwidthWeightings)
		instanceTypeScalar(fields, "network-info.efa-supported", network.EfaSupported)
		instanceTypeScalar(fields, "network-info.ena-support", network.EnaSupport)
		instanceTypeScalar(fields, "network-info.flexible-ena-queues-support", network.FlexibleEnaQueuesSupport)
		instanceTypeScalar(fields, "network-info.encryption-in-transit-supported", network.EncryptionInTransitSupported)
		instanceTypeScalar(fields, "network-info.ipv4-addresses-per-interface", network.Ipv4AddressesPerInterface)
		instanceTypeScalar(fields, "network-info.ipv6-addresses-per-interface", network.Ipv6AddressesPerInterface)
		instanceTypeScalar(fields, "network-info.ipv6-supported", network.Ipv6Supported)
		instanceTypeScalar(fields, "network-info.maximum-network-cards", network.MaximumNetworkCards)
		instanceTypeScalar(fields, "network-info.maximum-network-interfaces", network.MaximumNetworkInterfaces)
		instanceTypeScalar(fields, "network-info.network-performance", network.NetworkPerformance)
		if efa := network.EfaInfo; efa != nil {
			instanceTypeScalar(fields, "network-info.efa-info.maximum-efa-interfaces", efa.MaximumEfaInterfaces)
		}
	}
	return pageItem{ID: str(info.InstanceType), Fields: fields}
}

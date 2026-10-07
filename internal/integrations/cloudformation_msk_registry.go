package integrations

import "stackd/internal/services/cloudformation"

// CloudFormationEngineClusterHandlers registers only resource concepts owned by
// the configured native engine services. Generated AWS operation catalogs do not
// imply that serverless, multi-region or managed infrastructure owners exist.
func CloudFormationEngineClusterHandlers(commands StepFunctionsCommands, configurations CloudFormationMSKConfigurationOwner) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{
		"AWS::ElastiCache::CacheCluster":          cfnCacheCacheCluster{commands},
		"AWS::ElastiCache::ReplicationGroup":      cfnCacheReplicationGroup{commands},
		"AWS::ElastiCache::User":                  cfnCacheUser{commands},
		"AWS::ElastiCache::UserGroup":             cfnCacheUserGroup{commands},
		"AWS::ElastiCache::ParameterGroup":        cfnCacheParameterGroup{commands},
		"AWS::ElastiCache::SubnetGroup":           cfnCacheSubnetGroup{commands},
		"AWS::MemoryDB::Cluster":                  cfnMemoryCluster{commands},
		"AWS::MemoryDB::User":                     cfnMemoryUser{commands},
		"AWS::MemoryDB::ACL":                      cfnMemoryACL{commands},
		"AWS::MemoryDB::ParameterGroup":           cfnMemoryParameterGroup{commands},
		"AWS::MemoryDB::SubnetGroup":              cfnMemorySubnetGroup{commands},
		"AWS::MemoryDB::Snapshot":                 cfnMemorySnapshot{commands},
		"AWS::OpenSearchService::Domain":          cfnOpenSearchDomain{commands},
		"AWS::Elasticsearch::Domain":              cfnElasticsearchDomain{commands},
		"AWS::MSK::Cluster":                       cfnMSKCluster{commands},
		"AWS::MSK::Configuration":                 cfnMSKConfiguration{commands, configurations},
		"AWS::MSK::BatchScramSecret":              cfnMSKBatchScramSecret{commands},
		"AWS::MSK::ClusterPolicy":                 cfnMSKClusterPolicy{commands},
		"AWS::AmazonMQ::Broker":                   cfnMQBroker{commands},
		"AWS::AmazonMQ::Configuration":            cfnMQConfiguration{commands},
		"AWS::AmazonMQ::ConfigurationAssociation": cfnMQConfigurationAssociation{commands},
	}
}

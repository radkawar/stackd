package rds

// GlobalScope deliberately has no Region: AWS global cluster ARNs and names are
// account/partition-global, even before any regional database joins them.
type GlobalScope struct {
	Partition, AccountID string
}

type GlobalKey struct {
	GlobalScope
	Name string
}

func (k GlobalKey) ARN() string {
	return k.resourceKey().ARN()
}

func (k GlobalKey) resourceKey() Key {
	return Key{Scope: Scope{Partition: k.Partition, AccountID: k.AccountID}, Kind: "global-cluster", Name: k.Name}
}

// GlobalCluster owns the genuine initially-empty AWS global database lifecycle.
// There is intentionally no member/source/endpoint state: admitting a regional
// member requires a real cross-region replication engine, not a metadata claim.
// StorageEncrypted is the future member configuration, not an allocated volume.
// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateGlobalCluster.html
// https://docs.aws.amazon.com/documentdb/latest/APIReference/API_CreateGlobalCluster.html
type GlobalCluster struct {
	Key                                                                     GlobalKey
	ResourceID, Engine, EngineVersion, DatabaseName, EngineLifecycleSupport string
	DeletionProtection, StorageEncrypted                                    bool
	Tags                                                                    map[string]string
}

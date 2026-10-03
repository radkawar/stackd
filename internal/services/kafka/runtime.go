package kafka

import "context"

// Runtime owns real Kafka processes. Calls run outside resource transactions.
// Close detaches; Delete must verify the complete immutable native ownership.
type Runtime interface {
	Ensure(context.Context, Specification) (Endpoint, error)
	Status(context.Context, Specification) (Endpoint, error)
	Reboot(context.Context, Specification, int32) (Endpoint, error)
	Delete(context.Context, Specification) error
	Close() error
}

type Specification struct {
	ARN, Incarnation, Partition, AccountID, Region string
	Brokers                                        int32
	KafkaVersion, ServerProperties, SecurityMode   string
	Users                                          []SCRAMUser
}
type SCRAMUser struct{ Username, Password string }
type Broker struct {
	ID      int32
	Address string
}
type Endpoint struct {
	Brokers      []Broker
	CAPEM        []byte
	SecurityMode string
}

// Secrets resolves current secret versions and KMS authority without retaining
// password material in cluster state. ResolveSCRAM uses the calling principal;
// LoadSCRAM is restricted to the cluster's service-owned association.
type Secrets interface {
	ResolveSCRAM(context.Context, string, string) (SCRAMUser, error)
	LoadSCRAM(context.Context, string, string) (SCRAMUser, error)
	// Policy association changes join the caller's shared resource transaction.
	AssociateSCRAM(context.Context, string, string) error
	ReleaseSCRAM(context.Context, string, string) error
}

// ClusterDescribePermission selects the consumer's required describe authority.
// Lambda permits either API version; Pipes requires DescribeClusterV2.
type ClusterDescribePermission uint8

const (
	RequireDescribeClusterV2 ClusterDescribePermission = iota + 1
	AllowEitherDescribeCluster
)

// ClusterConnection is an authorized current endpoint, not a credential cache.
type ClusterConnection struct {
	ARN, Incarnation string
	Brokers          []string
	TLS              bool
	ServerCAPEM      []byte
	SASLMechanism    string
}

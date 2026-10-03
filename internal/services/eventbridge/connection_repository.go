package eventbridge

import (
	"context"
	"time"

	"stackd/internal/awswire"
)

// ConnectionSecrets is the sole credential store. Implementations join repository
// transactions for mutations and authenticate the actual EventBridge linked role.
type ConnectionSecrets interface {
	Create(ctx context.Context, connectionARN, name, keyID, value string) (string, *awswire.Error)
	Update(ctx context.Context, connectionARN, secretARN string, keyID *string, value string) *awswire.Error
	Delete(ctx context.Context, connectionARN, secretARN string) *awswire.Error
	ReadOwned(ctx context.Context, connectionARN, secretARN string) (string, *awswire.Error)
	ReadForInvocation(context.Context, string) (string, *awswire.Error)
}

type ConnectionKey struct {
	Scope
	Name string
}

// ConnectionParameter is public metadata, not a credential copy. Secret values
// MUST be empty; their actual values exist only in the managed secret.
type ConnectionParameter struct {
	Target, Location, Key, Value string
	Secret                       bool
}

type ConnectionRecord struct {
	Key                                                                ConnectionKey
	ID, Description, AuthorizationType, State, StateReason             string
	SecretARN, KmsKeyIdentifier                                        string
	Username, APIKeyName, ClientID, AuthorizationEndpoint, OAuthMethod string
	HasAuth, HasInvocation, HasOAuthHTTP                               bool
	Parameters                                                         []ConnectionParameter
	Created, Modified, LastAuthorized, Due                             time.Time
	Version                                                            uint64
}

func (v ConnectionRecord) ARN() string {
	return "arn:" + v.Key.Partition + ":events:" + v.Key.Region + ":" + v.Key.Account + ":connection/" + v.Key.Name + "/" + v.ID
}

type ConnectionReader interface {
	Connection(ConnectionKey) (ConnectionRecord, error)
	ConnectionByID(string) (ConnectionRecord, error)
	Connections(Scope) ([]ConnectionRecord, error)
	NextConnectionJob() (ConnectionRecord, bool, error)
	ConnectionARNs(string, string) ([]string, error)
}
type ConnectionWriter interface {
	PutConnection(ConnectionRecord) error
	DeleteConnection(ConnectionKey) error
}

// WithConnectionRoleUsage fences linked-role deletion against Connection changes.
func (s *Service) WithConnectionRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		arns, err := tx.ConnectionARNs(partition, account)
		if err != nil {
			return err
		}
		return fn(tx.Context(), arns)
	})
}

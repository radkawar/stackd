package eks

import (
	"context"
	"time"
)

// Addon retains accepted intent separately from the configuration last observed ready.
type Addon struct {
	Key                                                                    Key
	Name, ID, Version, AppliedVersion, Configuration, AppliedConfiguration string
	Status, Operation, Error, ErrorCode, ResolveConflicts, UpdateID        string
	ClientToken, RequestHash                                               string
	Tags                                                                   map[string]string
	Created, Modified, Due                                                 time.Time
	Generation                                                             int64
	Preserve                                                               bool
}

func (a Addon) ARN() string {
	return "arn:" + a.Key.Partition + ":eks:" + a.Key.Region + ":" + a.Key.AccountID + ":addon/" + a.Key.Name + "/" + a.Name + "/" + a.ID
}

type AddonReader interface {
	Addon(Key, string) (Addon, error)
	Addons(Key) ([]Addon, error)
}
type AddonTransaction interface {
	AddonReader
	PutAddon(Addon) error
	DeleteAddon(Key, string) error
}

// WorkloadRoles resolves current trust, subnet ownership and immutable role identity.
// Its implementation joins the existing IAM/EC2 owners, not a second evaluator.
type WorkloadRoles interface {
	ValidateFargateExecutionRole(context.Context, string, string) (string, error)
	ValidateFargateSubnets(context.Context, Key, string, []string) error
}

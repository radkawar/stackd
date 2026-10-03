package guardduty

import "context"

// IPListSource retains the IAM/S3 owners of list access. Policy changes join the
// caller's resource transaction and check its current IAM authority. Read uses
// the service-linked role and runs only outside GuardDuty transactions.
type IPListSource interface {
	PutPolicy(context.Context, IPList) error
	DeletePolicy(context.Context, IPList) error
	Read(context.Context, IPList) ([]byte, error)
}

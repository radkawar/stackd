package mq

import "context"

// ServiceLinkedRoles provisions protected roles using current caller authority.
// The IAM owner joins broker admission's transaction; existing roles are reused.
type ServiceLinkedRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

// WithMQRoleUsage holds a writable snapshot through IAM's deletion commit.
// All RabbitMQ brokers, including admitted creation and pending deletion, retain
// the account-wide role until their native resource has been removed.
func (s *Service) WithMQRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(r Transaction) error {
		brokers, err := r.AllBrokers()
		if err != nil {
			return err
		}
		var resources []string
		for _, broker := range brokers {
			if broker.Partition == partition && broker.AccountID == account && broker.Engine == "RABBITMQ" {
				resources = append(resources, broker.ARN)
			}
		}
		return fn(r.Context(), resources)
	})
}

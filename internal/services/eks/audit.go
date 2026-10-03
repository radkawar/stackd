package eks

import (
	"context"
	"errors"

	native "stackd/compute/eks"
	"stackd/journal"
)

// KubernetesAuditObserver consumes source-scoped native events in EKS's current
// transaction, independently of customer CloudWatch logging configuration.
type KubernetesAuditObserver interface {
	ObserveKubernetesAudit(context.Context, journal.Envelope, []journal.KubernetesAuditObserved) error
}

type clusterAuditSink struct {
	service *Service
	key     Key
	id      string
}

func (s *Service) runtimeAuditSink(c Cluster) native.AuditSink {
	if s.audit == nil {
		return nil
	}
	return clusterAuditSink{s, c.Key, c.ID}
}
func (sink clusterAuditSink) PutKubernetesAudit(ctx context.Context, id string, events []journal.KubernetesAuditObserved) error {
	if id != sink.id {
		return errors.New("EKS audit source incarnation mismatch")
	}
	return sink.service.repository.Update(ctx, func(tx Transaction) error {
		cluster, err := tx.Cluster(sink.key)
		if err != nil {
			return err
		}
		if cluster.ID != id || cluster.Status == "DELETING" {
			return ErrNotFound
		}
		for i := range events {
			events[i].ClusterARN = cluster.Key.ARN()
			events[i].ClusterName = cluster.Key.Name
			events[i].ClusterID = id
		}
		envelope := journal.Envelope{Partition: sink.key.Partition, AccountID: sink.key.AccountID, Region: sink.key.Region, At: sink.service.clock.Now().UTC(), ActorService: "eks.amazonaws.com"}
		return sink.service.audit.ObserveKubernetesAudit(tx.Context(), envelope, events)
	})
}

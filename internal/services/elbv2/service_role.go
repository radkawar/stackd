package elbv2

import (
	"context"
	"slices"
)

const ServicePrincipal = "elasticloadbalancing.amazonaws.com"

type LoadBalancerDependency struct{ Region, ARN string }

// WithLoadBalancerRoleUsage holds resource ownership stable while IAM decides
// linked-role deletion. Deleting balancers retain usage until native nodes and
// requester-managed network interfaces have actually been removed.
func (s *Service) WithLoadBalancerRoleUsage(ctx context.Context, partition, accountID string, fn func(context.Context, []LoadBalancerDependency) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		records, err := tx.LoadBalancers(Scope{})
		if err != nil {
			return err
		}
		var dependencies []LoadBalancerDependency
		for _, record := range records {
			if record.Partition == partition && record.AccountID == accountID {
				dependencies = append(dependencies, LoadBalancerDependency{Region: record.Region, ARN: value(record.Data.LoadBalancerArn)})
			}
		}
		slices.SortFunc(dependencies, func(a, b LoadBalancerDependency) int {
			if a.Region < b.Region {
				return -1
			}
			if a.Region > b.Region {
				return 1
			}
			if a.ARN < b.ARN {
				return -1
			}
			if a.ARN > b.ARN {
				return 1
			}
			return 0
		})
		return fn(tx.Context(), dependencies)
	})
}

// Start recovers retained native attachment and listener intent. Assembly invokes
// it only after dependencies and API endpoints are fully configured.
func (s *Service) Start() error {
	if s.dns != nil || s.runtime.native != nil {
		if err := s.RegisterDNS(context.Background()); err != nil {
			return err
		}
	}
	s.runtime.jobs.Start()
	s.runtime.jobs.Wake()
	return nil
}

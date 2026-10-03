package acm

import (
	"context"
	"errors"
	"stackd/internal/scheduler"
	"strings"
	"time"
)

func (s *Service) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var selected scheduler.Job
	found := false
	e := s.repository.View(ctx, func(r Reader) error {
		all, e := r.Certificates()
		if e != nil {
			return e
		}
		for _, c := range all {
			if c.NextCheck.IsZero() {
				continue
			}
			if !found || c.NextCheck.Before(selected.Due) || (c.NextCheck.Equal(selected.Due) && c.ARN < selected.Key) {
				selected = scheduler.Job{Key: c.ARN, Version: c.Version, Due: c.NextCheck}
				found = true
			}
		}
		return nil
	})
	return selected, found, e
}
func canonicalDNS(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) + "." }

// TODO: Comeback evaluate CAA policy and authenticated DNSSEC through the DNS owner;
// this local authority currently proves only the required public CNAMEs.
func (s *Service) validated(ctx context.Context, v Validation) bool {
	if s.dns == nil {
		return false
	}
	name := v.Name
	for range 5 {
		target, e := s.dns.LookupCNAME(ctx, name)
		if e != nil {
			return false
		}
		target = canonicalDNS(target)
		if target == canonicalDNS(v.Value) {
			return true
		}
		if target == canonicalDNS(name) {
			return false
		}
		name = target
	}
	return false
}

// Run performs DNS and private-key generation outside storage transactions and fences its result by certificate version.
func (s *Service) Run(ctx context.Context, job scheduler.Job) error {
	var before CertificateRecord
	var eligible bool
	now := s.clock.Now()
	e := s.repository.View(ctx, func(r Reader) error {
		var e error
		before, e = r.Certificate(job.Key)
		if e != nil {
			return e
		}
		if before.Version != job.Version || before.NextCheck.IsZero() || before.NextCheck.After(now) {
			return nil
		}
		users, e := s.users(r, before)
		if e != nil {
			return e
		}
		eligible = s.eligible(before, users)
		return nil
	})
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if before.Version != job.Version || before.NextCheck.IsZero() || before.NextCheck.After(now) {
		return nil
	}
	next := before
	status := s.currentStatus(before)
	switch status {
	case "VALIDATION_TIMED_OUT":
		next.Status = status
		next.NextCheck = time.Time{}
		for i := range next.Validations {
			if next.Validations[i].Status != "SUCCESS" {
				next.Validations[i].Status = "FAILED"
			}
		}
	case "EXPIRED":
		next.Status = status
		next.NextCheck = time.Time{}
		if next.RenewalStatus != "" && next.RenewalStatus != "SUCCESS" {
			next.RenewalStatus = "FAILED"
			next.RenewalUpdated = now
		}
	case "ISSUED", "PENDING_VALIDATION":
		renewal := status == "ISSUED"
		if renewal && (!eligible || before.Type != "AMAZON_ISSUED") {
			next.NextCheck = now.Add(24 * time.Hour)
			if next.NextCheck.After(next.NotAfter) {
				next.NextCheck = next.NotAfter
			}
			break
		}
		all := true
		next.Validations = append([]Validation(nil), before.Validations...)
		for i, v := range next.Validations {
			if s.validated(ctx, v) {
				next.Validations[i].Status = "SUCCESS"
			} else {
				next.Validations[i].Status = "PENDING_VALIDATION"
				all = false
			}
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if all {
			a, e := s.authority(ctx)
			if e != nil {
				return e
			}
			next, e = issue(next, a, now)
			if e != nil {
				return e
			}
			if renewal {
				next.RenewalStatus = "SUCCESS"
				next.RenewalUpdated = now
			}
		} else {
			next.NextCheck = now.Add(validationPoll)
			deadline := next.ValidationDeadline
			if renewal {
				deadline = next.NotAfter
				next.RenewalStatus = "PENDING_VALIDATION"
				next.RenewalUpdated = now
			}
			if next.NextCheck.After(deadline) {
				next.NextCheck = deadline
			}
		}
	default:
		next.NextCheck = time.Time{}
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		current, e := tx.Certificate(before.ARN)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if current.Version != before.Version {
			return nil
		}
		if len(next.CertificatePEM) > 0 && next.MaterialVersion > before.MaterialVersion {
			if s.currentStatus(current) != status {
				return nil
			}
			if status == "ISSUED" {
				users, e := s.users(tx, current)
				if e != nil {
					return e
				}
				if !s.eligible(current, users) {
					return nil
				}
			}
		}
		next.Version++
		return tx.PutCertificate(next)
	})
}

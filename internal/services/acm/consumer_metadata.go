package acm

import "context"

// CertificateType exposes provenance to trusted service consumers without
// granting a general certificate read or following a replaced ARN incarnation.
func (s *Service) CertificateType(ctx context.Context, scope Scope, arn, id string) (string, error) {
	var certificateType string
	err := s.repository.View(ctx, func(r Reader) error {
		record, err := r.Certificate(arn)
		if err != nil {
			return err
		}
		now := s.clock.Now()
		if record.Scope != scope || record.ID != id || record.Status != "ISSUED" || now.Before(record.NotBefore) || !now.Before(record.NotAfter) {
			return ErrNotFound
		}
		certificateType = record.Type
		return nil
	})
	return certificateType, err
}

package iam

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"time"
)

// ServerCertificateForTLS supplies a detached, usable certificate and private
// key only through this internal deployment interface, never through IAM wire APIs.
func (s *Service) ServerCertificateForTLS(ctx context.Context, scope Scope, arn string) (tls.Certificate, error) {
	prefix := "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":server-certificate/"
	if scope.AccountID == "" || scope.Partition == "" || !strings.HasPrefix(arn, prefix) {
		return tls.Certificate{}, ErrInvalidServerCertificate
	}
	return s.serverCertificateForTLS(ctx, scope, arn, "")
}

// CertificateID resolves an ARN at admission. Existing deployments retain this
// immutable identity so an IAM rename cannot replace their TLS material.
func (s *Service) CertificateID(ctx context.Context, scope Scope, arn string) (string, error) {
	prefix := "arn:" + scope.Partition + ":iam::" + scope.AccountID + ":server-certificate/"
	if scope.AccountID == "" || scope.Partition == "" || !strings.HasPrefix(arn, prefix) {
		return "", ErrInvalidServerCertificate
	}
	var id string
	err := s.viewAt(ctx, func(tx ReadTx, _ time.Time) error {
		name := arn[strings.LastIndex(arn, "/")+1:]
		record, err := tx.ServerCertificate(scope, name)
		if err != nil {
			return err
		}
		if record.ARN != arn {
			return ErrInvalidServerCertificate
		}
		id = record.ID
		return nil
	})
	if errors.Is(err, ErrRecordNotFound) {
		err = ErrInvalidServerCertificate
	}
	return id, err
}

// ServerCertificateForTLSByID supplies the current IAM-owned material of an
// existing deployment, including after a name/path change. An ID from another
// account or partition cannot resolve through this scope.
func (s *Service) ServerCertificateForTLSByID(ctx context.Context, scope Scope, id string) (tls.Certificate, error) {
	if scope.Partition == "" || scope.AccountID == "" || id == "" {
		return tls.Certificate{}, ErrInvalidServerCertificate
	}
	return s.serverCertificateForTLS(ctx, scope, "", id)
}

func (s *Service) serverCertificateForTLS(ctx context.Context, scope Scope, arn, id string) (tls.Certificate, error) {
	var result tls.Certificate
	err := s.viewAt(ctx, func(tx ReadTx, now time.Time) error {
		records, err := tx.ServerCertificates(scope)
		if err != nil {
			return err
		}
		for _, r := range records {
			if (id != "" && r.ID == id) || (id == "" && r.ARN == arn) {
				if !now.Before(r.Expiration) {
					return ErrInvalidServerCertificate
				}
				result, err = tls.X509KeyPair([]byte(r.Body+"\n"+r.Chain), r.PrivateKey)
				return err
			}
		}
		return ErrRecordNotFound
	})
	if errors.Is(err, ErrRecordNotFound) {
		err = ErrInvalidServerCertificate
	}
	return result, err
}

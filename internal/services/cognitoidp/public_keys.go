package cognitoidp

import (
	"context"
	"crypto/rsa"

	"stackd/internal/awsctx"
	"stackd/internal/jwt"
)

// PublicSigningKeys reads a pool's public issuer material in the request's
// partition and region, returning its authoritative resource ARN alongside the
// keys. This public lookup does not check sessions, revocation or client access.
func (s *Service) PublicSigningKeys(ctx context.Context, poolID string) (jwt.KeySet, string, error) {
	metadata := awsctx.FromContext(ctx)
	var result jwt.KeySet
	var resource string
	err := s.repository.View(ctx, func(reader Reader) error {
		pool, err := reader.PoolByID(metadata.Partition, metadata.Region, poolID)
		if err != nil {
			return err
		}
		resource = pool.Key.ARN()
		stored, err := reader.SigningKeys(pool.Key)
		if err != nil {
			return err
		}
		result = jwt.KeySet{Issuer: pool.IssuerURL, Keys: make(map[string]*rsa.PublicKey, 2)}
		for _, material := range []SigningKey{stored.Access, stored.ID} {
			private, err := signingPrivate(material)
			if err != nil {
				return err
			}
			result.Keys[material.ID] = &private.PublicKey
		}
		return nil
	})
	return result, resource, err
}

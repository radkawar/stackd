package identity

import "context"

// AccessKeysPerPrincipalQuota includes active and inactive long-term keys.
const AccessKeysPerPrincipalQuota = 2

// CreateAccessKey atomically enforces the two-key quota, including inactive keys.
func (s *Store) CreateAccessKey(p Principal) (Credential, error) {
	if !validPrincipal(p) {
		return Credential{}, ErrInvalidPrincipal
	}
	var c Credential
	err := s.repository.Update(context.Background(), func(tx Transaction) error {
		instant := s.now()
		records, err := tx.FindPrincipal(p.AccountID, p.ID)
		if err != nil {
			return err
		}
		count := 0
		for _, r := range records {
			if samePrincipal(r.Credential, p.AccountID, p.ID) && r.Credential.SessionToken == "" {
				count++
			}
		}
		if count >= AccessKeysPerPrincipalQuota {
			return ErrLimitExceeded
		}
		c, err = newCredential(p, "AKIA", instant)
		if err != nil {
			return err
		}
		return putNew(tx, c)
	})
	if err != nil {
		return Credential{}, err
	}
	return c, nil
}

func (s *Store) ListAccessKeys(accountID, id string) ([]AccessKey, error) {
	keys := make([]AccessKey, 0)
	err := s.repository.View(context.Background(), func(reader Reader) error {
		records, err := reader.FindPrincipal(accountID, id)
		if err != nil {
			return err
		}
		for _, r := range records {
			if samePrincipal(r.Credential, accountID, id) && r.Credential.SessionToken == "" {
				keys = append(keys, accessKeyMetadata(r))
			}
		}
		return nil
	})
	sortKeys(keys)
	return keys, err
}

func (s *Store) UpdateAccessKey(accountID, id, key string, status Status) error {
	if status != Active && status != Inactive {
		return ErrInvalidPrincipal
	}
	return s.repository.Update(context.Background(), func(tx Transaction) error {
		r, err := ownedKey(tx, accountID, id, key)
		if err != nil {
			return err
		}
		r.Status = status
		return tx.Put(r)
	})
}

func (s *Store) DeleteAccessKey(accountID, id, key string) error {
	return s.repository.Update(context.Background(), func(tx Transaction) error {
		if _, err := ownedKey(tx, accountID, id, key); err != nil {
			return err
		}
		return tx.Delete(key)
	})
}

func (s *Store) AccessKeyLastUsed(accountID, key string) (AccessKey, LastUsed, error) {
	var r Record
	err := s.repository.View(context.Background(), func(reader Reader) error {
		var err error
		r, err = reader.Get(key)
		if err != nil {
			return err
		}
		if r.Credential.AccountID != accountID || r.Credential.SessionToken != "" {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return AccessKey{}, LastUsed{}, err
	}
	return accessKeyMetadata(r), r.LastUsed, nil
}

func ownedKey(r Reader, accountID, id, key string) (Record, error) {
	record, err := r.Get(key)
	if err != nil {
		return Record{}, err
	}
	if !samePrincipal(record.Credential, accountID, id) || record.Credential.SessionToken != "" {
		return Record{}, ErrNotFound
	}
	return record, nil
}

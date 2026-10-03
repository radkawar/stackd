package eks

import (
	"errors"

	"github.com/google/uuid"
)

func validAuthenticationMode(mode string) bool {
	return mode == "CONFIG_MAP" || mode == "API_AND_CONFIG_MAP" || mode == "API"
}

// Authentication migrations cannot remove access entries or reenable aws-auth.
func authenticationModeTransition(from, to string) bool {
	return from == "CONFIG_MAP" && (to == "API_AND_CONFIG_MAP" || to == "API") || from == "API_AND_CONFIG_MAP" && to == "API"
}

// Enabling API access migrates only the original bootstrap creator. ConfigMap
// mappings remain native Kubernetes state and never become implicit API entries.
func (s *Service) createBootstrapEntry(tx Transaction, c Cluster) error {
	if !c.BootstrapAdmin {
		return nil
	}
	if _, err := tx.AccessEntry(c.Key, c.CreatorARN); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	now := s.clock.Now()
	entry := AccessEntry{Key: c.Key, ID: uuid.NewString(), PrincipalARN: c.CreatorARN, PrincipalID: c.CreatorID, Username: defaultUsername(c.CreatorARN), Type: "STANDARD", Created: now, Modified: now}
	if err := tx.PutAccessEntry(entry); err != nil {
		return err
	}
	return tx.PutAccessPolicy(AccessPolicy{Key: c.Key, PrincipalARN: c.CreatorARN, PolicyARN: policyARN(c.Key.Partition, "AmazonEKSClusterAdminPolicy"), ScopeType: "cluster", Associated: now, Modified: now})
}

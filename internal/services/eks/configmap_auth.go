package eks

import (
	"context"
	"errors"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
	native "stackd/compute/eks"
	"stackd/internal/awsctx"
)

// EKSNodeNames resolves the real EC2 name used by aws-auth node templates.
// Arguments are account, region and the authenticated role session's instance ID.
type EKSNodeNames interface {
	ResolveNodePrivateDNS(context.Context, string, string, string) (string, error)
}

// kubernetesIdentity gives a retained API entry precedence even when its IAM
// incarnation is stale. A stale entry must never fall through to a ConfigMap.
func (s *Service) kubernetesIdentity(ctx context.Context, key Key, id string, m awsctx.Metadata, data map[string]string, configRead bool) (native.Identity, Cluster, bool, error) {
	principal, principalID := principalIdentity(m)
	var identity native.Identity
	var cluster Cluster
	needsConfigMap := false
	err := s.repository.View(ctx, func(tx Reader) error {
		var err error
		cluster, err = tx.Cluster(key)
		if err != nil {
			return err
		}
		if cluster.ID != id || (cluster.Status != "ACTIVE" && cluster.Status != "UPDATING") || m.Partition != key.Partition {
			return ErrNotFound
		}
		if principalID == "" || !strings.HasPrefix(principal, "arn:"+key.Partition+":iam::") {
			return errors.New("invalid IAM identity")
		}
		// ConfigMap mappings intentionally bind reusable ARNs, unlike access
		// entries. Both methods still require an existing, current IAM identity.
		if !strings.HasSuffix(principal, ":root") {
			if s.principals == nil {
				return errors.New("IAM authority unavailable")
			}
			current, err := s.principals.ResolvePrincipal(tx.Context(), principal)
			if err != nil || current != principalID {
				return errors.New("IAM principal no longer exists")
			}
		}
		if cluster.AuthenticationMode == "API" || cluster.AuthenticationMode == "API_AND_CONFIG_MAP" {
			entry, err := tx.AccessEntry(key, principal)
			if err == nil {
				if entry.PrincipalID == "" || entry.PrincipalID != principalID {
					return errors.New("principal incarnation mismatch")
				}
				identity = native.Identity{Username: sessionUsername(entry.Username, m), Groups: slices.Clone(entry.Groups)}
				policies, err := tx.AccessPolicies(key, principal)
				if err != nil {
					return err
				}
				for _, policy := range policies {
					role, ok := policyRole(key.Partition, policy.PolicyARN)
					if !ok {
						return errors.New("unsupported retained access policy")
					}
					identity.Grants = append(identity.Grants, native.Grant{Role: role, Namespaces: slices.Clone(policy.Namespaces)})
				}
				return nil
			}
			if !errors.Is(err, ErrNotFound) || cluster.AuthenticationMode == "API" {
				return err
			}
		}
		if cluster.AuthenticationMode != "CONFIG_MAP" && cluster.AuthenticationMode != "API_AND_CONFIG_MAP" {
			return errors.New("invalid authentication mode")
		}
		// Enabling the API migrates this grant to an ordinary revocable access
		// entry. It must not reappear as hidden authority after entry deletion.
		if cluster.AuthenticationMode == "CONFIG_MAP" && cluster.BootstrapAdmin && cluster.CreatorARN == principal && cluster.CreatorID == principalID {
			identity = native.Identity{Username: sessionUsername(defaultUsername(principal), m), Groups: []string{"system:masters"}}
			return nil
		}
		needsConfigMap = true
		return nil
	})
	if err == nil && needsConfigMap && configRead {
		identity, err = s.configMapIdentity(ctx, key, principal, m, data)
	}
	if err == nil && identity.Username != "" {
		account, _, _ := strings.Cut(strings.TrimPrefix(principal, "arn:"+key.Partition+":iam::"), ":")
		identity.UID = "aws-iam-authenticator:" + account + ":" + principalID
		identity.Extra = map[string][]string{"arn": {m.PrincipalARN}}
	}
	return identity, cluster, needsConfigMap, err
}

type awsAuthMapping struct {
	RoleARN  string   `yaml:"rolearn"`
	UserARN  string   `yaml:"userarn"`
	Username string   `yaml:"username"`
	Groups   []string `yaml:"groups"`
}

func (s *Service) configMapIdentity(ctx context.Context, key Key, principal string, m awsctx.Metadata, data map[string]string) (native.Identity, error) {
	canonical := configMapPrincipal(principal)
	field := "mapUsers"
	role := strings.Contains(principal, ":role/")
	if role {
		field = "mapRoles"
	}
	var mappings []awsAuthMapping
	if err := yaml.Unmarshal([]byte(data[field]), &mappings); err != nil {
		return native.Identity{}, err
	}
	for _, mapping := range mappings {
		arn := mapping.UserARN
		if role {
			arn = mapping.RoleARN
			// The IAM role may have a path; the ConfigMap key may not.
			if arn != configMapPrincipal(arn) {
				continue
			}
		}
		if !strings.EqualFold(arn, canonical) {
			continue
		}
		identity := native.Identity{Groups: make([]string, len(mapping.Groups))}
		var err error
		identity.Username, err = s.configMapTemplate(ctx, key, mapping.Username, m)
		if err != nil || identity.Username == "" {
			return native.Identity{}, errors.New("invalid aws-auth username")
		}
		for i, group := range mapping.Groups {
			identity.Groups[i], err = s.configMapTemplate(ctx, key, group, m)
			if err != nil {
				return native.Identity{}, err
			}
		}
		return identity, nil
	}
	var accounts []string
	if err := yaml.Unmarshal([]byte(data["mapAccounts"]), &accounts); err != nil {
		return native.Identity{}, err
	}
	parts := strings.SplitN(canonical, ":", 6)
	if len(parts) == 6 && slices.Contains(accounts, parts[4]) {
		return native.Identity{Username: canonical}, nil
	}
	return native.Identity{}, ErrNotFound
}

func configMapPrincipal(principal string) string {
	prefix, name, role := strings.Cut(principal, ":role/")
	if role {
		return prefix + ":role/" + name[strings.LastIndex(name, "/")+1:]
	}
	return principal
}

func (s *Service) configMapTemplate(ctx context.Context, key Key, template string, m awsctx.Metadata) (string, error) {
	value := sessionUsername(template, m)
	principal, _ := principalIdentity(m)
	parts := strings.SplitN(principal, ":", 6)
	if len(parts) != 6 {
		return "", errors.New("invalid aws-auth principal")
	}
	value = strings.ReplaceAll(value, "{{AccountID}}", parts[4])
	value = strings.ReplaceAll(value, "{{AccessKeyID}}", m.AccessKeyID)
	if strings.Contains(value, "{{EC2PrivateDNSName}}") {
		if s.nodeNames == nil || m.IssuerARN == "" {
			return "", errors.New("EC2 node identity authority unavailable")
		}
		instanceID := m.PrincipalARN[strings.LastIndex(m.PrincipalARN, "/")+1:]
		dns, err := s.nodeNames.ResolveNodePrivateDNS(ctx, parts[4], key.Region, instanceID)
		if err != nil || dns == "" {
			return "", errors.New("EC2 node identity not found")
		}
		value = strings.ReplaceAll(value, "{{EC2PrivateDNSName}}", dns)
	}
	return value, nil
}

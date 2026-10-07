package eks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awsctx"
)

func principalIdentity(m awsctx.Metadata) (string, string) {
	if m.SessionType == "AssumeRole" && strings.Contains(m.PrincipalARN, ":sts::") && strings.Contains(m.PrincipalARN, ":assumed-role/") && m.IssuerARN != "" {
		return m.IssuerARN, m.IssuerID
	}
	return m.PrincipalARN, m.PrincipalID
}
func validateAccessIdentity(username string, groups []string) error {
	for _, prefix := range []string{"system:", "eks:", "aws:", "amazon:", "iam:", "stackd:"} {
		if strings.HasPrefix(username, prefix) {
			return invalid("Username uses a reserved prefix.")
		}
	}
	for _, g := range groups {
		if g == "" || strings.HasPrefix(g, "system:") || strings.HasPrefix(g, "stackd:") {
			return invalid("Kubernetes group uses an empty or reserved name.")
		}
	}
	for _, placeholder := range []string{"{{SessionName}}", "{{SessionNameRaw}}"} {
		if before, _, ok := strings.Cut(username, placeholder); ok && !strings.Contains(before, ":") {
			return invalid("Session username templates require a preceding colon.")
		}
	}
	stripped := strings.ReplaceAll(strings.ReplaceAll(username, "{{SessionName}}", ""), "{{SessionNameRaw}}", "")
	if strings.Contains(stripped, "{{") {
		return invalid("Invalid username session template.")
	}
	return nil
}
func (s *Service) createAccessEntry(ctx context.Context, tx Transaction, in *api.CreateAccessEntryRequest) (*api.CreateAccessEntryResponse, error) {
	principal := value(in.PrincipalArn)
	typ := value(in.Type)
	if typ == "" {
		typ = "STANDARD"
	}
	tags := tagsFromAPI(in.Tags)
	conditions := tagConditions(tags)
	conditions["eks:principalArn"] = []string{principal}
	conditions["eks:accessEntryType"] = []string{typ}
	conditions["eks:username"] = []string{value(in.Username)}
	if len(in.KubernetesGroups) > 0 {
		conditions["eks:kubernetesGroups"] = stringsFromAPI(in.KubernetesGroups)
	}
	key := Key{scopeFor(ctx), value(in.ClusterName)}
	c, e := tx.Cluster(key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	if errors.Is(e, ErrNotFound) {
		c.Key = key
	}
	if denied := s.authorize(ctx, c, "CreateAccessEntry", conditions); denied != nil {
		return nil, denied
	}
	if e != nil {
		return nil, e
	}
	if e = requireAccessAPI(c); e != nil {
		return nil, e
	}
	if c.Status != "ACTIVE" {
		return nil, failure("ResourceInUseException", "Cluster is not active.", 409)
	}
	hash, e := requestHash(in)
	if e != nil {
		return nil, e
	}
	token := value(in.ClientRequestToken)
	if old, e := tx.AccessEntry(c.Key, principal); e == nil {
		if token != "" && old.ClientToken == token && old.RequestHash == hash {
			return &api.CreateAccessEntryResponse{AccessEntry: accessAPI(old)}, nil
		}
		return nil, failure("ResourceInUseException", "Access entry already exists.", 409)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	if typ != "STANDARD" {
		return nil, unsupported("Only STANDARD IAM access entries are implemented; native nodes use private runtime identity.")
	}
	if !strings.HasPrefix(principal, "arn:"+c.Key.Partition+":iam::") || !strings.Contains(principal, ":user/") && !strings.Contains(principal, ":role/") {
		return nil, invalid("principalArn must identify an IAM user or role.")
	}
	if strings.Contains(principal, ":role/aws-service-role/") {
		return nil, invalid("Service-linked roles cannot be used for EKS access entries.")
	}
	if s.principals == nil {
		return nil, unsupported("IAM principal authority is not configured.")
	}
	id, e := s.principals.ResolvePrincipal(ctx, principal)
	if e != nil {
		return nil, invalid("The specified IAM principal is invalid.")
	}
	username := value(in.Username)
	if e = validateAccessIdentity(username, stringsFromAPI(in.KubernetesGroups)); e != nil {
		return nil, e
	}
	if username == "" {
		username = defaultUsername(principal)
	}
	if e = validateTags(tags); e != nil {
		return nil, e
	}
	now := s.clock.Now()
	a := AccessEntry{Key: c.Key, ID: uuid.NewString(), PrincipalARN: principal, PrincipalID: id, Username: username, Type: typ, Groups: stringsFromAPI(in.KubernetesGroups), Tags: tags, Created: now, Modified: now, ClientToken: token, RequestHash: hash}
	if e = tx.PutAccessEntry(a); e != nil {
		return nil, e
	}
	return &api.CreateAccessEntryResponse{AccessEntry: accessAPI(a)}, nil
}
func (s *Service) accessForAction(ctx context.Context, tx Reader, name, principal, action string, active bool, conditions map[string][]string) (Cluster, AccessEntry, error) {
	key := Key{scopeFor(ctx), name}
	c, clusterErr := tx.Cluster(key)
	if clusterErr != nil && !errors.Is(clusterErr, ErrNotFound) {
		return c, AccessEntry{}, clusterErr
	}
	a, entryErr := tx.AccessEntry(key, principal)
	if entryErr != nil && !errors.Is(entryErr, ErrNotFound) {
		return c, a, entryErr
	}
	if errors.Is(entryErr, ErrNotFound) {
		a = AccessEntry{Key: key, PrincipalARN: principal, ID: "*"}
	}
	if denied := s.authorizeResource(ctx, accessARN(a), a.Tags, action, conditions); denied != nil {
		return c, a, denied
	}
	if clusterErr != nil {
		return c, a, clusterErr
	}
	if err := requireAccessAPI(c); err != nil {
		return c, a, err
	}
	if entryErr != nil {
		return c, a, entryErr
	}
	if active && c.Status != "ACTIVE" {
		return c, a, failure("ResourceInUseException", "Cluster is not active.", 409)
	}
	return c, a, nil
}
func (s *Service) describeAccessEntry(ctx context.Context, tx Transaction, in *api.DescribeAccessEntryRequest) (*api.DescribeAccessEntryResponse, error) {
	_, a, e := s.accessForAction(ctx, tx, value(in.ClusterName), value(in.PrincipalArn), "DescribeAccessEntry", false, nil)
	if e != nil {
		return nil, e
	}
	return &api.DescribeAccessEntryResponse{AccessEntry: accessAPI(a)}, nil
}
func (s *Service) updateAccessEntry(ctx context.Context, tx Transaction, in *api.UpdateAccessEntryRequest) (*api.UpdateAccessEntryResponse, error) {
	conditions := map[string][]string{"eks:username": {value(in.Username)}}
	if len(in.KubernetesGroups) > 0 {
		conditions["eks:kubernetesGroups"] = stringsFromAPI(in.KubernetesGroups)
	}
	_, a, e := s.accessForAction(ctx, tx, value(in.ClusterName), value(in.PrincipalArn), "UpdateAccessEntry", true, conditions)
	if e != nil {
		return nil, e
	}
	token := value(in.ClientRequestToken)
	hash, e := requestHash(in)
	if e != nil {
		return nil, e
	}
	if token != "" {
		prior, e := tx.AccessMutation(a.Key, a.PrincipalARN, token)
		if e == nil {
			if prior.RequestHash != hash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &api.UpdateAccessEntryResponse{AccessEntry: accessAPI(a)}, nil
		}
		if !errors.Is(e, ErrNotFound) {
			return nil, e
		}
	}
	if in.Username != nil {
		a.Username = value(in.Username)
	}
	if in.KubernetesGroups != nil {
		a.Groups = stringsFromAPI(in.KubernetesGroups)
	}
	if e = validateAccessIdentity(a.Username, a.Groups); e != nil {
		return nil, e
	}
	a.Modified = s.clock.Now()
	if e = tx.PutAccessEntry(a); e != nil {
		return nil, e
	}
	if token != "" {
		if e = tx.PutAccessMutation(AccessMutation{Key: a.Key, PrincipalARN: a.PrincipalARN, Token: token, RequestHash: hash}); e != nil {
			return nil, e
		}
	}
	return &api.UpdateAccessEntryResponse{AccessEntry: accessAPI(a)}, nil
}
func (s *Service) deleteAccessEntry(ctx context.Context, tx Transaction, in *api.DeleteAccessEntryRequest) (*api.DeleteAccessEntryResponse, error) {
	c, _, e := s.accessForAction(ctx, tx, value(in.ClusterName), value(in.PrincipalArn), "DeleteAccessEntry", true, nil)
	if e != nil {
		return nil, e
	}
	if e = tx.DeleteAccessEntry(c.Key, value(in.PrincipalArn)); e != nil {
		return nil, e
	}
	return &api.DeleteAccessEntryResponse{}, nil
}
func (s *Service) listAccessEntries(ctx context.Context, tx Transaction, in *api.ListAccessEntriesRequest) (*api.ListAccessEntriesResponse, error) {
	c, e := s.load(ctx, tx, value(in.ClusterName), "ListAccessEntries")
	if e != nil {
		return nil, e
	}
	if e = requireAccessAPI(c); e != nil {
		return nil, e
	}
	all, e := tx.AccessEntries(c.Key)
	if e != nil {
		return nil, e
	}
	names := []string{}
	for _, a := range all {
		if filter := value(in.AssociatedPolicyArn); filter != "" {
			policies, e := tx.AccessPolicies(c.Key, a.PrincipalARN)
			if e != nil {
				return nil, e
			}
			found := false
			for _, p := range policies {
				if p.PolicyARN == filter {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		names = append(names, a.PrincipalARN)
	}
	page, next, e := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), c.Key.ARN()+"/entries/"+value(in.AssociatedPolicyArn))
	if e != nil {
		return nil, e
	}
	return &api.ListAccessEntriesResponse{AccessEntries: stringsToAPI(page), NextToken: next}, nil
}
func accessARN(a AccessEntry) string {
	parts := strings.SplitN(a.PrincipalARN, ":", 6)
	kind, name := "root", "root"
	account := a.Key.AccountID
	if len(parts) == 6 {
		account = parts[4]
		if k, n, ok := strings.Cut(parts[5], "/"); ok {
			kind, name = k, n
		}
	}
	id := a.ID
	if id == "" {
		h := sha256.Sum256([]byte(a.PrincipalID))
		id = hex.EncodeToString(h[:16])
	}
	return "arn:" + a.Key.Partition + ":eks:" + a.Key.Region + ":" + a.Key.AccountID + ":access-entry/" + a.Key.Name + "/" + kind + "/" + account + "/" + name + "/" + id
}
func defaultUsername(principal string) string {
	parts := strings.SplitN(principal, ":", 6)
	if len(parts) == 6 && strings.HasPrefix(parts[5], "role/") {
		name := parts[5][strings.LastIndex(parts[5], "/")+1:]
		return "arn:" + parts[1] + ":sts::" + parts[4] + ":assumed-role/" + name + "/{{SessionName}}"
	}
	return principal
}
func sessionUsername(template string, m awsctx.Metadata) string {
	session := ""
	if m.IssuerARN != "" {
		session = m.PrincipalARN[strings.LastIndex(m.PrincipalARN, "/")+1:]
	}
	return strings.ReplaceAll(strings.ReplaceAll(template, "{{SessionNameRaw}}", session), "{{SessionName}}", strings.ReplaceAll(session, "@", "-"))
}
func accessAPI(a AccessEntry) *api.AccessEntry {
	return &api.AccessEntry{AccessEntryArn: new(api.String(accessARN(a))), ClusterName: new(api.String(a.Key.Name)), PrincipalArn: new(api.String(a.PrincipalARN)), Username: new(api.String(a.Username)), Type: new(api.String(a.Type)), KubernetesGroups: stringsToAPI(a.Groups), Tags: tagsToAPI(a.Tags), CreatedAt: new(a.Created), ModifiedAt: new(a.Modified)}
}

func requireAccessAPI(c Cluster) error {
	if c.AuthenticationMode != "API" && c.AuthenticationMode != "API_AND_CONFIG_MAP" {
		return invalid("The cluster's authentication mode must be set to one of [API, API_AND_CONFIG_MAP] to perform this operation.")
	}
	return nil
}

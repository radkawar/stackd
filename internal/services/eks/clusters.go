package eks

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	native "stackd/compute/eks"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awsctx"
)

var clusterName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)

func (s *Service) createCluster(ctx context.Context, tx Transaction, in *api.CreateClusterRequest) (*api.CreateClusterResponse, error) {
	name := value(in.Name)
	c := Cluster{Key: Key{scopeFor(ctx), name}, Tags: tagsFromAPI(in.Tags)}
	if !clusterName.MatchString(name) {
		return nil, invalid("Invalid cluster name.")
	}
	if e := validateTags(c.Tags); e != nil {
		return nil, e
	}
	if e := s.authorize(ctx, c, "CreateCluster", tagConditions(c.Tags)); e != nil {
		return nil, e
	}
	hash, e := requestHash(in)
	if e != nil {
		return nil, e
	}
	token := value(in.ClientRequestToken)
	if old, e := tx.Cluster(c.Key); e == nil {
		if token != "" && old.ClientToken == token {
			if old.RequestHash != hash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &api.CreateClusterResponse{Cluster: clusterAPI(old)}, nil
		}
		return nil, failure("ResourceInUseException", "Cluster already exists with name: "+name, 409)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	if s.runtime == nil || s.authenticate == nil || s.networks == nil || s.principals == nil || s.serviceLinkedRoles == nil {
		return nil, unsupported("A configured Kubernetes runtime, IAM authenticator and dependency owners are required.")
	}
	c.AuthenticationMode = "CONFIG_MAP"
	c.BootstrapAdmin = true
	if in.AccessConfig != nil {
		if mode := value(in.AccessConfig.AuthenticationMode); mode != "" {
			c.AuthenticationMode = mode
		}
		if in.AccessConfig.BootstrapClusterCreatorAdminPermissions != nil {
			c.BootstrapAdmin = bool(*in.AccessConfig.BootstrapClusterCreatorAdminPermissions)
		}
	}
	if !validAuthenticationMode(c.AuthenticationMode) {
		return nil, invalid("Invalid authentication mode.")
	}
	if c.AuthenticationMode == "CONFIG_MAP" && !c.BootstrapAdmin {
		return nil, invalid("bootstrapClusterCreatorAdminPermissions must be true if cluster authentication mode is set to CONFIG_MAP")
	}
	// TODO: Comeback implement VPC/CNI, encryption, auto-mode and custom
	// control-plane configuration through their native dependency owners.
	if in.ComputeConfig != nil || in.ControlPlaneScalingConfig != nil || len(in.EncryptionConfig) > 0 || in.KubeApiServerConfig != nil || in.KubeControllerManagerConfig != nil || in.KubeSchedulerConfig != nil || in.KubernetesNetworkConfig != nil || in.OutpostConfig != nil || in.RemoteNetworkConfig != nil || in.StorageConfig != nil || in.UpgradePolicy != nil || in.ZonalShiftConfig != nil || in.BootstrapSelfManagedAddons != nil {
		return nil, unsupported("The requested cluster configuration is not implemented by this runtime.")
	}
	c.EnabledLogTypes, e = mergeLogging(nil, in.Logging)
	if e != nil {
		return nil, e
	}
	version := value(in.Version)
	if version == "" {
		version = native.KubernetesVersion
	}
	if !native.SupportsVersion(version) {
		return nil, unsupported("The requested Kubernetes version is not supported by the configured runtime.")
	}
	vpc := in.ResourcesVpcConfig
	if vpc == nil || len(vpc.SubnetIds) < 2 || len(vpc.SecurityGroupIds) > 5 {
		return nil, invalid("Specify at least two subnets and no more than five security groups.")
	}
	if vpc.EndpointPrivateAccess != nil && bool(*vpc.EndpointPrivateAccess) || vpc.EndpointPublicAccess != nil && !bool(*vpc.EndpointPublicAccess) || len(vpc.PublicAccessCidrs) > 0 || vpc.ControlPlaneEgressMode != nil {
		return nil, unsupported("Only the local public Kubernetes endpoint is implemented; private endpoints and CIDR controls are not supported.")
	}
	c.RoleARN = value(in.RoleArn)
	prefix := "arn:" + c.Key.Partition + ":iam::" + c.Key.AccountID + ":role/"
	if !strings.HasPrefix(c.RoleARN, prefix) || len(c.RoleARN) == len(prefix) {
		return nil, invalid("roleArn must identify an IAM role in the cluster account.")
	}
	if denied := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: c.RoleARN, Context: map[string][]string{"iam:PassedToService": {"eks.amazonaws.com"}}}); denied != nil {
		return nil, denied
	}
	if e = s.serviceLinkedRoles.EnsureServiceLinkedRole(ctx, "eks.amazonaws.com"); e != nil {
		return nil, e
	}
	c.Subnets = stringsFromAPI(vpc.SubnetIds)
	c.SecurityGroups = stringsFromAPI(vpc.SecurityGroupIds)
	c.VPCID, e = s.networks.ValidateClusterNetwork(ctx, c.RoleARN, c.Key.ARN(), c.Subnets, c.SecurityGroups)
	if e != nil {
		return nil, e
	}
	c.ID = uuid.NewString()
	c.KubernetesVersion = version
	c.Status = "CREATING"
	c.Operation = "create"
	c.Created = s.clock.Now()
	c.Due = c.Created
	c.Generation = 1
	c.ClientToken = token
	c.RequestHash = hash
	c.DeletionProtection = in.DeletionProtection != nil && bool(*in.DeletionProtection)
	m := awsctx.FromContext(ctx)
	c.CreatorARN, c.CreatorID = principalIdentity(m)
	if e = tx.PutCluster(c); e != nil {
		return nil, e
	}
	if c.BootstrapAdmin && c.AuthenticationMode != "CONFIG_MAP" {
		if e = s.createBootstrapEntry(tx, c); e != nil {
			return nil, e
		}
	}
	return &api.CreateClusterResponse{Cluster: clusterAPI(c)}, nil
}
func (s *Service) describeCluster(ctx context.Context, tx Transaction, in *api.DescribeClusterRequest) (*api.DescribeClusterResponse, error) {
	c, e := s.load(ctx, tx, value(in.Name), "DescribeCluster")
	if e != nil {
		return nil, e
	}
	return &api.DescribeClusterResponse{Cluster: clusterAPI(c)}, nil
}
func (s *Service) listClusters(ctx context.Context, tx Transaction, in *api.ListClustersRequest) (*api.ListClustersResponse, error) {
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, Cluster{Key: Key{Scope: sc}}, "ListClusters", nil); e != nil {
		return nil, e
	}
	if len(in.Include) > 0 {
		return nil, unsupported("External registered clusters are not implemented.")
	}
	all, e := tx.Clusters(sc)
	if e != nil {
		return nil, e
	}
	names := make([]string, 0, len(all))
	for _, c := range all {
		names = append(names, c.Key.Name)
	}
	page, next, e := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), scKey(sc)+"/clusters")
	if e != nil {
		return nil, e
	}
	return &api.ListClustersResponse{Clusters: stringsToAPI(page), NextToken: next}, nil
}
func (s *Service) deleteCluster(ctx context.Context, tx Transaction, in *api.DeleteClusterRequest) (*api.DeleteClusterResponse, error) {
	c, e := s.load(ctx, tx, value(in.Name), "DeleteCluster")
	if e != nil {
		return nil, e
	}
	if c.DeletionProtection {
		return nil, invalid("Cluster has deletion protection enabled.")
	}
	if c.Status == "CREATING" || c.Status == "UPDATING" {
		return nil, failure("ResourceInUseException", "Cluster has an operation in progress.", 409)
	}
	if e = ensureNoNodegroups(tx, c.Key); e != nil {
		return nil, e
	}
	if e = ensureNoComponents(tx, c.Key); e != nil {
		return nil, e
	}
	if c.Status != "DELETING" {
		c.Status = "DELETING"
		c.Operation = "delete"
		c.Error = ""
		c.Generation++
		c.Due = s.clock.Now()
		if e = tx.PutCluster(c); e != nil {
			return nil, e
		}
	}
	return &api.DeleteClusterResponse{Cluster: clusterAPI(c)}, nil
}
func clusterAPI(c Cluster) *api.Cluster {
	out := &api.Cluster{Name: new(api.String(c.Key.Name)), Arn: new(api.String(c.Key.ARN())), RoleArn: new(api.String(c.RoleARN)), Version: new(api.String(c.KubernetesVersion)), CreatedAt: new(c.Created), Status: new(api.ClusterStatus(c.Status)), Tags: tagsToAPI(c.Tags), DeletionProtection: new(api.BoxedBoolean(c.DeletionProtection)), AccessConfig: &api.AccessConfigResponse{AuthenticationMode: new(api.AuthenticationMode(c.AuthenticationMode)), BootstrapClusterCreatorAdminPermissions: new(api.BoxedBoolean(c.BootstrapAdmin))}, ResourcesVpcConfig: &api.VpcConfigResponse{VpcId: new(api.String(c.VPCID)), SubnetIds: stringsToAPI(c.Subnets), SecurityGroupIds: stringsToAPI(c.SecurityGroups), EndpointPublicAccess: new(api.Boolean(true)), EndpointPrivateAccess: new(api.Boolean(false))}}
	out.Logging = loggingAPI(c.EnabledLogTypes)
	if c.Endpoint != "" {
		out.Endpoint = new(api.String(c.Endpoint))
		out.CertificateAuthority = &api.Certificate{Data: new(api.String(c.CertificateAuthority))}
		out.Identity = &api.Identity{Oidc: &api.OIDC{Issuer: new(api.String(c.ServiceAccountIssuer()))}}
	}
	if c.Error != "" {
		out.Health = &api.ClusterHealth{Issues: api.ClusterIssueList{{Code: new(api.ClusterIssueCode("ClusterUnreachable")), Message: new(api.String(c.Error))}}}
	}
	return out
}
func requestHash(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func stringsFromAPI(v api.StringList) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = string(s)
	}
	return out
}
func stringsToAPI(v []string) api.StringList {
	out := make(api.StringList, len(v))
	for i, s := range v {
		out[i] = api.String(s)
	}
	return out
}
func tagsFromAPI(v api.TagMap) map[string]string {
	out := make(map[string]string, len(v))
	for k, s := range v {
		out[string(k)] = string(s)
	}
	return out
}
func tagsToAPI(v map[string]string) api.TagMap {
	out := make(api.TagMap, len(v))
	for k, s := range v {
		out[api.TagKey(k)] = api.TagValue(s)
	}
	return out
}
func tagConditions(tags map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range tags {
		out["aws:RequestTag/"+k] = []string{v}
		out["aws:TagKeys"] = append(out["aws:TagKeys"], k)
	}
	slices.Sort(out["aws:TagKeys"])
	return out
}
func validateTags(tags map[string]string) error {
	if len(tags) > 50 {
		return invalid("A resource may have at most 50 tags.")
	}
	for k, v := range tags {
		if len(k) == 0 || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return invalid("Invalid resource tag.")
		}
	}
	return nil
}
func pageLimit[T ~int32](v *T) int {
	if v == nil {
		return 100
	}
	return int(*v)
}
func scKey(s Scope) string { return s.Partition + ":" + s.AccountID + ":" + s.Region }
func pageStrings(values []string, token string, limit int, binding string) ([]string, *api.String, error) {
	if limit < 1 || limit > 100 {
		return nil, nil, invalid("maxResults must be between 1 and 100.")
	}
	slices.Sort(values)
	after := ""
	if token != "" {
		raw, e := base64.RawURLEncoding.DecodeString(token)
		prefix := binding + "\x00"
		if e != nil || !strings.HasPrefix(string(raw), prefix) {
			return nil, nil, invalid("Invalid nextToken.")
		}
		after = strings.TrimPrefix(string(raw), prefix)
	}
	start := 0
	if after != "" {
		start, _ = slices.BinarySearch(values, after)
		for start < len(values) && values[start] <= after {
			start++
		}
	}
	end := min(len(values), start+limit)
	var next *api.String
	if end < len(values) {
		next = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(binding + "\x00" + values[end-1]))))
	}
	return values[start:end], next, nil
}

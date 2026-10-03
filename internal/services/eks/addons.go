package eks

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"
	native "stackd/compute/eks"
	api "stackd/internal/awsapi/eks"
)

func registerAddons(s *Service) {
	register(s, "CreateAddon", s.createAddon)
	register(s, "DescribeAddon", s.describeAddon)
	register(s, "ListAddons", s.listAddons)
	register(s, "UpdateAddon", s.updateAddon)
	register(s, "DeleteAddon", s.deleteAddon)
	register(s, "DescribeAddonVersions", s.describeAddonVersions)
	register(s, "DescribeAddonConfiguration", s.describeAddonConfiguration)
}
func addonVersion(name, version string) (string, error) {
	switch name {
	case "coredns":
		if version == "" {
			version = native.CoreDNSVersion
		}
		if _, ok := native.CoreDNSImageForVersion(version); ok {
			return version, nil
		}
	case "eks-pod-identity-agent":
		if version == "" {
			version = native.PodIdentityAddonVersion
		}
		if version == native.PodIdentityAddonVersion {
			return version, nil
		}
	default:
		// k3s embeds kube-proxy and uses flannel, not the AWS VPC CNI. Neither
		// constitutes an independently installable managed add-on.
		return "", invalid("The requested add-on is not supported by the installed Kubernetes components.")
	}
	return "", invalid("The requested add-on version is not supported.")
}
func (s *Service) createAddon(ctx context.Context, tx Transaction, in *api.CreateAddonRequest) (*api.CreateAddonResponse, error) {
	c, err := s.load(ctx, tx, value(in.ClusterName), "CreateAddon")
	if err != nil {
		return nil, err
	}
	hash, err := requestHash(in)
	if err != nil {
		return nil, err
	}
	name := value(in.AddonName)
	if old, e := tx.Addon(c.Key, name); e == nil {
		if value(in.ClientRequestToken) != "" && old.ClientToken == value(in.ClientRequestToken) {
			if old.RequestHash != hash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &api.CreateAddonResponse{Addon: addonAPI(old)}, nil
		}
		return nil, failure("ResourceInUseException", "Add-on already exists.", 409)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	version, err := addonVersion(name, value(in.AddonVersion))
	if err != nil {
		return nil, err
	}
	if name == "coredns" && c.KubernetesVersion != "1.33" {
		return nil, invalid("The installed CoreDNS add-on versions support Kubernetes 1.33 only.")
	}
	if _, ok := s.runtime.(native.AddonRuntime); !ok {
		return nil, unsupported("The configured runtime does not manage native add-ons.")
	}
	if in.NamespaceConfig != nil && value(in.NamespaceConfig.Namespace) != "kube-system" {
		return nil, invalid("The add-on must be installed in kube-system.")
	}
	if in.ServiceAccountRoleArn != nil || len(in.PodIdentityAssociations) > 0 {
		return nil, invalid("This add-on does not use service-account IAM credentials.")
	}
	if err = validateAddonConfiguration(name, value(in.ConfigurationValues)); err != nil {
		return nil, invalid(err.Error())
	}
	conflict := value(in.ResolveConflicts)
	if conflict == "" {
		conflict = "NONE"
	}
	if conflict != "NONE" && conflict != "OVERWRITE" {
		return nil, invalid("CreateAddon resolveConflicts must be NONE or OVERWRITE.")
	}
	tags := tagsFromAPI(in.Tags)
	if err = validateTags(tags); err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, c, "CreateAddon", tagConditions(tags)); err != nil {
		return nil, err
	}
	a := Addon{Key: c.Key, Name: name, ID: uuid.NewString(), Version: version, Configuration: value(in.ConfigurationValues), Status: "CREATING", Operation: "create", ResolveConflicts: conflict, ClientToken: value(in.ClientRequestToken), RequestHash: hash, Tags: tags, Created: s.clock.Now(), Modified: s.clock.Now(), Due: s.clock.Now(), Generation: 1}
	if err = queueComponents(s, tx, c); err != nil {
		return nil, err
	}
	if err = tx.PutAddon(a); err != nil {
		return nil, err
	}
	return &api.CreateAddonResponse{Addon: addonAPI(a)}, nil
}
func (s *Service) describeAddon(ctx context.Context, tx Transaction, in *api.DescribeAddonRequest) (*api.DescribeAddonResponse, error) {
	_, a, err := s.loadAddon(ctx, tx, value(in.ClusterName), value(in.AddonName), "DescribeAddon")
	if err != nil {
		return nil, err
	}
	return &api.DescribeAddonResponse{Addon: addonAPI(a)}, nil
}
func (s *Service) listAddons(ctx context.Context, tx Transaction, in *api.ListAddonsRequest) (*api.ListAddonsResponse, error) {
	c, err := s.load(ctx, tx, value(in.ClusterName), "ListAddons")
	if err != nil {
		return nil, err
	}
	all, err := tx.Addons(c.Key)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(all))
	for _, a := range all {
		names = append(names, a.Name)
	}
	page, next, err := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), c.Key.ARN()+"/addons")
	if err != nil {
		return nil, err
	}
	return &api.ListAddonsResponse{Addons: stringsToAPI(page), NextToken: next}, nil
}
func (s *Service) updateAddon(ctx context.Context, tx Transaction, in *api.UpdateAddonRequest) (*api.UpdateAddonResponse, error) {
	c, a, err := s.loadAddon(ctx, tx, value(in.ClusterName), value(in.AddonName), "UpdateAddon")
	if err != nil {
		return nil, err
	}
	hash, err := requestHash(in)
	if err != nil {
		return nil, err
	}
	updates, err := tx.ClusterUpdates(c.Key)
	if err != nil {
		return nil, err
	}
	for _, u := range updates {
		if value(in.ClientRequestToken) != "" && u.ResourceType == "addon" && u.ResourceName == a.Name && u.ClientToken == value(in.ClientRequestToken) {
			if u.RequestHash != hash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &api.UpdateAddonResponse{Update: updateAPI(u)}, nil
		}
	}
	if a.Status != "ACTIVE" && a.Status != "DEGRADED" && a.Status != "UPDATE_FAILED" {
		return nil, failure("ResourceInUseException", "Add-on has an operation in progress.", 409)
	}
	if a.Name == "coredns" && c.KubernetesVersion != "1.33" {
		return nil, invalid("The installed CoreDNS add-on versions support Kubernetes 1.33 only.")
	}
	if in.ServiceAccountRoleArn != nil || len(in.PodIdentityAssociations) > 0 {
		return nil, invalid("This add-on does not use service-account IAM credentials.")
	}
	if in.AddonVersion != nil {
		a.Version, err = addonVersion(a.Name, value(in.AddonVersion))
		if err != nil {
			return nil, err
		}
	}
	if in.ConfigurationValues != nil {
		if err = validateAddonConfiguration(a.Name, value(in.ConfigurationValues)); err != nil {
			return nil, invalid(err.Error())
		}
		a.Configuration = value(in.ConfigurationValues)
	}
	conflict := value(in.ResolveConflicts)
	if conflict == "" {
		conflict = "NONE"
	}
	if conflict != "NONE" && conflict != "OVERWRITE" && conflict != "PRESERVE" {
		return nil, invalid("Invalid resolveConflicts value.")
	}
	u := Update{Key: c.Key, ID: uuid.NewString(), Type: "AddonUpdate", ResourceType: "addon", ResourceName: a.Name, Status: "InProgress", Created: s.clock.Now(), ClientToken: value(in.ClientRequestToken), RequestHash: hash}
	if in.AddonVersion != nil {
		u.Params = append(u.Params, UpdateParam{Type: "AddonVersion", Value: a.Version})
	}
	if in.ResolveConflicts != nil {
		u.Params = append(u.Params, UpdateParam{Type: "ResolveConflicts", Value: conflict})
	}
	if in.ConfigurationValues != nil {
		u.Params = append(u.Params, UpdateParam{Type: "ConfigurationValues", Value: a.Configuration})
	}
	a.Status = "UPDATING"
	a.Operation = "update"
	a.UpdateID = u.ID
	a.ResolveConflicts = conflict
	a.Error = ""
	a.ErrorCode = ""
	a.Generation++
	a.Due = s.clock.Now()
	a.Modified = s.clock.Now()
	if err = queueComponents(s, tx, c); err != nil {
		return nil, err
	}
	if err = tx.PutClusterUpdate(u); err != nil {
		return nil, err
	}
	if err = tx.PutAddon(a); err != nil {
		return nil, err
	}
	return &api.UpdateAddonResponse{Update: updateAPI(u)}, nil
}
func (s *Service) deleteAddon(ctx context.Context, tx Transaction, in *api.DeleteAddonRequest) (*api.DeleteAddonResponse, error) {
	c, a, err := s.loadAddon(ctx, tx, value(in.ClusterName), value(in.AddonName), "DeleteAddon")
	if err != nil {
		return nil, err
	}
	if a.Status == "CREATING" || a.Status == "UPDATING" {
		return nil, failure("InvalidRequestException", "Add-on has an operation in progress.", 400)
	}
	if c.Status != "ACTIVE" || c.Operation != "" && c.Operation != "components" && c.Operation != "reconcile" {
		return nil, failure("InvalidRequestException", "Cluster has an operation in progress.", 400)
	}
	if a.Status != "DELETING" {
		a.Status = "DELETING"
		a.Operation = "delete"
		a.Preserve = in.Preserve != nil && bool(*in.Preserve)
		a.Generation++
		a.Due = s.clock.Now()
		a.Modified = s.clock.Now()
		if err = queueComponents(s, tx, c); err != nil {
			return nil, err
		}
		if err = tx.PutAddon(a); err != nil {
			return nil, err
		}
	}
	return &api.DeleteAddonResponse{Addon: addonAPI(a)}, nil
}
func (s *Service) describeAddonVersions(ctx context.Context, tx Transaction, in *api.DescribeAddonVersionsRequest) (*api.DescribeAddonVersionsResponse, error) {
	if err := s.authorizeResource(ctx, "*", nil, "DescribeAddonVersions", nil); err != nil {
		return nil, err
	}
	out := &api.DescribeAddonVersionsResponse{Addons: api.Addons{}}
	if in.MaxResults != nil && (*in.MaxResults < 1 || *in.MaxResults > 100) {
		return nil, invalid("maxResults must be between 1 and 100.")
	}
	names := []string{}
	for _, name := range []string{"coredns", "eks-pod-identity-agent"} {
		if value(in.AddonName) != "" && value(in.AddonName) != name {
			continue
		}
		kind := "networking"
		if name == "eks-pod-identity-agent" {
			kind = "security"
		}
		if len(in.Owners) > 0 && !slices.Contains(in.Owners, api.String("aws")) || len(in.Publishers) > 0 && !slices.Contains(in.Publishers, api.String("eks")) || len(in.Types) > 0 && !slices.Contains(in.Types, api.String(kind)) {
			continue
		}
		if v := value(in.KubernetesVersion); v != "" {
			if _, ok := native.PinnedImage(v); !ok {
				continue
			}
		}
		if name == "coredns" && value(in.KubernetesVersion) != "" && value(in.KubernetesVersion) != "1.33" {
			continue
		}
		names = append(names, name)
	}
	filterHash, err := requestHash(struct {
		Name, Version             string
		Owners, Publishers, Types api.StringList
	}{value(in.AddonName), value(in.KubernetesVersion), in.Owners, in.Publishers, in.Types})
	if err != nil {
		return nil, err
	}
	page, next, err := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), scKey(scopeFor(ctx))+"/addon-versions/"+filterHash)
	if err != nil {
		return nil, err
	}
	out.NextToken = next
	for _, name := range page {
		kind := "networking"
		versions := []string{native.CoreDNSVersion, "v1.12.1-eksbuild.2"}
		if name == "eks-pod-identity-agent" {
			kind = "security"
			versions = []string{native.PodIdentityAddonVersion}
		}
		info := api.AddonInfo{AddonName: new(api.String(name)), DefaultNamespace: new(api.String("kube-system")), Owner: new(api.String("aws")), Publisher: new(api.String("eks")), Type: new(api.String(kind))}
		for i, version := range versions {
			compatible := api.Compatibilities{}
			clusterVersions := []string{"1.32", "1.33"}
			computeTypes := api.StringList{"ec2"}
			if name == "coredns" {
				clusterVersions = []string{"1.33"}
				computeTypes = append(computeTypes, "fargate")
			}
			for _, clusterVersion := range clusterVersions {
				if value(in.KubernetesVersion) == "" || value(in.KubernetesVersion) == clusterVersion {
					compatible = append(compatible, api.Compatibility{ClusterVersion: new(api.String(clusterVersion)), DefaultVersion: new(api.Boolean(i == 0)), PlatformVersions: api.StringList{"*"}})
				}
			}
			info.AddonVersions = append(info.AddonVersions, api.AddonVersionInfo{AddonVersion: new(api.String(version)), Architecture: api.StringList{"amd64", "arm64"}, ComputeTypes: computeTypes, RequiresConfiguration: new(api.Boolean(false)), RequiresIamPermissions: new(api.Boolean(false)), Compatibilities: compatible})
		}
		out.Addons = append(out.Addons, info)
	}
	return out, nil
}
func (s *Service) describeAddonConfiguration(ctx context.Context, tx Transaction, in *api.DescribeAddonConfigurationRequest) (*api.DescribeAddonConfigurationResponse, error) {
	if err := s.authorizeResource(ctx, "*", nil, "DescribeAddonConfiguration", nil); err != nil {
		return nil, err
	}
	version, err := addonVersion(value(in.AddonName), value(in.AddonVersion))
	if err != nil {
		return nil, err
	}
	schema := native.CoreDNSConfigurationSchema
	if value(in.AddonName) == "eks-pod-identity-agent" {
		schema = native.PodIdentityAddonConfigurationSchema
	}
	return &api.DescribeAddonConfigurationResponse{AddonName: in.AddonName, AddonVersion: new(api.String(version)), ConfigurationSchema: new(api.String(schema)), PodIdentityConfiguration: api.AddonPodIdentityConfigurationList{}}, nil
}
func addonAPI(a Addon) *api.Addon {
	out := &api.Addon{AddonArn: new(api.String(a.ARN())), AddonName: new(api.String(a.Name)), AddonVersion: new(api.String(a.Version)), ClusterName: new(api.ClusterName(a.Key.Name)), ConfigurationValues: new(api.String(a.Configuration)), CreatedAt: new(a.Created), ModifiedAt: new(a.Modified), NamespaceConfig: &api.AddonNamespaceConfigResponse{Namespace: new(api.Namespace("kube-system"))}, Status: new(api.AddonStatus(a.Status)), Tags: tagsToAPI(a.Tags), Health: &api.AddonHealth{Issues: api.AddonIssueList{}}}
	if a.Error != "" {
		out.Health.Issues = append(out.Health.Issues, api.AddonIssue{Code: new(api.AddonIssueCode(a.ErrorCode)), Message: new(api.String(a.Error))})
	}
	return out
}
func (s *Service) loadAddon(ctx context.Context, tx Reader, cluster, name, action string) (Cluster, Addon, error) {
	k := Key{Scope: scopeFor(ctx), Name: cluster}
	a, err := tx.Addon(k, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Cluster{}, a, err
	}
	if errors.Is(err, ErrNotFound) {
		a = Addon{Key: k, Name: name, ID: "*"}
	}
	if denied := s.authorizeResource(ctx, a.ARN(), a.Tags, action, nil); denied != nil {
		return Cluster{}, a, denied
	}
	if err != nil {
		return Cluster{}, a, err
	}
	c, err := tx.Cluster(k)
	return c, a, err
}
func validateAddonConfiguration(name, raw string) error {
	if name == "eks-pod-identity-agent" {
		return native.ValidatePodIdentityAddonConfiguration(raw)
	}
	_, err := native.ParseCoreDNSConfiguration(raw)
	return err
}

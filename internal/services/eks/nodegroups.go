package eks

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	native "stackd/compute/eks"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eks"
)

func registerNodegroups(s *Service) {
	register(s, "CreateNodegroup", s.createNodegroup)
	register(s, "DescribeNodegroup", s.describeNodegroup)
	register(s, "ListNodegroups", s.listNodegroups)
	register(s, "DeleteNodegroup", s.deleteNodegroup)
	register(s, "UpdateNodegroupConfig", s.updateNodegroupConfig)
	register(s, "UpdateNodegroupVersion", s.updateNodegroupVersion)
}
func (s *Service) loadNodegroup(ctx context.Context, r Reader, cluster, name, action string) (Cluster, Nodegroup, error) {
	key := Key{scopeFor(ctx), cluster}
	c, clusterErr := r.Cluster(key)
	if clusterErr != nil && !errors.Is(clusterErr, ErrNotFound) {
		return c, Nodegroup{}, clusterErr
	}
	n, groupErr := r.Nodegroup(NodegroupKey{key, name})
	if groupErr != nil && !errors.Is(groupErr, ErrNotFound) {
		return c, n, groupErr
	}
	if errors.Is(groupErr, ErrNotFound) {
		n = Nodegroup{Key: NodegroupKey{key, name}, ID: "*"}
	}
	if denied := s.authorizeResource(ctx, n.Key.ARN(n.ID), n.Tags, action, nil); denied != nil {
		return c, n, denied
	}
	if clusterErr != nil {
		return c, n, clusterErr
	}
	return c, n, groupErr
}
func (s *Service) createNodegroup(ctx context.Context, tx Transaction, in *api.CreateNodegroupRequest) (*api.CreateNodegroupResponse, error) {
	c, e := tx.Cluster(Key{scopeFor(ctx), value(in.ClusterName)})
	if e != nil {
		return nil, e
	}
	n := Nodegroup{Key: NodegroupKey{c.Key, value(in.NodegroupName)}, ID: uuid.NewString(), ClusterID: c.ID, NodeRoleARN: value(in.NodeRole), Version: value(in.Version), ReleaseVersion: value(in.ReleaseVersion), AmiType: value(in.AmiType), CapacityType: value(in.CapacityType), ClientToken: value(in.ClientRequestToken), Tags: tagsFromAPI(in.Tags), Labels: map[string]string{}, Subnets: stringsFromAPI(in.Subnets), InstanceTypes: stringsFromAPI(in.InstanceTypes), MinSize: 1, MaxSize: 2, DesiredSize: 2, DiskSize: 20, MaxUnavailable: 1, UpdateStrategy: "DEFAULT", Generation: 1, TemplateGeneration: 1}
	if !clusterName.MatchString(n.Key.Name) {
		return nil, invalid("Invalid nodegroup name.")
	}
	if e = validateTags(n.Tags); e != nil {
		return nil, e
	}
	if e = s.authorizeResource(ctx, n.Key.ARN(n.ID), n.Tags, "CreateNodegroup", tagConditions(n.Tags)); e != nil {
		return nil, e
	}
	n.RequestHash, e = requestHash(in)
	if e != nil {
		return nil, e
	}
	if old, e := tx.Nodegroup(n.Key); e == nil {
		if n.ClientToken != "" && n.ClientToken == old.ClientToken {
			if n.RequestHash != old.RequestHash {
				return nil, invalid("ClientRequestToken was previously used with different parameters.")
			}
			return &api.CreateNodegroupResponse{Nodegroup: nodegroupAPI(old)}, nil
		}
		return nil, failure("ResourceInUseException", "Nodegroup already exists.", 409)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	if c.Status != "ACTIVE" {
		return nil, failure("ResourceInUseException", "Cluster is not active.", 409)
	}
	if s.nodegroups == nil {
		return nil, unsupported("Managed nodegroup compute owners are not configured.")
	}
	if _, ok := s.runtime.(native.WorkerRuntime); !ok {
		return nil, unsupported("Native EC2 worker join is not configured.")
	}
	if in.NodeRepairConfig != nil || in.WarmPoolConfig != nil {
		return nil, unsupported("Node repair and warm-pool execution are not configured.")
	}
	if in.RemoteAccess != nil {
		return nil, unsupported("Node remote-access security-group provisioning is not configured; use an explicit launch template key and security groups.")
	}
	if n.Version == "" {
		n.Version = c.KubernetesVersion
	}
	if n.Version != c.KubernetesVersion {
		return nil, invalid("Nodegroup version must match the cluster Kubernetes version.")
	}
	if n.CapacityType == "" {
		n.CapacityType = "ON_DEMAND"
	}
	if n.CapacityType != "ON_DEMAND" {
		return nil, unsupported("The EC2 owner does not provide Spot or capacity-block worker execution.")
	}
	if in.LaunchTemplate != nil {
		n.LaunchTemplateID = value(in.LaunchTemplate.Id)
		n.LaunchTemplateName = value(in.LaunchTemplate.Name)
		n.LaunchTemplateVersion = value(in.LaunchTemplate.Version)
		if (n.LaunchTemplateID == "") == (n.LaunchTemplateName == "") {
			return nil, invalid("Specify exactly one launch template ID or name.")
		}
		if in.DiskSize != nil {
			return nil, invalid("diskSize cannot be specified with a launch template.")
		}
		n.DiskSize = 0
	}
	if in.DiskSize != nil {
		n.DiskSize = int32(*in.DiskSize)
	}
	if in.ScalingConfig != nil {
		if in.ScalingConfig.MinSize == nil || in.ScalingConfig.MaxSize == nil || in.ScalingConfig.DesiredSize == nil {
			return nil, invalid("All scalingConfig fields are required at creation.")
		}
		mergeNodegroupScaling(&n, in.ScalingConfig)
	}
	for k, v := range in.Labels {
		n.Labels[string(k)] = string(v)
	}
	n.Taints, e = nodegroupTaints(in.Taints)
	if e != nil {
		return nil, e
	}
	if e = mergeNodegroupUpdateConfig(&n, in.UpdateConfig); e != nil {
		return nil, e
	}
	if e = validateNodegroup(n); e != nil {
		return nil, e
	}
	prefix := "arn:" + c.Key.Partition + ":iam::" + c.Key.AccountID + ":role/"
	if !strings.HasPrefix(n.NodeRoleARN, prefix) || len(n.NodeRoleARN) == len(prefix) {
		return nil, invalid("nodeRole must identify an IAM role in the cluster account.")
	}
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: n.NodeRoleARN, Context: map[string][]string{"iam:PassedToService": {"ec2.amazonaws.com"}}}); rejected != nil {
		return nil, rejected
	}
	if s.principals == nil {
		return nil, unsupported("IAM principal ownership is required.")
	}
	n.NodeRoleID, e = s.principals.ResolvePrincipal(ctx, n.NodeRoleARN)
	if e != nil {
		return nil, e
	}
	n.GroupName = "eks-" + n.Key.Name + "-" + n.ID
	n.ProfileName = n.GroupName
	customImage, e := s.nodegroups.Admit(ctx, c, &n)
	if e != nil {
		return nil, e
	}
	if customImage && (in.AmiType != nil || in.Version != nil || in.ReleaseVersion != nil) {
		return nil, invalid("A custom AMI launch template cannot be combined with amiType, version or releaseVersion.")
	}
	if in.AmiType != nil && value(in.AmiType) != n.AmiType {
		return nil, invalid("The requested AMI type is not configured for this Kubernetes version.")
	}
	n.Status = "CREATING"
	n.Operation = "create"
	n.Created = s.clock.Now()
	n.Modified = n.Created
	n.Due = n.Created
	if e = tx.PutNodegroup(n); e != nil {
		return nil, e
	}
	return &api.CreateNodegroupResponse{Nodegroup: nodegroupAPI(n)}, nil
}
func (s *Service) describeNodegroup(ctx context.Context, tx Transaction, in *api.DescribeNodegroupRequest) (*api.DescribeNodegroupResponse, error) {
	_, n, e := s.loadNodegroup(ctx, tx, value(in.ClusterName), value(in.NodegroupName), "DescribeNodegroup")
	if e != nil {
		return nil, e
	}
	return &api.DescribeNodegroupResponse{Nodegroup: nodegroupAPI(n)}, nil
}
func (s *Service) listNodegroups(ctx context.Context, tx Transaction, in *api.ListNodegroupsRequest) (*api.ListNodegroupsResponse, error) {
	c, e := s.load(ctx, tx, value(in.ClusterName), "ListNodegroups")
	if e != nil {
		return nil, e
	}
	all, e := tx.Nodegroups(c.Key)
	if e != nil {
		return nil, e
	}
	names := make([]string, 0, len(all))
	for _, n := range all {
		names = append(names, n.Key.Name)
	}
	page, next, e := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), c.Key.ARN()+"/nodegroups")
	if e != nil {
		return nil, e
	}
	return &api.ListNodegroupsResponse{Nodegroups: stringsToAPI(page), NextToken: next}, nil
}
func (s *Service) deleteNodegroup(ctx context.Context, tx Transaction, in *api.DeleteNodegroupRequest) (*api.DeleteNodegroupResponse, error) {
	_, n, e := s.loadNodegroup(ctx, tx, value(in.ClusterName), value(in.NodegroupName), "DeleteNodegroup")
	if e != nil {
		return nil, e
	}
	if n.Status != "DELETING" {
		if n.UpdateID != "" {
			u, e := tx.NodegroupUpdate(n.Key, n.UpdateID)
			if e != nil {
				return nil, e
			}
			u.Status = "Cancelled"
			if e = tx.PutNodegroupUpdate(u); e != nil {
				return nil, e
			}
		}
		n.Status = "DELETING"
		n.Operation = "delete"
		n.UpdateID = ""
		n.ErrorCode = ""
		n.ErrorMessage = ""
		n.Generation++
		n.Modified = s.clock.Now()
		n.Due = n.Modified
		n.Force = true
		n.Deadline = time.Time{}
		if e = tx.PutNodegroup(n); e != nil {
			return nil, e
		}
	}
	return &api.DeleteNodegroupResponse{Nodegroup: nodegroupAPI(n)}, nil
}
func ensureNoNodegroups(r Reader, k Key) error {
	all, e := r.Nodegroups(k)
	if e != nil {
		return e
	}
	if len(all) > 0 {
		return failure("ResourceInUseException", "Cluster has managed nodegroups; delete them first.", 409)
	}
	return nil
}

var nodeLabelPart = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$`)

func validNodeLabelKey(k string) bool {
	prefix, name, ok := strings.Cut(k, "/")
	if !ok {
		return nodeLabelPart.MatchString(k)
	}
	if len(prefix) > 253 || prefix == "" || strings.Contains(name, "/") {
		return false
	}
	for _, part := range strings.Split(prefix, ".") {
		if len(part) == 0 || len(part) > 63 || strings.Trim(part, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}
	return nodeLabelPart.MatchString(name)
}
func validateNodegroup(n Nodegroup) error {
	if len(n.Subnets) == 0 || len(n.Subnets) > 16 {
		return invalid("Specify between one and sixteen subnets.")
	}
	seen := map[string]bool{}
	for _, v := range n.Subnets {
		if v == "" || seen[v] {
			return invalid("Subnets cannot be empty or duplicated.")
		}
		seen[v] = true
	}
	if n.MinSize < 0 || n.MaxSize < 1 || n.DesiredSize < n.MinSize || n.DesiredSize > n.MaxSize || n.MinSize > n.MaxSize {
		return invalid("Scaling configuration must satisfy 0 <= minSize <= desiredSize <= maxSize, with maxSize positive.")
	}
	if len(n.Labels) > 50 || len(n.Taints) > 50 {
		return invalid("At most 50 labels and 50 taints are supported.")
	}
	for k, v := range n.Labels {
		if !validNodeLabelKey(k) || (v != "" && !nodeLabelPart.MatchString(v)) {
			return invalid("Invalid Kubernetes label.")
		}
		if strings.HasPrefix(k, "eks.amazonaws.com/") || strings.HasPrefix(k, "kubernetes.io/") || strings.HasPrefix(k, "k8s.io/") {
			return invalid("Reserved Kubernetes and EKS labels cannot be managed by this request.")
		}
	}
	if len(n.InstanceTypes) > 1 {
		return unsupported("The current Auto Scaling owner requires one concrete worker instance type.")
	}
	return nil
}
func mergeNodegroupScaling(n *Nodegroup, v *api.NodegroupScalingConfig) {
	if v.MinSize != nil {
		n.MinSize = int32(*v.MinSize)
	}
	if v.MaxSize != nil {
		n.MaxSize = int32(*v.MaxSize)
	}
	if v.DesiredSize != nil {
		n.DesiredSize = int32(*v.DesiredSize)
	}
}
func mergeNodegroupUpdateConfig(n *Nodegroup, v *api.NodegroupUpdateConfig) error {
	if v == nil {
		return nil
	}
	if v.MaxUnavailable != nil && v.MaxUnavailablePercentage != nil {
		return invalid("Specify maxUnavailable or maxUnavailablePercentage, not both.")
	}
	if v.MaxUnavailable != nil {
		n.MaxUnavailable = int32(*v.MaxUnavailable)
		n.MaxUnavailablePercentage = 0
		if n.MaxUnavailable < 1 || n.MaxUnavailable > 100 {
			return invalid("maxUnavailable must be between 1 and 100.")
		}
	}
	if v.MaxUnavailablePercentage != nil {
		n.MaxUnavailablePercentage = int32(*v.MaxUnavailablePercentage)
		n.MaxUnavailable = 0
		if n.MaxUnavailablePercentage < 1 || n.MaxUnavailablePercentage > 100 {
			return invalid("maxUnavailablePercentage must be between 1 and 100.")
		}
	}
	if v.UpdateStrategy != nil {
		n.UpdateStrategy = value(v.UpdateStrategy)
		if n.UpdateStrategy != "DEFAULT" && n.UpdateStrategy != "MINIMAL" {
			return invalid("Invalid updateStrategy.")
		}
	}
	return nil
}
func nodegroupTaints(v api.TaintsList) ([]native.WorkerTaint, error) {
	out := make([]native.WorkerTaint, 0, len(v))
	for _, t := range v {
		effect := map[string]string{"NO_SCHEDULE": "NoSchedule", "PREFER_NO_SCHEDULE": "PreferNoSchedule", "NO_EXECUTE": "NoExecute"}[value(t.Effect)]
		key, val := value(t.Key), value(t.Value)
		if effect == "" || !validNodeLabelKey(key) || (val != "" && !nodeLabelPart.MatchString(val)) {
			return nil, invalid("Invalid Kubernetes taint.")
		}
		if slices.ContainsFunc(out, func(p native.WorkerTaint) bool { return p.Key == key && p.Effect == effect }) {
			return nil, invalid("Duplicate taint key/effect.")
		}
		out = append(out, native.WorkerTaint{Key: key, Value: val, Effect: effect})
	}
	return out, nil
}
func nodegroupAPI(n Nodegroup) *api.Nodegroup {
	out := &api.Nodegroup{ClusterName: new(api.String(n.Key.Cluster.Name)), NodegroupName: new(api.String(n.Key.Name)), NodegroupArn: new(api.String(n.Key.ARN(n.ID))), NodeRole: new(api.String(n.NodeRoleARN)), Status: new(api.NodegroupStatus(n.Status)), Version: new(api.String(n.Version)), CreatedAt: new(n.Created), ModifiedAt: new(n.Modified), CapacityType: new(api.CapacityTypes(n.CapacityType)), Subnets: stringsToAPI(n.Subnets), InstanceTypes: stringsToAPI(n.InstanceTypes), Tags: tagsToAPI(n.Tags), Labels: api.LabelsMap{}, Taints: api.TaintsList{}, ScalingConfig: &api.NodegroupScalingConfig{MinSize: new(api.ZeroCapacity(n.MinSize)), MaxSize: new(api.Capacity(n.MaxSize)), DesiredSize: new(api.ZeroCapacity(n.DesiredSize))}, Health: &api.NodegroupHealth{Issues: api.IssueList{}}, UpdateConfig: &api.NodegroupUpdateConfig{UpdateStrategy: new(api.NodegroupUpdateStrategies(n.UpdateStrategy))}}
	if n.DiskSize > 0 {
		out.DiskSize = new(api.BoxedInteger(n.DiskSize))
	}
	if n.AmiType != "" {
		out.AmiType = new(api.AMITypes(n.AmiType))
	}
	if n.ReleaseVersion != "" {
		out.ReleaseVersion = new(api.String(n.ReleaseVersion))
	}
	if n.LaunchTemplateID != "" || n.LaunchTemplateName != "" {
		out.LaunchTemplate = &api.LaunchTemplateSpecification{}
		if n.LaunchTemplateID != "" {
			out.LaunchTemplate.Id = new(api.String(n.LaunchTemplateID))
		}
		if n.LaunchTemplateName != "" {
			out.LaunchTemplate.Name = new(api.String(n.LaunchTemplateName))
		}
		if n.LaunchTemplateVersion != "" {
			out.LaunchTemplate.Version = new(api.String(n.LaunchTemplateVersion))
		}
	}
	for k, v := range n.Labels {
		out.Labels[api.LabelKey(k)] = api.LabelValue(v)
	}
	effects := map[string]string{"NoSchedule": "NO_SCHEDULE", "PreferNoSchedule": "PREFER_NO_SCHEDULE", "NoExecute": "NO_EXECUTE"}
	for _, t := range n.Taints {
		out.Taints = append(out.Taints, api.Taint{Key: new(api.TaintKey(t.Key)), Value: new(api.TaintValue(t.Value)), Effect: new(api.TaintEffect(effects[t.Effect]))})
	}
	if n.MaxUnavailable > 0 {
		out.UpdateConfig.MaxUnavailable = new(api.NonZeroInteger(n.MaxUnavailable))
	} else {
		out.UpdateConfig.MaxUnavailablePercentage = new(api.PercentCapacity(n.MaxUnavailablePercentage))
	}
	if n.GroupARN != "" {
		out.Resources = &api.NodegroupResources{AutoScalingGroups: api.AutoScalingGroupList{{Name: new(api.String(n.GroupName))}}}
	}
	if n.ErrorMessage != "" {
		out.Health.Issues = append(out.Health.Issues, api.Issue{Code: new(api.NodegroupIssueCode(n.ErrorCode)), Message: new(api.String(n.ErrorMessage))})
	}
	return out
}

// PodIdentityNodeRole rejects stale node incarnations and current IAM recreation.
func (s *Service) PodIdentityNodeRole(ctx context.Context, cluster Key, nodeName, nodeUID string) (string, string, error) {
	var found Nodegroup
	var worker NodegroupWorker
	e := s.repository.View(ctx, func(r Reader) error {
		all, e := r.Nodegroups(cluster)
		if e != nil {
			return e
		}
		for _, n := range all {
			if n.Status == "DELETING" {
				continue
			}
			for _, w := range n.Workers {
				if w.Ready && w.NodeName == nodeName && w.NodeUID == nodeUID {
					found = n
					worker = w
					return nil
				}
			}
		}
		return ErrNotFound
	})
	if errors.Is(e, ErrNotFound) {
		return "", "", failure("AccessDeniedException", "The token is not bound to a current managed worker.", 400)
	}
	if e != nil {
		return "", "", e
	}
	id, e := s.principals.ResolvePrincipal(ctx, found.NodeRoleARN)
	if errors.Is(e, authorization.ErrInvalidPrincipal) {
		return "", "", failure("AccessDeniedException", "The worker IAM role no longer exists.", 400)
	}
	if e != nil {
		return "", "", e
	}
	if id != found.NodeRoleID {
		return "", "", failure("AccessDeniedException", "The worker IAM role incarnation changed.", 400)
	}
	current, e := s.nodegroups.Observe(ctx, found)
	if e != nil {
		return "", "", e
	}
	if !slices.ContainsFunc(current.Workers, func(w NodegroupWorker) bool {
		return w.InstanceID == worker.InstanceID && w.PrivateIP == worker.PrivateIP && w.LifecycleState == "InService"
	}) {
		return "", "", failure("AccessDeniedException", "The worker is no longer an active EC2 member of the managed nodegroup.", 400)
	}
	return found.NodeRoleARN, found.NodeRoleID, nil
}

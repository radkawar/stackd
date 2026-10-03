package memorydb

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"maps"
	"slices"
	engine "stackd/engine/valkey"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/memorydb"
	"strings"
)

func keyFor(ctx context.Context, kind, name string) (Key, error) {
	k := Key{Scope: scopeFor(ctx), Kind: kind, Name: strings.ToLower(name)}
	if strings.HasPrefix(name, "arn:") {
		prefix := Key{Scope: k.Scope, Kind: kind}.ARN()
		if !strings.HasPrefix(name, prefix) {
			return Key{}, notFound(kind)
		}
		k.Name = strings.TrimPrefix(name, prefix)
	}
	if !validName(k.Name) {
		return Key{}, invalid("Invalid MemoryDB resource name.")
	}
	return k, nil
}
func validName(v string) bool {
	if len(v) < 1 || len(v) > 255 || v[0] < 'a' || v[0] > 'z' || strings.Contains(v, "--") || strings.HasSuffix(v, "-") {
		return false
	}
	for _, c := range v {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func kindTitle(kind string) string {
	switch kind {
	case "cluster":
		return "Cluster"
	case "user":
		return "User"
	case "acl":
		return "ACL"
	case "parametergroup":
		return "ParameterGroup"
	case "subnetgroup":
		return "SubnetGroup"
	default:
		return "Snapshot"
	}
}
func notFound(kind string) error {
	return failure(kindTitle(kind)+"NotFoundFault", "The requested MemoryDB resource does not exist.")
}
func exists(kind string) error {
	return failure(kindTitle(kind)+"AlreadyExistsFault", "The MemoryDB resource already exists.")
}
func stateError(kind string) error {
	return failure("Invalid"+kindTitle(kind)+"StateFault", "The resource is not in a state that permits this operation.")
}
func (s *Service) authorize(ctx context.Context, action string, k Key, tags, requestTags map[string]string) error {
	conditions := map[string][]string{}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	for k, v := range requestTags {
		conditions["aws:RequestTag/"+k] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], k)
	}
	arn := k.ARN()
	if k.Kind == "" {
		arn = "*"
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "memorydb:" + action, ResourceARN: arn, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func tagsFrom(in api.TagList) (map[string]string, error) {
	out := map[string]string{}
	if len(in) > 50 {
		return nil, failure("TagQuotaPerResourceExceeded", "At most 50 tags are allowed.")
	}
	for _, t := range in {
		k, v := value(t.Key), value(t.Value)
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, invalid("Invalid tag.")
		}
		if _, ok := out[k]; ok {
			return nil, invalid("Duplicate tag key.")
		}
		out[k] = v
	}
	return out, nil
}
func tagList(tags map[string]string) api.TagList {
	out := api.TagList{}
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, api.Tag{Key: new(api.String(k)), Value: new(api.String(tags[k]))})
	}
	return out
}
func incarnation() string { return "memorydb-" + uuid.NewString() }
func page[T any](items []T, max *api.IntegerOptional, token *api.String, binding string, name func(T) string) ([]T, *api.String, error) {
	limit := 100
	if max != nil {
		limit = int(*max)
		if limit < 1 || limit > 100 {
			return nil, nil, invalid("MaxResults must be between 1 and 100.")
		}
	}
	start := 0
	if value(token) != "" {
		decoded, e := base64.RawURLEncoding.DecodeString(value(token))
		if e != nil || !strings.HasPrefix(string(decoded), binding+"\n") {
			return nil, nil, invalid("Invalid NextToken.")
		}
		last := strings.TrimPrefix(string(decoded), binding+"\n")
		start = len(items)
		for i, v := range items {
			if name(v) > last {
				start = i
				break
			}
		}
	}
	end := min(start+limit, len(items))
	var next *api.String
	if end < len(items) {
		next = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(binding + "\n" + name(items[end-1])))))
	}
	return items[start:end], next, nil
}
func binding(ctx context.Context, action, filter string) string {
	sc := scopeFor(ctx)
	return sc.Partition + ":" + sc.AccountID + ":" + sc.Region + ":" + action + ":" + filter
}
func (s *Service) loadCluster(ctx context.Context, r Reader, action, name string) (Cluster, error) {
	k, e := keyFor(ctx, "cluster", name)
	if e != nil {
		return Cluster{}, e
	}
	v, e := r.Cluster(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(k.Kind)
	}
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func engineFamily(name string) string {
	if name == "valkey" {
		return "memorydb_valkey7"
	}
	return "memorydb_redis7"
}
func engineVersion(name string) string {
	if name == "valkey" {
		return engine.Version
	}
	return engine.RedisCompatibility
}
func endpointDTO(v engine.Endpoint) *api.Endpoint {
	if v.Address == "" {
		return nil
	}
	return &api.Endpoint{Address: new(api.String(v.Address)), Port: new(api.Integer(v.Port))}
}
func clusterDTO(v Cluster, detail bool) *api.Cluster {
	status := "in-sync"
	if v.Status != "available" {
		status = "applying"
	}
	out := &api.Cluster{Name: new(api.String(v.Key.Name)), ARN: new(api.String(v.Key.ARN())), Status: new(api.String(v.Status)), Description: new(api.String(v.Description)), NodeType: new(api.String(v.NodeType)), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), EnginePatchVersion: new(api.String(engine.Version)), ACLName: new(api.ACLName(v.ACLName)), NumberOfShards: new(api.IntegerOptional(v.Shards)), ParameterGroupName: new(api.String(v.ParameterGroup)), ParameterGroupStatus: new(api.String(status)), TLSEnabled: new(api.BooleanOptional(v.TLSEnabled)), AutoMinorVersionUpgrade: new(api.BooleanOptional(false)), SnapshotRetentionLimit: new(api.IntegerOptional(0)), DataTiering: new(api.DataTieringStatus("false")), ClusterEndpoint: endpointDTO(v.Deployment.Endpoint)}
	if detail {
		for shard := int32(0); shard < v.Shards; shard++ {
			row := api.Shard{Name: new(api.String(fmt.Sprintf("%04d", shard+1))), Status: new(api.String(v.Status)), NumberOfNodes: new(api.IntegerOptional(v.Replicas + 1)), Slots: new(api.String(fmt.Sprintf("%d-%d", 16384*shard/v.Shards, 16384*(shard+1)/v.Shards-1)))}
			for _, node := range v.Deployment.Nodes {
				if node.Shard == shard {
					row.Nodes = append(row.Nodes, api.Node{Name: new(api.String(node.ID)), Status: new(api.String(v.Status)), CreateTime: new(api.TStamp(v.Created)), Endpoint: endpointDTO(node.Endpoint)})
				}
			}
			out.Shards = append(out.Shards, row)
		}
	}
	return out
}

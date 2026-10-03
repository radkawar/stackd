package elasticache

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"maps"
	"slices"
	engine "stackd/engine/valkey"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/elasticache"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"strconv"
	"strings"
)

func resourceKey(ctx context.Context, kind, name string) (Key, error) {
	sc := scopeFor(ctx)
	k := Key{Scope: sc, Kind: kind, Name: strings.ToLower(name)}
	if strings.HasPrefix(name, "arn:") {
		prefix := Key{Scope: sc, Kind: kind}.ARN()
		if !strings.HasPrefix(name, prefix) {
			return Key{}, notFound(kind)
		}
		k.Name = strings.TrimPrefix(name, prefix)
	}
	max := 255
	if kind == "cluster" {
		max = 50
	} else if kind == "replicationgroup" {
		max = 40
	}
	if !validName(k.Name, max) && !(kind == "parametergroup" && builtinParameterFamily(k.Name) != "") {
		return Key{}, failure("InvalidParameterValue", "Invalid resource identifier.")
	}
	return k, nil
}
func validName(v string, max int) bool {
	if len(v) < 1 || len(v) > max || v[0] < 'a' || v[0] > 'z' || strings.HasSuffix(v, "-") || strings.Contains(v, "--") {
		return false
	}
	for _, c := range v {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func resourcePrefix(kind string) string {
	switch kind {
	case "cluster":
		return "CacheCluster"
	case "replicationgroup":
		return "ReplicationGroup"
	case "snapshot":
		return "Snapshot"
	case "user":
		return "User"
	case "usergroup":
		return "UserGroup"
	case "parametergroup":
		return "CacheParameterGroup"
	case "subnetgroup":
		return "CacheSubnetGroup"
	}
	return ""
}

func resourceError(kind, suffix string) error {
	prefix := resourcePrefix(kind)
	if prefix == "" {
		return failure("InvalidARN", "Unsupported ElastiCache resource type.")
	}
	model, _ := awscatalog.LookupService("elasticache")
	shape, ok := model.Shape(awscatalog.ShapeID("com.amazonaws.elasticache#" + prefix + suffix + "Fault"))
	if !ok {
		return failure("InternalFailure", "Missing generated resource error contract.")
	}
	message := "The requested resource does not exist."
	if suffix == "AlreadyExists" {
		message = "The requested resource already exists."
	}
	return &awswire.Error{Code: shape.Error.Code, Message: message, StatusCode: shape.Error.HTTPStatus}
}
func notFound(kind string) error    { return resourceError(kind, "NotFound") }
func existsError(kind string) error { return resourceError(kind, "AlreadyExists") }
func stateError(kind string) error {
	prefix := resourcePrefix(kind)
	return failure("Invalid"+prefix+"State", "The resource is not in a state that permits this operation.")
}
func (s *Service) authorize(ctx context.Context, action string, k Key, tags, requestTags map[string]string) error {
	conditions := map[string][]string{}
	for key, v := range tags {
		conditions["aws:ResourceTag/"+key] = []string{v}
	}
	for key, v := range requestTags {
		conditions["aws:RequestTag/"+key] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
	}
	arn := k.ARN()
	if k.Kind == "" {
		arn = "*"
	}
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "elasticache:" + action, ResourceARN: arn, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) loadCluster(ctx context.Context, r Reader, action, kind, name string) (Cluster, error) {
	k, e := resourceKey(ctx, kind, name)
	if e != nil {
		return Cluster{}, e
	}
	v, e := r.Cluster(k)
	if errors.Is(e, ErrNotFound) {
		if kind == "cluster" {
			all, err := r.Clusters(k.Scope)
			if err != nil {
				return Cluster{}, err
			}
			for _, group := range all {
				if !ownsMember(group, k.Name) {
					continue
				}
				if err = s.authorize(ctx, action, k, group.Tags, nil); err != nil {
					return Cluster{}, err
				}
				// TODO: Comeback implement per-member native restart and
				// ownership transfer before exposing member mutations.
				return Cluster{}, unsupported("Replication-group members are managed by their immutable native topology; this per-member operation is not supported.")
			}
		}
		e = notFound(kind)
	}
	if e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}

func ownsMember(group Cluster, name string) bool {
	if group.Key.Kind != "replicationgroup" {
		return false
	}
	suffix, ok := strings.CutPrefix(name, group.Key.Name+"-")
	if !ok || len(suffix) != 4 {
		return false
	}
	index, err := strconv.Atoi(suffix)
	return err == nil && index > 0 && index <= int(group.Shards*(group.Replicas+1))
}
func tagsFrom(in api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, t := range in {
		k, v := value(t.Key), value(t.Value)
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, failure("InvalidParameterValue", "Invalid tag.")
		}
		if _, ok := out[k]; ok {
			return nil, failure("InvalidParameterValue", "Tag keys must be unique.")
		}
		out[k] = v
	}
	if len(out) > 50 {
		return nil, failure("TagQuotaPerResourceExceeded", "At most 50 tags are permitted.")
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
func hashPassword(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
func tokenHash(v string) (string, error) {
	if len(v) < 16 || len(v) > 128 {
		return "", failure("InvalidParameterValue", "AUTH tokens must contain 16 to 128 characters.")
	}
	for _, c := range v {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!&#$^<>-", c)) {
			return "", failure("InvalidParameterValue", "AUTH token contains an unsupported character.")
		}
	}
	return hashPassword(v), nil
}
func engineVersion(name, version string) (string, string, error) {
	name = strings.ToLower(name)
	if name == "" {
		name = "redis"
	}
	supported := engine.Version
	if name == "redis" {
		supported = engine.RedisCompatibility
	} else if name != "valkey" {
		return "", "", unsupported("Only Valkey and explicit Redis 7.2 protocol compatibility are supported.")
	}
	if version != "" && version != supported && !(name == "valkey" && version == "8.1") {
		return "", "", unsupported("The requested engine version is not installed.")
	}
	return name, supported, nil
}
func nodeMemory(name string) (int64, error) {
	switch name {
	case "cache.t2.micro", "cache.t3.micro", "cache.t4g.micro":
		return 512 << 20, nil
	case "cache.t3.small", "cache.t4g.small":
		return 1 << 30, nil
	case "cache.t3.medium", "cache.t4g.medium":
		return 2 << 30, nil
	}
	return 0, unsupported("The requested node type has no supported native memory allocation.")
}
func newRuntimeID() string { return "elasticache-" + uuid.NewString() }
func (s *Service) requireRuntime() error {
	if s.runtime == nil {
		return unsupported("A real Valkey runtime must be configured.")
	}
	return nil
}
func page[T any](ctx context.Context, action, filter string, items []T, marker *api.String, maximum *api.IntegerOptional, key func(T) string) ([]T, *api.String, error) {
	limit := int(integer(maximum, 100))
	if action == "DescribeUsers" || action == "DescribeUserGroups" {
		if limit < 1 {
			return nil, nil, failure("InvalidParameterValue", "MaxRecords must be positive.")
		}
	} else if limit < 20 || limit > 100 {
		return nil, nil, failure("InvalidParameterValue", "MaxRecords must be between 20 and 100.")
	}
	sc := scopeFor(ctx)
	prefix := sc.Partition + "/" + sc.AccountID + "/" + sc.Region + "/" + action + "/" + filter + "/"
	after := ""
	if marker != nil {
		raw, e := base64.RawURLEncoding.DecodeString(value(marker))
		if e != nil || !strings.HasPrefix(string(raw), prefix) {
			return nil, nil, failure("InvalidParameterValue", "Invalid pagination marker.")
		}
		after = strings.TrimPrefix(string(raw), prefix)
	}
	start := 0
	for start < len(items) && key(items[start]) <= after {
		start++
	}
	end := min(start+limit, len(items))
	var next *api.String
	if end < len(items) {
		next = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + key(items[end-1])))))
	}
	return items[start:end], next, nil
}

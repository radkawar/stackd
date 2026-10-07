package docdb

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/docdb"
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
	if !validName(k.Name) {
		return Key{}, failure("InvalidParameterValue", "Invalid DocumentDB resource identifier.")
	}
	return k, nil
}
func validName(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' || strings.HasSuffix(s, "-") || strings.Contains(s, "--") {
		return false
	}
	for _, c := range s {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func notFound(kind string) error {
	code := "DBClusterNotFoundFault"
	if kind == "db" {
		code = "DBInstanceNotFound"
	}
	if kind == "cluster-snapshot" {
		code = "DBClusterSnapshotNotFoundFault"
	}
	return failure(code, "The requested DocumentDB resource does not exist.")
}
func stateError(kind string) error {
	code := "InvalidDBClusterStateFault"
	if kind == "db" {
		code = "InvalidDBInstanceState"
	}
	if kind == "cluster-snapshot" {
		code = "InvalidDBClusterSnapshotStateFault"
	}
	return failure(code, "The resource is not in a state that permits this operation.")
}
func duplicate(kind string) error {
	code := "DBClusterAlreadyExistsFault"
	if kind == "db" {
		code = "DBInstanceAlreadyExists"
	}
	if kind == "cluster-snapshot" {
		code = "DBClusterSnapshotAlreadyExistsFault"
	}
	return failure(code, "The requested DocumentDB resource already exists.")
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
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "rds:" + action, ResourceARN: arn, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) loadCluster(ctx context.Context, r Reader, action, name string) (Cluster, error) {
	k, e := resourceKey(ctx, "cluster", name)
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
	if e = checkCloudFormationOwner(ctx, k, v.Owner); e != nil {
		return v, e
	}
	if e = checkCloudFormationSnapshot(ctx, k, "cluster-"+v.RuntimeID); e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func (s *Service) loadInstance(ctx context.Context, r Reader, action, name string) (Instance, error) {
	k, e := resourceKey(ctx, "db", name)
	if e != nil {
		return Instance{}, e
	}
	v, e := r.Instance(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(k.Kind)
	}
	if e != nil {
		return v, e
	}
	if e = checkCloudFormationOwner(ctx, k, v.Owner); e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func (s *Service) loadSnapshot(ctx context.Context, r Reader, action, name string) (Snapshot, error) {
	k, e := resourceKey(ctx, "cluster-snapshot", name)
	if e != nil {
		return Snapshot{}, e
	}
	v, e := r.Snapshot(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(k.Kind)
	}
	if e != nil {
		return v, e
	}
	if e = checkCloudFormationOwner(ctx, k, v.Owner); e != nil {
		return v, e
	}
	if e = checkCloudFormationSnapshot(ctx, k, "cluster-"+v.SourceRuntimeID); e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}
func tagsFrom(in api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, t := range in {
		k, v := value(t.Key), value(t.Value)
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") || strings.HasPrefix(strings.ToLower(k), "rds:") {
			return nil, failure("InvalidParameterValue", "Invalid resource tag.")
		}
		if _, ok := out[k]; ok {
			return nil, failure("InvalidParameterValue", "Duplicate tag key.")
		}
		out[k] = v
	}
	if len(out) > 50 {
		return nil, failure("InvalidParameterValue", "At most 50 customer tags are supported.")
	}
	return out, nil
}
func tagList(in map[string]string) api.TagList {
	out := make(api.TagList, 0, len(in))
	for _, k := range slices.Sorted(maps.Keys(in)) {
		out = append(out, api.Tag{Key: new(api.String(k)), Value: new(api.String(in[k]))})
	}
	return out
}
func incarnation() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func validateCredentials(user, password string) error {
	if len(user) < 1 || len(user) > 63 {
		return failure("InvalidParameterValue", "Invalid master username.")
	}
	for i, c := range user {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return failure("InvalidParameterValue", "Invalid master username.")
		}
	}
	if len(password) < 8 || len(password) > 100 {
		return failure("InvalidParameterValue", "Invalid master password length.")
	}
	for _, c := range password {
		if c < 33 || c > 126 || c == '/' || c == '"' || c == '@' {
			return failure("InvalidParameterValue", "Invalid master password characters.")
		}
	}
	return nil
}
func (s *Service) ensureRuntime() error {
	if s.runtime == nil || s.cipher == nil {
		return unsupported("A native DocumentDB compatibility runtime and credential protection are required.")
	}
	return nil
}
func page(marker string, max *api.IntegerOptional, scope Scope, kind string) (string, int, error) {
	limit := 100
	if max != nil {
		limit = int(*max)
		if limit < 20 || limit > 100 {
			return "", 0, failure("InvalidParameterValue", "MaxRecords must be between 20 and 100.")
		}
	}
	if marker == "" {
		return "", limit, nil
	}
	raw, e := base64.RawURLEncoding.DecodeString(marker)
	prefix := scope.Partition + ":" + scope.AccountID + ":" + scope.Region + ":" + kind + ":"
	if e != nil || !strings.HasPrefix(string(raw), prefix) {
		return "", 0, failure("InvalidParameterValue", "Invalid pagination marker.")
	}
	return strings.TrimPrefix(string(raw), prefix), limit, nil
}
func markerFor(k Key) *api.String {
	return new(api.String(base64.RawURLEncoding.EncodeToString([]byte(k.Partition + ":" + k.AccountID + ":" + k.Region + ":" + k.Kind + ":" + k.Name))))
}

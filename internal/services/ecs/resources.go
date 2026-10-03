package ecs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awswire"
	"strconv"
	"strings"
)

var resourceName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)

func resourceID(ctx context.Context, id, kind string) (Scope, string, *awswire.Error) {
	scope := scopeFor(ctx)
	if !strings.HasPrefix(id, "arn:") {
		return scope, id, nil
	}
	p := strings.SplitN(id, ":", 6)
	if len(p) != 6 || p[0] != "arn" || p[1] != scope.Partition || p[2] != "ecs" || p[3] != scope.Region || p[4] != scope.AccountID || !strings.HasPrefix(p[5], kind+"/") {
		return Scope{}, "", failure("InvalidParameterException", "Invalid identifier: "+id)
	}
	return scope, strings.TrimPrefix(p[5], kind+"/"), nil
}
func clusterKey(ctx context.Context, id string) (ClusterKey, *awswire.Error) {
	scope, name, err := resourceID(ctx, id, "cluster")
	if err != nil {
		return ClusterKey{}, err
	}
	if name == "" {
		name = "default"
	}
	if !resourceName.MatchString(name) {
		return ClusterKey{}, failure("InvalidParameterException", "Cluster name contains invalid characters.")
	}
	return ClusterKey{scope, name}, nil
}
func serviceKey(ctx context.Context, cluster ClusterKey, id string) (ServiceKey, *awswire.Error) {
	scope, name, rejected := resourceID(ctx, id, "service")
	if rejected != nil {
		return ServiceKey{}, rejected
	}
	if owner, service, qualified := strings.Cut(name, "/"); qualified {
		if owner != cluster.Name {
			return ServiceKey{}, failure("InvalidParameterException", "The service does not belong to the specified cluster.")
		}
		name = service
	}
	if !resourceName.MatchString(name) {
		return ServiceKey{}, failure("InvalidParameterException", "Service name contains invalid characters.")
	}
	return ServiceKey{ClusterKey: ClusterKey{Scope: scope, Name: cluster.Name}, ServiceName: name}, nil
}
func definitionKey(ctx context.Context, id string, qualified bool) (TaskDefinitionKey, *awswire.Error) {
	scope, name, err := resourceID(ctx, id, "task-definition")
	if err != nil {
		return TaskDefinitionKey{}, err
	}
	family, revision, has := strings.Cut(name, ":")
	if !resourceName.MatchString(family) {
		return TaskDefinitionKey{}, failure("InvalidParameterException", "Invalid task definition: Invalid family name.")
	}
	key := TaskDefinitionKey{FamilyKey: FamilyKey{scope, family}}
	if !has {
		if qualified {
			return key, failure("InvalidParameterException", "Revision is missing")
		}
		return key, nil
	}
	n, e := strconv.ParseInt(revision, 10, 32)
	if e != nil || n <= 0 {
		return key, failure("InvalidParameterException", "Invalid task definition: Invalid revision number.")
	}
	key.Revision = int32(n)
	return key, nil
}
func tagsFor(r Reader, scope Scope, arn string) (api.Tags, error) {
	v, err := r.Tags(TagKey{scope, arn})
	if errors.Is(err, ErrNotFound) {
		return api.Tags{}, nil
	}
	return v.Tags, err
}
func loadDefinition(r Reader, key TaskDefinitionKey) (TaskDefinitionRecord, error) {
	if key.Revision != 0 {
		return r.TaskDefinition(key)
	}
	rows, err := r.TaskDefinitions(TaskDefinitionQuery{Scope: key.Scope, Family: key.Family, Status: "ACTIVE", Descending: true, Limit: 1})
	if err != nil {
		return TaskDefinitionRecord{}, err
	}
	if len(rows) == 0 {
		return TaskDefinitionRecord{}, ErrNotFound
	}
	return rows[0], nil
}

type pageCursor struct{ Collection, After string }

func page(token *api.String, collection string) (string, *awswire.Error) {
	if token == nil {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(value(token))
	var c pageCursor
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Collection != collection || c.After == "" {
		return "", failure("InvalidParameterException", "Invalid next token.")
	}
	return c.After, nil
}
func nextPage(collection, after string) *api.String {
	raw, _ := json.Marshal(pageCursor{collection, after})
	return new(api.String(base64.RawURLEncoding.EncodeToString(raw)))
}
func pageSize(max *api.BoxedInteger) (int, *awswire.Error) {
	if max == nil {
		return 100, nil
	}
	if *max < 1 || *max > 100 {
		return 0, failure("InvalidParameterException", "maxResults must be between 1 and 100.")
	}
	return int(*max), nil
}
func collection(scope Scope, parts ...string) string {
	return scope.Partition + ":" + scope.AccountID + ":" + scope.Region + ":" + strings.Join(parts, ":")
}

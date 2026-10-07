package rds

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/rds"
)

func resourceKey(ctx context.Context, kind, name string) (Key, error) {
	sc := scopeFor(ctx)
	k := Key{Scope: sc, Kind: kind, Name: strings.ToLower(name)}
	if strings.HasPrefix(name, "arn:") {

		prefix := "arn:" + sc.Partition + ":rds:" + sc.Region + ":" + sc.AccountID + ":" + kind + ":"
		if !strings.HasPrefix(name, prefix) {
			return Key{}, notFound(kind)
		}
		k.Name = strings.TrimPrefix(name, prefix)

	}
	if !validName(k.Name, 255) {
		return Key{}, failure("InvalidParameterValue", "Invalid RDS resource identifier.")
	}
	return k, nil
}

func validName(v string, max int) bool {
	if len(v) == 0 || len(v) > max || v[0] < 'a' || v[0] > 'z' || strings.HasSuffix(v, "-") || strings.Contains(v, "--") {
		return false
	}
	for _, c := range v {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func notFound(kind string) error {
	code := "DBInstanceNotFound"
	switch kind {

	case "cluster":
		code = "DBClusterNotFoundFault"
	case "snapshot":
		code = "DBSnapshotNotFound"
	case "cluster-snapshot":
		code = "DBClusterSnapshotNotFoundFault"
	case "pg", "cluster-pg":
		code = "DBParameterGroupNotFound"
	case "subgrp":
		code = "DBSubnetGroupNotFoundFault"

	}
	return failure(code, "The requested RDS resource does not exist.")
}

func existsError(kind string) error {
	code := "DBInstanceAlreadyExists"
	switch kind {

	case "cluster":
		code = "DBClusterAlreadyExistsFault"
	case "snapshot":
		code = "DBSnapshotAlreadyExists"
	case "cluster-snapshot":
		code = "DBClusterSnapshotAlreadyExistsFault"
	case "pg", "cluster-pg":
		code = "DBParameterGroupAlreadyExists"
	case "subgrp":
		code = "DBSubnetGroupAlreadyExists"

	}
	return failure(code, "The requested RDS resource already exists.")
}

func stateError(kind string) error {
	code := "InvalidDBInstanceState"
	if kind == "cluster" {
		code = "InvalidDBClusterStateFault"
	}
	if kind == "snapshot" {
		code = "InvalidDBSnapshotState"
	}
	if kind == "cluster-snapshot" {
		code = "InvalidDBClusterSnapshotStateFault"
	}
	return failure(code, "The resource is not in a state that permits this operation.")
}

func (s *Service) authorize(ctx context.Context, action string, key Key, tags, requestTags map[string]string) error {
	conditions := map[string][]string{}
	for k, v := range tags {

		conditions["aws:ResourceTag/"+k] = []string{v}
		conditions["rds:"+key.Kind+"-tag/"+k] = []string{v}

	}
	for k, v := range requestTags {

		conditions["aws:RequestTag/"+k] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], k)

	}
	arn := key.ARN()
	if key.Kind == "" {
		arn = "*"
	}
	now := s.clock.Now()
	if e := s.authorizer.Authorize(ctx, authorization.Request{Action: "rds:" + action, ResourceARN: arn, Context: conditions, EvaluationTime: &now}); e != nil {
		return e
	}
	return nil
}

func (s *Service) loadDatabase(ctx context.Context, tx Reader, action, kind, name string) (Database, error) {
	k, e := resourceKey(ctx, kind, name)
	if e != nil {
		return Database{}, e
	}
	v, e := tx.Database(k)
	if errors.Is(e, ErrNotFound) {
		e = notFound(kind)
	}
	if e != nil {
		return v, e
	}
	if e = checkCloudFormationOwner(ctx, k, v.Owner); e != nil {
		return v, e
	}
	id := "db-" + v.ResourceID
	if kind == "cluster" {
		id = "cluster-" + v.ResourceID
	}
	if e = checkCloudFormationSnapshot(ctx, k, id); e != nil {
		return v, e
	}
	return v, s.authorize(ctx, action, k, v.Tags, nil)
}

func tagsFrom(in api.TagList) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for _, t := range in {

		k, v := value(t.Key), value(t.Value)
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") || strings.HasPrefix(strings.ToLower(k), "rds:") {
			return nil, failure("InvalidParameterValue", "Invalid RDS tag.")
		}
		if _, ok := out[k]; ok {
			return nil, failure("InvalidParameterValue", "Tag keys must be unique.")
		}
		out[k] = v

	}
	if len(out) > 50 {
		return nil, failure("InvalidParameterValue", "At most 50 customer tags are supported.")
	}
	return out, nil
}

func tagList(in map[string]string) api.TagList {
	keys := slices.Sorted(maps.Keys(in))
	out := make(api.TagList, 0, len(keys))
	for _, k := range keys {
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

func validateCredentials(engine, username, password string) error {
	if len(username) < 1 || len(username) > 16 || !unicode.IsLetter(rune(username[0])) {
		return failure("InvalidParameterValue", "Invalid master username.")
	}
	for _, c := range username {
		if c > 127 || (!unicode.IsLetter(c) && !unicode.IsDigit(c)) {
			return failure("InvalidParameterValue", "Invalid master username.")
		}
	}
	max := 128
	if strings.Contains(engine, "mysql") {
		max = 41
	}
	if len(password) < 8 || len(password) > max {
		return failure("InvalidParameterValue", "Invalid master password length.")
	}
	for _, c := range password {
		if c < 33 || c > 126 || c == '/' || c == '"' || c == '@' {
			return failure("InvalidParameterValue", "Invalid master password characters.")
		}
	}
	return nil
}

func validateDBName(v string) error {
	if len(v) > 63 {
		return failure("InvalidParameterValue", "Invalid database name.")
	}
	for i, c := range v {
		if c > 127 || (!unicode.IsLetter(c) && (!unicode.IsDigit(c) || i == 0) && c != '_') {
			return failure("InvalidParameterValue", "Invalid database name.")
		}
	}
	return nil
}

func engineVersion(engine string) string {
	switch engine {

	case "postgres", "aurora-postgresql":
		return "17.11"
	case "mysql", "aurora-mysql":
		return "8.4.11"

	}
	return ""
}

func engineFamily(engine string) string {
	switch engine {

	case "postgres":
		return "postgres17"
	case "aurora-postgresql":
		return "aurora-postgresql17"
	case "mysql":
		return "mysql8.4"
	case "aurora-mysql":
		return "aurora-mysql8.4"

	}
	return ""
}

func (s *Service) ensureRuntime() error {
	if s.runtime == nil || s.cipher == nil {
		return unsupported("A native RDS runtime and credential encryption owner must be configured.")
	}
	return nil
}

// CloudFormationRequestedPort distinguishes an owner-selected listener from a
// fixed port while the endpoint is unavailable during a native transition.
func (s *Service) CloudFormationRequestedPort(ctx context.Context, kind, name string) (int32, error) {
	if s.documents != nil {
		if port, handled, err := s.documents.CloudFormationRequestedPort(ctx, kind, name); handled || err != nil {
			return port, err
		}
	}
	action := "DescribeDBInstances"
	if kind == "cluster" {
		action = "DescribeDBClusters"
	}
	var port int32
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.loadDatabase(r.Context(), r, action, kind, name)
		if err != nil {
			return err
		}
		port = v.RequestedPort
		return nil
	})
	return port, err
}

func instanceDTO(v Database) api.DBInstance {
	out := api.DBInstance{DBInstanceIdentifier: new(api.String(v.Key.Name)), DBInstanceArn: new(api.String(v.Key.ARN())), DbiResourceId: new(api.String("db-" + v.ResourceID)), DBInstanceClass: new(api.String(v.Class)), DBInstanceStatus: new(api.String(v.Status)), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), MasterUsername: new(api.String(v.Username)), InstanceCreateTime: new(api.TStamp(v.Created)), MultiAZ: new(api.Boolean(false)), StorageEncrypted: new(api.Boolean(false)), PubliclyAccessible: new(api.Boolean(false)), DeletionProtection: new(api.Boolean(v.DeletionProtection)), CopyTagsToSnapshot: new(api.Boolean(v.CopyTags)), BackupRetentionPeriod: new(api.Integer(0)), AutoMinorVersionUpgrade: new(api.Boolean(false)), IAMDatabaseAuthenticationEnabled: new(api.Boolean(false)), TagList: tagList(v.Tags)}
	if v.DatabaseName != "" {
		out.DBName = new(api.String(v.DatabaseName))
	}
	if v.Cluster != "" {
		out.DBClusterIdentifier = new(api.String(v.Cluster))
	}
	if v.Status == "available" && v.Endpoint.Address != "" {
		out.Endpoint = &api.Endpoint{Address: new(api.String(v.Endpoint.Address)), Port: new(api.Integer(v.Endpoint.Port))}
	}
	if v.ParameterGroup != "" {
		out.DBParameterGroups = api.DBParameterGroupStatusList{{DBParameterGroupName: new(api.String(v.ParameterGroup)), ParameterApplyStatus: new(api.String(parameterStatus(v)))}}
	}
	return out
}

func clusterDTO(v Database, members []Database) api.DBCluster {
	out := api.DBCluster{DBClusterIdentifier: new(api.String(v.Key.Name)), DBClusterArn: new(api.String(v.Key.ARN())), DbClusterResourceId: new(api.String("cluster-" + v.ResourceID)), Status: new(api.String(v.Status)), Engine: new(api.String(v.Engine)), EngineVersion: new(api.String(v.EngineVersion)), EngineMode: new(api.String("provisioned")), MasterUsername: new(api.String(v.Username)), ClusterCreateTime: new(api.TStamp(v.Created)), MultiAZ: new(api.BooleanOptional(false)), StorageEncrypted: new(api.Boolean(false)), DeletionProtection: new(api.BooleanOptional(v.DeletionProtection)), CopyTagsToSnapshot: new(api.BooleanOptional(v.CopyTags)), HttpEndpointEnabled: new(api.BooleanOptional(v.HTTPEnabled)), IAMDatabaseAuthenticationEnabled: new(api.BooleanOptional(false)), TagList: tagList(v.Tags)}
	if v.DatabaseName != "" {
		out.DatabaseName = new(api.String(v.DatabaseName))
	}
	if v.ParameterGroup != "" {
		out.DBClusterParameterGroup = new(api.String(v.ParameterGroup))
	}
	for _, m := range members {
		if m.Key.Kind == "db" && m.Cluster == v.Key.Name {
			out.DBClusterMembers = append(out.DBClusterMembers, api.DBClusterMember{DBInstanceIdentifier: new(api.String(m.Key.Name)), IsClusterWriter: new(api.Boolean(true)), DBClusterParameterGroupStatus: new(api.String(parameterStatus(v))), PromotionTier: new(api.IntegerOptional(0))})
		}
	}
	if v.Status == "available" && len(out.DBClusterMembers) > 0 && v.Endpoint.Address != "" {

		out.Endpoint = new(api.String(v.Endpoint.Address))
		out.Port = new(api.IntegerOptional(v.Endpoint.Port))

	}
	return out
}

func (s *Service) publishTransition(ctx context.Context, v Database, message string) error {
	if s.events == nil {
		return nil
	}
	return s.events.PublishRDSEvent(ctx, RDSEvent{ARN: v.Key.ARN(), Identifier: v.Key.Name, Kind: v.Key.Kind, Status: v.Status, Operation: v.Operation, Message: message, At: s.clock.Now()})
}

func parameterStatus(v Database) string {
	if v.Operation == "parameters" {
		return "applying"
	}
	if v.PendingParameters {
		return "pending-reboot"
	}
	return "in-sync"
}

// WithRDSRoleUsage holds the read snapshot while IAM evaluates role deletion.
func (s *Service) WithRDSRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.View(ctx, func(r Reader) error {
		dbs, e := r.AllDatabases()
		if e != nil {
			return e
		}
		snaps, e := r.AllSnapshots()
		if e != nil {
			return e
		}
		arns := []string{}
		for _, v := range dbs {
			if v.Key.Partition == partition && v.Key.AccountID == account {
				arns = append(arns, v.Key.ARN())
			}
		}
		for _, v := range snaps {
			if v.Key.Partition == partition && v.Key.AccountID == account {
				arns = append(arns, v.Key.ARN())
			}
		}
		slices.Sort(arns)
		return fn(r.Context(), arns)
	})
}

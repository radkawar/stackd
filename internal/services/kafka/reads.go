package kafka

import (
	"context"
	"encoding/base64"
	"encoding/json"
	api "stackd/internal/awsapi/kafka"
	"strconv"
	"strings"
)

type pageCursor struct{ Binding, Last string }

func page[T any](rows []T, max *api.MaxResults, token, binding string, key func(T) string) ([]T, string, error) {
	limit := 100
	if max != nil {
		limit = int(*max)
		if limit < 1 || limit > 100 {
			return nil, "", invalid("MaxResults must be between 1 and 100")
		}
	}
	last := ""
	if token != "" {
		b, e := base64.RawURLEncoding.DecodeString(token)
		var c pageCursor
		if e != nil || json.Unmarshal(b, &c) != nil || c.Binding != binding || c.Last == "" {
			return nil, "", invalid("Invalid NextToken")
		}
		last = c.Last
	}
	start := 0
	for start < len(rows) && key(rows[start]) <= last {
		start++
	}
	end := start + limit
	if end >= len(rows) {
		return rows[start:], "", nil
	}
	b, _ := json.Marshal(pageCursor{binding, key(rows[end-1])})
	return rows[start:end], base64.RawURLEncoding.EncodeToString(b), nil
}
func pageBinding(ctx context.Context, action, filter string) string {
	sc := scopeFor(ctx)
	return sc.Partition + ":" + sc.AccountID + ":" + sc.Region + ":" + action + ":" + filter
}
func software(v ClusterRecord) *api.BrokerSoftwareInfo {
	out := &api.BrokerSoftwareInfo{}
	text(&out.KafkaVersion, v.KafkaVersion)
	if v.ConfigurationARN != "" {
		text(&out.ConfigurationArn, v.ConfigurationARN)
		number(&out.ConfigurationRevision, v.ConfigurationRevision)
	}
	return out
}
func clusterInfo(v ClusterRecord) *api.ClusterInfo {
	out := &api.ClusterInfo{State: new(api.ClusterState(v.State)), CreationTime: new(v.Created), CurrentBrokerSoftwareInfo: software(v), BrokerNodeGroupInfo: &api.BrokerNodeGroupInfo{}, ClientAuthentication: &api.ClientAuthentication{}, EncryptionInfo: &api.EncryptionInfo{EncryptionInTransit: &api.EncryptionInTransit{}}}
	text(&out.ClusterArn, v.ARN)
	text(&out.ClusterName, v.Name)
	text(&out.CurrentVersion, strconv.FormatInt(v.Version, 10))
	number(&out.NumberOfBrokerNodes, int64(v.Brokers))
	text(&out.BrokerNodeGroupInfo.InstanceType, "kafka.local")
	stringList(&out.BrokerNodeGroupInfo.ClientSubnets, nil)
	tagMap(&out.Tags, v.Tags)
	mode := "TLS"
	if v.SecurityMode == "PLAINTEXT" {
		mode = "PLAINTEXT"
	}
	out.EncryptionInfo.EncryptionInTransit.ClientBroker = new(api.ClientBroker(mode))
	boolean(&out.EncryptionInfo.EncryptionInTransit.InCluster, true)
	if v.SecurityMode == "SASL_SCRAM" {
		out.ClientAuthentication.Sasl = &api.Sasl{Scram: &api.Scram{}}
		boolean(&out.ClientAuthentication.Sasl.Scram.Enabled, true)
		out.ClientAuthentication.Unauthenticated = &api.Unauthenticated{}
		boolean(&out.ClientAuthentication.Unauthenticated.Enabled, false)
	} else {
		out.ClientAuthentication.Unauthenticated = &api.Unauthenticated{}
		boolean(&out.ClientAuthentication.Unauthenticated.Enabled, true)
	}
	if v.OperationARN != "" && (v.State == "UPDATING" || v.State == "HEALING") {
		text(&out.ActiveOperationArn, v.OperationARN)
	}
	if v.Failure != "" {
		out.StateInfo = &api.StateInfo{}
		text(&out.StateInfo.Code, "NATIVE_ENGINE_FAILURE")
		text(&out.StateInfo.Message, v.Failure)
	}
	return out
}
func clusterV2(v ClusterRecord) *api.Cluster {
	c := clusterInfo(v)
	p := &api.Provisioned{BrokerNodeGroupInfo: c.BrokerNodeGroupInfo, ClientAuthentication: c.ClientAuthentication, CurrentBrokerSoftwareInfo: c.CurrentBrokerSoftwareInfo, EncryptionInfo: c.EncryptionInfo}
	number(&p.NumberOfBrokerNodes, int64(v.Brokers))
	return &api.Cluster{ActiveOperationArn: c.ActiveOperationArn, ClusterArn: c.ClusterArn, ClusterName: c.ClusterName, ClusterType: new(api.ClusterType("PROVISIONED")), CreationTime: c.CreationTime, CurrentVersion: c.CurrentVersion, Provisioned: p, State: c.State, StateInfo: c.StateInfo, Tags: c.Tags}
}
func (s *Service) describeCluster(ctx context.Context, t Transaction, in *api.DescribeClusterInput) (*api.DescribeClusterOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "DescribeCluster")
	if e != nil {
		return nil, e
	}
	return &api.DescribeClusterOutput{ClusterInfo: clusterInfo(v)}, nil
}
func (s *Service) describeClusterV2(ctx context.Context, t Transaction, in *api.DescribeClusterV2Input) (*api.DescribeClusterV2Output, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "DescribeClusterV2")
	if e != nil {
		return nil, e
	}
	return &api.DescribeClusterV2Output{ClusterInfo: clusterV2(v)}, nil
}
func (s *Service) clusterRows(ctx context.Context, t Transaction, action, filter string) ([]ClusterRecord, error) {
	if e := s.authorize(ctx, ClusterRecord{}, action, nil); e != nil {
		return nil, e
	}
	rows, e := t.Clusters(scopeFor(ctx))
	if e != nil {
		return nil, e
	}
	out := []ClusterRecord{}
	for _, v := range rows {
		if strings.HasPrefix(v.Name, filter) {
			out = append(out, v)
		}
	}
	return out, nil
}
func (s *Service) listClusters(ctx context.Context, t Transaction, in *api.ListClustersInput) (*api.ListClustersOutput, error) {
	rows, e := s.clusterRows(ctx, t, "ListClusters", value(in.ClusterNameFilter))
	if e != nil {
		return nil, e
	}
	rows, next, e := page(rows, in.MaxResults, value(in.NextToken), pageBinding(ctx, "ListClusters", value(in.ClusterNameFilter)), func(v ClusterRecord) string { return v.ARN })
	if e != nil {
		return nil, e
	}
	out := &api.ListClustersOutput{}
	for _, v := range rows {
		out.ClusterInfoList = append(out.ClusterInfoList, *clusterInfo(v))
	}
	if next != "" {
		text(&out.NextToken, next)
	}
	return out, nil
}
func (s *Service) listClustersV2(ctx context.Context, t Transaction, in *api.ListClustersV2Input) (*api.ListClustersV2Output, error) {
	filter := value(in.ClusterTypeFilter)
	if filter != "" && filter != "PROVISIONED" && filter != "SERVERLESS" {
		return nil, invalid("Invalid cluster type filter")
	}
	rows, e := s.clusterRows(ctx, t, "ListClustersV2", value(in.ClusterNameFilter))
	if e != nil {
		return nil, e
	}
	if filter == "SERVERLESS" {
		rows = nil
	}
	rows, next, e := page(rows, in.MaxResults, value(in.NextToken), pageBinding(ctx, "ListClustersV2", value(in.ClusterNameFilter)+"/"+filter), func(v ClusterRecord) string { return v.ARN })
	if e != nil {
		return nil, e
	}
	out := &api.ListClustersV2Output{}
	for _, v := range rows {
		out.ClusterInfoList = append(out.ClusterInfoList, *clusterV2(v))
	}
	if next != "" {
		text(&out.NextToken, next)
	}
	return out, nil
}
func (s *Service) bootstrap(ctx context.Context, t Transaction, in *api.GetBootstrapBrokersInput) (*api.GetBootstrapBrokersOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "GetBootstrapBrokers")
	if e != nil {
		return nil, e
	}
	if v.State != "ACTIVE" || len(v.Endpoint.Brokers) == 0 {
		return nil, invalid("The cluster has no protocol-ready brokers")
	}
	addresses := make([]string, 0, len(v.Endpoint.Brokers))
	for _, b := range v.Endpoint.Brokers {
		addresses = append(addresses, b.Address)
	}
	out := &api.GetBootstrapBrokersOutput{}
	switch v.SecurityMode {
	case "PLAINTEXT":
		text(&out.BootstrapBrokerString, strings.Join(addresses, ","))
	case "TLS":
		text(&out.BootstrapBrokerStringTls, strings.Join(addresses, ","))
	case "SASL_SCRAM":
		text(&out.BootstrapBrokerStringSaslScram, strings.Join(addresses, ","))
	}
	return out, nil
}
func (s *Service) listNodes(ctx context.Context, t Transaction, in *api.ListNodesInput) (*api.ListNodesOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "ListNodes")
	if e != nil {
		return nil, e
	}
	rows, next, e := page(v.Endpoint.Brokers, in.MaxResults, value(in.NextToken), pageBinding(ctx, "ListNodes", v.ARN), func(v Broker) string { return strconv.FormatInt(int64(v.ID), 10) })
	if e != nil {
		return nil, e
	}
	out := &api.ListNodesOutput{}
	for _, b := range rows {
		n := api.NodeInfo{NodeType: new(api.NodeTypeBROKER), BrokerNodeInfo: &api.BrokerNodeInfo{CurrentBrokerSoftwareInfo: software(v)}}
		number(&n.BrokerNodeInfo.BrokerId, int64(b.ID))
		stringList(&n.BrokerNodeInfo.Endpoints, []string{b.Address})
		text(&n.InstanceType, "kafka.local")
		text(&n.NodeARN, v.ARN+"/broker/"+strconv.Itoa(int(b.ID)))
		out.NodeInfoList = append(out.NodeInfoList, n)
	}
	if next != "" {
		text(&out.NextToken, next)
	}
	return out, nil
}
func operationInfo(v OperationRecord) *api.ClusterOperationInfo {
	out := &api.ClusterOperationInfo{CreationTime: new(v.Created)}
	text(&out.OperationArn, v.ARN)
	text(&out.ClusterArn, v.ClusterARN)
	text(&out.OperationType, v.Type)
	text(&out.OperationState, v.State)
	if !v.Ended.IsZero() {
		out.EndTime = new(v.Ended)
	}
	if v.Failure != "" {
		out.ErrorInfo = &api.ErrorInfo{}
		text(&out.ErrorInfo.ErrorCode, "NATIVE_ENGINE_FAILURE")
		text(&out.ErrorInfo.ErrorString, v.Failure)
	}
	if v.SourceConfigurationARN != "" {
		out.SourceClusterInfo = &api.MutableClusterInfo{ConfigurationInfo: &api.ConfigurationInfo{}}
		text(&out.SourceClusterInfo.ConfigurationInfo.Arn, v.SourceConfigurationARN)
		number(&out.SourceClusterInfo.ConfigurationInfo.Revision, v.SourceRevision)
	}
	if v.TargetConfigurationARN != "" {
		out.TargetClusterInfo = &api.MutableClusterInfo{ConfigurationInfo: &api.ConfigurationInfo{}}
		text(&out.TargetClusterInfo.ConfigurationInfo.Arn, v.TargetConfigurationARN)
		number(&out.TargetClusterInfo.ConfigurationInfo.Revision, v.TargetRevision)
	}
	return out
}
func (s *Service) describeOperation(ctx context.Context, t Transaction, in *api.DescribeClusterOperationInput) (*api.DescribeClusterOperationOutput, error) {
	v, e := t.Operation(value(in.ClusterOperationArn))
	if e != nil {
		return nil, e
	}
	if _, e = s.load(ctx, t, v.ClusterARN, "DescribeClusterOperation"); e != nil {
		return nil, e
	}
	return &api.DescribeClusterOperationOutput{ClusterOperationInfo: operationInfo(v)}, nil
}
func (s *Service) listOperations(ctx context.Context, t Transaction, in *api.ListClusterOperationsInput) (*api.ListClusterOperationsOutput, error) {
	v, e := s.load(ctx, t, value(in.ClusterArn), "ListClusterOperations")
	if e != nil {
		return nil, e
	}
	rows, e := t.Operations(v.ARN)
	if e != nil {
		return nil, e
	}
	rows, next, e := page(rows, in.MaxResults, value(in.NextToken), pageBinding(ctx, "ListClusterOperations", v.ARN), func(v OperationRecord) string { return v.ARN })
	if e != nil {
		return nil, e
	}
	out := &api.ListClusterOperationsOutput{}
	for _, v := range rows {
		out.ClusterOperationInfoList = append(out.ClusterOperationInfoList, *operationInfo(v))
	}
	if next != "" {
		text(&out.NextToken, next)
	}
	return out, nil
}

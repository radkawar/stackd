package ssmcommands

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awswire"
	"stackd/journal"
)

// HandlesAgentRequest is deliberately exact: private health reporting does not
// bypass the generated frontend for any public AmazonSSM operation.
func HandlesAgentRequest(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == "/" && r.Header.Get("X-Amz-Target") == "AmazonSSM.UpdateInstanceInformation"
}

// ServeAgentHTTP receives a request already authenticated by gateway.Authenticate
// with signing service ssm. Registration still verifies live EC2-origin authority.
func (s *Service) ServeAgentHTTP(w http.ResponseWriter, r *http.Request) {
	if !HandlesAgentRequest(r) {
		http.NotFound(w, r)
		return
	}
	var in UpdateInstanceInformationInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&in); err != nil {
		awswire.JSONError(w, r, failure("SerializationException", "Invalid agent health request."))
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		awswire.JSONError(w, r, failure("SerializationException", "Invalid trailing agent request data."))
		return
	}
	if err := in.validate(); err != nil {
		awswire.JSONError(w, r, s.wireError(r.Context(), err))
		return
	}
	ctx, err := apievents.Reserve(r.Context())
	if err != nil {
		awswire.JSONError(w, r, s.wireError(r.Context(), err))
		return
	}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		if err := s.AuthorizeAgent(tx.Context(), value(in.InstanceId), "ssm:UpdateInstanceInformation"); err != nil {
			return err
		}
		if value(in.PlatformType) != "" && value(in.PlatformType) != "Linux" {
			// TODO: Comeback support managed Windows/macOS command plugins with native guest execution.
			return failure("UnsupportedPlatformType", "Only Linux managed guest execution is implemented.")
		}
		node, err := tx.Node(keyFor(ctx, value(in.InstanceId)))
		if errors.Is(err, ErrNotFound) {
			node = Node{Key: keyFor(ctx, value(in.InstanceId)), RegisteredAt: s.clock.Now().UTC()}
		} else if err != nil {
			return err
		}
		if in.AgentVersion != nil {
			node.AgentVersion = *in.AgentVersion
		}
		if in.AgentName != nil {
			node.AgentName = *in.AgentName
		}
		if in.PlatformType != nil {
			node.PlatformType = *in.PlatformType
		}
		if in.PlatformName != nil {
			node.PlatformName = *in.PlatformName
		}
		if in.PlatformVersion != nil {
			node.PlatformVersion = *in.PlatformVersion
		}
		if in.ComputerName != nil {
			node.ComputerName = *in.ComputerName
		}
		node.LastPing = s.clock.Now().UTC()
		if err = tx.PutNode(node); err != nil {
			return err
		}
		return s.recordAgentHealth(tx.Context(), in, nil)
	})
	if err != nil {
		rejected := s.wireError(ctx, err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err = s.recordAgentHealth(completion, in, rejected); err != nil {
			rejected = s.wireError(ctx, err)
		}
		awswire.JSONError(w, r, rejected)
		return
	}
	awswire.WriteJSONBytes(w, r, []byte("{}"))
}
func (s *Service) recordAgentHealth(ctx context.Context, in UpdateInstanceInformationInput, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	// The public Smithy model omits this private request. Its official-SDK-derived
	// projection retains native field presence and redacts, rather than drops, IPAddress.
	request, err := json.Marshal(in.auditParameters())
	if err != nil {
		return err
	}
	call := journal.APICallCompleted{EventID: apievents.EventID(ctx), EventSource: "ssm.amazonaws.com", EventName: "UpdateInstanceInformation", Category: journal.CategoryManagement, RequestParameters: request}
	if rejected != nil {
		call.ErrorCode = rejected.Code
		call.ErrorMessage = rejected.Message
	}
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
func (s *Service) describeInstanceInformation(tx Transaction, in *api.DescribeInstanceInformationRequest) (*api.DescribeInstanceInformationResult, error) {
	if err := s.authorize(tx.Context(), "ssm:DescribeInstanceInformation", "*", nil); err != nil {
		return nil, err
	}
	if len(in.Filters) > 0 && len(in.InstanceInformationFilterList) > 0 {
		return nil, failure("ValidationException", "Filters and InstanceInformationFilterList cannot be combined.")
	}
	filters := make([]Target, 0, len(in.Filters)+len(in.InstanceInformationFilterList))
	for _, f := range in.Filters {
		t := Target{Key: value(f.Key)}
		for _, v := range f.Values {
			t.Values = append(t.Values, string(v))
		}
		filters = append(filters, t)
	}
	for _, f := range in.InstanceInformationFilterList {
		t := Target{Key: value(f.Key)}
		for _, v := range f.ValueSet {
			t.Values = append(t.Values, string(v))
		}
		filters = append(filters, t)
	}
	tags, other := false, false
	for _, f := range filters {
		if len(f.Values) == 0 {
			return nil, failure("ValidationException", "Managed node filters require values.")
		}
		if strings.HasPrefix(f.Key, "tag:") || f.Key == "tag-key" {
			tags = true
		} else {
			other = true
		}
		switch f.Key {
		case "InstanceIds", "AgentVersion", "PingStatus", "PlatformTypes", "ResourceType", "SourceIds", "SourceTypes", "ActivationIds", "IamRole", "AssociationStatus", "tag-key":
		default:
			if !strings.HasPrefix(f.Key, "tag:") || len(f.Key) == 4 {
				return nil, failure("ValidationException", "Unsupported managed node filter.")
			}
		}
	}
	if tags && other {
		return nil, failure("ValidationException", "Tag filters cannot be combined with other managed node filters.")
	}
	nodes, err := tx.Nodes(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	rows := make([]api.InstanceInformation, 0, len(nodes))
	for _, node := range nodes {
		instance, err := s.instances.Instance(tx.Context(), node.Key.ID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if instance.State != "running" {
			continue
		}
		ping := "Online"
		if s.clock.Now().Sub(node.LastPing) > 5*time.Minute {
			ping = "ConnectionLost"
		}
		match := true
		for _, f := range filters {
			actual := ""
			present := true
			switch f.Key {
			case "InstanceIds", "SourceIds":
				actual = node.Key.ID
			case "AgentVersion":
				actual = node.AgentVersion
			case "PingStatus":
				actual = ping
			case "PlatformTypes":
				actual = node.PlatformType
			case "ResourceType":
				actual = "EC2Instance"
			case "SourceTypes":
				actual = "AWS::EC2::Instance"
			case "tag-key":
				present = false
				for _, k := range f.Values {
					if _, ok := instance.Tags[k]; ok {
						actual = k
						present = true
						break
					}
				}
			default:
				if strings.HasPrefix(f.Key, "tag:") {
					actual, present = instance.Tags[strings.TrimPrefix(f.Key, "tag:")]
				}
			}
			if !present || !slices.Contains(f.Values, actual) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		rows = append(rows, api.InstanceInformation{InstanceId: new(api.InstanceId(node.Key.ID)), AgentVersion: new(api.Version(node.AgentVersion)), ComputerName: new(api.ComputerName(node.ComputerName)), IPAddress: new(api.IPAddress(instance.PrivateIP)), LastPingDateTime: new(api.DateTime(node.LastPing)), PlatformType: new(api.PlatformType(node.PlatformType)), PlatformName: new(api.String(node.PlatformName)), PlatformVersion: new(api.String(node.PlatformVersion)), PingStatus: new(api.PingStatus(ping)), ResourceType: new(api.ResourceType("EC2Instance")), SourceId: new(api.SourceId(node.Key.ID)), SourceType: new(api.SourceType("AWS::EC2::Instance"))})
	}
	size := 50
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	if size < 5 {
		return nil, failure("ValidationException", "MaxResults must be at least 5.")
	}
	query := *in
	query.NextToken = nil
	query.MaxResults = nil
	rows, next, err := page(s, tx, "DescribeInstanceInformation", query, rows, func(n api.InstanceInformation) string { return value(n.InstanceId) }, size, 50, in.NextToken)
	if err != nil {
		return nil, err
	}
	return &api.DescribeInstanceInformationResult{InstanceInformationList: rows, NextToken: next}, nil
}

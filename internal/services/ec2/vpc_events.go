package ec2

import (
	"context"
	"encoding/json"
	"time"

	"stackd/journal"
)

// VPC default resources are one native service-generated outcome, not three
// fictitious customer API calls. Their event commits with the VPC transition.
func (s *Service) recordVPCResources(ctx context.Context, vpc ResourceKey, eventName, aclID, routeID, groupID string) error {
	if s.recorder == nil {
		return nil
	}
	details, _ := json.Marshal(struct {
		VPCID string `json:"vpcId"`
	}{VPCID: vpc.ID})
	call := journal.APICallCompleted{
		EventSource:         "ec2.amazonaws.com",
		EventName:           eventName,
		Category:            journal.CategoryManagement,
		ServiceEvent:        true,
		ServiceEventDetails: details,
		EventResources: []journal.APIEventResource{
			{AccountID: vpc.Scope.AccountID, Type: "AWS::EC2::NetworkAcl", ARN: resourceARN(vpc.Scope, "network-acl", aclID)},
			{AccountID: vpc.Scope.AccountID, Type: "AWS::EC2::RouteTable", ARN: resourceARN(vpc.Scope, "route-table", routeID)},
			{AccountID: vpc.Scope.AccountID, Type: "AWS::EC2::SecurityGroup", ARN: resourceARN(vpc.Scope, "security-group", groupID)},
		},
	}
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now().Truncate(time.Second), Partition: vpc.Scope.Partition, AccountID: vpc.Scope.AccountID, Region: vpc.Scope.Region}, call)
}

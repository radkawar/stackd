package ec2

import (
	"encoding/json"

	api "stackd/internal/awsapi/ec2"
)

func cloneAPI[T any](value T) T {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var cloned T
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		panic(err)
	}
	return cloned
}

func CloneCreateNatGatewayRequest(value api.CreateNatGatewayRequest) api.CreateNatGatewayRequest {
	return cloneAPI(value)
}
func CloneNatGateway(value api.NatGateway) api.NatGateway { return cloneAPI(value) }
func CloneCreateVpcEndpointRequest(value api.CreateVpcEndpointRequest) api.CreateVpcEndpointRequest {
	return cloneAPI(value)
}
func CloneVpcEndpoint(value api.VpcEndpoint) api.VpcEndpoint { return cloneAPI(value) }

func cloneNatGateway(v NatGatewayRecord) NatGatewayRecord { v.Data = CloneNatGateway(v.Data); return v }
func cloneVPCEndpoint(v VPCEndpointRecord) VPCEndpointRecord {
	v.Data = CloneVpcEndpoint(v.Data)
	return v
}
func cloneNetworkOwnerCreation(v NetworkOwnerCreationRecord) NetworkOwnerCreationRecord { return v }
func (r memoryReader) NatGateway(k ResourceKey) (NatGatewayRecord, error) {
	return getRecord(r.tx, r.s.natGateways, k, cloneNatGateway)
}
func (r memoryReader) NatGateways(s Scope) ([]NatGatewayRecord, error) {
	return listRecords(r.tx, r.s.natGateways, s, cloneNatGateway)
}
func (w memoryWriter) PutNatGateway(v NatGatewayRecord) error {
	return putClaimed(w.tx, w.s.natGateways, v.Key, v, cloneNatGateway)
}
func (w memoryWriter) DeleteNatGateway(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.natGateways, k)
}
func (r memoryReader) VPCEndpoint(k ResourceKey) (VPCEndpointRecord, error) {
	return getRecord(r.tx, r.s.vpcEndpoints, k, cloneVPCEndpoint)
}
func (r memoryReader) VPCEndpoints(s Scope) ([]VPCEndpointRecord, error) {
	return listRecords(r.tx, r.s.vpcEndpoints, s, cloneVPCEndpoint)
}
func (w memoryWriter) PutVPCEndpoint(v VPCEndpointRecord) error {
	return putClaimed(w.tx, w.s.vpcEndpoints, v.Key, v, cloneVPCEndpoint)
}
func (w memoryWriter) DeleteVPCEndpoint(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.vpcEndpoints, k)
}
func (r memoryReader) NetworkOwnerCreation(k NetworkCreationKey) (NetworkOwnerCreationRecord, error) {
	return getRecord(r.tx, r.s.networkOwnerCreations, k, cloneNetworkOwnerCreation)
}
func (w memoryWriter) PutNetworkOwnerCreation(v NetworkOwnerCreationRecord) error {
	return putRecord(w.tx, w.s.networkOwnerCreations, v.Key, v, cloneNetworkOwnerCreation)
}

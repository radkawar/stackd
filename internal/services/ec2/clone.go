package ec2

import api "stackd/internal/awsapi/ec2"

func copyPointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	return new(*value)
}

func cloneVPC(record VPCRecord) VPCRecord {
	record.Data = api.CloneVpc(record.Data)
	return record
}

func cloneSubnet(record SubnetRecord) SubnetRecord {
	record.Data = api.CloneSubnet(record.Data)
	return record
}

func cloneGroup(record SecurityGroupRecord) SecurityGroupRecord {
	record.Data = api.CloneSecurityGroup(record.Data)
	return record
}

func cloneRule(record SecurityGroupRuleRecord) SecurityGroupRuleRecord {
	record.Data = api.CloneSecurityGroupRule(record.Data)
	return record
}

func cloneRouteTable(record RouteTableRecord) RouteTableRecord {
	record.Data = api.CloneRouteTable(record.Data)
	return record
}

func cloneInternetGateway(record InternetGatewayRecord) InternetGatewayRecord {
	record.Data = api.CloneInternetGateway(record.Data)
	return record
}

func cloneNetworkInterface(record NetworkInterfaceRecord) NetworkInterfaceRecord {
	record.Data = api.CloneNetworkInterface(record.Data)
	return record
}

func cloneNetworkInterfaceCreation(record NetworkInterfaceCreationRecord) NetworkInterfaceCreationRecord {
	record.Input = api.CloneCreateNetworkInterfaceRequest(record.Input)
	return record
}

func cloneACL(record NetworkACLRecord) NetworkACLRecord {
	record.Data = api.CloneNetworkAcl(record.Data)
	return record
}

func cloneDHCPOptions(record DHCPOptionsRecord) DHCPOptionsRecord {
	record.Data = api.CloneDhcpOptions(record.Data)
	return record
}

func cloneNetworkCreation(record NetworkCreationRecord) NetworkCreationRecord {
	record.Tags = api.CloneTagList(record.Tags)
	return record
}

func cloneKeyPair(record KeyPairRecord) KeyPairRecord {
	record.Data = api.CloneKeyPairInfo(record.Data)
	return record
}

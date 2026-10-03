package ec2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

var ec2AuditRequest = awsapi.DocumentProjection{PreserveNames: true, Fields: map[string]awsapi.FieldProjection{
	"DryRun":                      {Mode: awsapi.OmitField},
	"PresignedUrl":                {Mode: awsapi.OmitField},
	"UserData":                    {Mode: awsapi.RedactValueField, Redaction: "<sensitiveDataRemoved>"},
	"LaunchTemplateData.UserData": {Mode: awsapi.RedactValueField, Redaction: "<sensitiveDataRemoved>"},
}}

var ec2AuditAttributeRequest = awsapi.DocumentProjection{PreserveNames: true, Fields: map[string]awsapi.FieldProjection{
	"DryRun":    {Mode: awsapi.OmitField},
	"Attribute": {Mode: awsapi.OmitField},
}}

var ec2AuditResetInterfaceRequest = awsapi.DocumentProjection{PreserveNames: true, Fields: map[string]awsapi.FieldProjection{
	"DryRun":          {Mode: awsapi.OmitField},
	"SourceDestCheck": {Mode: awsapi.OmitField},
}}

var ec2AuditResponse = awsapi.DocumentProjection{PreserveNames: true, Fields: map[string]awsapi.FieldProjection{
	// Preserve exact instants until native audit conversion to milliseconds.
	"Instances.LaunchTime":                              {TimeLayout: time.RFC3339Nano},
	"Instances.NetworkInterfaces.Attachment.AttachTime": {TimeLayout: time.RFC3339Nano},
}}

var ec2AuditCreateKeyPairResponse = awsapi.DocumentProjection{PreserveNames: true, Fields: map[string]awsapi.FieldProjection{
	"KeyMaterial": {Mode: awsapi.RedactValueField, Redaction: "<sensitiveDataRemoved>"},
}}

// EC2's audit documents are not its SDK JSON documents. Project public modeled
// fields first, then apply the native XML names and collection envelopes. This
// keeps secret filtering in the shared codec and operation membership in Smithy.
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ec2")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{
		Category: journal.CategoryManagement,
		ReadOnly: strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "Get"),
		Request:  ec2AuditRequest,
	}
	if action == "DescribeVpcAttribute" || action == "DescribeNetworkInterfaceAttribute" {
		projection.Request = ec2AuditAttributeRequest
	}
	if action == "ResetNetworkInterfaceAttribute" {
		projection.Request = ec2AuditResetInterfaceRequest
	}
	if request, ok := in.(*api.DescribeKeyPairsRequest); ok && request != nil && request.IncludePublicKey == nil {
		copied := *request
		copied.IncludePublicKey = new(api.Boolean(false))
		in = &copied
	}
	if request, ok := in.(*api.CreateKeyPairRequest); ok && request != nil {
		copied := *request
		if copied.KeyFormat == nil {
			copied.KeyFormat = new(api.KeyFormat("pem"))
		}
		if str(copied.KeyName) == "" {
			copied.KeyName = nil
		}
		in = &copied
	}
	if !projection.ReadOnly {
		projection.Response = &ec2AuditResponse
	}
	if action == "CreateKeyPair" {
		projection.Response = &ec2AuditCreateKeyPairResponse
	}
	if launchTemplateAction(action) && !projection.ReadOnly {
		projection.Response = &launchTemplateAuditResponse
	}
	if request, ok := in.(*api.ModifyInstanceAttributeRequest); ok && request != nil && str(request.Attribute) == "userData" {
		projection.Request = awsapi.DocumentProjection{PreserveNames: true, Fields: map[string]awsapi.FieldProjection{
			"DryRun":   {Mode: awsapi.OmitField},
			"UserData": {Mode: awsapi.RedactValueField, Redaction: "<sensitiveDataRemoved>"},
			"Value":    {Mode: awsapi.RedactValueField, Redaction: "<sensitiveDataRemoved>"},
		}}
	}
	call, err := projection.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	if request, ok := in.(*api.DeleteKeyPairRequest); ok && request != nil && str(request.KeyName) == "" && str(request.KeyPairId) == "" {
		call.RequestParameters = nil
	}
	// Only admitted imports can expose their public blob. Failed imports may
	// contain an accidentally uploaded private key, so the shared codec's blob
	// omission remains authoritative for every rejected request.
	if action == "ImportKeyPair" && rejected == nil {
		if request, ok := in.(*api.ImportKeyPairRequest); ok && request != nil {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(call.RequestParameters, &fields); err != nil {
				return err
			}
			fields["PublicKeyMaterial"], err = json.Marshal(base64.StdEncoding.EncodeToString(request.PublicKeyMaterial))
			if err != nil {
				return err
			}
			call.RequestParameters, err = json.Marshal(fields)
			if err != nil {
				return err
			}
		}
	}
	call.EventID = apievents.EventID(ctx)
	// These newer APIs retain query-name envelopes instead of the older sets.
	queryEnvelope := launchTemplateAction(action) || action == "DescribeSecurityGroupRules" || action == "GetConsoleScreenshot" || strings.HasPrefix(action, "UpdateSecurityGroupRuleDescriptions")
	call.RequestParameters, err = ec2AuditDocument(model, op.Input, call.RequestParameters, true, queryEnvelope)
	if err != nil {
		return err
	}
	call.RequestParameters, err = ec2DiskAuditRequest(in, call.RequestParameters)
	if err != nil {
		return err
	}
	if launchTemplateAction(action) {
		call.RequestParameters, err = launchTemplateAuditRequest(call.RequestParameters)
		if err != nil {
			return err
		}
	}
	if queryEnvelope && len(call.RequestParameters) != 0 && string(call.RequestParameters) != "null" {
		call.RequestParameters, err = json.Marshal(map[string]json.RawMessage{action + "Request": call.RequestParameters})
		if err != nil {
			return err
		}
	}
	if rejected != nil {
		call.ErrorCode = "Client." + rejected.Code
		if action == "ResetNetworkInterfaceAttribute" && rejected.Code == "InvalidRequest" {
			call.RequestParameters = nil
		}
		if request, ok := in.(*api.DescribeAddressesRequest); ok && request != nil {
			for _, address := range request.PublicIps {
				if validatePublicIPv4(string(address)) != nil {
					// Native rejects malformed address selectors before retaining
					// the request document, including when DryRun is set.
					call.RequestParameters = nil
					break
				}
			}
		}
	} else if !projection.ReadOnly {
		var response json.RawMessage
		if launchTemplateAction(action) {
			response, err = launchTemplateAuditResponseDocument(model, op.Output, call.ResponseElements)
		} else {
			response, err = ec2AuditDocument(model, op.Output, call.ResponseElements, false, false)
		}
		if err != nil {
			return err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(response, &fields); err != nil {
			return err
		}
		if fields == nil {
			fields = make(map[string]json.RawMessage)
		}
		fields["requestId"], err = json.Marshal(awsctx.FromContext(ctx).RequestID)
		if err != nil {
			return err
		}
		switch action {
		case "DeleteLaunchTemplateVersions":
			for _, name := range []string{"successfullyDeletedLaunchTemplateVersionSet", "unsuccessfullyDeletedLaunchTemplateVersionSet"} {
				if _, present := fields[name]; !present {
					fields[name] = json.RawMessage(`""`)
				}
			}
		case "CreateVolume":
			if volume, ok := out.(*api.Volume); ok && volume != nil {
				if volume.CreateTime != nil {
					fields["createTime"] = json.RawMessage(strconv.FormatInt(volume.CreateTime.UnixMilli(), 10))
				}
				if volume.Size != nil {
					fields["size"], err = json.Marshal(strconv.FormatInt(int64(*volume.Size), 10))
				}
			}
			if _, present := fields["tagSet"]; !present {
				fields["tagSet"] = json.RawMessage("{}")
			}
		case "CreateSnapshot":
			if snapshot, ok := out.(*api.Snapshot); ok && snapshot != nil {
				if snapshot.StartTime != nil {
					fields["startTime"] = json.RawMessage(strconv.FormatInt(snapshot.StartTime.UnixMilli(), 10))
				}
				if snapshot.VolumeSize != nil {
					fields["volumeSize"], err = json.Marshal(strconv.FormatInt(int64(*snapshot.VolumeSize), 10))
				}
				if str(snapshot.Description) == "" {
					delete(fields, "description")
				}
				if str(snapshot.Progress) == "" {
					delete(fields, "progress")
				}
			}
			if _, present := fields["tagSet"]; !present {
				fields["tagSet"] = json.RawMessage("{}")
			}
		}
		if err != nil {
			return err
		}
		if op.Output == "smithy.api#Unit" || action == "CreateSecurityGroup" || action == "AssignPrivateIpAddresses" || action == "AssociateAddress" {
			fields["_return"] = json.RawMessage("true")
		}
		if action == "DisassociateRouteTable" {
			fields["associationState"] = json.RawMessage(`{"state":"disassociating"}`)
		}
		if queryEnvelope {
			if value, present := fields["_return"]; present {
				fields["return"] = value
				delete(fields, "_return")
			}
			fields["xmlns"], err = json.Marshal(Namespace)
			if err != nil {
				return err
			}
			body, encodeErr := json.Marshal(fields)
			if encodeErr != nil {
				return encodeErr
			}
			call.ResponseElements, err = json.Marshal(map[string]json.RawMessage{action + "Response": body})
		} else {
			call.ResponseElements, err = json.Marshal(fields)
		}
		if err != nil {
			return err
		}
	}
	call.APIVersion = model.Version
	scope := scopeFor(ctx)
	envelope := journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}
	switch action {
	case "CopySnapshot", "CreateVolume":
		return RecordSnapshotAudit(ctx, s.recorder, envelope, call, true)
	case "DescribeSnapshotAttribute", "ModifySnapshotAttribute", "ResetSnapshotAttribute", "CreateTags", "DeleteTags":
		return RecordSnapshotAudit(ctx, s.recorder, envelope, call, false)
	default:
		return s.recorder.Record(ctx, envelope, call)
	}
}

func ec2DiskAuditRequest(in any, document json.RawMessage) (json.RawMessage, error) {
	var id, attribute string
	var permission map[string]any
	switch request := in.(type) {
	case *api.DeleteVolumeRequest:
		if request == nil {
			return nil, nil
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(document, &fields); err != nil {
			return nil, err
		}
		if fields == nil {
			fields = make(map[string]json.RawMessage)
		}
		fields["reportVolumeFailure"] = json.RawMessage("false")
		return json.Marshal(fields)
	case *api.DescribeSnapshotAttributeRequest:
		if request == nil {
			return nil, nil
		}
		id, attribute = str(request.SnapshotId), str(request.Attribute)
	case *api.ResetSnapshotAttributeRequest:
		if request == nil || str(request.Attribute) != "createVolumePermission" {
			return nil, nil
		}
		id, attribute = str(request.SnapshotId), str(request.Attribute)
	case *api.ModifySnapshotAttributeRequest:
		if request == nil {
			return nil, nil
		}
		id, attribute = str(request.SnapshotId), "createVolumePermission"
		permission = make(map[string]any)
		type item struct {
			UserID string `json:"userId,omitempty"`
			Group  string `json:"group,omitempty"`
		}
		if request.CreateVolumePermission != nil {
			for _, change := range [2]struct {
				operation string
				values    api.CreateVolumePermissionList
			}{{"add", request.CreateVolumePermission.Add}, {"remove", request.CreateVolumePermission.Remove}} {
				items := make([]item, 0, len(change.values))
				for _, value := range change.values {
					if value.UserId != nil || value.Group != nil {
						items = append(items, item{str(value.UserId), str(value.Group)})
					}
				}
				if len(items) != 0 {
					permission[change.operation] = map[string]any{"items": items}
				}
			}
		}
		if len(permission) == 0 {
			operation := str(request.OperationType)
			if operation != "add" && operation != "remove" {
				return nil, nil
			}
			if str(request.Attribute) == "createVolumePermission" {
				items := make([]item, 0, len(request.UserIds)+len(request.GroupNames))
				for _, user := range request.UserIds {
					items = append(items, item{UserID: string(user)})
				}
				for _, group := range request.GroupNames {
					items = append(items, item{Group: string(group)})
				}
				if len(items) != 0 {
					permission[operation] = map[string]any{"items": items}
				}
			}
		}
	default:
		return document, nil
	}
	fields := map[string]any{"snapshotId": id}
	switch attribute {
	case "createVolumePermission":
		fields["attributeType"] = "CREATE_VOLUME_PERMISSION"
	case "productCodes":
		fields["attributeType"] = "PRODUCT_CODES"
	default:
		return nil, nil
	}
	if len(permission) != 0 {
		fields["createVolumePermission"] = permission
	}
	return json.Marshal(fields)
}

func ec2AuditDocument(model awscatalog.Service, id awscatalog.ShapeID, document json.RawMessage, request, queryEnvelope bool) (json.RawMessage, error) {
	if len(document) == 0 || string(document) == "null" {
		return document, nil
	}
	shape, _ := model.Shape(id)
	if !request && shape.Kind == "timestamp" && document[0] == '"' {
		var stamp time.Time
		if err := json.Unmarshal(document, &stamp); err != nil {
			return nil, err
		}
		return json.RawMessage(strconv.FormatInt(stamp.UnixMilli(), 10)), nil
	}
	if shape.Kind != "structure" && shape.Kind != "union" {
		return document, nil
	}
	var original map[string]json.RawMessage
	if err := json.Unmarshal(document, &original); err != nil {
		return nil, err
	}
	fields := make(map[string]json.RawMessage, len(original))
	for _, member := range shape.Members {
		value, present := original[member.Name]
		target, _ := model.Shape(member.Target)
		collection := target.Kind == "list" || target.Kind == "set"
		name := ec2AuditMemberName(id, member, request, queryEnvelope)
		if !present {
			// Only native mandatory empty containers survive absence. In particular,
			// tag specifications and optional rule-ID selectors are not invented.
			if queryEnvelope || !ec2AuditEmptyMember(shape, member, request) {
				continue
			}
			fields[name] = json.RawMessage("{}")
			continue
		}
		if request && shape.ID == "com.amazonaws.ec2#Tag" && member.Name == "Value" && string(value) == `""` {
			continue
		}
		if !request && shape.ID == "com.amazonaws.ec2#NetworkInterfacePrivateIpAddress" && member.Name == "PrivateDnsName" && string(value) == `""` {
			continue
		}
		if !request && string(value) == `""` {
			switch shape.ID {
			case "com.amazonaws.ec2#NetworkInterface", "com.amazonaws.ec2#InstanceNetworkInterface":
				if member.Name == "Description" {
					continue
				}
			case "com.amazonaws.ec2#Instance":
				if member.Name == "PublicDnsName" || member.Name == "StateTransitionReason" {
					continue
				}
			case "com.amazonaws.ec2#Placement":
				if member.Name == "GroupName" {
					continue
				}
			}
		}
		if collection {
			var items []json.RawMessage
			if err := json.Unmarshal(value, &items); err != nil {
				return nil, err
			}
			if !request && member.Name == "Tags" && len(items) == 0 {
				continue
			}
			for i, item := range items {
				converted, err := ec2AuditDocument(model, target.Member.Target, item, request, queryEnvelope)
				if err != nil {
					return nil, err
				}
				if queryEnvelope {
					var entry map[string]json.RawMessage
					if len(converted) > 0 && converted[0] == '{' {
						if err := json.Unmarshal(converted, &entry); err != nil {
							return nil, err
						}
					} else {
						entry = map[string]json.RawMessage{"content": converted}
					}
					entry["tag"], err = json.Marshal(i + 1)
					if err != nil {
						return nil, err
					}
					converted, err = json.Marshal(entry)
					if err != nil {
						return nil, err
					}
				} else if element, _ := model.Shape(target.Member.Target); element.Kind != "structure" && element.Kind != "union" {
					itemName := ec2AuditLower(member.EC2QueryName)
					if target.Member.XMLName != "" && target.Member.XMLName != "item" {
						itemName = ec2AuditLower(target.Member.XMLName)
					}
					if member.Name == "Groups" {
						itemName = "groupId"
					}
					if request && member.Name == "KeyNames" && string(converted) == `""` {
						converted = json.RawMessage("{}")
					} else {
						converted, err = json.Marshal(map[string]json.RawMessage{itemName: converted})
					}
					if err != nil {
						return nil, err
					}
				}
				items[i] = converted
			}
			var err error
			switch {
			case queryEnvelope && len(items) == 1:
				value = items[0]
			case queryEnvelope || shape.ID == "com.amazonaws.ec2#TagSpecification":
				if shape.ID == "com.amazonaws.ec2#TagSpecification" && !queryEnvelope {
					name = "tags"
				}
				value, err = json.Marshal(items)
			case len(items) == 0:
				value = json.RawMessage("{}")
			default:
				envelope := "items"
				if !request {
					switch target.ID {
					case "com.amazonaws.ec2#NetworkInterfacePrivateIpAddressList", "com.amazonaws.ec2#InstancePrivateIpAddressList":
						envelope = "item"
					case "com.amazonaws.ec2#AssignedPrivateIpAddressList":
						envelope = "assignedPrivateIpAddressSetType"
					}
				}
				value, err = json.Marshal(map[string][]json.RawMessage{envelope: items})
			}
			if err != nil {
				return nil, err
			}
		} else {
			var err error
			value, err = ec2AuditDocument(model, member.Target, value, request, queryEnvelope)
			if err != nil {
				return nil, err
			}
		}
		fields[name] = value
	}
	if request && shape.ID == "com.amazonaws.ec2#RunInstancesRequest" {
		instance := make(map[string]json.RawMessage, 3)
		for _, name := range []string{"imageId", "minCount", "maxCount"} {
			if value, present := fields[name]; present {
				instance[name] = value
				delete(fields, name)
			}
		}
		var err error
		fields["instancesSet"], err = json.Marshal(map[string][]map[string]json.RawMessage{"items": {instance}})
		if err != nil {
			return nil, err
		}
		for _, name := range []string{"disableApiStop", "disableApiTermination"} {
			if _, present := fields[name]; !present {
				fields[name] = json.RawMessage("false")
			}
		}
		if _, present := fields["monitoring"]; !present {
			fields["monitoring"] = json.RawMessage(`{"enabled":false}`)
		}
	}
	if !request && shape.ID == "com.amazonaws.ec2#InternetGateway" {
		// Native audit records include this empty, unmodeled container.
		fields["association"] = json.RawMessage("{}")
	}
	if !request && shape.ID == "com.amazonaws.ec2#InstanceNetworkInterface" {
		fields["tagSet"] = json.RawMessage("{}")
	}
	if !request && shape.ID == "com.amazonaws.ec2#InstanceMetadataOptionsResponse" {
		// Native launch audit retains this protocol field absent from the SDK.
		fields["httpProtocolIpv4"] = json.RawMessage(`"enabled"`)
	}
	return json.Marshal(fields)
}

func ec2AuditMemberName(shape awscatalog.ShapeID, member awscatalog.Member, request, queryEnvelope bool) string {
	if queryEnvelope {
		return member.EC2QueryName
	}
	if shape == "com.amazonaws.ec2#RunInstancesRequest" && member.Name == "NetworkInterfaces" {
		return "networkInterfaceSet"
	}
	if shape == "com.amazonaws.ec2#DescribeAddressesRequest" {
		switch member.Name {
		case "AllocationIds":
			return "allocationIdsSet"
		case "PublicIps":
			return "publicIpsSet"
		}
	}
	if shape == "com.amazonaws.ec2#CreateVolumeRequest" || shape == "com.amazonaws.ec2#Volume" {
		switch member.Name {
		case "AvailabilityZone":
			return "zone"
		case "KmsKeyId":
			return "masterEncryptionKeyId"
		}
	}
	if request {
		if shape == "com.amazonaws.ec2#CopySnapshotRequest" && member.Name == "KmsKeyId" {
			return "masterEncryptionKeyId"
		}
		switch member.Name {
		case "Resources":
			return "resourcesSet"
		case "Tags":
			return "tagSet"
		case "TagSpecifications":
			return "tagSpecificationSet"
		case "KeyNames":
			return "keySet"
		case "KeyPairIds":
			return "keyPairIdSet"
		case "SnapshotIds":
			return "snapshotSet"
		case "OwnerIds":
			return "ownersSet"
		case "RestorableByUserIds":
			return "sharedUsersSet"
		case "Filters":
			return "filterSet"
		case "Values":
			return "valueSet"
		case "VpcIds":
			return "vpcSet"
		case "SubnetIds":
			return "subnetSet"
		case "Groups":
			return "groupSet"
		case "PrivateIpAddresses":
			return "privateIpAddressesSet"
		case "Ipv4Prefixes":
			return "ipv4Prefixes"
		case "NetworkInterfaceIds":
			return "networkInterfaceIdSet"
		case "GroupNames":
			return "securityGroupSet"
		case "GroupIds":
			return "securityGroupIdSet"
		case "RouteTableIds":
			return "routeTableIdSet"
		case "InternetGatewayIds":
			return "internetGatewayIdSet"
		case "NetworkAclIds":
			return "networkAclIdSet"
		case "SecurityGroupRuleIds":
			return "securityGroupRuleIds"
		}
	}
	if member.Name == "Protocol" {
		return "aclProtocol"
	}
	if member.Name == "Return" {
		return "_return"
	}
	if member.XMLName != "" {
		return ec2AuditLower(member.XMLName)
	}
	return ec2AuditLower(member.Name)
}

func ec2AuditEmptyMember(shape awscatalog.Shape, member awscatalog.Member, request bool) bool {
	if request {
		switch member.Name {
		case "KeyNames", "KeyPairIds":
			return shape.ID == "com.amazonaws.ec2#DescribeKeyPairsRequest"
		case "AllocationIds", "PublicIps":
			return shape.ID == "com.amazonaws.ec2#DescribeAddressesRequest"
		case "SnapshotIds", "OwnerIds", "RestorableByUserIds":
			return shape.ID == "com.amazonaws.ec2#DescribeSnapshotsRequest"
		case "Values":
			return shape.ID == "com.amazonaws.ec2#Filter"
		case "BlockDeviceMappings":
			return shape.ID == "com.amazonaws.ec2#RunInstancesRequest"
		case "PrivateIpAddresses":
			return shape.ID != "com.amazonaws.ec2#InstanceNetworkInterfaceSpecification"
		case "Filters", "VpcIds", "SubnetIds", "GroupNames", "GroupIds", "RouteTableIds", "InternetGatewayIds", "NetworkInterfaceIds", "NetworkAclIds", "IpPermissions", "IcmpTypeCode":
			return true
		case "Groups":
			return shape.ID == "com.amazonaws.ec2#CreateNetworkInterfaceRequest"
		case "Ipv4Prefixes":
			return shape.ID == "com.amazonaws.ec2#AssignPrivateIpAddressesRequest" || shape.ID == "com.amazonaws.ec2#UnassignPrivateIpAddressesRequest"
		}
		return shape.ID == "com.amazonaws.ec2#IpPermission" && (member.Name == "UserIdGroupPairs" || member.Name == "IpRanges" || member.Name == "Ipv6Ranges" || member.Name == "PrefixListIds")
	}
	switch member.Name {
	case "Groups":
		return shape.ID == "com.amazonaws.ec2#Reservation"
	case "ProductCodes", "BlockDeviceMappings":
		return shape.ID == "com.amazonaws.ec2#Instance"
	case "Ipv6Addresses":
		return shape.ID == "com.amazonaws.ec2#InstanceNetworkInterface"
	case "Ipv6CidrBlockAssociationSet", "Associations", "PropagatingVgws":
		return true
	case "IcmpTypeCode", "PortRange":
		return shape.ID == "com.amazonaws.ec2#NetworkAclEntry"
	}
	return false
}

func ec2AuditLower(name string) string {
	if name != "" && name[0] >= 'A' && name[0] <= 'Z' {
		return string(name[0]+('a'-'A')) + name[1:]
	}
	return name
}

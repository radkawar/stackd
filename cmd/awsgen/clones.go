package main

import (
	"bytes"
	"fmt"
	"go/format"
	"strings"

	"stackd/internal/awsschema"
)

// cloneRoots tracks production resource state and admitted inputs, not all service
// shapes. Members and nested aggregates are discovered from the compiled model.
func cloneRoots(service string) []string {
	switch service {
	case "appsync":
		return []string{"GraphqlApi", "DataSource", "Resolver", "FunctionConfiguration", "ApiKey"}
	case "applicationautoscaling":
		return []string{"ScalableTarget", "ScalingPolicy", "ScheduledAction", "ScalingActivity"}
	case "autoscaling":
		return []string{"AutoScalingGroup", "Activity", "ScalingPolicy", "ScheduledUpdateGroupAction", "LifecycleHook", "InstanceRefresh"}
	case "codebuild":
		return []string{"Project", "Build", "Fleet", "LogsConfig", "ProjectArtifacts", "CreateProjectInput", "UpdateProjectInput", "StartBuildInput"}
	case "ecr":
		return []string{"ImageTagMutabilityExclusionFilters", "LifecyclePolicyPreviewResultList", "RegistryScanningConfiguration", "ReplicationConfiguration", "ImageScanFindingList"}
	case "athena":
		return []string{"WorkGroup", "DataCatalog", "NamedQuery", "PreparedStatement", "QueryExecution", "ColumnInfo", "ResultConfiguration", "WorkGroupConfiguration"}
	case "cognitoidentity":
		return []string{"CognitoIdentityProviderList", "RoleMappingMap"}
	case "cognitoidp":
		return []string{"UserPoolType", "UserPoolClientType", "UserType", "GroupType"}
	case "dynamodb":
		return []string{"TableDescription", "CreateTableInput", "UpdateTableInput", "TimeToLiveDescription", "BackupDescription", "Key", "AttributeMap"}
	case "dynamodbstreams":
		return []string{"StreamDescription", "Record"}
	case "elbv2":
		return []string{"LoadBalancer", "TargetGroup", "Listener", "Rule", "TargetDescription", "TagList"}
	case "ecs":
		return []string{"Cluster", "CreateClusterRequest", "RegisterTaskDefinitionRequest", "TaskDefinition", "RunTaskRequest", "Task", "Service", "ServiceRevision", "CreateServiceRequest"}
	case "ec2":
		return []string{"Vpc", "Subnet", "SecurityGroup", "SecurityGroupRule", "RouteTable", "InternetGateway", "NetworkInterface", "Address", "CreateNetworkInterfaceRequest", "NetworkAcl", "DhcpOptions", "AvailabilityZone", "Region", "KeyPairInfo", "CreateVolumeRequest", "Image", "LaunchPermissionList", "Instance", "InstanceStatusSummary", "RunInstancesRequest", "ModifyInstanceAttributeRequest", "InstanceTypeInfo", "ModifyInstanceCreditSpecificationResult", "LaunchTemplate", "LaunchTemplateVersion", "RequestLaunchTemplateData"}
	case "eventbridge":
		return []string{"EcsParameters", "KinesisParameters"}
	case "firehose":
		return []string{"ExtendedS3DestinationDescription"}
	case "glue":
		return []string{"Catalog", "CatalogImportStatus", "Database", "Table", "TableVersion", "Partition", "PartitionIndex", "PartitionIndexDescriptor", "ColumnStatistics", "UserDefinedFunction", "Job", "JobRun", "Crawler", "Classifier", "Connection", "Crawl", "GetRegistryResponse", "GetSchemaResponse", "GetSchemaVersionResponse", "Workflow", "Trigger", "SecurityConfiguration", "WorkflowRun"}
	case "guardduty":
		return []string{"FindingCriteria", "Finding", "CreateDetectorRequest"}
	case "kinesis":
		return []string{"StreamDescription", "StreamDescriptionSummary", "ConsumerDescription", "Consumer", "TagList", "MinimumThroughputBillingCommitmentOutput"}
	case "pipes":
		return []string{"PipeTargetParameters"}
	case "secretsmanager":
		return []string{"RotationRulesType"}
	case "stepfunctions":
		return []string{"HistoryEvent"}
	default:
		return nil
	}
}

// renderClones emits typed deep copies for production roots and their reachable
// aggregates. Services without copy consumers do not get a generated file.
func renderClones(c contract) ([]byte, error) {
	roots := cloneRoots(c.Info.Name)
	if len(roots) == 0 {
		return nil, nil
	}
	shapes := make(map[awsschema.ShapeID]awsschema.Shape, len(c.Shapes))
	names := make(map[string]awsschema.ShapeID, len(c.Shapes))
	for _, shape := range c.Shapes {
		shapes[shape.ID] = shape
		names[exportedName(shapeName(shape.ID))] = shape.ID
	}
	seen := make(map[awsschema.ShapeID]bool)
	aggregates := make(map[string]awsschema.Shape)
	var visit func(awsschema.ShapeID) error
	visit = func(id awsschema.ShapeID) error {
		if seen[id] {
			return nil
		}
		shape, ok := shapes[id]
		if !ok {
			return fmt.Errorf("unresolved clone target %s", id)
		}
		seen[id] = true
		var members []awsschema.Member
		switch shape.Kind {
		case "structure", "union":
			if shape.Kind == "union" && shape.Streaming {
				return fmt.Errorf("cannot clone streaming union %s", id)
			}
			members = shape.Members
		case "list", "set":
			members = []awsschema.Member{shape.Member}
		case "map":
			members = []awsschema.Member{shape.Key, shape.Value}
		case "blob", "document":
		case "string", "enum", "intEnum", "boolean", "byte", "short", "integer", "long", "float", "double", "timestamp":
			// Scalar values (including time.Time) have value semantics. Their
			// containing pointers, if any, are copied by the member emitter.
			return nil
		default:
			return fmt.Errorf("cannot clone %s shape %s", shape.Kind, id)
		}
		aggregates[exportedName(shapeName(id))] = shape
		for _, member := range members {
			if err := visit(member.Target); err != nil {
				return fmt.Errorf("%s.%s: %w", id, member.Name, err)
			}
		}
		return nil
	}
	for _, root := range roots {
		id, ok := names[root]
		if !ok {
			return nil, fmt.Errorf("missing %s clone root %s", c.Info.Name, root)
		}
		if err := visit(id); err != nil {
			return nil, err
		}
	}

	var out bytes.Buffer
	out.WriteString(generatedHeader)
	fmt.Fprintf(&out, "package %s\n\n", c.Info.Name)
	for _, name := range sortedKeys(aggregates) {
		shape := aggregates[name]
		fmt.Fprintf(&out, "// Clone%s returns an independent copy, preserving nil collections and pointer presence.\n", name)
		fmt.Fprintf(&out, "func Clone%s(value %s) %s {\n", name, name, name)
		switch shape.Kind {
		case "structure", "union":
			for _, member := range shape.Members {
				field := "value." + exportedName(member.Name)
				// Use the type emitter's pointer policy rather than infer
				// presence from required/default Smithy traits.
				if strings.HasPrefix(memberGoType(member, shapes), "*") {
					fmt.Fprintf(&out, "if %s != nil {\ncloned := %s\n%s = &cloned\n}\n", field, cloneValueExpression(member.Target, "*"+field, shapes), field)
				} else {
					fmt.Fprintf(&out, "%s = %s\n", field, cloneValueExpression(member.Target, field, shapes))
				}
			}
			fmt.Fprintln(&out, "return value")
		case "document":
			// The frontend decodes documents into JSON maps, lists and
			// immutable scalar values. Copy only their mutable aggregates.
			fmt.Fprintf(&out, `switch value := value.(type) {
case map[string]any:
	if value == nil { return value }
	out := make(map[string]any, len(value))
	for key, element := range value { out[key] = Clone%s(element) }
	return out
case []any:
	if value == nil { return value }
	out := make([]any, len(value))
	for key, element := range value { out[key] = Clone%s(element) }
	return out
default:
	return value
}
`, name, name)
		case "list", "set", "map", "blob":
			fmt.Fprintf(&out, "if value == nil { return nil }\nout := make(%s, len(value))\n", name)
			if shape.Kind == "blob" {
				fmt.Fprintln(&out, "copy(out, value)")
			} else {
				member := shape.Member
				if shape.Kind == "map" {
					member = shape.Value
				}
				expression := cloneValueExpression(member.Target, "element", shapes)
				if shape.Kind != "map" && !shape.Sparse && expression == "element" {
					fmt.Fprintln(&out, "copy(out, value)")
				} else {
					fmt.Fprintln(&out, "for key, element := range value {")
					// Sparse collection elements are pointers in renderTypes;
					// map entries with nil values must not disappear.
					if shape.Sparse {
						fmt.Fprintln(&out, "if element == nil { out[key] = nil; continue }")
						fmt.Fprintf(&out, "cloned := %s\nout[key] = &cloned\n", cloneValueExpression(member.Target, "*element", shapes))
					} else {
						fmt.Fprintf(&out, "out[key] = %s\n", expression)
					}
					fmt.Fprintln(&out, "}")
				}
			}
			fmt.Fprintln(&out, "return out")
		}
		fmt.Fprintln(&out, "}")
	}
	return format.Source(out.Bytes())
}

func cloneValueExpression(id awsschema.ShapeID, value string, shapes map[awsschema.ShapeID]awsschema.Shape) string {
	switch shapes[id].Kind {
	case "structure", "union", "list", "set", "map", "blob", "document":
		return "Clone" + exportedName(shapeName(id)) + "(" + value + ")"
	default:
		return value
	}
}

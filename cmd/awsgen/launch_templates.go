package main

import (
	"bytes"
	"fmt"
	"go/format"
	"strings"

	"stackd/internal/awsschema"
)

// Launch-template requests, responses and RunInstances are different Smithy
// shapes. Generate structural conversions instead of maintaining DTO copies or
// losing typed fields through JSON/reflection at the admission boundary.
func renderLaunchTemplateConversions(c contract) ([]byte, error) {
	shapes := make(map[awsschema.ShapeID]awsschema.Shape, len(c.Shapes))
	names := map[string]awsschema.ShapeID{}
	for _, shape := range c.Shapes {
		shapes[shape.ID] = shape
		names[shapeName(shape.ID)] = shape.ID
	}
	type pair struct{ from, to awsschema.ShapeID }
	seen := map[pair]bool{}
	var out bytes.Buffer
	out.WriteString(generatedHeader)
	out.WriteString("package ec2\n\n")
	var convert func(awsschema.ShapeID, awsschema.ShapeID) (string, error)
	convert = func(from, to awsschema.ShapeID) (string, error) {
		name := "LaunchTemplateConvert" + exportedName(shapeName(from)) + "To" + exportedName(shapeName(to))
		p := pair{from, to}
		if seen[p] {
			return name, nil
		}
		seen[p] = true
		src, dst := shapes[from], shapes[to]
		var body bytes.Buffer
		fmt.Fprintf(&body, "func %s(in %s) %s {\n", name, shapeName(from), shapeName(to))
		switch dst.Kind {
		case "structure":
			fmt.Fprintf(&body, "var out %s\n", shapeName(to))
			for _, target := range dst.Members {
				if shapeName(from) == "Instance" && (target.Name == "NetworkInterfaces" || target.Name == "BlockDeviceMappings" || target.Name == "SecurityGroups") {
					continue
				}
				var source *awsschema.Member
				for _, member := range src.Members {
					if strings.EqualFold(member.Name, target.Name) || (member.Name == "ElasticGpuSpecifications" && target.Name == "ElasticGpuSpecification") || (member.Name == "ElasticGpuSpecification" && target.Name == "ElasticGpuSpecifications") {
						source = &member
						break
					}
				}
				if source == nil {
					continue
				}
				field, dest := "in."+exportedName(source.Name), "out."+exportedName(target.Name)
				pointer := strings.HasPrefix(memberGoType(*source, shapes), "*")
				expr := field
				if pointer {
					expr = "*" + expr
				}
				fn, err := convert(source.Target, target.Target)
				if err != nil {
					return "", err
				}
				if pointer {
					fmt.Fprintf(&body, "if %s != nil { v := %s(%s); %s = &v }\n", field, fn, expr, dest)
				} else {
					fmt.Fprintf(&body, "%s = %s(%s)\n", dest, fn, expr)
				}
			}
			body.WriteString("return out\n")
		case "list", "set":
			fn, err := convert(src.Member.Target, dst.Member.Target)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&body, "if in == nil { return nil }; out := make(%s, len(in)); for i, v := range in { out[i] = %s(v) }; return out\n", shapeName(to), fn)
		case "string", "enum", "boolean", "integer", "long", "float", "double", "timestamp":
			fmt.Fprintf(&body, "return %s(in)\n", shapeName(to))
		default:
			return "", fmt.Errorf("unsupported template conversion %s to %s (%s)", from, to, dst.Kind)
		}
		body.WriteString("}\n")
		out.Write(body.Bytes())
		return name, nil
	}
	for _, root := range [][2]string{{"RequestLaunchTemplateData", "ResponseLaunchTemplateData"}, {"RequestLaunchTemplateData", "RunInstancesRequest"}, {"RunInstancesRequest", "RequestLaunchTemplateData"}, {"Instance", "RequestLaunchTemplateData"}} {
		if _, err := convert(names[root[0]], names[root[1]]); err != nil {
			return nil, err
		}
	}
	for _, root := range []string{"RequestLaunchTemplateData"} {
		fmt.Fprintf(&out, "// Overlay%s replaces present top-level members; base and overrides must be caller-owned.\nfunc Overlay%s(base *%s, overrides %s) {\n", root, root, root, root)
		for _, member := range shapes[names[root]].Members {
			field := exportedName(member.Name)
			fmt.Fprintf(&out, "if overrides.%s != nil { base.%s = overrides.%s }\n", field, field, field)
		}
		out.WriteString("}\n")
	}
	merged := map[awsschema.ShapeID]bool{}
	var merge func(awsschema.ShapeID)
	merge = func(id awsschema.ShapeID) {
		if merged[id] {
			return
		}
		merged[id] = true
		shape := shapes[id]
		root := shapeName(id)
		var body bytes.Buffer
		fmt.Fprintf(&body, "// Merge%s merges present nested members into caller-owned data.\nfunc Merge%s(base *%s, overrides %s) {\n", root, root, root, root)
		for _, member := range shape.Members {
			field := exportedName(member.Name)
			if shapes[member.Target].Kind == "structure" {
				merge(member.Target)
				fmt.Fprintf(&body, "if overrides.%s != nil { if base.%s == nil { base.%s = overrides.%s } else { Merge%s(base.%s, *overrides.%s) } }\n", field, field, field, field, shapeName(member.Target), field, field)
			} else {
				fmt.Fprintf(&body, "if overrides.%s != nil { base.%s = overrides.%s }\n", field, field, field)
			}
		}
		body.WriteString("}\n")
		out.Write(body.Bytes())
	}
	for _, root := range []string{"RunInstancesRequest", "BlockDeviceMapping", "InstanceNetworkInterfaceSpecification"} {
		merge(names[root])
	}
	presence := map[awsschema.ShapeID]bool{}
	var hasData func(awsschema.ShapeID)
	hasData = func(id awsschema.ShapeID) {
		if presence[id] {
			return
		}
		presence[id] = true
		name := shapeName(id)
		var body bytes.Buffer
		fmt.Fprintf(&body, "// Has%s reports whether the query structure contains data, not merely empty nested objects.\nfunc Has%s(value %s) bool {\n", name, name, name)
		for _, member := range shapes[id].Members {
			field := exportedName(member.Name)
			switch shapes[member.Target].Kind {
			case "structure":
				hasData(member.Target)
				fmt.Fprintf(&body, "if value.%s != nil && Has%s(*value.%s) { return true }\n", field, shapeName(member.Target), field)
			case "list", "set":
				fmt.Fprintf(&body, "if len(value.%s) > 0 { return true }\n", field)
			default:
				fmt.Fprintf(&body, "if value.%s != nil { return true }\n", field)
			}
		}
		body.WriteString("return false\n}\n")
		out.Write(body.Bytes())
	}
	hasData(names["RequestLaunchTemplateData"])
	return format.Source(out.Bytes())
}

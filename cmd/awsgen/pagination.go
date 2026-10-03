package main

import (
	"bytes"
	"fmt"
	"go/format"

	"stackd/internal/awsschema"
)

// Shared paginators consume modeled controls, including APIs whose models
// omit the SDK pagination trait or do not accept a page-size parameter.
func renderPagination(c contract) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(generatedHeader)
	fmt.Fprintf(&out, "package %s\n", c.Info.Name)
	tokenMember, sizeMember := "Marker", "MaxItems"
	if c.Info.Name == "organizations" {
		tokenMember, sizeMember = "NextToken", "MaxResults"
	}
	shapes := make(map[awsschema.ShapeID]awsschema.Shape, len(c.Shapes))
	for _, shape := range c.Shapes {
		shapes[shape.ID] = shape
	}
	seen := make(map[awsschema.ShapeID]bool)
	for _, op := range c.Operations {
		if seen[op.Input] {
			continue
		}
		seen[op.Input] = true
		var token, size awsschema.Member
		for _, member := range shapes[op.Input].Members {
			switch member.Name {
			case tokenMember:
				token = member
			case sizeMember:
				size = member
			}
		}
		if token.Name == "" || (size.Name == "" && c.Info.Name != "organizations") {
			continue
		}
		if shapes[token.Target].Kind != "string" || (size.Name != "" && shapes[size.Target].Kind != "integer") {
			return nil, fmt.Errorf("%s pagination requires a string marker and integer page size", op.Name)
		}
		name := exportedName(shapeName(op.Input))
		if c.Info.Name == "organizations" {
			fmt.Fprintln(&out, "// Pagination returns the validated token and optional page size, preserving presence.")
			fmt.Fprintf(&out, "func (in *%s) Pagination() (*string, *int32) {\n", name)
			if size.Name == "" {
				fmt.Fprintln(&out, "return (*string)(in.NextToken), nil\n}")
			} else {
				fmt.Fprintln(&out, "return (*string)(in.NextToken), (*int32)(in.MaxResults)\n}")
			}
			continue
		}
		fmt.Fprintln(&out, "// Pagination returns the token, optional page size, and the typed selection")
		fmt.Fprintln(&out, "// without pagination controls. It leaves the validated input unchanged.")
		fmt.Fprintf(&out, "func (in *%s) Pagination() (string, *int32, any) {\n", name)
		fmt.Fprintln(&out, "token := \"\"\nif in.Marker != nil { token = string(*in.Marker) }\nselection := *in\nselection.Marker, selection.MaxItems = nil, nil\nreturn token, (*int32)(in.MaxItems), selection\n}")
	}
	return format.Source(out.Bytes())
}

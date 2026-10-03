package main

import (
	"bytes"
	"fmt"
	"go/format"
	"slices"
)

// renderCommandInputs keeps the constructor registry outside awsapi: generated
// service packages already import awsapi for binding and must not form a cycle.
// Operations remain owned by each generated service's NewInput switch.
func renderCommandInputs(contracts []contract) ([]byte, error) {
	names := make([]string, 0, len(contracts))
	for _, c := range contracts {
		names = append(names, c.Info.Name)
	}
	slices.Sort(names)
	var out bytes.Buffer
	out.WriteString(generatedHeader)
	fmt.Fprintln(&out, "package awscommands")
	fmt.Fprintln(&out, "import (\n\"fmt\"\n\n\"stackd/internal/awsapi\"")
	for _, name := range names {
		fmt.Fprintf(&out, "%sapi %q\n", name, "stackd/internal/awsapi/"+name)
	}
	fmt.Fprintln(&out, ")")
	fmt.Fprintln(&out, "// NewInput allocates the generated DTO for a selected service operation.")
	fmt.Fprintln(&out, "// Binding and admission remain the caller's responsibility.")
	fmt.Fprintln(&out, "func NewInput(service, operation string) (any, error) {\nswitch service {")
	for _, name := range names {
		fmt.Fprintf(&out, "case %q:\nreturn %sapi.NewInput(operation)\n", name, name)
	}
	out.WriteString("default:\nreturn nil, fmt.Errorf(\"%w: %s.%s\", awsapi.ErrUnknownOperation, service, operation)\n}\n}\n")
	return format.Source(out.Bytes())
}

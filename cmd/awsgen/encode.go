package main

import (
	"bytes"
	"fmt"
	"go/format"
)

func renderEncoder(c contract) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(generatedHeader)
	fmt.Fprintf(&out, "package %s\n\nimport (\"fmt\";\"stackd/internal/awsapi\";\"stackd/internal/awscatalog\")\n", c.Info.Name)
	fmt.Fprintln(&out, "// EncodeResponse checks the operation's generated output type before wire serialization.")
	fmt.Fprintln(&out, "func EncodeResponse(operation string, output any) ([]byte,error) {")
	fmt.Fprintf(&out, "service,_:=awscatalog.LookupService(%q)\n", c.Info.Name)
	out.WriteString("op,ok:=service.Operation(operation)\nif !ok {return nil,fmt.Errorf(\"%w: %s\",awsapi.ErrUnknownOperation,operation)}\nswitch op.Name {\n")
	for _, op := range c.Operations {
		fmt.Fprintf(&out, "case %q: value,ok:=output.(*%sOutput); if !ok || value==nil {return nil,fmt.Errorf(\"expected *%sOutput for %s\")};return awsapi.EncodeResponse(service,op,value)\n", op.Name, op.Name, op.Name, op.Name)
	}
	out.WriteString("default: return nil,fmt.Errorf(\"%w: %s\",awsapi.ErrUnknownOperation,operation)\n}\n}\n")
	return format.Source(out.Bytes())
}

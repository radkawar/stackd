package main

import (
	"bytes"
	"fmt"
	"go/format"

	"stackd/internal/awsschema"
)

// These roots are consumed by S3's existing payload and multipart owners. The
// algorithm names, scalar types and member sets come from the compiled model.
func renderChecksums(c contract) ([]byte, error) {
	if c.Info.Name != "s3" {
		return nil, nil
	}
	shapes := make(map[string]awsschema.Shape, len(c.Shapes))
	for _, shape := range c.Shapes {
		shapes[exportedName(shapeName(shape.ID))] = shape
	}
	algorithms, ok := shapes["ChecksumAlgorithm"]
	if !ok || len(algorithms.Enum) == 0 {
		return nil, fmt.Errorf("missing S3 checksum algorithm enum")
	}
	var out bytes.Buffer
	out.WriteString(generatedHeader)
	fmt.Fprintln(&out, "package s3")
	for _, root := range []struct {
		name  string
		input bool
	}{
		{"PutObjectRequest", true},
		{"UploadPartRequest", true},
		{"CompleteMultipartUploadRequest", true},
		{"CompletedPart", true},
		{"PutObjectOutput", false},
		{"GetObjectOutput", false},
		{"HeadObjectOutput", false},
		{"CopyObjectResult", false},
		{"Checksum", false},
		{"ObjectPart", false},
		{"Part", false},
		{"UploadPartOutput", false},
		{"CopyPartResult", false},
		{"CompleteMultipartUploadOutput", false},
	} {
		shape, ok := shapes[root.name]
		if !ok || shape.Kind != "structure" {
			return nil, fmt.Errorf("missing S3 checksum root %s", root.name)
		}
		members := make(map[string]awsschema.Member, len(shape.Members))
		for _, member := range shape.Members {
			members[member.Name] = member
		}
		for _, algorithm := range algorithms.Enum {
			member, ok := members["Checksum"+algorithm.Value]
			if !ok || shapes[exportedName(shapeName(member.Target))].Kind != "string" {
				return nil, fmt.Errorf("missing string checksum member %s.Checksum%s", root.name, algorithm.Value)
			}
		}
		if root.input {
			fmt.Fprintln(&out, "// Checksums yields present modeled checksums, including explicitly empty values.")
			fmt.Fprintf(&out, "func (v *%s) Checksums(yield func(string, string) bool) {\n", root.name)
			for _, algorithm := range algorithms.Enum {
				field := exportedName(members["Checksum"+algorithm.Value].Name)
				fmt.Fprintf(&out, "if v.%s != nil && !yield(%q, string(*v.%s)) { return }\n", field, algorithm.Value, field)
			}
			fmt.Fprintln(&out, "}")
			if root.name == "CompletedPart" {
				fmt.Fprintln(&out, "// ChecksumValue returns the selected modeled field, preserving absence.")
				fmt.Fprintf(&out, "func (v *%s) ChecksumValue(algorithm string) *string {\nswitch algorithm {\n", root.name)
				for _, algorithm := range algorithms.Enum {
					field := exportedName(members["Checksum"+algorithm.Value].Name)
					fmt.Fprintf(&out, "case %q: return (*string)(v.%s)\n", algorithm.Value, field)
				}
				fmt.Fprintln(&out, "}\nreturn nil\n}")
			}
			continue
		}
		fmt.Fprintln(&out, "// SetChecksum writes the modeled field for the selected checksum algorithm.")
		fmt.Fprintf(&out, "func (v *%s) SetChecksum(algorithm, digest string) {\nswitch algorithm {\n", root.name)
		for _, algorithm := range algorithms.Enum {
			member := members["Checksum"+algorithm.Value]
			fmt.Fprintf(&out, "case %q: v.%s = new(%s(digest))\n", algorithm.Value, exportedName(member.Name), exportedName(shapeName(member.Target)))
		}
		fmt.Fprintln(&out, "}\n}")
	}
	return format.Source(out.Bytes())
}

package awscatalog_test

import (
	"encoding/hex"
	"testing"

	"stackd/internal/awscatalog"
)

func TestGeneratedCatalogIntegrity(t *testing.T) {
	for _, info := range awscatalog.Services() {
		t.Run(info.Name, func(t *testing.T) {
			service, ok := awscatalog.LookupService(info.Name)
			if !ok {
				t.Fatal("catalog lookup failed")
			}
			if info.Source.Revision == "" || info.Source.Path == "" || info.Version == "" || info.SigningName == "" {
				t.Fatalf("missing provenance or routing metadata: %+v", info)
			}
			if checksum, err := hex.DecodeString(info.Source.SHA256); err != nil || len(checksum) != 32 {
				t.Fatal("invalid source checksum")
			}
			for _, op := range service.Operations() {
				for _, id := range append([]awscatalog.ShapeID{op.Input, op.Output}, op.Errors...) {
					if _, ok := service.Shape(id); !ok {
						t.Errorf("operation %s has unresolved target %s", op.Name, id)
					}
				}
			}
			for _, shape := range service.Shapes() {
				for _, member := range append(shape.Members, shape.Member, shape.Key, shape.Value) {
					if member.Target != "" {
						if _, ok := service.Shape(member.Target); !ok {
							t.Errorf("shape %s has unresolved member target %s", shape.ID, member.Target)
						}
					}
				}
			}
		})
	}
}

func TestCatalogAccessCannotMutateSharedContracts(t *testing.T) {
	service, ok := awscatalog.LookupService("iam")
	if !ok {
		t.Fatal("missing IAM service")
	}
	operation, ok := service.Operation("CreateUser")
	if !ok || len(operation.Errors) == 0 {
		t.Fatal("missing CreateUser error models")
	}
	operation.Errors[0] = "changed"
	again, _ := service.Operation("CreateUser")
	if again.Errors[0] == "changed" {
		t.Fatal("operation getter exposed mutable catalog slice")
	}
	shape, ok := service.Shape(operation.Input)
	if !ok || len(shape.Members) == 0 {
		t.Fatal("missing input shape")
	}
	shape.Members[0].Required = !shape.Members[0].Required
	againShape, _ := service.Shape(operation.Input)
	if againShape.Members[0].Required == shape.Members[0].Required {
		t.Fatal("shape getter exposed mutable catalog slice")
	}
}

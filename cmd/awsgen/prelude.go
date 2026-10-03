package main

import (
	"stackd/internal/awsschema"
	"stackd/internal/smithy"
)

// Smithy models may refer to prelude shapes without declaring them. Include only
// referenced scalar shapes so generated DTOs keep the source model's namespace.
// Unit also represents operation inputs/outputs omitted from the model.
func addSmithyPrelude(model *smithy.Model) {
	if model.Shapes == nil {
		return
	}
	if _, present := model.Shapes["smithy.api#Unit"]; !present {
		model.Shapes["smithy.api#Unit"] = smithy.Shape{Type: "structure"}
	}
	kinds := map[awsschema.ShapeID]awsschema.ShapeKind{
		"smithy.api#String": "string", "smithy.api#Boolean": "boolean", "smithy.api#Blob": "blob",
		"smithy.api#Byte": "byte", "smithy.api#Short": "short", "smithy.api#Integer": "integer", "smithy.api#Long": "long",
		"smithy.api#Float": "float", "smithy.api#Double": "double", "smithy.api#Timestamp": "timestamp", "smithy.api#Document": "document",
	}
	add := func(ref smithy.Reference) {
		if kind, known := kinds[ref.Target]; known {
			if _, declared := model.Shapes[string(ref.Target)]; !declared {
				model.Shapes[string(ref.Target)] = smithy.Shape{Type: kind}
			}
		}
	}
	for _, shape := range model.Shapes {
		add(shape.Input)
		add(shape.Output)
		add(shape.Member)
		add(shape.Key)
		add(shape.Value)
		for _, member := range shape.Members {
			add(member)
		}
	}
}

// Package smithy reads the AWS SDK's Smithy JSON model representation for generators.
package smithy

import (
	"encoding/json"

	"stackd/internal/awsschema"
)

type Model struct {
	Smithy string           `json:"smithy"`
	Shapes map[string]Shape `json:"shapes"`
}

type Reference struct {
	Target awsschema.ShapeID `json:"target"`
	Traits Traits            `json:"traits"`
}

type Traits map[string]json.RawMessage

type Shape struct {
	Type                 awsschema.ShapeKind  `json:"type"`
	Version              string               `json:"version"`
	Operations           []Reference          `json:"operations"`
	Resources            []Reference          `json:"resources"`
	CollectionOperations []Reference          `json:"collectionOperations"`
	Create               Reference            `json:"create"`
	Put                  Reference            `json:"put"`
	Read                 Reference            `json:"read"`
	Update               Reference            `json:"update"`
	Delete               Reference            `json:"delete"`
	List                 Reference            `json:"list"`
	Input                Reference            `json:"input"`
	Output               Reference            `json:"output"`
	Errors               []Reference          `json:"errors"`
	Members              map[string]Reference `json:"members"`
	Member               Reference            `json:"member"`
	Key                  Reference            `json:"key"`
	Value                Reference            `json:"value"`
	Traits               Traits               `json:"traits"`
}

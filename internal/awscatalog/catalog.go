// Package awscatalog contains generated AWS Smithy service contracts. These
// describe the upstream API; membership does not imply emulator implementation.
package awscatalog

import (
	"slices"
	"stackd/internal/awsschema"
	"strings"
)

// Descriptor types belong to the source-independent schema package.
type ShapeID = awsschema.ShapeID
type OperationName = awsschema.OperationName
type ShapeKind = awsschema.ShapeKind
type Protocol = awsschema.Protocol
type Source = awsschema.Source
type ServiceInfo = awsschema.ServiceInfo
type Operation = awsschema.Operation
type Pagination = awsschema.Pagination
type Bound = awsschema.Bound
type Bounds = awsschema.Bounds
type Constraints = awsschema.Constraints
type Member = awsschema.Member
type EnumValue = awsschema.EnumValue
type ErrorInfo = awsschema.ErrorInfo
type Shape = awsschema.Shape

const (
	AWSQuery  = awsschema.AWSQuery
	AWSJSON10 = awsschema.AWSJSON10
	AWSJSON11 = awsschema.AWSJSON11
	EC2Query  = awsschema.EC2Query
	RestJSON  = awsschema.RestJSON
	RestXML   = awsschema.RestXML
	RPCV2CBOR = awsschema.RPCV2CBOR
)

// Service provides immutable access to operation and shape contracts.
type Service struct {
	ServiceInfo
	operations map[OperationName]Operation
	shapes     map[ShapeID]Shape
	errors     map[string]ShapeID
	httpRoutes []httpRoute
}

func newService(info ServiceInfo, operations []Operation, shapes []Shape) Service {
	s := Service{ServiceInfo: info, operations: make(map[OperationName]Operation), shapes: make(map[ShapeID]Shape), errors: make(map[string]ShapeID)}
	for _, op := range operations {
		s.operations[op.Name] = op
	}
	for _, shape := range shapes {
		s.shapes[shape.ID] = shape
		if shape.Error.Fault != "" {
			s.errors[shape.Error.Code] = shape.ID
			_, name, _ := strings.Cut(string(shape.ID), "#")
			s.errors[name] = shape.ID
		}
	}
	s.httpRoutes = compileHTTPRoutes(s, operations)
	return s
}

// ErrorShape resolves the modeled wire code or Smithy error name.
func (s Service) ErrorShape(code string) (Shape, bool) {
	id, ok := s.errors[code]
	if !ok {
		return Shape{}, false
	}
	return s.Shape(id)
}

func LookupService(name string) (Service, bool) {
	s, ok := catalog[name]
	s.AuthSchemes = slices.Clone(s.AuthSchemes)
	s.Protocols = slices.Clone(s.Protocols)
	return s, ok
}

func Services() []ServiceInfo {
	result := make([]ServiceInfo, 0, len(catalog))
	for _, s := range catalog {
		info := s.ServiceInfo
		info.AuthSchemes = slices.Clone(info.AuthSchemes)
		info.Protocols = slices.Clone(info.Protocols)
		result = append(result, info)
	}
	slices.SortFunc(result, func(a, b ServiceInfo) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return result
}

func (s Service) Operation(name string) (Operation, bool) {
	op, ok := s.operations[OperationName(name)]
	op.Errors = slices.Clone(op.Errors)
	op.AuthSchemes = slices.Clone(op.AuthSchemes)
	op.RequestCompression = slices.Clone(op.RequestCompression)
	return op, ok
}

func (s Service) Operations() []Operation {
	result := make([]Operation, 0, len(s.operations))
	for name := range s.operations {
		op, _ := s.Operation(string(name))
		result = append(result, op)
	}
	slices.SortFunc(result, func(a, b Operation) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return result
}

func (s Service) Shape(id ShapeID) (Shape, bool) {
	shape, ok := s.shapes[id]
	shape.Members = slices.Clone(shape.Members)
	shape.Enum = slices.Clone(shape.Enum)
	return shape, ok
}

func (s Service) Shapes() []Shape {
	result := make([]Shape, 0, len(s.shapes))
	for id := range s.shapes {
		shape, _ := s.Shape(id)
		result = append(result, shape)
	}
	slices.SortFunc(result, func(a, b Shape) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return result
}

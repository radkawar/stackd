// Package awsschema defines the AWS model contracts shared by code generation
// and runtime binding. It has no dependency on generated service data.
package awsschema

type ShapeID string
type OperationName string
type ShapeKind string
type Protocol string

const (
	AWSQuery  Protocol = "awsQuery"
	AWSJSON10 Protocol = "awsJson1_0"
	AWSJSON11 Protocol = "awsJson1_1"
	EC2Query  Protocol = "ec2Query"
	RestJSON  Protocol = "restJson1"
	RestXML   Protocol = "restXml"
	RPCV2CBOR Protocol = "rpcv2Cbor"
)

// Source ties generated contracts to the exact checkout and model content.
type Source struct {
	Repository string
	Revision   string
	Path       string
	SHA256     string
	Modified   bool
	// Corrections identify reviewed local constraints applied after reading the
	// upstream model. SHA256 above always identifies unchanged upstream bytes.
	CorrectionsPath   string
	CorrectionsSHA256 string
}

type ServiceInfo struct {
	Name                  string
	ID                    ShapeID
	SDKID                 string
	Version               string
	Protocol              Protocol
	Protocols             []Protocol
	QueryCompatible       bool
	SigningName           string
	EndpointPrefix        string
	ARNNamespace          string
	CloudTrailEventSource string
	XMLNamespace          string
	XMLNoErrorWrapping    bool
	TargetPrefix          string
	AuthSchemes           []ShapeID
	Source                Source
}

type Operation struct {
	Name         OperationName
	ID           ShapeID
	Input        ShapeID
	Output       ShapeID
	Errors       []ShapeID
	ReadOnly     bool
	Idempotent   bool
	OptionalAuth bool
	// UnsignedPayload comes from aws.auth#unsignedPayload, not a caller header.
	UnsignedPayload    bool `json:",omitempty"`
	AuthSchemes        []ShapeID
	RequestCompression []string
	// RequestChecksumAlgorithmMember comes from aws.protocols#httpChecksum.
	// Its absence distinguishes domain digests from HTTP payload checksums.
	RequestChecksumAlgorithmMember string `json:",omitempty"`
	RequestChecksumRequired        bool   `json:",omitempty"`
	Pagination                     Pagination
	HTTPMethod                     string
	HTTPURI                        string
	HTTPStatus                     int
	XMLUnwrappedOutput             bool
}

type Pagination struct {
	InputToken  string
	OutputToken string
	PageSize    string
	Items       string
}

// Bound preserves both the absence of a constraint and its exact JSON number.
type Bound struct {
	Set   bool
	Value string
}
type Bounds struct {
	Min Bound
	Max Bound
}
type Constraints struct {
	Length      Bounds
	Range       Bounds
	Pattern     string
	UniqueItems bool
}

type Member struct {
	Name             string
	Target           ShapeID
	Required         bool
	Sensitive        bool
	IdempotencyToken bool
	JSONName         string
	TimestampFormat  string
	XMLName          string
	// EC2QueryName is the resolved request key, including modeled case rules.
	EC2QueryName       string `json:",omitempty"`
	XMLFlattened       bool
	XMLAttribute       bool
	XMLNamespace       string
	XMLNamespacePrefix string
	Default            string
	Constraints        Constraints
	// JSONResponseNull emits an absent member as null in JSON wire responses,
	// without changing requests, audit projections, or present empty collections.
	JSONResponseNull bool
	// HTTP bindings apply only to root input/output/error structure members.
	HTTPLabel            bool
	HostLabel            bool
	HTTPQuery            string
	HTTPHeader           string
	HTTPPayload          bool
	HTTPResponseCode     bool
	HTTPQueryParams      bool
	HTTPPrefixHeaders    string
	HTTPPrefixHeadersSet bool
	EventHeader          bool
	EventPayload         bool
}

type EnumValue struct {
	Name  string
	Value string
}
type ErrorInfo struct {
	Fault      string
	HTTPStatus int
	Code       string
}

type Shape struct {
	ID   ShapeID
	Kind ShapeKind
	// JSONIntegerCoercion records native decimal truncation and signed-width
	// saturation before modeled constraints, rather than strict integer parsing.
	JSONIntegerCoercion bool
	Members             []Member
	Member              Member
	Key                 Member
	Value               Member
	Enum                []EnumValue
	Constraints         Constraints
	Sensitive           bool
	Sparse              bool
	Streaming           bool
	MediaType           string
	XMLName             string
	XMLFlattened        bool
	XMLNamespace        string
	XMLNamespacePrefix  string
	Default             string
	TimestampFormat     string
	Error               ErrorInfo
}

package cloudformation

import (
	"reflect"
	"testing"
)

func TestTemplateParameterBindingAndConstraints(t *testing.T) {
	template, err := ParseTemplate(`
Parameters:
  Environment:
    Type: String
    Default: dev
    AllowedValues: [dev, prod]
  Ports:
    Type: List<Number>
    Default: '80, 443'
  Names:
    Type: CommaDelimitedList
    Default: 'alpha, beta'
    AllowedPattern: '[a-z]+'
    AllowedValues: [alpha, beta]
  Secret:
    Type: String
    NoEcho: true
    MinLength: 3
    MaxLength: 5
    AllowedPattern: '[a-z]+'
  Count:
    Type: Number
    Default: 2
    MinValue: 1
    MaxValue: 4
Resources:
  Queue:
    Type: AWS::SQS::Queue
`)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := template.BindParameters(map[string]string{"Secret": "abc"}, map[string]string{"Environment": "prod"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bound["Environment"] != "dev" || bound["Count"] != "2" {
		t.Fatalf("omitted parameters must use template defaults: %#v", bound)
	}
	bound, err = template.BindParameters(map[string]string{"Secret": "abc"}, map[string]string{"Environment": "prod"}, map[string]bool{"Environment": true})
	if err != nil || bound["Environment"] != "prod" {
		t.Fatalf("explicit previous value: %#v, %v", bound, err)
	}
	cases := []struct {
		name            string
		input, previous map[string]string
		usePrevious     map[string]bool
	}{
		{"missing-required", nil, nil, nil},
		{"unknown-input", map[string]string{"Secret": "abc", "Typo": "x"}, nil, nil},
		{"missing-previous", map[string]string{"Secret": "abc"}, nil, map[string]bool{"Environment": true}},
		{"conflicting-previous", map[string]string{"Secret": "abc", "Environment": "dev"}, map[string]string{"Environment": "prod"}, map[string]bool{"Environment": true}},
		{"previous-must-meet-new-constraints", map[string]string{"Secret": "abc"}, map[string]string{"Environment": "retired"}, map[string]bool{"Environment": true}},
		{"pattern-must-match-whole-value", map[string]string{"Secret": "!abc"}, nil, nil},
		{"minimum-length", map[string]string{"Secret": "ab"}, nil, nil},
		{"maximum-length", map[string]string{"Secret": "abcdef"}, nil, nil},
		{"list-elements-validated", map[string]string{"Secret": "abc", "Names": "alpha,invalid"}, nil, nil},
		{"numeric-list-elements-validated", map[string]string{"Secret": "abc", "Ports": "80,NaN"}, nil, nil},
		{"numeric-minimum", map[string]string{"Secret": "abc", "Count": "0"}, nil, nil},
		{"numeric-maximum", map[string]string{"Secret": "abc", "Count": "5"}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := template.BindParameters(tc.input, tc.previous, tc.usePrevious); err == nil {
				t.Fatal("invalid binding was accepted")
			}
		})
	}
}

func TestTemplateSelectedDependenciesAndDisabledPropagation(t *testing.T) {
	template, err := ParseTemplate(`
Parameters:
  Mode: {Type: String, Default: dev}
Conditions:
  Production: !Equals [!Ref Mode, prod]
Resources:
  ZQueue:
    Type: AWS::SQS::Queue
    Condition: Production
  AConsumer:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !If [Production, !GetAtt ZQueue.Arn, development]
  BDisabled:
    Type: AWS::SNS::Topic
    DependsOn: ZQueue
  CTransitive:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !Sub '${BDisabled}'
  DShadow:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !Sub ['${ZQueue}-${!literal}', {ZQueue: shadow}]
`)
	if err != nil {
		t.Fatal(err)
	}
	order, err := template.Order(Evaluation{Parameters: map[string]string{"Mode": "dev"}})
	if err != nil || !reflect.DeepEqual(order, []string{"AConsumer", "DShadow"}) {
		t.Fatalf("disabled resource propagation or Sub shadowing: %v, %v", order, err)
	}
	order, err = template.Order(Evaluation{Parameters: map[string]string{"Mode": "prod"}})
	if err != nil || !reflect.DeepEqual(order, []string{"ZQueue", "AConsumer", "BDisabled", "CTransitive", "DShadow"}) {
		t.Fatalf("selected branch dependency: %v, %v", order, err)
	}
	props, err := template.ResolveResource("DShadow", Evaluation{})
	if err != nil || props["DisplayName"] != "shadow-${literal}" {
		t.Fatalf("Sub map override and escaping: %#v, %v", props, err)
	}
}

func TestTemplateConditionalNoValueAndImports(t *testing.T) {
	template, err := ParseTemplate(`
Transform: AWS::LanguageExtensions
Parameters:
  Names: {Type: CommaDelimitedList, Default: 'alpha, beta'}
Conditions:
  Never: !Equals [a, b]
  Always: !Not [!Condition Never]
Mappings:
  Regional:
    us-east-1: {Suffix: east}
Resources:
  Queue:
    Type: AWS::SQS::Queue
    DeletionPolicy: RetainExceptOnCreate
    Properties:
      QueueName: !Sub '${AWS::StackName}-${AWS::Region}'
      Removed: !If [Never, discarded, !Ref AWS::NoValue]
      Tags:
        - !If [Never, {Key: removed, Value: removed}, !Ref AWS::NoValue]
        - Key: import
          Value: !ImportValue Shared
      Selected: !Select [1, !Ref Names]
      Mapping: !FindInMap [Regional, !Ref AWS::Region, Suffix]
      Encoded: !Base64 'hello'
      Joined: !Join [':', !Split [',', 'a,,b']]
      Count:
        Fn::Length: !Ref Names
      Skipped: !If [Never, !ImportValue Missing, kept]
Outputs:
  QueueARN:
    Value: !GetAtt Queue.Arn
    Export:
      Name: !Sub '${AWS::StackName}-Arn'
  Account:
    Value: !Sub '${AWS::Partition}:${AWS::AccountId}:${AWS::URLSuffix}'
  Hidden:
    Condition: Never
    Value: !ImportValue Missing
`)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := template.BindParameters(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	evaluation := Evaluation{
		Scope:     Scope{Partition: "aws", Region: "us-east-1", Account: "123456789012"},
		StackName: "example", Parameters: parameters,
		Imports:   map[string]string{"Shared": "shared-value"},
		Resources: map[string]ResourceResult{"Queue": {Ref: "queue-url", Attributes: map[string]any{"Arn": "queue-arn"}}},
	}
	properties, err := template.ResolveResource("Queue", evaluation)
	if err != nil {
		t.Fatal(err)
	}
	want := Properties{
		"QueueName": "example-us-east-1",
		"Tags":      []any{map[string]any{"Key": "import", "Value": "shared-value"}},
		"Selected":  "beta", "Mapping": "east", "Encoded": "aGVsbG8=",
		"Joined": "a::b", "Count": float64(2), "Skipped": "kept",
	}
	if !reflect.DeepEqual(properties, want) {
		t.Fatalf("resolved properties = %#v, want %#v", properties, want)
	}
	outputs, imports, err := template.ResolveOutputs(evaluation)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(imports, []string{"Shared"}) {
		t.Fatalf("resource-only imports must be retained, inactive imports omitted: %v", imports)
	}
	if !reflect.DeepEqual(outputs, map[string]OutputValue{
		"QueueARN": {Value: "queue-arn", ExportName: "example-Arn"},
		"Account":  {Value: "aws:123456789012:amazonaws.com"},
	}) {
		t.Fatalf("unexpected outputs: %#v", outputs)
	}
	delete(evaluation.Imports, "Shared")
	if _, err := template.Order(evaluation); err == nil {
		t.Fatal("missing resource import was not rejected before deployment")
	}
}

func TestTemplateRejectsUnsupportedOrAmbiguousEffects(t *testing.T) {
	cases := map[string]string{
		"duplicate-json-key":           `{"Resources":{"Queue":{"Type":"AWS::SQS::Queue","Type":"AWS::SNS::Topic"}}}`,
		"duplicate-yaml-key":           "Resources:\n  Queue: {Type: AWS::SQS::Queue, Type: AWS::SNS::Topic}",
		"multiple-documents":           "Resources: {Queue: {Type: AWS::SQS::Queue}}\n---\nResources: {}",
		"yaml-alias":                   "Resources:\n  Queue: &queue {Type: AWS::SQS::Queue}\n  Other: *queue",
		"yaml-set":                     "Resources: {Queue: {Type: AWS::SQS::Queue, Properties: {Value: !!set {abc: null}}}}",
		"macro":                        "Transform: CustomMacro\nResources: {Queue: {Type: AWS::SQS::Queue}}",
		"creation-policy":              "Resources: {Queue: {Type: AWS::SQS::Queue, CreationPolicy: {ResourceSignal: {Count: 1}}}}",
		"update-policy":                "Resources: {Queue: {Type: AWS::SQS::Queue, UpdatePolicy: {Anything: true}}}",
		"retain-except-replacement":    "Resources: {Queue: {Type: AWS::SQS::Queue, UpdateReplacePolicy: RetainExceptOnCreate}}",
		"custom-resource":              "Resources: {Queue: {Type: 'Custom::Queue'}}",
		"nested-stack":                 "Resources: {Queue: {Type: AWS::CloudFormation::Stack}}",
		"dynamic-reference":            "Resources: {Queue: {Type: AWS::SQS::Queue, Properties: {QueueName: '{{resolve:ssm:secret}}'}}}",
		"unknown-inactive-intrinsic":   "Conditions: {Never: !Equals [a, b]}\nResources: {Queue: {Type: AWS::SQS::Queue, Properties: {Value: !If [Never, {Fn::Unknown: ignored}, accepted]}}}",
		"condition-resource-reference": "Conditions: {Invalid: !Equals [!Ref Queue, x]}\nResources: {Queue: {Type: AWS::SQS::Queue}}",
		"condition-cycle":              "Conditions: {First: !Condition Second, Second: !Condition First}\nResources: {Queue: {Type: AWS::SQS::Queue}}",
		"unknown-reference":            "Resources: {Queue: {Type: AWS::SQS::Queue, Properties: {Value: !Ref Missing}}}",
		"resource-import-name":         "Resources: {Queue: {Type: AWS::SQS::Queue}, Consumer: {Type: AWS::SNS::Topic, Properties: {Value: !ImportValue {Ref: Queue}}}}",
		"resource-export-name":         "Resources: {Queue: {Type: AWS::SQS::Queue}}\nOutputs: {Invalid: {Value: fine, Export: {Name: !Sub '${Queue.Arn}'}}}",
		"length-without-transform":     "Resources: {Queue: {Type: AWS::SQS::Queue, Properties: {Value: {Fn::Length: [a, b]}}}}",
		"length-short-form":            "Transform: AWS::LanguageExtensions\nResources: {Queue: {Type: AWS::SQS::Queue, Properties: {Value: !Length [a, b]}}}",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTemplate(body); err == nil {
				t.Fatal("invalid or unsupported template accepted")
			}
		})
	}
}

func TestTemplateCycleSelectedBranchAndMissingAttribute(t *testing.T) {
	template, err := ParseTemplate(`
Parameters:
  Mode: {Type: String}
Conditions:
  Cycle: !Equals [!Ref Mode, cycle]
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      Value: !If [Cycle, !Ref Topic, literal]
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      Value: !GetAtt Queue.Arn
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := template.Order(Evaluation{Parameters: map[string]string{"Mode": "cycle"}}); err == nil {
		t.Fatal("selected dependency cycle was accepted")
	}
	order, err := template.Order(Evaluation{Parameters: map[string]string{"Mode": "normal"}})
	if err != nil || !reflect.DeepEqual(order, []string{"Queue", "Topic"}) {
		t.Fatalf("inactive branch must not introduce a cycle: %v, %v", order, err)
	}
	if _, err := template.ResolveResource("Topic", Evaluation{Resources: map[string]ResourceResult{"Queue": {Ref: "queue"}}}); err == nil {
		t.Fatal("missing resource attribute was silently resolved")
	}
}

func TestTemplateImportAndExportNamesCannotHideResourceReferences(t *testing.T) {
	for _, expression := range []string{
		`{"Fn::Sub":"${Queue}"}`,
		`{"Fn::Sub":["${Name}",{"Name":{"Ref":"Queue"}}]}`,
		`{"Fn::If":["Never",{"Ref":"Queue"},"fixed"]}`,
	} {
		for _, output := range []bool{false, true} {
			body := `{"Conditions":{"Never":{"Fn::Equals":["a","b"]}},"Resources":{"Queue":{"Type":"AWS::SQS::Queue"}`
			if output {
				body += `},"Outputs":{"Value":{"Value":"v","Export":{"Name":` + expression + `}}}}`
			} else {
				body += `,"Consumer":{"Type":"AWS::SNS::Topic","Properties":{"Value":{"Fn::ImportValue":` + expression + `}}}}}`
			}
			if _, err := ParseTemplate(body); err == nil {
				t.Fatalf("resource-dependent cross-stack name accepted: %s", body)
			}
		}
	}
}

func TestTemplateNamedIAMCapabilityIsNotHiddenByCondition(t *testing.T) {
	template, err := ParseTemplate(`
Transform: AWS::LanguageExtensions
Conditions:
  Never: !Equals [a, b]
Resources:
  Named:
    Type: AWS::IAM::Role
    Condition: Never
    Properties:
      RoleName: !Sub '${AWS::StackName}-role'
  Unnamed:
    Type: AWS::IAM::Role
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := template.Capabilities(); !reflect.DeepEqual(got, []string{"CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"}) {
		t.Fatalf("named IAM acknowledgment must be required before condition evaluation: %v", got)
	}
}

func TestTemplateBootstrapRuleUsesResolvedValue(t *testing.T) {
	template, err := ParseTemplate(`
Parameters:
  BootstrapVersion:
    Type: AWS::SSM::Parameter::Value<String>
    Default: /cdk-bootstrap/hnb659fds/version
Rules:
  CheckBootstrapVersion:
    Assertions:
      - Assert:
          Fn::Not:
            - Fn::Contains:
                - ["1", "2", "3", "4", "5"]
                - Ref: BootstrapVersion
        AssertDescription: bootstrap version must be at least six
Resources:
  Parameter:
    Type: AWS::SSM::Parameter
    Properties:
      Type: String
      Value: !Ref BootstrapVersion
`)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := template.BindParameters(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"5", "32"} {
		evaluation := Evaluation{Parameters: bound, ResolvedParameters: map[string]string{"BootstrapVersion": version}}
		err := template.ValidateRules(evaluation)
		if (err != nil) != (version == "5") {
			t.Fatalf("bootstrap version %s: %v", version, err)
		}
		properties, err := template.ResolveResource("Parameter", evaluation)
		if err != nil || properties["Value"] != version {
			t.Fatalf("resolved parameter: %#v, %v", properties, err)
		}
		output := parametersOutput("", bound, evaluation.ResolvedParameters)
		if len(output) != 1 || text(output[0].ParameterValue) != "/cdk-bootstrap/hnb659fds/version" || text(output[0].ResolvedValue) != version {
			t.Fatalf("parameter key and captured value must remain distinct: %#v", output)
		}
	}
	if err := template.ValidateRules(Evaluation{Parameters: bound}); err == nil {
		t.Fatal("unresolved SSM value passed bootstrap assertion")
	}
}

func TestTemplateRuleConditionAndMemberAssertions(t *testing.T) {
	template, err := ParseTemplate(`
Parameters:
  Mode: {Type: String}
  Members: {Type: CommaDelimitedList}
Rules:
  AllowedMembers:
    RuleCondition: !Equals [!Ref Mode, strict]
    Assertions:
      - Assert: {Fn::EachMemberIn: [!Ref Members, [one, two]]}
Resources:
  Queue: {Type: AWS::SQS::Queue}
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		mode, members string
		rejected      bool
	}{
		{"strict", "one,two", false}, {"strict", "one,other", true}, {"relaxed", "other", false},
	} {
		err := template.ValidateRules(Evaluation{Parameters: map[string]string{"Mode": row.mode, "Members": row.members}})
		if (err != nil) != row.rejected {
			t.Fatalf("%+v: %v", row, err)
		}
	}
}

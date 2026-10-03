package appconfig

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/amazon-ion/ion-go/ion"
)

// Rules use Ion s-expressions. This is an admission parser, not an evaluator:
// AppConfig Data returns the default variant; the real Agent owns evaluation.
// Named operands are Ion annotations, represented as a node with one child.
type variantRuleNode struct {
	Kind, Text string
	Children   []variantRuleNode
}

func validateVariantRule(rule string) error {
	_, err := parseVariantRule(rule)
	return err
}

func parseVariantRule(rule string) (variantRuleNode, error) {
	reader := ion.NewReaderString(rule)
	if !reader.Next() {
		return variantRuleNode{}, fmt.Errorf("rule must be an expression")
	}
	node, err := readVariantRuleNode(reader)
	if err != nil {
		return node, err
	}
	if node.Kind != "expression" || reader.Next() {
		return node, fmt.Errorf("rule must contain one expression")
	}
	if err := reader.Err(); err != nil {
		return node, err
	}
	return node, checkVariantRuleExpression(node)
}

func readVariantRuleNode(reader ion.Reader) (variantRuleNode, error) {
	var node variantRuleNode
	if reader.IsNull() {
		return node, fmt.Errorf("null is not a rule operand")
	}
	annotations, err := reader.Annotations()
	if err != nil {
		return node, err
	}
	if len(annotations) > 1 {
		return node, fmt.Errorf("rule operands have one name")
	}
	switch reader.Type() {
	case ion.SexpType, ion.ListType:
		node.Kind = "list"
		if reader.Type() == ion.SexpType {
			node.Kind = "expression"
		}
		if err := reader.StepIn(); err != nil {
			return node, err
		}
		if node.Kind == "expression" {
			if !reader.Next() || reader.Type() != ion.SymbolType {
				return node, fmt.Errorf("expression operator is required")
			}
			symbol, err := reader.SymbolValue()
			if err != nil || symbol == nil || symbol.Text == nil {
				return node, fmt.Errorf("invalid expression operator")
			}
			node.Text = *symbol.Text
		}
		for reader.Next() {
			child, err := readVariantRuleNode(reader)
			if err != nil {
				return node, err
			}
			node.Children = append(node.Children, child)
		}
		if err := reader.Err(); err != nil {
			return node, err
		}
		if err := reader.StepOut(); err != nil {
			return node, err
		}
	case ion.StringType:
		value, err := reader.StringValue()
		if err != nil {
			return node, err
		}
		node.Kind, node.Text = "string", *value
	case ion.SymbolType:
		value, err := reader.SymbolValue()
		if err != nil || value == nil || value.Text == nil || !strings.HasPrefix(*value.Text, "$") || len(*value.Text) < 2 {
			return node, fmt.Errorf("unknown rule symbol")
		}
		node.Kind, node.Text = "context", (*value.Text)[1:]
	case ion.BoolType:
		value, err := reader.BoolValue()
		if err != nil {
			return node, err
		}
		node.Kind, node.Text = "bool", strconv.FormatBool(*value)
	case ion.IntType:
		value, err := reader.Int64Value()
		if err != nil {
			return node, err
		}
		node.Kind, node.Text = "number", strconv.FormatInt(*value, 10)
	case ion.FloatType:
		value, err := reader.FloatValue()
		if err != nil {
			return node, err
		}
		node.Kind, node.Text = "number", strconv.FormatFloat(*value, 'g', -1, 64)
	case ion.DecimalType:
		value, err := reader.DecimalValue()
		if err != nil {
			return node, err
		}
		node.Kind, node.Text = "number", strings.Replace(value.String(), "d", "e", 1)
	case ion.TimestampType:
		value, err := reader.TimestampValue()
		if err != nil {
			return node, err
		}
		node.Kind, node.Text = "timestamp", value.String()
	default:
		return node, fmt.Errorf("invalid rule operand type")
	}
	if len(annotations) != 0 {
		if annotations[0].Text == nil {
			return node, fmt.Errorf("invalid named operand")
		}
		node = variantRuleNode{Kind: "named", Text: *annotations[0].Text, Children: []variantRuleNode{node}}
	}
	return node, nil
}

func checkVariantRuleExpression(node variantRuleNode) error {
	for _, child := range node.Children {
		if child.Kind == "expression" {
			if err := checkVariantRuleExpression(child); err != nil {
				return err
			}
		}
	}
	count := len(node.Children)
	switch node.Text {
	case "eq", "gt", "gte", "lt", "lte", "begins_with", "ends_with", "contains", "in":
		if count != 2 {
			return fmt.Errorf("%s requires two operands", node.Text)
		}
	case "and", "or":
		if count < 2 {
			return fmt.Errorf("%s requires at least two operands", node.Text)
		}
	case "not":
		if count != 1 {
			return fmt.Errorf("not requires one operand")
		}
	case "matches", "exists", "split":
		return checkNamedVariantOperands(node)
	default:
		return fmt.Errorf("unknown rule operator %q", node.Text)
	}
	for _, child := range node.Children {
		if child.Kind == "named" {
			return fmt.Errorf("%s uses positional operands", node.Text)
		}
		if node.Text == "and" || node.Text == "or" || node.Text == "not" {
			if child.Kind != "bool" && child.Kind != "context" && child.Kind != "expression" {
				return fmt.Errorf("logical operands must be boolean")
			}
		}
		if child.Kind == "list" {
			for _, item := range child.Children {
				if item.Kind != "string" && item.Kind != "number" && item.Kind != "bool" && item.Kind != "timestamp" {
					return fmt.Errorf("list operands must be constants")
				}
			}
		}
	}
	if node.Text == "in" && node.Children[1].Kind != "list" {
		return fmt.Errorf("in requires a constant list")
	}
	return nil
}

func checkNamedVariantOperands(node variantRuleNode) error {
	operands := make(map[string]variantRuleNode, len(node.Children))
	for _, child := range node.Children {
		if child.Kind != "named" || len(child.Children) != 1 {
			return fmt.Errorf("%s requires named operands", node.Text)
		}
		if _, duplicate := operands[child.Text]; duplicate {
			return fmt.Errorf("duplicate operand %s", child.Text)
		}
		operands[child.Text] = child.Children[0]
	}
	switch node.Text {
	case "exists":
		if len(operands) != 1 || operands["key"].Kind != "string" {
			return fmt.Errorf("exists requires key")
		}
	case "matches":
		if len(operands) != 2 || operands["in"].Kind == "" || operands["pattern"].Kind != "string" {
			return fmt.Errorf("matches requires in and pattern")
		}
		if _, err := compileContentRegexp(operands["pattern"].Text); err != nil {
			return err
		}
	case "split":
		if len(operands) < 2 || len(operands) > 3 || operands["pct"].Kind != "number" || operands["by"].Kind == "" {
			return fmt.Errorf("split requires pct and by")
		}
		if len(operands) == 3 && operands["seed"].Kind != "string" {
			return fmt.Errorf("split seed must be a string")
		}
		pct, err := strconv.ParseFloat(operands["pct"].Text, 64)
		if err != nil || pct < 0 || pct > 100 {
			return fmt.Errorf("split pct must be between zero and 100")
		}
	}
	return nil
}

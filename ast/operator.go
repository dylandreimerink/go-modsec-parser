package ast

import "net"

type Operator interface {
	Node

	Operator()
	GetNegative() bool
	SetNegative(bool)
}

type AbstractOperator struct {
	AbstractNode

	Negative bool
}

func (op *AbstractOperator) SetNegative(neg bool) {
	op.Negative = neg
}

func (op *AbstractOperator) GetNegative() bool {
	return op.Negative
}

//OperatorContains Returns true if the parameter string is found anywhere in the input. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#contains
type OperatorContains struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorContains) Name() string {
	return "contains"
}

func (o *OperatorContains) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorContains) Operator() {}

//OperatorEndsWith Returns true if the parameter string is found at the end of the input. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#endsWith
type OperatorEndsWith struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorEndsWith) Name() string {
	return "endsWith"
}

func (o *OperatorEndsWith) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorEndsWith) Operator() {}

//OperatorEquals Performs numerical comparison and returns true if the input value is equal to the provided parameter. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#eq
type OperatorEquals struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorEquals) Name() string {
	return "eq"
}

func (o *OperatorEquals) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorEquals) Operator() {}

//OperatorGreaterThan Performs numerical comparison and returns true if the input value is greater than the operator parameter. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#gt
type OperatorGreaterThan struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorGreaterThan) Name() string {
	return "gt"
}

func (o *OperatorGreaterThan) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorGreaterThan) Operator() {}

//OperatorIPMatch Performs a fast ipv4 or ipv6 match of REMOTE_ADDR variable data.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ipMatch
type OperatorIPMatch struct {
	AbstractOperator

	IPs []net.IPNet
}

func (o *OperatorIPMatch) Name() string {
	return "ipMatch"
}

func (o *OperatorIPMatch) Children() []Node {
	return []Node{}
}

func (o *OperatorIPMatch) Operator() {}

//OperatorLessThanOrEqual Performs numerical comparison and returns true if the input value is less than or equal to the operator parameter. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#le
type OperatorLessThanOrEqual struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorLessThanOrEqual) Name() string {
	return "le"
}

func (o *OperatorLessThanOrEqual) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorLessThanOrEqual) Operator() {}

//OperatorLessThan Performs numerical comparison and returns true if the input value is less than to the operator parameter. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#lt
type OperatorLessThan struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorLessThan) Name() string {
	return "lt"
}

func (o *OperatorLessThan) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorLessThan) Operator() {}

//OperatorRegex Performs a regular expression match of the pattern provided as parameter. This is the default operator; the rules that do not explicitly specify an operator default to @rx.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#rx
type OperatorRegex struct {
	AbstractOperator

	Value string
}

func (o *OperatorRegex) Name() string {
	return "rx"
}

func (o *OperatorRegex) Children() []Node {
	return []Node{}
}

func (o *OperatorRegex) Operator() {}

//OperatorStreq Performs a string comparison and returns true if the parameter string is identical to the input string. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#streq
type OperatorStreq struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorStreq) Name() string {
	return "streq"
}

func (o *OperatorStreq) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorStreq) Operator() {}

package ast

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

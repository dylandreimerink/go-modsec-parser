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

//OperatorBeginsWith Returns true if the parameter string is found at the beginning of the input. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#beginsWith
type OperatorBeginsWith struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorBeginsWith) Name() string {
	return "beginsWith"
}

func (o *OperatorBeginsWith) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorBeginsWith) Operator() {}

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

//OperatorGreaterThanOrEquals Performs numerical comparison and returns true if the input value is greater than or equal to the provided parameter. Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ge
type OperatorGreaterThanOrEquals struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorGreaterThanOrEquals) Name() string {
	return "ge"
}

func (o *OperatorGreaterThanOrEquals) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorGreaterThanOrEquals) Operator() {}

//OperatorGeoLookup performs a geolocation lookup using the IP address in input against the geolocation database previously configured using SecGeoLookupDb. If the lookup is successful, the obtained information is captured in the GEO collection.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#geoLookup
type OperatorGeoLookup struct {
	AbstractOperator
}

func (o *OperatorGeoLookup) Name() string {
	return "geoLookup"
}

func (o *OperatorGeoLookup) Children() []Node {
	return []Node{}
}

func (o *OperatorGeoLookup) Operator() {}

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

//OperatorPM Performs a case-insensitive match of the provided phrases against the desired input value.
// The operator uses a set-based matching algorithm (Aho-Corasick), which means that it will match any number of keywords in parallel.
// When matching of a large number of keywords is needed, this operator performs much better than a regular expression.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#pm
type OperatorPM struct {
	AbstractOperator

	Phrases []string
}

func (o *OperatorPM) Name() string {
	return "pm"
}

func (o *OperatorPM) Children() []Node {
	return []Node{}
}

func (o *OperatorPM) Operator() {}

//OperatorPMFromFile Performs a case-insensitive match of the provided phrases against the desired input value.
// The operator uses a set-based matching algorithm (Aho-Corasick),
// which means that it will match any number of keywords in parallel.
// When matching of a large number of keywords is needed, this operator performs much better than a regular expression.
//
// This operator is the same as @pm, except that it takes a list of files as arguments.
// It will match any one of the phrases listed in the file(s) anywhere in the target value.
//
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#pmFromFile
type OperatorPMFromFile struct {
	AbstractOperator

	Files []string
}

func (o *OperatorPMFromFile) Name() string {
	return "pmFromFile"
}

func (o *OperatorPMFromFile) Children() []Node {
	return []Node{}
}

func (o *OperatorPMFromFile) Operator() {}

//OperatorRBL Looks up the input value in the RBL (real-time block list) given as parameter. The parameter can be an IPv4 address or a hostname.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#rbl
type OperatorRBL struct {
	AbstractOperator

	Value string
}

func (o *OperatorRBL) Name() string {
	return "rbl"
}

func (o *OperatorRBL) Children() []Node {
	return []Node{}
}

func (o *OperatorRBL) Operator() {}

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

type ByteRange struct {
	AbstractNode

	StartID byte
	EndID   byte
}

func (o *ByteRange) Name() string {
	return "byte-range"
}

func (o *ByteRange) Children() []Node {
	return []Node{}
}

//OperatorValidateByteRange Validates that the byte values used in input fall into the range specified by the operator parameter.
// This operator matches on an input value that contains bytes that are not in the specified range.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#validateByteRange
type OperatorValidateByteRange struct {
	AbstractOperator

	Ranges []*ByteRange
}

func (o *OperatorValidateByteRange) Name() string {
	return "validateByteRange"
}

func (o *OperatorValidateByteRange) Children() []Node {
	nodes := []Node{}
	for _, brange := range o.Ranges {
		nodes = append(nodes, Node(brange))
	}
	return nodes
}

func (o *OperatorValidateByteRange) Operator() {}

//OperatorValidateURLEncoding Validates the URL-encoded characters in the provided input string.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#validateUrlEncoding
type OperatorValidateURLEncoding struct {
	AbstractOperator
}

func (o *OperatorValidateURLEncoding) Name() string {
	return "validateUrlEncoding"
}

func (o *OperatorValidateURLEncoding) Children() []Node {
	return []Node{}
}

func (o *OperatorValidateURLEncoding) Operator() {}

//OperatorValidateUTF8Encoding Check whether the input is a valid UTF-8 string.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#validateUtf8Encoding
type OperatorValidateUTF8Encoding struct {
	AbstractOperator
}

func (o *OperatorValidateUTF8Encoding) Name() string {
	return "validateUtf8Encoding"
}

func (o *OperatorValidateUTF8Encoding) Children() []Node {
	return []Node{}
}

func (o *OperatorValidateUTF8Encoding) Operator() {}

//OperatorWithin Returns true if the input value (the needle) is found anywhere within the @within parameter (the haystack). Macro expansion is performed on the parameter string before comparison.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#within
type OperatorWithin struct {
	AbstractOperator

	Value *ExpandableString
}

func (o *OperatorWithin) Name() string {
	return "within"
}

func (o *OperatorWithin) Children() []Node {
	return []Node{o.Value}
}

func (o *OperatorWithin) Operator() {}

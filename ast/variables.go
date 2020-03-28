package ast

//VariableList defines a list of variables selectors, it represents the first argument of the SecRule directive.
//Every variable selector is seperated by a |
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#args
type VariableList struct {
	AbstractNode

	VariableSelectors []*VariableSelector
}

func (vl *VariableList) Name() string {
	return "variable-list"
}

func (vl *VariableList) Children() []Node {
	nodes := []Node{}
	for _, variable := range vl.VariableSelectors {
		nodes = append(nodes, variable)
	}

	return nodes
}

func (vl *VariableList) AddSelector(vs *VariableSelector) {
	if vl.VariableSelectors == nil {
		vl.VariableSelectors = []*VariableSelector{}
	}

	vs.SetParent(vl)

	vl.VariableSelectors = append(vl.VariableSelectors, vs)
}

//VariableSelector is element of a variable list and defines which variable / collection (parts) are select for matching a SecRule
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#args
type VariableSelector struct {
	AbstractNode

	Variable           Variable
	SelectorOperation  VariableSelectionOperation
	CollectionSelector VariableCollectionSelection
}

func (vs *VariableSelector) Name() string {
	return "variable-selector"
}

func (vs *VariableSelector) Children() []Node {
	return []Node{vs.Variable}
}

//VariableSelectionOperation defines how the variable selector should modify the produces list of variables at runtime
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#args
type VariableSelectionOperation int

func (selOp VariableSelectionOperation) String() string {
	switch selOp {
	case VARIABLE_SELECTION_ADD:
		return "add"
	case VARIABLE_SELECTION_REMOVE:
		return "remove"
	case VARIABLE_SELECTION_COUNT:
		return "count"
	default:
		return "UNKNOWN"
	}
}

const (
	//Add a variable / collection to the variable list
	VARIABLE_SELECTION_ADD VariableSelectionOperation = iota + 1

	//Remove variables from variable list
	VARIABLE_SELECTION_REMOVE

	//Add count to variable list
	VARIABLE_SELECTION_COUNT
)

//VariableCollectionSelection defines how part of a collection should be selected. ModSec supports single key or regex selection
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#args
type VariableCollectionSelection interface {
	Node
	VariableCollectionSelection()
}

//KeyVariableCollectionSelection defines that a selector will pick one specific key from a collection
type KeyVariableCollectionSelection struct {
	AbstractNode
	Value string
}

func (cs *KeyVariableCollectionSelection) Name() string {
	return "key-variable-collection-selector"
}

func (cs *KeyVariableCollectionSelection) Children() []Node {
	return []Node{}
}

func (cs *KeyVariableCollectionSelection) VariableCollectionSelection() {}

//RegexVariableCollectionSelection defines that a selector will pick all keys from a collection where the name matches the regex
type RegexVariableCollectionSelection struct {
	AbstractNode
	Value string
}

func (cs *RegexVariableCollectionSelection) Name() string {
	return "regex-variable-collection-selector"
}

func (cs *RegexVariableCollectionSelection) Children() []Node {
	return []Node{}
}

func (cs *RegexVariableCollectionSelection) VariableCollectionSelection() {}

type Variable interface {
	Node
	IsCollection() bool
}

//VariableArgs is a collection and can be used on its own (means all arguments including the POST Payload),
// with a static parameter (matches arguments with that name),
// or with a regular expression (matches all arguments with name that matches the regular expression).
// To look at only the query string or body arguments, see the ARGS_GET and ARGS_POST collections.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ARGS
type VariableArgs struct {
	AbstractNode
}

func (v *VariableArgs) Name() string {
	return "ARGS"
}

func (v *VariableArgs) IsCollection() bool {
	return true
}

func (v *VariableArgs) Children() []Node {
	return []Node{}
}

//VariableArgsNames Contains all request parameter names. You can search for specific parameter names that you want to inspect
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ARGS_NAMES
type VariableArgsNames struct {
	AbstractNode
}

func (v *VariableArgsNames) Name() string {
	return "ARGS_NAMES"
}

func (v *VariableArgsNames) IsCollection() bool {
	return true
}

func (v *VariableArgsNames) Children() []Node {
	return []Node{}
}

//VariableDuration Contains the number of milliseconds elapsed since the beginning of the current transaction.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#DURATION
type VariableDuration struct {
	AbstractNode
}

func (v *VariableDuration) Name() string {
	return "DURATION"
}

func (v *VariableDuration) IsCollection() bool {
	return false
}

func (v *VariableDuration) Children() []Node {
	return []Node{}
}

//VariableRequestBodyProcessor Contains the name of the currently used request body processor. The possible values are URLENCODED, MULTIPART, and XML.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#REQBODY_PROCESSOR
type VariableRequestBodyProcessor struct {
	AbstractNode
}

func (v *VariableRequestBodyProcessor) Name() string {
	return "REQBODY_PROCESSOR"
}

func (v *VariableRequestBodyProcessor) IsCollection() bool {
	return false
}

func (v *VariableRequestBodyProcessor) Children() []Node {
	return []Node{}
}

//VariableRequestBody Holds the raw request body.
// This variable is available only if the URLENCODED request body processor was used,
// which will occur by default when the application/x-www-form-urlencoded content type is detected,
// or if the use of the URLENCODED request body parser was forced.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#request_body
type VariableRequestBody struct {
	AbstractNode
}

func (v *VariableRequestBody) Name() string {
	return "REQUEST_BODY"
}

func (v *VariableRequestBody) IsCollection() bool {
	return false
}

func (v *VariableRequestBody) Children() []Node {
	return []Node{}
}

//VariableRequestCookies This variable is a collection of all of request cookies
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#request_cookies
type VariableRequestCookies struct {
	AbstractNode
}

func (v *VariableRequestCookies) Name() string {
	return "REQUEST_COOKIES"
}

func (v *VariableRequestCookies) IsCollection() bool {
	return true
}

func (v *VariableRequestCookies) Children() []Node {
	return []Node{}
}

//VariableRequestCookiesNames This variable is a collection of the names of all request cookies
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#request_cookies_names
type VariableRequestCookiesNames struct {
	AbstractNode
}

func (v *VariableRequestCookiesNames) Name() string {
	return "REQUEST_COOKIES_NAMES"
}

func (v *VariableRequestCookiesNames) IsCollection() bool {
	return true
}

func (v *VariableRequestCookiesNames) Children() []Node {
	return []Node{}
}

//VariableRequestFilename This variable holds the relative request URL without the query string part (e.g., /index.php).
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#request_cookies_names
type VariableRequestFilename struct {
	AbstractNode
}

func (v *VariableRequestFilename) Name() string {
	return "REQUEST_FILENAME"
}

func (v *VariableRequestFilename) IsCollection() bool {
	return false
}

func (v *VariableRequestFilename) Children() []Node {
	return []Node{}
}

//VariableRequestHeaders This variable can be used as either a collection of all of the request headers or can be used to inspect selected headers (by using the REQUEST_HEADERS:Header-Name syntax).
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#request_headers
type VariableRequestHeaders struct {
	AbstractNode
}

func (v *VariableRequestHeaders) Name() string {
	return "REQUEST_HEADERS"
}

func (v *VariableRequestHeaders) IsCollection() bool {
	return true
}

func (v *VariableRequestHeaders) Children() []Node {
	return []Node{}
}

//VariableRequestMethod This variable holds the request method used in the transaction.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#REQUEST_METHOD
type VariableRequestMethod struct {
	AbstractNode
}

func (v *VariableRequestMethod) Name() string {
	return "REQUEST_METHOD"
}

func (v *VariableRequestMethod) IsCollection() bool {
	return false
}

func (v *VariableRequestMethod) Children() []Node {
	return []Node{}
}

//VariableTransientTransactionCollection This is the transient transaction collection,
// which is used to store pieces of data, create a transaction anomaly score, and so on.
// The variables placed into this collection are available only until the transaction is complete.
//
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#tx
type VariableTransientTransactionCollection struct {
	AbstractNode
}

func (v *VariableTransientTransactionCollection) Name() string {
	return "TX"
}

func (v *VariableTransientTransactionCollection) IsCollection() bool {
	return true
}

func (v *VariableTransientTransactionCollection) Children() []Node {
	return []Node{}
}

//VariableUniqueID This variable holds the data created by mod_unique_id.
// The UNIQUE_ID environment variable is constructed by encoding the 112-bit (32-bit IP address, 32 bit pid, 32 bit time stamp, 16 bit counter) quadruple using the alphabet [A-Za-z0-9@-] in a manner similar to MIME base64 encoding, producing 19 characters.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#UNIQUE_ID
type VariableUniqueID struct {
	AbstractNode
}

func (v *VariableUniqueID) Name() string {
	return "UNIQUE_ID"
}

func (v *VariableUniqueID) IsCollection() bool {
	return false
}

func (v *VariableUniqueID) Children() []Node {
	return []Node{}
}

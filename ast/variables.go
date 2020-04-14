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

//VariableCustomCollection is used to describe a variable which is not part of the Modsec config specification but is defined by the user.
// Users can create custom collections using the initcol action. If we encounter a unknown variable name, we have to assume it is a custom collection
type VariableCustomCollection struct {
	AbstractNode
	VariableName string
}

func (v *VariableCustomCollection) Name() string {
	return v.VariableName
}

func (v *VariableCustomCollection) IsCollection() bool {
	return true
}

func (v *VariableCustomCollection) Children() []Node {
	return []Node{}
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

//VariableArgsCombinedSize Contains the combined size of all request parameters.
// Files are excluded from the calculation. This variable can be useful, for example,
// to create a rule to ensure that the total size of the argument data is below a certain threshold.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ARGS_COMBINED_SIZE
type VariableArgsCombinedSize struct {
	AbstractNode
}

func (v *VariableArgsCombinedSize) Name() string {
	return "ARGS_COMBINED_SIZE"
}

func (v *VariableArgsCombinedSize) IsCollection() bool {
	return false
}

func (v *VariableArgsCombinedSize) Children() []Node {
	return []Node{}
}

//VariableArgsGet is similar to ARGS, but contains only query string parameters.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ARGS_GET
type VariableArgsGet struct {
	AbstractNode
}

func (v *VariableArgsGet) Name() string {
	return "ARGS_GET"
}

func (v *VariableArgsGet) IsCollection() bool {
	return true
}

func (v *VariableArgsGet) Children() []Node {
	return []Node{}
}

//VariableArgsGetNames is similar to ARGS_NAMES, but contains only the names of query string parameters.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ARGS_GET_NAMES
type VariableArgsGetNames struct {
	AbstractNode
}

func (v *VariableArgsGetNames) Name() string {
	return "ARGS_GET_NAMES"
}

func (v *VariableArgsGetNames) IsCollection() bool {
	return true
}

func (v *VariableArgsGetNames) Children() []Node {
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

//VariableFiles Contains a collection of original file names (as they were called on the remote user’s filesys- tem). Available only on inspected multipart/form-data requests.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#FILES
type VariableFiles struct {
	AbstractNode
}

func (v *VariableFiles) Name() string {
	return "FILES"
}

func (v *VariableFiles) IsCollection() bool {
	return true
}

func (v *VariableFiles) Children() []Node {
	return []Node{}
}

//VariableFilesCombinedSize Contains the total size of the files transported in request body. Available only on inspected multipart/form-data requests.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#FILES_COMBINED_SIZE
type VariableFilesCombinedSize struct {
	AbstractNode
}

func (v *VariableFilesCombinedSize) Name() string {
	return "FILES_COMBINED_SIZE"
}

func (v *VariableFilesCombinedSize) IsCollection() bool {
	return false
}

func (v *VariableFilesCombinedSize) Children() []Node {
	return []Node{}
}

//VariableFilesNames Contains a list of form fields that were used for file upload. Available only on inspected multipart/form-data requests.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#FILES_NAMES
type VariableFilesNames struct {
	AbstractNode
}

func (v *VariableFilesNames) Name() string {
	return "FILES_NAMES"
}

func (v *VariableFilesNames) IsCollection() bool {
	return true
}

func (v *VariableFilesNames) Children() []Node {
	return []Node{}
}

//VariableGEO is a collection populated by the results of the last @geoLookup operator. The collection can be used to match geographical fields looked from an IP address or hostname.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#GEO
type VariableGEO struct {
	AbstractNode
}

func (v *VariableGEO) Name() string {
	return "GEO"
}

func (v *VariableGEO) IsCollection() bool {
	return true
}

func (v *VariableGEO) Children() []Node {
	return []Node{}
}

//VariableMatchedVars Similar to MATCHED_VAR except that it is a collection of all matches for the current operator check.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#MATCHED_VARS
type VariableMatchedVars struct {
	AbstractNode
}

func (v *VariableMatchedVars) Name() string {
	return "MATCHED_VARS"
}

func (v *VariableMatchedVars) IsCollection() bool {
	return true
}

func (v *VariableMatchedVars) Children() []Node {
	return []Node{}
}

//VariableMatchedVarsNames Similar to MATCHED_VAR_NAME except that it is a collection of all matches for the current operator check.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#MATCHED_VARS_NAMES
type VariableMatchedVarsNames struct {
	AbstractNode
}

func (v *VariableMatchedVarsNames) Name() string {
	return "MATCHED_VARS_NAMES"
}

func (v *VariableMatchedVarsNames) IsCollection() bool {
	return true
}

func (v *VariableMatchedVarsNames) Children() []Node {
	return []Node{}
}

//VariableMultipartStructError MULTIPART_STRICT_ERROR will be set to 1 when any of the following variables is also set to 1:
// REQBODY_PROCESSOR_ERROR, MULTIPART_BOUNDARY_QUOTED, MULTIPART_BOUNDARY_WHITESPACE, MULTIPART_DATA_BEFORE,
// MULTIPART_DATA_AFTER, MULTIPART_HEADER_FOLDING, MULTIPART_LF_LINE, MULTIPART_MISSING_SEMICOLON MULTIPART_INVALID_QUOTING MULTIPART_INVALID_HEADER_FOLDING MULTIPART_FILE_LIMIT_EXCEEDED.
// Each of these variables covers one unusual (although sometimes legal) aspect of the request body in multipart/form-data format.
// Your policies should always contain a rule to check either this variable (easier) or one or more individual variables (if you know exactly what you want to accomplish).
// Depending on the rate of false positives and your default policy you should decide whether to block or just warn when the rule is triggered.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#MULTIPART_STRICT_ERROR
type VariableMultipartStructError struct {
	AbstractNode
}

func (v *VariableMultipartStructError) Name() string {
	return "MULTIPART_STRICT_ERROR"
}

func (v *VariableMultipartStructError) IsCollection() bool {
	return false
}

func (v *VariableMultipartStructError) Children() []Node {
	return []Node{}
}

//VariableQueryString Contains the query string part of a request URI. The value in QUERY_STRING is always provided raw, without URL decoding taking place.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#QUERY_STRING
type VariableQueryString struct {
	AbstractNode
}

func (v *VariableQueryString) Name() string {
	return "QUERY_STRING"
}

func (v *VariableQueryString) IsCollection() bool {
	return false
}

func (v *VariableQueryString) Children() []Node {
	return []Node{}
}

//VariableRemoteAddress This variable holds the IP address of the remote client.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#REMOTE_ADDR
type VariableRemoteAddress struct {
	AbstractNode
}

func (v *VariableRemoteAddress) Name() string {
	return "REMOTE_ADDR"
}

func (v *VariableRemoteAddress) IsCollection() bool {
	return false
}

func (v *VariableRemoteAddress) Children() []Node {
	return []Node{}
}

//VariableRequestBodyError Contains the status of the request body processor used for request body parsing. The values can be 0 (no error) or 1 (error).
// This variable will be set by request body processors (typically the multipart/request-data parser, JSON or the XML parser) when they fail to do their work.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#REQBODY_ERROR
type VariableRequestBodyError struct {
	AbstractNode
}

func (v *VariableRequestBodyError) Name() string {
	return "REQBODY_ERROR"
}

func (v *VariableRequestBodyError) IsCollection() bool {
	return false
}

func (v *VariableRequestBodyError) Children() []Node {
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

//VariableRequestBasename This variable holds just the filename part of REQUEST_FILENAME (e.g., index.php).
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#request_body
type VariableRequestBasename struct {
	AbstractNode
}

func (v *VariableRequestBasename) Name() string {
	return "REQUEST_BASENAME"
}

func (v *VariableRequestBasename) IsCollection() bool {
	return false
}

func (v *VariableRequestBasename) Children() []Node {
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

//VariableRequestHeadersNames This variable is a collection of the names of all of the request headers.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#request_headers_names
type VariableRequestHeadersNames struct {
	AbstractNode
}

func (v *VariableRequestHeadersNames) Name() string {
	return "REQUEST_HEADERS_NAMES"
}

func (v *VariableRequestHeadersNames) IsCollection() bool {
	return true
}

func (v *VariableRequestHeadersNames) Children() []Node {
	return []Node{}
}

//VariableRequestLine This variable holds the complete request line sent to the server (including the request method and HTTP version information).
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#REQUEST_LINE
type VariableRequestLine struct {
	AbstractNode
}

func (v *VariableRequestLine) Name() string {
	return "REQUEST_LINE"
}

func (v *VariableRequestLine) IsCollection() bool {
	return false
}

func (v *VariableRequestLine) Children() []Node {
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

//VariableRequestProtocol This variable holds the request protocol version information.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#REQUEST_PROTOCOL
type VariableRequestProtocol struct {
	AbstractNode
}

func (v *VariableRequestProtocol) Name() string {
	return "REQUEST_PROTOCOL"
}

func (v *VariableRequestProtocol) IsCollection() bool {
	return false
}

func (v *VariableRequestProtocol) Children() []Node {
	return []Node{}
}

//VariableRequestURI This variable holds the full request URL including the query string data (e.g., /index.php? p=X).
// However, it will never contain a domain name, even if it was provided on the request line.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#REQUEST_URI
type VariableRequestURI struct {
	AbstractNode
}

func (v *VariableRequestURI) Name() string {
	return "REQUEST_URI"
}

func (v *VariableRequestURI) IsCollection() bool {
	return false
}

func (v *VariableRequestURI) Children() []Node {
	return []Node{}
}

//VariableRequestURIRaw Same as REQUEST_URI but will contain the domain name if it was provided on the request line (e.g., http://www.example.com/index.php?p=X).
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#REQUEST_URI_RAW
type VariableRequestURIRaw struct {
	AbstractNode
}

func (v *VariableRequestURIRaw) Name() string {
	return "REQUEST_URI_RAW"
}

func (v *VariableRequestURIRaw) IsCollection() bool {
	return false
}

func (v *VariableRequestURIRaw) Children() []Node {
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

//VariableXML Special collection used to interact with the XML parser.
// It can be used standalone as a target for the validateDTD and validateSchema operator.
// Otherwise, it must contain a valid XPath expression, which will then be evaluated against a previously parsed XML DOM tree.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#UNIQUE_ID
type VariableXML struct {
	AbstractNode
}

func (v *VariableXML) Name() string {
	return "XML"
}

func (v *VariableXML) IsCollection() bool {
	return true
}

func (v *VariableXML) Children() []Node {
	return []Node{}
}

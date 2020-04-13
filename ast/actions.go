package ast

//Action is a action like used in the SecAction directive
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#Actions
type Action interface {
	Node
	ActionType() ActionType
}

//An ActionType indicates what the purpose of an action is
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#Actions
type ActionType string

const (
	//ACTION_TYPE_DISRUPTIVE Cause ModSecurity to do something. In many cases something means block transaction, but not in all.
	ACTION_TYPE_DISRUPTIVE = "disruptive"

	//ACTION_TYPE_NON_DISRUPTIVE Do something, but that something does not and cannot affect the rule processing flow.
	ACTION_TYPE_NON_DISRUPTIVE = "non-disruptive"

	//ACTION_TYPE_FLOW These actions affect the rule flow
	ACTION_TYPE_FLOW = "flow"

	//ACTION_TYPE_META_DATA Meta-data actions are used to provide more information about rules.
	ACTION_TYPE_META_DATA = "meta-data"

	//ACTION_TYPE_DATA Not really actions, these are mere containers that hold data used by other actions.
	ACTION_TYPE_DATA = "data"
)

//ActionAccuracy Specifies the relative accuracy level of the rule related to false positives/negatives.
//The value is a string based on a numeric scale (1-9 where 9 is very strong and 1 has many false positives).
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#accuracy
type ActionAccuracy struct {
	AbstractNode
	Value int
}

func (action *ActionAccuracy) Name() string {
	return "accuracy"
}

func (action *ActionAccuracy) ActionType() ActionType {
	return ACTION_TYPE_META_DATA
}

func (action *ActionAccuracy) Children() []Node {
	return []Node{}
}

//ActionAllow Stops rule processing on a successful match and allows the transaction to proceed.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#allow
type ActionAllow struct {
	AbstractNode
}

func (action *ActionAllow) Name() string {
	return "allow"
}

func (action *ActionAllow) ActionType() ActionType {
	return ACTION_TYPE_DISRUPTIVE
}

func (action *ActionAllow) Children() []Node {
	return []Node{}
}

//Appends text given as parameter to the end of response body.
// Content injection must be en- abled (using the SecContentInjection directive).
// No content type checks are made, which means that before using any of the content injection actions,
// you must check whether the content type of the response is adequate for injection.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#append
type ActionAppend struct {
	AbstractNode
	Value *ExpandableString
}

func (action *ActionAppend) Name() string {
	return "append"
}

func (action *ActionAppend) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionAppend) Children() []Node {
	return []Node{action.Value}
}

//ActionAuditLog Marks the transaction for logging in the audit log.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#auditlog
type ActionAuditLog struct {
	AbstractNode
}

func (action *ActionAuditLog) Name() string {
	return "auditlog"
}

func (action *ActionAuditLog) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionAuditLog) Children() []Node {
	return []Node{}
}

//ActionBlock Performs the disruptive action defined by the previous SecDefaultAction.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#block
type ActionBlock struct {
	AbstractNode
}

func (action *ActionBlock) Name() string {
	return "block"
}

func (action *ActionBlock) ActionType() ActionType {
	return ACTION_TYPE_DISRUPTIVE
}

func (action *ActionBlock) Children() []Node {
	return []Node{}
}

//ActionCapture When used together with the regular expression operator (@rx), the capture action will create copies of the regular expression captures and place them into the transaction variable collection.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#capture
type ActionCapture struct {
	AbstractNode
}

func (action *ActionCapture) Name() string {
	return "capture"
}

func (action *ActionCapture) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionCapture) Children() []Node {
	return []Node{}
}

//ActionChain Chains the current rule with the rule that immediately follows it, creating a rule chain. Chained rules allow for more complex processing logic.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#chain
type ActionChain struct {
	AbstractNode
}

func (action *ActionChain) Name() string {
	return "chain"
}

func (action *ActionChain) ActionType() ActionType {
	return ACTION_TYPE_FLOW
}

func (action *ActionChain) Children() []Node {
	return []Node{}
}

//ActionCTL Changes ModSecurity configuration on transient, per-transaction basis.
// Any changes made using this action will affect only the transaction in which the action is executed.
// The default configuration, as well as the other transactions running in parallel, will be unaffected.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ctl
type ActionCTL struct {
	AbstractNode

	// Option is of type directive, this allows us to resuse the directive parsing. This is valid, as stated by the Reference manual:
	// "With the exception of the requestBodyProcessor and forceRequestBodyVariable settings, each configuration option corresponds to one configuration directive and the usage is identical."
	// For requestBodyProcessor and forceRequestBodyVariable special structs are created which implement the Directive interface but are never parsed as directives
	Option Directive
}

func (action *ActionCTL) Name() string {
	return "ctl"
}

func (action *ActionCTL) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionCTL) Children() []Node {
	return []Node{action.Option}
}

type ActionCTLAuditLogPartsOP int

const (
	ActionCTLAuditLogPartsOPSet ActionCTLAuditLogPartsOP = iota
	ActionCTLAuditLogPartsOPAdd
	ActionCTLAuditLogPartsOPSubtract
)

func (alpo ActionCTLAuditLogPartsOP) Valid() bool {
	return alpo == ActionCTLAuditLogPartsOPSet || alpo == ActionCTLAuditLogPartsOPAdd || alpo == ActionCTLAuditLogPartsOPSubtract
}

func (alpo ActionCTLAuditLogPartsOP) String() string {
	switch alpo {
	case ActionCTLAuditLogPartsOPSet:
		return "="
	case ActionCTLAuditLogPartsOPAdd:
		return "+"
	case ActionCTLAuditLogPartsOPSubtract:
		return "-"
	}

	return "INVALID"
}

//ActionCTLAuditLogParts is a special purpose "Directive" which should only be used as Option value for ActionCTL
// it adds or removes parts from the audit log at runtime
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ctl
type ActionCTLAuditLogParts struct {
	AbstractNode
	Value []SecAuditLogPart
	Op    ActionCTLAuditLogPartsOP
}

func (frbv *ActionCTLAuditLogParts) Name() string {
	return "auditLogParts"
}

//Directive is a marker to associate the struct with the Directive interface
func (frbv *ActionCTLAuditLogParts) Directive() {}

func (frbv *ActionCTLAuditLogParts) Children() []Node {
	return []Node{}
}

//ActionCTLForceRequestBodyVariable is a special purpose "Directive" which should only be used as Option value for ActionCTL
// The forceRequestBodyVariable option allows you to configure the REQUEST_BODY variable to be set when there is no request body processor configured. This allows for inspection of request bodies of unknown types.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ctl
type ActionCTLForceRequestBodyVariable struct {
	AbstractNode

	Enabled bool
}

func (frbv *ActionCTLForceRequestBodyVariable) Name() string {
	return "forceRequestBodyVariable"
}

//Directive is a marker to associate the struct with the Directive interface
func (frbv *ActionCTLForceRequestBodyVariable) Directive() {}

func (frbv *ActionCTLForceRequestBodyVariable) Children() []Node {
	return []Node{}
}

type RequestBodyProcessorType string

const (
	RequestBodyProcessorTypeURLEncoded RequestBodyProcessorType = "URLENCODED"
	RequestBodyProcessorTypeMultipart  RequestBodyProcessorType = "MULTIPART"
	RequestBodyProcessorTypeJSON       RequestBodyProcessorType = "JSON"
	RequestBodyProcessorTypeXML        RequestBodyProcessorType = "XML"
)

func (rbpt RequestBodyProcessorType) Valid() bool {
	return rbpt == RequestBodyProcessorTypeURLEncoded ||
		rbpt == RequestBodyProcessorTypeMultipart ||
		rbpt == RequestBodyProcessorTypeJSON ||
		rbpt == RequestBodyProcessorTypeXML
}

//ActionCTLRequestBodyProcessor is a special purpose "Directive" which should only be used as Option value for ActionCTL
// The requestBodyProcessor option allows you to configure the request body processor.
// By default, ModSecurity will use the URLENCODED and MULTIPART processors to process an application/x-www-form-urlencoded and a multipart/form-data body, respectively.
// Other two processors are also supported: JSON and XML, but they are never used implicitly.
// Instead, you must tell ModSecurity to use it by placing a few rules in the REQUEST_HEADERS processing phase.
// After the request body is processed as XML, you will be able to use the XML-related features to inspect it.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ctl
type ActionCTLRequestBodyProcessor struct {
	AbstractNode

	Processor RequestBodyProcessorType
}

func (frbv *ActionCTLRequestBodyProcessor) Name() string {
	return "requestBodyProcessor"
}

//Directive is a marker to associate the struct with the Directive interface
func (frbv *ActionCTLRequestBodyProcessor) Directive() {}

func (frbv *ActionCTLRequestBodyProcessor) Children() []Node {
	return []Node{}
}

//ActionCTLRuleRemoveByID Removes a rule  at runtime.
//It is similar to SecRuleRemoveById with the limitation that this ctl option only removes one rule or one range
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#SecRuleRemoveById
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ctl
type ActionCTLRuleRemoveByID struct {
	AbstractNode

	StartID int
	EndID   int
}

func (frbv *ActionCTLRuleRemoveByID) Name() string {
	return "ruleRemoveByID"
}

//Directive is a marker to associate the struct with the Directive interface
func (frbv *ActionCTLRuleRemoveByID) Directive() {}

func (frbv *ActionCTLRuleRemoveByID) Children() []Node {
	return []Node{}
}

//ActionCTLRuleRemoveByTag Removes all rules at runtime for which a tag in that rule matches the regex.
//It is similar to SecRuleRemoveByTag but works at runtime
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#SecRuleRemoveByTag
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ctl
type ActionCTLRuleRemoveByTag struct {
	AbstractNode

	Regex string
}

func (frbv *ActionCTLRuleRemoveByTag) Name() string {
	return "ruleRemoveByTag"
}

//Directive is a marker to associate the struct with the Directive interface
func (frbv *ActionCTLRuleRemoveByTag) Directive() {}

func (frbv *ActionCTLRuleRemoveByTag) Children() []Node {
	return []Node{}
}

//ActionCTLRuleRemoveTargetById Removes variables from a variable list of a rule at runtime.
//It is similar to SecRuleUpdateTargetByID with the limitation that this ctl option can only remove targets and only does it for 1 target not multiple
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#SecRuleUpdateTargetById
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ctl
type ActionCTLRuleRemoveTargetById struct {
	AbstractNode

	StartID            int
	EndID              int
	Variable           Variable
	CollectionSelector VariableCollectionSelection
}

func (frbv *ActionCTLRuleRemoveTargetById) Name() string {
	return "ruleRemoveTargetById"
}

//Directive is a marker to associate the struct with the Directive interface
func (frbv *ActionCTLRuleRemoveTargetById) Directive() {}

func (frbv *ActionCTLRuleRemoveTargetById) Children() []Node {
	return []Node{frbv.Variable, frbv.CollectionSelector}
}

//ActionCTLRuleRemoveTargetByTag Removes variables from a variable list of a rules wit the given tag at runtime.
//It is similar to SecRuleUpdateTargetByTag with the limitation that this ctl option can only remove targets and only does it for 1 target not multiple
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#SecRuleRemoveTargetByTag
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ctl
type ActionCTLRuleRemoveTargetByTag struct {
	AbstractNode

	Tag                string
	Variable           Variable
	CollectionSelector VariableCollectionSelection
}

func (frbv *ActionCTLRuleRemoveTargetByTag) Name() string {
	return "ruleRemoveTargetByTag"
}

//Directive is a marker to associate the struct with the Directive interface
func (frbv *ActionCTLRuleRemoveTargetByTag) Directive() {}

func (frbv *ActionCTLRuleRemoveTargetByTag) Children() []Node {
	return []Node{frbv.Variable, frbv.CollectionSelector}
}

//ActionDeny Stops rule processing and intercepts transaction.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#deny
type ActionDeny struct {
	AbstractNode
}

func (action *ActionDeny) Name() string {
	return "deny"
}

func (action *ActionDeny) ActionType() ActionType {
	return ACTION_TYPE_DISRUPTIVE
}

func (action *ActionDeny) Children() []Node {
	return []Node{}
}

//ActionDrop Stops rule processing and intercepts transaction.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#drop
type ActionDrop struct {
	AbstractNode
}

func (action *ActionDrop) Name() string {
	return "drop"
}

func (action *ActionDrop) ActionType() ActionType {
	return ACTION_TYPE_DISRUPTIVE
}

func (action *ActionDrop) Children() []Node {
	return []Node{}
}

//ActionExpireVar Configures a collection variable to expire after the given time period (in seconds).
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#expirevar
type ActionExpireVar struct {
	AbstractNode

	//The variable collection, optional
	Collection *ExpandableString

	//The name of the variable being modified, required
	Variable *ExpandableString

	//The amount of seconds after which the variable wil expire
	TTL *ExpandableString
}

func (action *ActionExpireVar) Name() string {
	return "expirevar"
}

func (action *ActionExpireVar) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionExpireVar) Children() []Node {
	return []Node{action.Collection, action.Variable}
}

//ActionID  Assigns a unique ID to the rule or chain in which it appears.
// Starting with ModSecurity 2.7 this action is mandatory and must be numeric.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#id
type ActionID struct {
	AbstractNode
	Value int
}

func (action *ActionID) Name() string {
	return "id"
}

func (action *ActionID) ActionType() ActionType {
	return ACTION_TYPE_META_DATA
}

func (action *ActionID) Children() []Node {
	return []Node{}
}

//ActionInitcol Initializes a named persistent collection, either by loading data from storage or by creating a new collection in memory.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#initcol
type ActionInitcol struct {
	AbstractNode

	//The variable collection, optional
	Collection *ExpandableString

	//The value to which the collection will be initalized
	Modifier *ExpandableString
}

func (action *ActionInitcol) Name() string {
	return "initcol"
}

func (action *ActionInitcol) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionInitcol) Children() []Node {
	return []Node{action.Collection, action.Modifier}
}

//ActionLog Indicates that a successful match of the rule needs to be logged.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#log
type ActionLog struct {
	AbstractNode
}

func (action *ActionLog) Name() string {
	return "log"
}

func (action *ActionLog) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionLog) Children() []Node {
	return []Node{}
}

//ActionLogData Logs a data fragment as part of the alert message.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#logdata
type ActionLogData struct {
	AbstractNode
	Value *ExpandableString
}

func (action *ActionLogData) Name() string {
	return "logdata"
}

func (action *ActionLogData) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionLogData) Children() []Node {
	return []Node{action.Value}
}

//ActionMessage Assigns a custom message to the rule or chain in which it appears. The message will be logged along with every alert.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#msg
type ActionMessage struct {
	AbstractNode
	Value *ExpandableString
}

func (action *ActionMessage) Name() string {
	return "msg"
}

func (action *ActionMessage) ActionType() ActionType {
	return ACTION_TYPE_META_DATA
}

func (action *ActionMessage) Children() []Node {
	return []Node{action.Value}
}

//ActionNoAuditLog Indicates that a successful match of the rule should not be used as criteria to determine whether the transaction should be logged to the audit log.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#noauditlog
type ActionNoAuditLog struct {
	AbstractNode
}

func (action *ActionNoAuditLog) Name() string {
	return "noauditlog"
}

func (action *ActionNoAuditLog) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionNoAuditLog) Children() []Node {
	return []Node{}
}

//ActionNoLog Prevents rule matches from appearing in both the error and audit logs.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#nolog
type ActionNoLog struct {
	AbstractNode
}

func (action *ActionNoLog) Name() string {
	return "nolog"
}

func (action *ActionNoLog) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionNoLog) Children() []Node {
	return []Node{}
}

//ActionPass Continues processing with the next rule in spite of a successful match.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#pass
type ActionPass struct {
	AbstractNode
}

func (action *ActionPass) Name() string {
	return "pass"
}

func (action *ActionPass) ActionType() ActionType {
	return ACTION_TYPE_DISRUPTIVE
}

func (action *ActionPass) Children() []Node {
	return []Node{}
}

//ActionPhase Places the rule or chain into one of five available processing phases.
// It can also be used in SecDefaultAction to establish the rule defaults.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#phase
type ActionPhase struct {
	AbstractNode
	Value int
}

func (action *ActionPhase) Name() string {
	return "phase"
}

func (action *ActionPhase) ActionType() ActionType {
	return ACTION_TYPE_META_DATA
}

func (action *ActionPhase) Children() []Node {
	return []Node{}
}

//ActionSeverity Assigns severity to the rule in which it is used.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#severity
type ActionSeverity struct {
	AbstractNode
	Value int
}

func (action *ActionSeverity) Name() string {
	return "severity"
}

func (action *ActionSeverity) ActionType() ActionType {
	return ACTION_TYPE_META_DATA
}

func (action *ActionSeverity) Children() []Node {
	return []Node{}
}

type SetVarOp int

const (
	SET_VAR_DELETE SetVarOp = iota + 1
	SET_VAR_ADD
	SET_VAR_SUB
	SET_VAR_SET
)

func (op SetVarOp) String() string {
	switch op {
	case SET_VAR_DELETE:
		return "delete"
	case SET_VAR_ADD:
		return "add"
	case SET_VAR_SUB:
		return "sub"
	case SET_VAR_SET:
		return "set"
	default:
		return "UNKNOWN"
	}
}

//ActionSetVar Creates, removes, or updates a variable. Variable names are case-insensitive.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#setvar
type ActionSetVar struct {
	AbstractNode

	//The operation which is being performed
	Op SetVarOp

	//The variable collection, optional
	Collection *ExpandableString

	//The name of the variable being modified, required
	Variable *ExpandableString

	//The value by which the variable is being modified
	//required if op != delete
	Modifier *ExpandableString
}

func (action *ActionSetVar) Name() string {
	return "setvar"
}

func (action *ActionSetVar) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionSetVar) Children() []Node {
	return []Node{action.Collection, action.Variable, action.Modifier}
}

//TODO make Value of ActionSkipAfter a normal string, since it doesn't support macro expansion

//ActionSkipAfter Skips one or more rules (or chains) on a successful match, resuming rule execution with the first rule that follows the rule (or marker created by SecMarker) with the provided ID.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#skipAfter
type ActionSkipAfter struct {
	AbstractNode
	Value *ExpandableString
}

func (action *ActionSkipAfter) Name() string {
	return "skipafter"
}

func (action *ActionSkipAfter) ActionType() ActionType {
	return ACTION_TYPE_FLOW
}

func (action *ActionSkipAfter) Children() []Node {
	return []Node{action.Value}
}

//ActionStatus Specifies the response status code to use with actions deny and redirect.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#status
type ActionStatus struct {
	AbstractNode
	Value int
}

func (action *ActionStatus) Name() string {
	return "status"
}

func (action *ActionStatus) ActionType() ActionType {
	return ACTION_TYPE_DATA
}

func (action *ActionStatus) Children() []Node {
	return []Node{}
}

//ActionPhase This action is used to specify the transformation pipeline to use to transform the value of each variable used in the rule before matching.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#t
type ActionTransform struct {
	AbstractNode
	Value TransformType
}

func (action *ActionTransform) Name() string {
	return "t"
}

func (action *ActionTransform) ActionType() ActionType {
	return ACTION_TYPE_NON_DISRUPTIVE
}

func (action *ActionTransform) Children() []Node {
	return []Node{action.Value}
}

//ActionTag Assigns a tag (category) to a rule or a chain.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#tag
type ActionTag struct {
	AbstractNode
	Value *ExpandableString
}

func (action *ActionTag) Name() string {
	return "tag"
}

func (action *ActionTag) ActionType() ActionType {
	return ACTION_TYPE_META_DATA
}

func (action *ActionTag) Children() []Node {
	return []Node{action.Value}
}

//ActionVer Specifies the rule set version.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#ver
type ActionVer struct {
	AbstractNode
	Value *ExpandableString
}

func (action *ActionVer) Name() string {
	return "ver"
}

func (action *ActionVer) ActionType() ActionType {
	return ACTION_TYPE_META_DATA
}

func (action *ActionVer) Children() []Node {
	return []Node{action.Value}
}

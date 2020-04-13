package ast

type Directive interface {
	Node
	Directive()
}

//DirectiveSecAction Unconditionally processes the action list it receives as the first and only parameter.
// The syntax of the parameter is identical to that of the third parameter of SecRule.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secaction
type DirectiveSecAction struct {
	AbstractNode
	ActionNodes []Action
}

func (dir *DirectiveSecAction) Name() string {
	return "SecAction"
}

//Directive is a marker to associate the struct with the Directive interface
func (dir *DirectiveSecAction) Directive() {}

//Children returns all child nodes, this satisfies the Node interface
func (dir *DirectiveSecAction) Children() []Node {
	nodes := make([]Node, len(dir.ActionNodes))
	for i, action := range dir.ActionNodes {
		nodes[i] = Node(action)
	}
	return nodes
}

//Actions returns all actions of the directive
func (dir *DirectiveSecAction) Actions() []Action {
	return dir.ActionNodes
}

func (dir *DirectiveSecAction) AddAction(action Action) {
	dir.ActionNodes = append(dir.ActionNodes, action)
}

//SecAuditEngineValue is the value of the DirectiveSecAuditEngine directive
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecAuditEngine
type SecAuditEngineValue string

func (sev SecAuditEngineValue) Valid() bool {
	return sev == ModsecOn ||
		sev == ModsecOff ||
		sev == ModsecRelevantOnly
}

//DirectiveSecAuditEngine Configures the audit logging engine.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecAuditEngine
type DirectiveSecAuditEngine struct {
	AbstractNode
	Value SecAuditEngineValue
}

func (dir *DirectiveSecAuditEngine) Name() string {
	return "SecAuditEngine"
}

//Directive is a marker to associate the struct with the Directive interface
func (dir *DirectiveSecAuditEngine) Directive() {}

//Children returns all child nodes, this satisfies the Node interface
func (dir *DirectiveSecAuditEngine) Children() []Node {
	return []Node{}
}

//SecAuditLogPart describes a single part of the audit log format
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#SecAuditLogParts
type SecAuditLogPart rune

const (
	//SecAuditLogPartA represents: Audit log header (mandatory).
	SecAuditLogPartA SecAuditLogPart = 'A'

	//SecAuditLogPartB represents: Request headers.
	SecAuditLogPartB SecAuditLogPart = 'B'

	//SecAuditLogPartC represents: Request body (present only if the request body exists and ModSecurity is configured to intercept it. This would require SecRequestBodyAccess to be set to on).
	SecAuditLogPartC SecAuditLogPart = 'C'

	//SecAuditLogPartD represents: Reserved for intermediary response headers; not implemented yet.
	SecAuditLogPartD SecAuditLogPart = 'D'

	//SecAuditLogPartE represents: Intermediary response body (present only if ModSecurity is configured to intercept response bodies,
	// and if the audit log engine is configured to record it. Intercepting response bodies requires SecResponseBodyAccess to be enabled).
	// Intermediary response body is the same as the actual response body unless ModSecurity intercepts the intermediary response body,
	// in which case the actual response body will contain the error message (either the Apache default error message, or the ErrorDocument page).
	SecAuditLogPartE SecAuditLogPart = 'E'

	//SecAuditLogPartF represents: Final response headers (excluding the Date and Server headers, which are always added by Apache in the late stage of content delivery).
	SecAuditLogPartF SecAuditLogPart = 'F'

	//SecAuditLogPartG represents: Reserved for the actual response body; not implemented yet.
	SecAuditLogPartG SecAuditLogPart = 'G'

	//SecAuditLogPartH represents: Audit log trailer.
	SecAuditLogPartH SecAuditLogPart = 'H'

	//SecAuditLogPartI represents: his part is a replacement for part C. It will log the same data as C in all cases except when multipart/form-data encoding in used.
	// In this case, it will log a fake application/x-www-form-urlencoded body that contains the information about parameters but not about the files.
	// This is handy if you don’t want to have (often large) files stored in your audit logs.
	SecAuditLogPartI SecAuditLogPart = 'I'

	//SecAuditLogPartJ represents: This part contains information about the files uploaded using multipart/form-data encoding.
	SecAuditLogPartJ SecAuditLogPart = 'J'

	//SecAuditLogPartK represents: This part contains a full list of every rule that matched (one per line) in the order they were matched. The rules are fully qualified and will thus show inherited actions and default operators. Supported as of v2.5.0.
	SecAuditLogPartK SecAuditLogPart = 'K'

	//SecAuditLogPartZ represents: Final boundary, signifies the end of the entry (mandatory).
	SecAuditLogPartZ SecAuditLogPart = 'Z'
)

func (alp SecAuditLogPart) Valid() bool {
	if alp >= SecAuditLogPartA && alp <= SecAuditLogPartK || alp == SecAuditLogPartZ {
		return true
	}

	return false
}

func (alp SecAuditLogPart) String() string {
	return string([]rune{rune(alp)})
}

//DirectiveSecAuditLogParts Defines which parts of each transaction are going to be recorded in the audit log.
// Each part is assigned a single letter; when a letter appears in the list then the equivalent part will be recorded.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#SecAuditLogParts
type DirectiveSecAuditLogParts struct {
	AbstractNode
	Value []SecAuditLogPart
}

func (dir *DirectiveSecAuditLogParts) Name() string {
	return "SecAuditLogParts"
}

//Directive is a marker to associate the struct with the Directive interface
func (dir *DirectiveSecAuditLogParts) Directive() {}

//Children returns all child nodes, this satisfies the Node interface
func (dir *DirectiveSecAuditLogParts) Children() []Node {
	return []Node{}
}

//DirectiveSecComponentSignature Appends component signature to the ModSecurity signature.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#seccomponentsignature
type DirectiveSecComponentSignature struct {
	AbstractNode
	Signature string
}

func (dir *DirectiveSecComponentSignature) Name() string {
	return "SecComponentSignature"
}

//Directive is a marker to associate the struct with the Directive interface
func (dir *DirectiveSecComponentSignature) Directive() {}

//Children returns all child nodes, this satisfies the Node interface
func (dir *DirectiveSecComponentSignature) Children() []Node {
	return []Node{}
}

//DirectiveSecMarker Adds a fixed rule marker that can be used as a target in a skipAfter action. A SecMarker directive essentially creates a rule that does nothing and whose only purpose is to carry the given ID.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#secmarker
type DirectiveSecMarker struct {
	AbstractNode
	Value string
}

func (dir *DirectiveSecMarker) Name() string {
	return "SecMarker"
}

//Directive is a marker to associate the struct with the Directive interface
func (dir *DirectiveSecMarker) Directive() {}

//Children returns all child nodes, this satisfies the Node interface
func (dir *DirectiveSecMarker) Children() []Node {
	return []Node{}
}

//SecRequestBodyAccessValue is the value of the SecRequestBodyAccess directive
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecRequestBodyAccess
type SecRequestBodyAccessValue string

const (
	SecRequestBodyAccessOn  SecRequestBodyAccessValue = "On"
	SecRequestBodyAccessOff SecRequestBodyAccessValue = "Off"
)

func (sev SecRequestBodyAccessValue) Valid() bool {
	return sev == SecRequestBodyAccessOn ||
		sev == SecRequestBodyAccessOff
}

//DirectiveSecRequestBodyAccessConfigures whether request bodies will be buffered and processed by ModSecurity.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecRequestBodyAccess
type DirectiveSecRequestBodyAccess struct {
	AbstractNode
	Value SecRequestBodyAccessValue
}

func (dir *DirectiveSecRequestBodyAccess) Name() string {
	return "SecRequestBodyAccess"
}

//Directive is a marker to associate the struct with the Directive interface
func (dir *DirectiveSecRequestBodyAccess) Directive() {}

//Children returns all child nodes, this satisfies the Node interface
func (dir *DirectiveSecRequestBodyAccess) Children() []Node {
	return []Node{}
}

//DirectiveSecRule Creates a rule that will analyze the selected variables using the selected operator.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#secrule
type DirectiveSecRule struct {
	AbstractNode
	Variable    *VariableList
	Operator    Operator
	ActionNodes []Action
}

func (dir *DirectiveSecRule) Name() string {
	return "SecRule"
}

//Directive is a marker to associate the struct with the Directive interface
func (dir *DirectiveSecRule) Directive() {}

//Children returns all child nodes, this satisfies the Node interface
func (dir *DirectiveSecRule) Children() []Node {
	nodes := make([]Node, len(dir.ActionNodes))
	for i, action := range dir.ActionNodes {
		nodes[i] = Node(action)
	}
	return nodes
}

//Actions returns all actions of the directive
func (dir *DirectiveSecRule) Actions() []Action {
	return dir.ActionNodes
}

func (dir *DirectiveSecRule) AddAction(action Action) {
	action.SetParent(dir)
	dir.ActionNodes = append(dir.ActionNodes, action)
}

//SecRuleEngineValue is the value of the SecRuleEngine directive
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#secruleengine
type SecRuleEngineValue string

func (sev SecRuleEngineValue) Valid() bool {
	return sev == ModsecOn ||
		sev == ModsecOff ||
		sev == ModsecDetectionOnly
}

//DirectiveSecRuleEngine Configures the rules engine.
// https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#secruleengine
type DirectiveSecRuleEngine struct {
	AbstractNode
	Value SecRuleEngineValue
}

func (dir *DirectiveSecRuleEngine) Name() string {
	return "SecRuleEngine"
}

//Directive is a marker to associate the struct with the Directive interface
func (dir *DirectiveSecRuleEngine) Directive() {}

//Children returns all child nodes, this satisfies the Node interface
func (dir *DirectiveSecRuleEngine) Children() []Node {
	return []Node{}
}

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

const (
	SecRuleEngineOn            SecRuleEngineValue = "On"
	SecRuleEngineOff           SecRuleEngineValue = "Off"
	SecRuleEngineDetectionOnly SecRuleEngineValue = "DetectionOnly"
)

func (sev SecRuleEngineValue) Valid() bool {
	return sev == SecRuleEngineOn ||
		sev == SecRuleEngineOff ||
		sev == SecRuleEngineDetectionOnly
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

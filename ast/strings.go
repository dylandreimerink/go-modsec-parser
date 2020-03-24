package ast

//A ExpandableString expandable string is a string which may contain normal string parts and macros
type ExpandableString struct {
	AbstractNode
	Parts []ExpandableStringPart
}

func (str *ExpandableString) Name() string {
	return "expandable-string"
}

func (str *ExpandableString) Children() []Node {
	nodes := make([]Node, len(str.Parts))
	for i, node := range str.Parts {
		nodes[i] = Node(node)
	}
	return nodes
}

type ExpandableStringPart interface {
	Node
	ExpandableStringPart()
}

//A StringMacro defines a macro inside a string. Macros allow for using place holders in rules that will be expanded out to their values at runtime.
//Format can be %{VARIABLE} or %{COLLECTION.VARIABLE}
type StringMacro struct {
	AbstractNode

	//The collection from where a variable is selected, optional
	Collection string

	//The variable name, required
	Variable string
}

func (str *StringMacro) Name() string {
	return "string-macro"
}

func (str *StringMacro) Children() []Node {
	return []Node{}
}

func (str *StringMacro) ExpandableStringPart() {}

//A StringPart is a part of a string which has no macro expansion
type StringPart struct {
	AbstractNode

	Value string
}

func (str *StringPart) ExpandableStringPart() {}

func (str *StringPart) Name() string {
	return "string-part"
}

func (str *StringPart) Children() []Node {
	return []Node{}
}

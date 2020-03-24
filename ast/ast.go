package ast

//AbstractNode is generic struct which has functionality which is common for all AST nodes
type AbstractNode struct {
	//The parent node to which it is attached
	ParentNode Node
}

func (n *AbstractNode) Parent() Node {
	return n.ParentNode
}

func (n *AbstractNode) SetParent(node Node) {
	n.ParentNode = node
}

type Node interface {
	Name() string
	Parent() Node
	SetParent(Node)
	Children() []Node
}

package ast

//Root AST object, it describes a complete config file/document
type Document struct {
	AbstractNode
	ChildNodes []Node
}

func (doc *Document) Name() string {
	return "document"
}

//Children returns all child nodes, this satisfies the Node interface
func (doc *Document) Children() []Node {
	return doc.ChildNodes
}

func (doc *Document) AddChild(node Node) {
	doc.ChildNodes = append(doc.ChildNodes, node)
}

//Directives only returns the directives in the document and not the comments
func (doc *Document) Directives() []Directive {
	directives := []Directive{}
	for _, node := range doc.ChildNodes {
		if dir, ok := node.(Directive); ok {
			directives = append(directives, dir)
		}
	}
	return directives
}

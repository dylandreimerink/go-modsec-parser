package ast

type Comment struct {
	AbstractNode
	Value string
}

func (c *Comment) Name() string {
	return "comment"
}

func (c *Comment) Children() []Node {
	return []Node{}
}

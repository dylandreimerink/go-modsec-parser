package ast

import "github.com/alecthomas/participle/lexer"

type SecRule struct {
	Pos lexer.Position

	VariableSelector *SecRuleVariableSelector `(Whitespace | Space)* "SecRule" Space @@`
	Operator         *SecRuleOperator         ` (Whitespace | Space)+ DoubleQuote @@ DoubleQuote`
	Action           *SecRuleActionList       ` ((Whitespace | Space)+ DoubleQuote @@ DoubleQuote)?`
}

type SecRuleVariableSelector struct {
	Pos lexer.Position

	Selectors []*SecRuleVariable `(@@)+`
}

type SecAction struct {
	Pos lexer.Position

	Actions *SecRuleActionList `"SecAction" (Whitespace | Space)+ DoubleQuote @@ DoubleQuote`
}

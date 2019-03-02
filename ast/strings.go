package ast

import "github.com/alecthomas/participle/lexer"

type String struct {
	Pos lexer.Position

	Unquoted     *UnquotedString     `( @@`
	DoubleQuoted *DoubleQuotedString `| @@`
	SingleQuoted *SingleQuotedString ` | @@)`
}

type UnquotedString struct {
	Pos lexer.Position

	Parts []*MacroExpandedStringPart `(@@)+`
}

type SingleQuotedString struct {
	Pos lexer.Position

	String *MacroExpandedSingleQuotedString `SingleQuote @@ SingleQuote`
}

type DoubleQuotedString struct {
	Pos lexer.Position

	String *MacroExpandedDoubleQuotedString `DoubleQuote @@ DoubleQuote`
}

type SingleQuotedStringValue struct {
	Pos lexer.Position

	Value string `@(Ident | Space | Exclamation | Punct | Number | Dot | Comma | Colon | ForwardSlash | Pipe | NumberSign | MacroExpansionStop | Amp | SemiColon | Equals | At | EscapedBackslash | EscapedForwardSlash | EscapedDoubleQuote | Increment | Other)+`
}

type DoubleQuotedStringValue struct {
	Pos lexer.Position

	Value string `@(Ident | Space | Exclamation | Punct | Number | Dot | Comma | Colon | ForwardSlash | Pipe | NumberSign | MacroExpansionStop | Amp | SemiColon | Equals | At | EscapedBackslash | EscapedForwardSlash | EscapedDoubleQuote | Increment | Other | SingleQuote | EscapedDoubleQuote)+`
}

type StringValue struct {
	Pos lexer.Position

	Value string `@(Ident | Number )+`
}

type MacroExpandedSingleQuotedString struct {
	Parts []*MacroExpandedSingleQuotedStringPart `(@@)+`
}

type MacroExpandedDoubleQuotedString struct {
	Parts []*MacroExpandedDoubleQuotedStringPart `(@@)+`
}

type MacroExpandedSingleQuotedStringPart struct {
	Pos lexer.Position

	MacroExpansion *MacroExpansion          `( @@`
	String         *SingleQuotedStringValue ` | @@)`
}

type MacroExpandedDoubleQuotedStringPart struct {
	Pos lexer.Position

	MacroExpansion *MacroExpansion          `( @@`
	String         *DoubleQuotedStringValue ` | @@)`
}

type MacroExpandedStringPart struct {
	Pos lexer.Position

	MacroExpansion *MacroExpansion `( @@`
	String         *StringValue    ` | @@)`
}

type MacroExpansion struct {
	Pos lexer.Position

	Collection string `MacroExpansionStart @Ident (Dot`
	Variable   string ` @(Ident | Number))? MacroExpansionStop`
}

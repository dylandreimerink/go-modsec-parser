package parser

import (
	"github.com/alecthomas/participle/lexer"
	"github.com/alecthomas/participle/lexer/ebnf"
)

var ModsecLexer = lexer.Must(ebnf.New(`
	Ident = (alpha | "_") { "_" | alpha | digit } .
	Number = digit {"." digit | digit} .
	
	NumberSign = "#" .
	EscapedNewLine = "\\\n" .
	EscapedBackslash = "\\\\" .
	NewLine = "\n" .
	Space = " " .
	Amp = "&" .
	Colon = ":" .
	Pipe = "|" .
	Decrement = "=-" .
	Increment = "=+" .
	Equals = "=" .
	SingleQuote = "'" .
	EscapedDoubleQuote = "\\\"" .
	DoubleQuote = "\"" .
	SemiColon = ";" .
	At = "@" .
	Exclamation = "!" .
	MacroExpansionStart = "%{" .
	MacroExpansionStop = "}" . 
	Dot = "." .
	Comma = "," .
	EscapedForwardSlash = "\\/" .
	ForwardSlash = "/" .

	Whitespace = "\t" | "\r" .
    Punct = "!"…"/" | ":"…"@" | "["…` + "\"`\"" + ` | "{"…"~" .

    alpha = "a"…"z" | "A"…"Z" .
	digit = "0"…"9" .
	
	Other = "\u0000"…"\uffff" .
`))

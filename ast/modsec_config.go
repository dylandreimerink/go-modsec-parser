package ast

import (
	"strings"

	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
)

type ModsecConfig struct {
	Pos lexer.Position

	Directives []*Directive "( @@ | NewLine )*"
}

type Directive struct {
	Pos lexer.Position

	Comment               *Comment               `( @@ `
	SecAction             *SecAction             `| @@`
	SecComponentSignature *SecComponentSignature `| @@`
	SecMarker             *SecMarker             `| @@`
	SecRule               *SecRule               `| @@ ) ( NewLine | EOF)`
}

type Comment struct {
	Pos lexer.Position

	Comment string
}

func (comment *Comment) Parse(lex lexer.PeekingLexer) error {

	token, err := lex.Peek(0)
	if err != nil {
		return err
	}

	//The first token is not # then it isn't a comment
	//If the # is not the first token of the line it is not a comment
	if token.Value != "#" || token.Pos.Column != 1 {
		return participle.NextMatch
	}

	comment.Pos = token.Pos

	//Move the iterator
	_, err = lex.Next()
	if err != nil {
		return err
	}

	sb := strings.Builder{}

	for {
		token, err := lex.Peek(0)
		if err != nil {
			return err
		}

		//If the token is a non escaped newline it is the end of the comment
		if token.Value == "\n" {
			break
		}

		//Increment the iterator
		_, err = lex.Next()
		if err != nil {
			return err
		}

		//Write the token value to the string builder
		_, err = sb.WriteString(token.Value)
		if err != nil {
			return err
		}
	}

	//Get the full string and set it as the comment value
	comment.Comment = sb.String()

	return nil
}

type SecComponentSignature struct {
	Pos lexer.Position

	Signature *SingleQuotedStringValue `"SecComponentSignature" Space DoubleQuote @@ DoubleQuote`
}

type SecMarker struct {
	Pos lexer.Position

	Marker string `"SecMarker" Space DoubleQuote @(Ident | Number | Punct)+ DoubleQuote`
}

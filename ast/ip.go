package ast

import (
	"fmt"
	"net"

	"github.com/alecthomas/participle/lexer"
)

type IPAddresses struct {
	Pos lexer.Position

	IPs []*IPAddress `(@@ Comma?)+`
}

type IPAddress struct {
	Pos lexer.Position

	IPv6 *IPv6 `( @@ `
	IPv4 *IPv4 `| @@)`
}

type IPv4 struct {
	Pos lexer.Position

	Value string `@((Number | Dot)+ (ForwardSlash Number)?)`
}

type IPv6 struct {
	Pos lexer.Position

	Value string
}

func (ip *IPv6) Parse(lex lexer.PeekingLexer) error {
	for {
		token, err := lex.Peek(0)
		if err != nil {
			return err
		}

		//Check if all chars are hex
		isHex := true
		for _, c := range token.Value {
			if !('0' <= c && c <= '9' ||
				'a' <= c && c <= 'f' ||
				'A' <= c && c <= 'F') {

				isHex = false
				break
			}
		}

		//If token is hex, ':' or '/'
		if isHex ||
			token.Value == ":" ||
			token.Value == "/" {

			//Append it the the ip value
			ip.Value += token.Value

			//Move the lex iterator
			_, err := lex.Next()
			if err != nil {
				return err
			}
			continue
		}

		//If the next char is not part of the IP check it
		ipAddr := net.ParseIP(ip.Value)
		_, _, err = net.ParseCIDR(ip.Value)
		if ipAddr == nil && err != nil {
			return fmt.Errorf("(%s) Invalid IP: %s", token.Pos.String(), err.Error())
		}

		break
	}

	return nil
}

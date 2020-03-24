package main

import (
	"bufio"
	"io/ioutil"
	"os"

	"github.com/davecgh/go-spew/spew"
)

func main() {
	// spew.Dump(parser.ParseDirectory("testdata/owasp-modsecurity-crs/rules"))
	//spew.Dump(parser.ParseDirectory("testdata/cwaf_rules_nginx_3-1.198"))
	filename := os.Args[1]
	file, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(file)

	input, err := ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}

	lexer := lex(filename, string(input))
	doc, err := parseDocument(lexer)
	// _, err = parseDocument(lexer)
	// if err == nil {
	spew.Dump(doc)
	// }
	spew.Dump(err)
}

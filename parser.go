package parser

import (
	"io"
	"os"
	"strings"

	"github.com/alecthomas/participle"
	"github.com/dylandreimerink/go-modsec-parser/ast"
)

func NewParser(grammer ast.Node) *participle.Parser {
	return participle.MustBuild(grammer,
		participle.Lexer(ModsecLexer),
		participle.CaseInsensitive("Ident"), //Names are often case insensitive, if they are not they should be made into tokens
		participle.Elide("EscapedNewLine"),  //Escaped newlines serve no other purpose then formatting in apache config
	)
}

func MustParse(reader io.Reader) *ast.ModsecConfig {
	ast, err := Parse(reader)
	if err != nil {
		panic(err)
	}

	return ast
}

//Parse will attempt to parse a config file from a arbitrary io.Reader
func Parse(reader io.Reader) (*ast.ModsecConfig, error) {
	parser := NewParser(&ast.ModsecConfig{})
	ast := ast.ModsecConfig{}

	err := parser.Parse(reader, &ast)
	if err != nil {
		return nil, err
	}

	return &ast, nil
}

//ParseFile will attempt to parse a single into a AST
func ParseFile(filename string) (*ast.ModsecConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	return Parse(file)
}

//ParseDirectory parses a all .conf files in that directory
// this function doesn't parse subdirectories
// this function will append all files into one AST
func ParseDirectory(dirname string) (*ast.ModsecConfig, error) {
	dir, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}

	names, err := dir.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	fullConfig := ast.ModsecConfig{}

	for _, filename := range names {
		if strings.HasSuffix(filename, ".conf") {
			ast, err := ParseFile("testdata/owasp-modsecurity-crs/rules/" + filename)
			if err != nil {
				return nil, err
			}

			for _, directive := range ast.Directives {
				fullConfig.Directives = append(fullConfig.Directives, directive)
			}
		}
	}

	return &fullConfig, nil
}

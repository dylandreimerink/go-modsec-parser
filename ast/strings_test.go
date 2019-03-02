package ast_test

import (
	"testing"

	parser "github.com/dylandreimerink/go-modsec-parser"
	"github.com/dylandreimerink/go-modsec-parser/ast"
	"github.com/go-test/deep"
)

func TestSingleQuotedString(t *testing.T) {
	modsecParser := parser.NewParser(&ast.SecRuleVariable{})

	tests := []struct {
		name    string
		config  string
		want    ast.DoubleQuotedString
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ast.DoubleQuotedString{}
			err := modsecParser.ParseString(tt.config, &got)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Error(err)
			}

			if diff := deep.Equal(got, tt.want); diff != nil {
				t.Error(diff)
			}
		})
	}
}

//TODO test DoubleQuotedString
//TODO test MacroExpansion

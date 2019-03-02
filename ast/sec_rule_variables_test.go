package ast_test

import (
	"testing"

	"github.com/alecthomas/participle/lexer"
	parser "github.com/dylandreimerink/go-modsec-parser"
	"github.com/dylandreimerink/go-modsec-parser/ast"
	"github.com/go-test/deep"
)

func TestModsecVariable(t *testing.T) {
	modsecParser := parser.NewParser(&ast.SecRuleVariable{})

	tests := []struct {
		name    string
		config  string
		want    ast.SecRuleVariable
		wantErr bool
	}{
		{
			name:   "Happy path - Args, no modifiers, no selectors",
			config: "ARGS",
			want: ast.SecRuleVariable{
				Pos: lexer.Position{Column: 1, Line: 1},
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 1, Line: 1},
				},
			},
		},
		{
			name:   "Happy path - Args, exclude, no selectors",
			config: "!ARGS",
			want: ast.SecRuleVariable{
				Pos:     lexer.Position{Column: 1, Line: 1},
				Exclude: true,
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 2, Line: 1, Offset: 1},
				},
			},
		},
		{
			name:   "Happy path - Args, count, no selectors",
			config: "&ARGS",
			want: ast.SecRuleVariable{
				Pos:   lexer.Position{Column: 1, Line: 1},
				Count: true,
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 2, Line: 1, Offset: 1},
				},
			},
		},
		{
			name:   "Happy path - Args, no modifiers, key selector",
			config: "ARGS:abc",
			want: ast.SecRuleVariable{
				Pos: lexer.Position{Column: 1, Line: 1},
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 1, Line: 1},
					KeySelector: &ast.SelectorKey{
						Pos:       lexer.Position{Column: 6, Line: 1, Offset: 5},
						KeySelect: "abc",
					},
				},
			},
		},
		{
			name:   "Happy path - Args, no modifiers, regex selector",
			config: "ARGS:/a?bc/",
			want: ast.SecRuleVariable{
				Pos: lexer.Position{Column: 1, Line: 1},
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 1, Line: 1},
					RegexSelector: &ast.SelectorRegex{
						Pos:   lexer.Position{Column: 6, Line: 1, Offset: 5},
						Regex: "a?bc",
					},
				},
			},
		},
		{
			name:   "Happy path - Args, exclude, key selector",
			config: "!ARGS:abc",
			want: ast.SecRuleVariable{
				Pos:     lexer.Position{Column: 1, Line: 1},
				Exclude: true,
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 2, Line: 1, Offset: 1},
					KeySelector: &ast.SelectorKey{
						Pos:       lexer.Position{Column: 7, Line: 1, Offset: 6},
						KeySelect: "abc",
					},
				},
			},
		},
		{
			name:   "Happy path - Args, exclude, regex selector",
			config: "!ARGS:/a?bc/",
			want: ast.SecRuleVariable{
				Pos:     lexer.Position{Column: 1, Line: 1},
				Exclude: true,
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 2, Line: 1, Offset: 1},
					RegexSelector: &ast.SelectorRegex{
						Pos:   lexer.Position{Column: 7, Line: 1, Offset: 6},
						Regex: "a?bc",
					},
				},
			},
		},
		{
			name:   "Happy path - Args, Count, key selector",
			config: "&ARGS:abc",
			want: ast.SecRuleVariable{
				Pos:   lexer.Position{Column: 1, Line: 1},
				Count: true,
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 2, Line: 1, Offset: 1},
					KeySelector: &ast.SelectorKey{
						Pos:       lexer.Position{Column: 7, Line: 1, Offset: 6},
						KeySelect: "abc",
					},
				},
			},
		},
		{
			name:   "Happy path - Args, Count, regex selector",
			config: "&ARGS:/a?bc/",
			want: ast.SecRuleVariable{
				Pos:   lexer.Position{Column: 1, Line: 1},
				Count: true,
				Args: &ast.VariableArgs{
					Pos: lexer.Position{Column: 2, Line: 1, Offset: 1},
					RegexSelector: &ast.SelectorRegex{
						Pos:   lexer.Position{Column: 7, Line: 1, Offset: 6},
						Regex: "a?bc",
					},
				},
			},
		},
		{
			name:    "Edge case - Exclude and count modifier 1",
			config:  "&!ARGS",
			wantErr: true,
		},
		{
			name:    "Edge case - Exclude and count modifier 2",
			config:  "!&ARGS",
			wantErr: true,
		},
		{
			name:    "Edge case - Exclude and count modifier 2",
			config:  "!&ARGS",
			wantErr: true,
		},
		{
			name:    "Edge case - Midding selector",
			config:  "ARGS:",
			wantErr: true,
		},
		{
			name:    "Edge case - Unclosed regex",
			config:  "ARGS:/a?bc",
			wantErr: true,
		},
		{
			name:    "Edge case - Unclosed regex",
			config:  "ARGS:/a?bc",
			wantErr: true,
		},
		//TODO test XML/XPath
		//TODO test allowed and banned tokens/characters
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ast.SecRuleVariable{}
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

//TODO write test for variable list

package ast

import (
	"github.com/alecthomas/participle/lexer"
)

type SecRuleActionList struct {
	Pos lexer.Position

	Actions []*SecRuleAction `(@@)+`
}

type SecRuleAction struct {
	Pos lexer.Position

	Accuracy       *ActionAccuracy       `( @@`
	Allow          *ActionAllow          `| @@`
	AuditLog       *ActionAuditLog       `| @@`
	Block          *ActionBlock          `| @@`
	Capture        *ActionCapture        `| @@`
	Chain          *ActionChain          `| @@`
	Control        *ActionControl        `| @@`
	Deny           *ActionDeny           `| @@`
	Drop           *ActionDrop           `| @@`
	ExpireVariable *ActionExpireVariable `| @@`
	ID             *ActionID             `| @@`
	InitCollection *ActionInitCollection `| @@`
	Log            *ActionLog            `| @@`
	LogData        *ActionLogData        `| @@`
	Message        *ActionMessage        `| @@`
	MultiMatch     *ActionMultiMatch     `| @@`
	NoAuditLog     *ActionNoAutditLog    `| @@`
	NoLog          *ActionNoLog          `| @@`
	Pass           *ActionPass           `| @@`
	Phase          *ActionPhase          `| @@`
	Severity       *ActionSeverity       `| @@`
	SetVar         *ActionSetVariable    `| @@`
	SkipAfter      *ActionSkipAfter      `| @@`
	Status         *ActionStatus         `| @@`
	Transform      *SecRuleTransform     `| @@`
	Tag            *ActionTag            `| @@`
	Version        *ActionVersion        `| @@ ) (Comma (Whitespace | Space)*)?`
}

type ActionAccuracy struct {
	Pos lexer.Position

	Accuracy int `"accuracy" Colon SingleQuote? @Number SingleQuote?`
}

type ActionAllow struct {
	Pos lexer.Position

	Allow bool `@"allow"`
}

type ActionAuditLog struct {
	Pos lexer.Position

	Log bool `@"auditlog"`
}

type ActionBlock struct {
	Pos lexer.Position

	Block bool `@"block"`
}

type ActionCapture struct {
	Pos lexer.Position

	Capture bool `@"capture"`
}

type ActionChain struct {
	Pos lexer.Position

	Chain bool `@"chain"`
}

type ActionControl struct {
	Pos lexer.Position

	Configuration          string `"ctl" Colon @Ident`
	Operator               string `@(Equals | Increment)`
	Value                  string `@(Ident | Number | Punct)+`
	ConditionCollection    string `(SemiColon @Ident`
	ConditionCollectionKey string `(Colon @(Ident | Number | Dot | Punct)+ )? )?`
}

type ActionDeny struct {
	Pos lexer.Position

	Deny bool `@"deny"`
}

type ActionDrop struct {
	Pos lexer.Position

	Drop bool `@"drop"`
}

type ActionExpireVariable struct {
	Pos lexer.Position

	Collection string                           `"expirevar" Colon SingleQuote @Ident Dot`
	Key        string                           `@(Ident | Exclamation | Punct | Number | Dot | Comma | Colon | ForwardSlash | Pipe | NumberSign | MacroExpansionStop | Amp | SemiColon | At | EscapedBackslash | EscapedForwardSlash | EscapedDoubleQuote | Increment | Other)+ Equals`
	Timeout    *MacroExpandedSingleQuotedString `@@ SingleQuote`
}

type ActionID struct {
	Pos lexer.Position

	ID int `"id" Colon SingleQuote? @Number SingleQuote?`
}

type ActionInitCollection struct {
	Pos lexer.Position

	Collection string          `"initcol" Colon SingleQuote? @Ident Equals`
	Value      *UnquotedString `@@ SingleQuote?`
}

type ActionLog struct {
	Pos lexer.Position

	Log bool `@"log"`
}

type ActionLogData struct {
	Pos lexer.Position

	LogData *String `"logdata" Colon @@`
}

type ActionMessage struct {
	Pos lexer.Position

	Message *String `"msg" Colon @@`
}

type ActionMultiMatch struct {
	Pos lexer.Position

	MultiMatch bool `@"multiMatch"`
}

type ActionNoAutditLog struct {
	Pos lexer.Position

	NoAuditLog bool `@"noauditlog"`
}

type ActionNoLog struct {
	Pos lexer.Position

	NoLog bool `@"nolog"`
}

type ActionPass struct {
	Pos lexer.Position

	Pass bool `@"pass"`
}

type ActionPhase struct {
	Pos lexer.Position

	Phase ModsecPhase `"phase" Colon SingleQuote? @(Ident | Number) SingleQuote?`
}

type ActionSeverity struct {
	Pos lexer.Position

	Severity ModsecSeverity `"severity" Colon SingleQuote? @(Ident | Number) SingleQuote?`
}

type ActionSetVariable struct {
	Pos lexer.Position

	Unset      bool                             `"setvar" Colon SingleQuote @Exclamation?`
	Collection string                           `@Ident Dot`
	Key        *MacroExpandedSingleQuotedString `@@`
	Operator   string                           `( @(Equals | Increment | Decrement)`
	Value      *MacroExpandedSingleQuotedString `@@ )? SingleQuote`
}

type ActionSkipAfter struct {
	Pos lexer.Position

	Tag string `"skipAfter" Colon @(Ident | Punct | Number)+`
}

type ActionStatus struct {
	Pos lexer.Position

	StatusCode int `"status" Colon SingleQuote? @Number SingleQuote?`
}

type ActionTag struct {
	Pos lexer.Position

	Tag *SingleQuotedString `"tag" Colon @@`
}

type ActionVersion struct {
	Pos lexer.Position

	Version string `"ver" Colon SingleQuote? @(Ident | ForwardSlash | Dot | Number )+ SingleQuote?`
}

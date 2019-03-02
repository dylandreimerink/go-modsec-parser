package ast

import (
	"github.com/alecthomas/participle/lexer"
)

type SecRuleOperator struct {
	Pos lexer.Position

	Invert               bool                          `@Exclamation? `
	BeginsWith           *OperatorBeginsWith           `( @@`
	Contains             *OperatorContains             `| @@`
	EndsWith             *OperatorEndsWith             `| @@`
	Equals               *OperatorEquals               `| @@`
	GreaterThenOrEquals  *OperatorsGreaterThenOrEquals `| @@`
	GeoLookup            *OperatorGeoLoopkup           `| @@`
	GreaterThen          *OperatorGreaterThen          `| @@`
	IPMatch              *OperatorIPMatch              `| @@`
	LessThen             *OperatorLessThen             `| @@`
	PM                   *OperatorPM                   `| @@`
	PMF                  *OperatorPMF                  `| @@`
	RealTimeBlocklist    *OperatorRealTimeBlocklist    `| @@`
	Regex                *OperatorRegex                `| @@`
	StringEquals         *OperatorStringEquals         `| @@`
	ValidateByteRange    *OperatorValidateByteRange    `| @@`
	ValidateUrlEncoding  *OperatorValidateUrlEncoding  `| @@`
	ValidateUtf8Encoding *OperatorValidateUtf8Encoding `| @@`
	Within               *OperatorWithin               `| @@ )`
}

type OperatorBeginsWith struct {
	Pos lexer.Position

	Compare *MacroExpandedSingleQuotedString `At "beginsWith" Space @@`
}

type OperatorContains struct {
	Pos lexer.Position

	Compare *MacroExpandedSingleQuotedString `At "contains" Space @@`
}

type OperatorEndsWith struct {
	Pos lexer.Position

	Compare *MacroExpandedSingleQuotedString `At "endsWith" Space @@`
}

type OperatorEquals struct {
	Pos lexer.Position

	Compare *MacroExpandedSingleQuotedStringPart `At "eq" Space @@`
}

type OperatorsGreaterThenOrEquals struct {
	Pos lexer.Position

	Compare *MacroExpandedSingleQuotedStringPart `At "ge" Space @@`
}

type OperatorGeoLoopkup struct {
	Pos lexer.Position

	GeoLookup bool `@(At "geoLookup")`
}

type OperatorGreaterThen struct {
	Pos lexer.Position

	Compare *MacroExpandedSingleQuotedStringPart `At "gt" Space @@`
}

type OperatorIPMatch struct {
	Pos lexer.Position

	IPList *IPAddresses `At "ipMatch" Space @@`
}

type OperatorLessThen struct {
	Pos lexer.Position

	Compare *MacroExpandedSingleQuotedStringPart `At "lt" Space @@`
}

type OperatorPM struct {
	Pos lexer.Position

	Matches []string `At "pm" Space (@(Ident | Exclamation | Punct | Number | Dot | Comma | Colon | ForwardSlash | NumberSign | MacroExpansionStop | Amp | SemiColon | Equals | At | EscapedBackslash | SingleQuote | EscapedDoubleQuote)+ (Pipe | Space)?)+`
}

type OperatorPMF struct {
	Pos lexer.Position

	Filename string `At ("pmf" | "pmFromFile") Space @(Ident | Exclamation | Punct | Number | Dot | Comma | Colon | ForwardSlash | Pipe | NumberSign | MacroExpansionStop | Amp | SemiColon | Equals | At | EscapedBackslash | SingleQuote | EscapedDoubleQuote)+`
}

type OperatorRealTimeBlocklist struct {
	Pos lexer.Position

	URL string `At "rbl" Space @(Ident | Dot | Number | Punct)+`
}

type OperatorRegex struct {
	Pos lexer.Position

	Regex *MacroExpandedDoubleQuotedString `(At "rx" Space)? @@`
}

type OperatorStringEquals struct {
	Pos lexer.Position

	Compare *MacroExpandedSingleQuotedString `At "streq" Space @@`
}

type OperatorValidateByteRange struct {
	Pos lexer.Position

	ByteRanges []*ByteRange `At "validateByteRange" Space (@@)+`
}

type ByteRange struct {
	Pos lexer.Position

	Start int `@Number`
	End   int `("-"@Number)? Comma?`
}

type OperatorValidateUrlEncoding struct {
	Pos lexer.Position

	ValidateUrlEncoding bool `At "validateUrlEncoding"`
}

type OperatorValidateUtf8Encoding struct {
	Pos lexer.Position

	ValidateUtf8Encoding bool `At "validateUtf8Encoding"`
}

type OperatorWithin struct {
	Pos lexer.Position

	Haystack *MacroExpandedSingleQuotedString `At "within" Space @@`
}

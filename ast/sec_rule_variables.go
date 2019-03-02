package ast

import "github.com/alecthomas/participle/lexer"

type SecRuleVariable struct {
	Pos lexer.Position

	Count                bool                          `(@Amp`
	Exclude              bool                          ` | @Exclamation)?`
	Args                 *VariableArgs                 `( @@`
	ArgsCombinedSize     *VariableArgsCombinedSize     `| @@`
	ArgsGet              *VariableArgsGet              `| @@`
	ArgsGetNames         *VariableArgsGetNames         `| @@`
	ArgsNames            *VariableArgsNames            `| @@`
	Duration             *VariableDuration             `| @@`
	Files                *VariableFiles                `| @@`
	FilesCombinedSize    *VariableFilesCombinedSize    `| @@`
	FileNames            *VariableFileNames            `| @@`
	GEO                  *VariableGEO                  `| @@`
	MatchedVars          *VariableMatchedVars          `| @@`
	MatchedVarsNames     *VariableMatchedVarsNames     `| @@`
	MultipartStrictError *VariableMultipartStrictError `| @@`
	QueryString          *VariableQueryString          `| @@`
	RemoteAddress        *VariableRemoteAddress        `| @@`
	RequestBodyError     *VariableRequestBodyError     `| @@`
	RequestBodyProcessor *VariableRequestBodyProcessor `| @@`
	RequestBasename      *VariableRequestBasename      `| @@`
	RequestBody          *VariableRequestBody          `| @@`
	RequestCookies       *VariableRequestCookies       `| @@`
	RequestCookiesNames  *VariableRequestCookiesNames  `| @@`
	RequestFilename      *VariableRequestFilename      `| @@`
	RequestHeaders       *VariableRequestHeaders       `| @@`
	RequestMethod        *VariableRequestMethod        `| @@`
	RequestProtocol      *VariableRequestProtocol      `| @@`
	RequestHeaderNames   *VariableRequestHeaderNames   `| @@`
	RequestLine          *VariableRequestLine          `| @@`
	RequestURI           *VariableRequestURI           `| @@`
	RequestURIRaw        *VariableRequestURIRaw        `| @@`
	ResponseBody         *VariableResponseBody         `| @@`
	ResponseStatus       *VariableResponseStatus       `| @@`
	IP                   *VariableIP                   `| @@`
	TX                   *VariableTX                   `| @@`
	UniqueID             *VariableUniqueID             `| @@`
	XML                  *VariableXML                  `| @@) Pipe?`
}

//TODO this is a temp variable until I have come around to adding seperate structs for them
type VariableOther struct {
	Pos lexer.Position

	VariableName  string         `@Ident`
	KeySelector   *SelectorKey   `(Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableArgs struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"ARGS" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableArgsCombinedSize struct {
	Pos lexer.Position

	ArgsCombinedSize bool `@"ARGS_COMBINED_SIZE"`
}

type VariableArgsGet struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"ARGS_GET" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableArgsGetNames struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"ARGS_GET_NAMES" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableArgsNames struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"ARGS_NAMES" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableDuration struct {
	Pos lexer.Position

	Duration bool `@"DURATION"`
}

type VariableFiles struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"FILES" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableFilesCombinedSize struct {
	Pos lexer.Position

	FilesCombinedSize bool `@"FILES_COMBINED_SIZE"`
}

type VariableFileNames struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"FILES_NAMES" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableGEO struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"GEO" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableMatchedVars struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"MATCHED_VARS" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableMatchedVarsNames struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"MATCHED_VARS_NAMES" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableMultipartStrictError struct {
	Pos lexer.Position

	MultipartStrictError bool `@"MULTIPART_STRICT_ERROR"`
}

type VariableQueryString struct {
	Pos lexer.Position

	QueryString bool `@"QUERY_STRING"`
}

type VariableRemoteAddress struct {
	Pos lexer.Position

	RemoteAdress bool `@"REMOTE_ADDR"`
}

type VariableRequestBodyError struct {
	Pos lexer.Position

	RequestBodyError bool `@"REQBODY_ERROR"`
}

type VariableRequestBodyProcessor struct {
	Pos lexer.Position

	RequestBodyProcessor bool `@"REQBODY_PROCESSOR"`
}

type VariableRequestBasename struct {
	Pos lexer.Position

	RequestBasename bool `@"REQUEST_BASENAME"`
}

type VariableRequestBody struct {
	Pos lexer.Position

	RequestBody bool `@"REQUEST_BODY"`
}

type VariableRequestCookies struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"REQUEST_COOKIES" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableRequestCookiesNames struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"REQUEST_COOKIES_NAMES" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableRequestFilename struct {
	Pos lexer.Position

	RequestFilename bool `@"REQUEST_FILENAME"`
}

type VariableRequestHeaders struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"REQUEST_HEADERS" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableRequestMethod struct {
	Pos lexer.Position

	RequestMethod bool `@"REQUEST_METHOD"`
}

type VariableRequestProtocol struct {
	Pos lexer.Position

	RequestProtocol bool `@"REQUEST_PROTOCOL"`
}

type VariableRequestHeaderNames struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"REQUEST_HEADERS_NAMES" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableRequestLine struct {
	Pos lexer.Position

	RequestLine bool `@"REQUEST_LINE"`
}

type VariableRequestURI struct {
	Pos lexer.Position

	RequestURI bool `@"REQUEST_URI"`
}

type VariableRequestURIRaw struct {
	Pos lexer.Position

	RequestURIRaw bool `@"REQUEST_URI_RAW"`
}

type VariableResponseBody struct {
	Pos lexer.Position

	ResponseBody bool `@"RESPONSE_BODY"`
}

type VariableResponseStatus struct {
	Pos lexer.Position

	ResponseStatus bool `@"RESPONSE_STATUS"`
}

type SelectorKey struct {
	Pos lexer.Position

	KeySelect string `@(Ident | Number | Punct)+`
}

type SelectorRegex struct {
	Pos lexer.Position

	Regex string `ForwardSlash @(Ident | Space | Exclamation | Punct | Number | Dot | Comma | Colon | Pipe | NumberSign | EscapedBackslash | EscapedForwardSlash )+ ForwardSlash`
}

//TODO remove this type after all other types are added and make it a dynamic collection variable type
type VariableIP struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"IP" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableTX struct {
	Pos lexer.Position

	KeySelector   *SelectorKey   `"TX" (Colon SingleQuote? ( @@`
	RegexSelector *SelectorRegex `| @@) SingleQuote? )?`
}

type VariableUniqueID struct {
	Pos lexer.Position

	UniqueID bool `@"UNIQUE_ID"`
}

type VariableXML struct {
	Pos lexer.Position

	XPath string `"XML" Colon @(ForwardSlash | Ident | Number | Punct | At | SingleQuote)+`
}

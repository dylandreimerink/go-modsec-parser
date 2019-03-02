package ast

import (
	"github.com/alecthomas/participle/lexer"
)

type SecRuleTransform struct {
	Pos lexer.Position

	Base64Decode        *TransformBase64Decode       `"t" Colon SingleQuote? (@@`
	CMDLine             *TransformCMDLine            `| @@`
	CompressWhitespace  *TransformCompressWhitespace `| @@`
	CSSDecode           *TransformCSSDecode          `| @@`
	HexEncode           *TransformHexEncode          `| @@`
	HTMLEntityDecode    *TransformHTMLEntityDecode   `| @@`
	JSDecode            *TransformJSDecode           `| @@`
	Length              *TransformLength             `| @@`
	Lowecase            *TransformLowercase          `| @@`
	None                *TransformNone               `| @@`
	NormalizePath       *TransformNormalizePath      `| @@`
	NormalizePathWin    *TransformNormalizePathWin   `| @@`
	RemoveNulls         *TransformRemoveNulls        `| @@`
	ReplaceComments     *TransformRepaceComments     `| @@`
	UrlDecode           *TransformUrlDecode          `| @@`
	UrlDecodeUni        *TransformUrlDecodeUni       `| @@`
	UTF8DecodeToUnicode *TransformUTF8toUnicode      `| @@`
	Sha1                *TransformSha1               `| @@`
	Trim                *TransformTrim               `| @@) SingleQuote?`
}

type TransformBase64Decode struct {
	Pos lexer.Position

	Base64Decode bool `@"base64Decode"`
}

type TransformCMDLine struct {
	Pos lexer.Position

	CMDLine bool `@"cmdLine"`
}

type TransformCompressWhitespace struct {
	Pos lexer.Position

	CompressWhitespace bool `@"compressWhiteSpace"`
}

type TransformCSSDecode struct {
	Pos lexer.Position

	CSSDecode bool `@"cssDecode"`
}

type TransformHexEncode struct {
	Pos lexer.Position

	HexEncode bool `@"hexEncode"`
}

type TransformHTMLEntityDecode struct {
	Pos lexer.Position

	HTMLEntityDecode bool `@"htmlEntityDecode"`
}

type TransformJSDecode struct {
	Pos lexer.Position

	JSDecode bool `@"jsDecode"`
}

type TransformLength struct {
	Pos lexer.Position

	Length bool `@"length"`
}

type TransformLowercase struct {
	Pos lexer.Position

	Lowercase bool `@"lowercase"`
}

type TransformNone struct {
	Pos lexer.Position

	None bool `@"none"`
}

type TransformNormalizePath struct {
	Pos lexer.Position

	NormalizePath bool `@("normalizePath" | "normalisePath")`
}

type TransformNormalizePathWin struct {
	Pos lexer.Position

	NormalizePathWin bool `@("normalizePathWin" | "normalisePathWin")`
}

type TransformRemoveNulls struct {
	Pos lexer.Position

	RemoveNulls bool `@"removeNulls"`
}

type TransformRepaceComments struct {
	Pos lexer.Position

	RepaceComments bool `@"replaceComments"`
}

type TransformUrlDecode struct {
	Pos lexer.Position

	UrlDecode bool `@"urlDecode"`
}

type TransformUrlDecodeUni struct {
	Pos lexer.Position

	UrlDecodeUni bool `@"urlDecodeUni"`
}

type TransformUTF8toUnicode struct {
	Pos lexer.Position

	UTF8toUnicode bool `@"utf8toUnicode"`
}

type TransformSha1 struct {
	Pos lexer.Position

	Sha1 bool `@"sha1"`
}

type TransformTrim struct {
	Pos lexer.Position

	Trim bool `@"trim"`
}

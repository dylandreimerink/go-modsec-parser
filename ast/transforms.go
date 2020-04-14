package ast

type TransformType interface {
	Node
	Transform()
}

//TransformBase64Decode Decodes a Base64-encoded string.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#base64decode
type TransformBase64Decode struct {
	AbstractNode
}

func (t *TransformBase64Decode) Name() string {
	return "base64Decode"
}

func (t *TransformBase64Decode) Children() []Node {
	return []Node{}
}

func (t *TransformBase64Decode) Transform() {}

//TransformCMDLine In Windows and Unix, commands may be escaped by different means. See reference manual for more details
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#cmdline
type TransformCMDLine struct {
	AbstractNode
}

func (t *TransformCMDLine) Name() string {
	return "cmdLine"
}

func (t *TransformCMDLine) Children() []Node {
	return []Node{}
}

func (t *TransformCMDLine) Transform() {}

//TransformCompressWhitespace Converts any of the whitespace characters (0x20, \f, \t, \n, \r, \v, 0xa0) to spaces (ASCII 0x20), compressing multiple consecutive space characters into one.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#compressWhitespace
type TransformCompressWhitespace struct {
	AbstractNode
}

func (t *TransformCompressWhitespace) Name() string {
	return "compressWhitespace"
}

func (t *TransformCompressWhitespace) Children() []Node {
	return []Node{}
}

func (t *TransformCompressWhitespace) Transform() {}

//TransformCSSDecode Decodes characters encoded using the CSS 2.x escape rules syndata.html#characters.
// This function uses only up to two bytes in the decoding process,
// meaning that it is useful to uncover ASCII characters encoded using CSS encoding (that wouldn’t normally be encoded),
// or to counter evasion, which is a combination of a backslash and non-hexadecimal characters (e.g., ja\vascript is equivalent to javascript).
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#cssDecode
type TransformCSSDecode struct {
	AbstractNode
}

func (t *TransformCSSDecode) Name() string {
	return "cssDecode"
}

func (t *TransformCSSDecode) Children() []Node {
	return []Node{}
}

func (t *TransformCSSDecode) Transform() {}

//TransformHexEncode Encodes string (possibly containing binary characters) by replacing each input byte with two hexadecimal characters. For example, xyz is encoded as 78797a.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#hexencode
type TransformHexEncode struct {
	AbstractNode
}

func (t *TransformHexEncode) Name() string {
	return "hexEncode"
}

func (t *TransformHexEncode) Children() []Node {
	return []Node{}
}

func (t *TransformHexEncode) Transform() {}

//TransformHTMLEntityDecode Decodes the characters encoded as HTML entities. The following variants are supported:
//
//	HH and HH; (where H is any hexadecimal number)
//	DDD and DDD; (where D is any decimal number)
//	&quotand"
//	&nbspand
//	&ltand<
//	&gtand>
//
//This function always converts one HTML entity into one byte, possibly resulting in a loss of information (if the entity refers to a character that cannot be represented with the single byte). It is thus useful to uncover bytes that would otherwise not need to be encoded, but it cannot do anything meaningful with the characters from the range above 0xff.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#htmlEntityDecode
type TransformHTMLEntityDecode struct {
	AbstractNode
}

func (t *TransformHTMLEntityDecode) Name() string {
	return "htmlEntityDecode"
}

func (t *TransformHTMLEntityDecode) Children() []Node {
	return []Node{}
}

func (t *TransformHTMLEntityDecode) Transform() {}

//TransformJSDecode Decodes JavaScript escape sequences. If a \uHHHH code is in the range of FF01-FF5E (the full width ASCII codes), then the higher byte is used to detect and adjust the lower byte.
// Otherwise, only the lower byte will be used and the higher byte zeroed (leading to possible loss of information).
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#jsDecode
type TransformJSDecode struct {
	AbstractNode
}

func (t *TransformJSDecode) Name() string {
	return "jsDecode"
}

func (t *TransformJSDecode) Children() []Node {
	return []Node{}
}

func (t *TransformJSDecode) Transform() {}

//TransformLength Looks up the length of the input string in bytes, placing it (as string) in output. For example, if it gets ABCDE on input, this transformation function will return 5 on output.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#length
type TransformLength struct {
	AbstractNode
}

func (t *TransformLength) Name() string {
	return "length"
}

func (t *TransformLength) Children() []Node {
	return []Node{}
}

func (t *TransformLength) Transform() {}

//TransformLowercase Converts all characters to lowercase using the current C locale.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#lowercase
type TransformLowercase struct {
	AbstractNode
}

func (t *TransformLowercase) Name() string {
	return "lowercase"
}

func (t *TransformLowercase) Children() []Node {
	return []Node{}
}

func (t *TransformLowercase) Transform() {}

//TransformNone Not an actual transformation function, but an instruction to ModSecurity to remove all transformation functions associated with the current rule.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#none
type TransformNone struct {
	AbstractNode
}

func (t *TransformNone) Name() string {
	return "none"
}

func (t *TransformNone) Children() []Node {
	return []Node{}
}

func (t *TransformNone) Transform() {}

//TransformNormalizePath Removes multiple slashes, directory self-references, and directory back-references (except when at the beginning of the input) from input string.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#normalizePath
type TransformNormalizePath struct {
	AbstractNode
}

func (t *TransformNormalizePath) Name() string {
	return "normalizePath"
}

func (t *TransformNormalizePath) Children() []Node {
	return []Node{}
}

func (t *TransformNormalizePath) Transform() {}

//TransformNormalizePathWin Same as normalizePath, but first converts backslash characters to forward slashes.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#normalizePathWin
type TransformNormalizePathWin struct {
	AbstractNode
}

func (t *TransformNormalizePathWin) Name() string {
	return "normalizePathWin"
}

func (t *TransformNormalizePathWin) Children() []Node {
	return []Node{}
}

func (t *TransformNormalizePathWin) Transform() {}

//TransformRemoveNulls Removes all NUL bytes from input.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#removeNulls
type TransformRemoveNulls struct {
	AbstractNode
}

func (t *TransformRemoveNulls) Name() string {
	return "removeNulls"
}

func (t *TransformRemoveNulls) Children() []Node {
	return []Node{}
}

func (t *TransformRemoveNulls) Transform() {}

//TransformReplaceCommentsReplaces each occurrence of a C-style comment (/* ... */) with a single space (multiple consecutive occurrences of which will not be compressed).
// Unterminated comments will also be replaced with a space (ASCII 0x20). However, a standalone termination of a comment (*/) will not be acted upon.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#replaceComments
type TransformReplaceComments struct {
	AbstractNode
}

func (t *TransformReplaceComments) Name() string {
	return "replaceComments"
}

func (t *TransformReplaceComments) Children() []Node {
	return []Node{}
}

func (t *TransformReplaceComments) Transform() {}

//TransformUrlDecode Decodes a URL-encoded input string.
// Invalid encodings (i.e., the ones that use non-hexadecimal characters,
// or the ones that are at the end of string and have one or two bytes missing) are not converted,
// but no error is raised. To detect invalid encodings, use the @validateUrlEncoding operator on the input data first.
// The transformation function should not be used against variables that have already been URL-decoded (such as request parameters) unless it is your intention to perform URL decoding twice!
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#urlDecode
type TransformUrlDecode struct {
	AbstractNode
}

func (t *TransformUrlDecode) Name() string {
	return "urlDecode"
}

func (t *TransformUrlDecode) Children() []Node {
	return []Node{}
}

func (t *TransformUrlDecode) Transform() {}

//TransformUrlDecodeUni Like urlDecode, but with support for the Microsoft-specific %u encoding. If the code is in the range of FF01-FF5E (the full-width ASCII codes), then the higher byte is used to detect and adjust the lower byte. Otherwise, only the lower byte will be used and the higher byte zeroed.
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#urlDecodeUni
type TransformUrlDecodeUni struct {
	AbstractNode
}

func (t *TransformUrlDecodeUni) Name() string {
	return "urlDecodeUni"
}

func (t *TransformUrlDecodeUni) Children() []Node {
	return []Node{}
}

func (t *TransformUrlDecodeUni) Transform() {}

//TransformUTF8ToUnicode Converts all UTF-8 characters sequences to Unicode. This help input normalization specially for non-english languages minimizing false-positives and false-negatives. (available with 2.7.0)
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#utf8toUnicode
type TransformUTF8ToUnicode struct {
	AbstractNode
}

func (t *TransformUTF8ToUnicode) Name() string {
	return "utf8toUnicode"
}

func (t *TransformUTF8ToUnicode) Children() []Node {
	return []Node{}
}

func (t *TransformUTF8ToUnicode) Transform() {}

//TransformSHA1 Calculates a SHA1 hash from the input string. The computed hash is in a raw binary form and may need encoded into text to be printed (or logged). Hash functions are commonly used in combination with hexEncode (for example, t:sha1,t:hexEncode).
//https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#sha1
type TransformSHA1 struct {
	AbstractNode
}

func (t *TransformSHA1) Name() string {
	return "sha1"
}

func (t *TransformSHA1) Children() []Node {
	return []Node{}
}

func (t *TransformSHA1) Transform() {}

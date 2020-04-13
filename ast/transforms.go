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

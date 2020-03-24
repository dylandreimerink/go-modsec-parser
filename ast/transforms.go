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

//TransformNone Encodes string (possibly containing binary characters) by replacing each input byte with two hexadecimal characters. For example, xyz is encoded as 78797a.
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

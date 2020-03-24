package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

//Based on https://talks.golang.org/2011/lex.slide + https://www.youtube.com/watch?v=HxaD_trXwRE

const (
	eof = 0x7fffffff
)

type stateFn func(l *lexer) stateFn

// item represents a token returned from the scanner.
type item struct {
	typ   itemType // Type, such as itemNumber.
	val   string   // Value, such as "23.2".
	start itemPos
}

type itemPos struct {
	file   string
	line   int
	column int
}

func (pos itemPos) String() string {
	if pos.file == "" {
		return fmt.Sprintf("%d:%d", pos.line, pos.column)
	} else {
		return fmt.Sprintf("%s:%d:%d", pos.file, pos.line, pos.column)
	}
}

type itemType int

// itemType identifies the type of lex items.
const (
	itemError itemType = iota // error occurred; value is text of error
	itemEOF
	itemCommentStart    // A # at the start of a line
	itemComment         // The text following a comment start
	itemDirective       // The directive name
	itemArgumentStart   // Marks the start of a directive argument
	itemArgumentStop    // Marks the end of a directive argument
	itemIdent           // A string of characters which form a identifier together
	itemWhitespace      // Whitespace when it has meaning, like inside a quoted string
	itemAt              // @ which is the "modsec operator" operator
	itemAmpresant       // & which may indicate a count operator
	itemColon           // : which may represent a loopup in collection operator
	itemPipe            // | which may represent a conjoin operator
	itemComma           // , which may represent a list divider
	itemEquals          // =
	itemSemicolon       // ;
	itemSingleQuote     // '
	itemPercent         // %
	itemCurlyBraceOpen  // {
	itemCurlyBraceClose // }
	itemDot             // .
	itemPlus            // +
	itemMinus           // -
	itemExclamation     // !
	itemForwardSlash    // /
)

func (item itemType) String() string {
	switch item {
	case itemError:
		return "itemError"
	case itemEOF:
		return "itemEOF"
	case itemCommentStart:
		return "itemCommentStart"
	case itemComment:
		return "itemComment"
	case itemDirective:
		return "itemDirective"
	case itemArgumentStart:
		return "itemArgumentStart"
	case itemArgumentStop:
		return "itemArgumentStop"
	case itemIdent:
		return "itemIdent"
	case itemWhitespace:
		return "itemWhitespace"
	case itemAt:
		return "itemAt"
	case itemAmpresant:
		return "itemAmpresant"
	case itemColon:
		return "itemColon"
	case itemPipe:
		return "itemPipe"
	case itemComma:
		return "itemComma"
	case itemEquals:
		return "itemEquals"
	case itemSemicolon:
		return "itemSemicolon"
	case itemSingleQuote:
		return "itemSingleQuote"
	case itemPercent:
		return "itemPercent"
	case itemCurlyBraceOpen:
		return "itemCurlyBraceOpen"
	case itemCurlyBraceClose:
		return "itemCurlyBraceClose"
	case itemDot:
		return "itemDot"
	case itemPlus:
		return "itemPlus"
	case itemMinus:
		return "itemMinus"
	case itemExclamation:
		return "itemExclamation"
	case itemForwardSlash:
		return "itemForwardSlash"
	}

	return "UNKNOWN"
}

// lexer holds the state of the scanner.
type lexer struct {
	name  string    // used only for error reports.
	input string    // the string being scanned.
	start int       // start position of this item.
	line  int       // the line count of the start pos
	pos   int       // current position in the input.
	width int       // width of last rune read from input.
	state stateFn   // the current state of the lexer
	items chan item // channel of scanned items.
}

func lex(name, input string) *lexer {
	l := &lexer{
		name:  name,
		input: input,
		state: lexLine,
		line:  1,
		items: make(chan item, 100),
	}
	return l
}

// nextItem returns the next item from the input.
func (l *lexer) nextItem() item {
	for {
		select {
		case item := <-l.items:
			return item
		default:
			l.state = l.state(l)
		}
	}
	panic("not reached")
}

// emit passes an item back to the client.
func (l *lexer) emit(t itemType) {

	l.items <- item{
		typ: t,
		val: l.input[l.start:l.pos],
		start: itemPos{
			file: l.name,
			line: l.line,
			//Column is the offset from the last newline
			column: len(l.input[:l.start]) - strings.LastIndex(l.input[:l.start], "\n"),
		},
	}

	//The line of start is the current line plus the amount of newlines we processes just now
	l.line += strings.Count(l.input[l.start:l.pos], "\n")

	l.start = l.pos
}

// next returns the next rune in the input.
func (l *lexer) next() (r rune) {
	if l.pos >= len(l.input) {
		l.width = 0
		return eof
	}
	r, l.width =
		utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += l.width
	return r
}

// ignore skips over the pending input before this point.
func (l *lexer) ignore() {

	//The line of start is the current line plus the amount of newlines we processes just now
	l.line += strings.Count(l.input[l.start:l.pos], "\n")

	l.start = l.pos
}

// backup steps back one rune.
// Can be called only once per call of next.
func (l *lexer) backup() {
	l.pos -= l.width
}

// peek returns but does not consume
// the next rune in the input.
func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}

// accept consumes the next rune
// if it's from the valid set.
func (l *lexer) accept(valid string) bool {
	if strings.IndexRune(valid, l.next()) >= 0 {
		return true
	}
	l.backup()
	return false
}

// acceptRun consumes a run of runes from the valid set.
func (l *lexer) acceptRun(valid string) {
	for strings.IndexRune(valid, l.next()) >= 0 {
	}
	l.backup()
}

// error returns an error token and terminates the scan
// by passing back a nil pointer that will be the next
// state, terminating l.run.
func (l *lexer) errorf(format string, args ...interface{}) stateFn {
	l.items <- item{
		typ: itemError,
		val: fmt.Sprintf(format, args...),
		start: itemPos{
			file: l.name,
			line: l.line,
			//Column is the offset from the last newline
			column: strings.LastIndex("\n", l.input[:l.start]),
		},
	}
	return nil
}

//lex from the start of a line
func lexLine(l *lexer) stateFn {

	//First char of line
	first := l.next()
	switch first {
	case '#':
		return lexCommentStart
	case '\n':
		l.ignore()
		return lexLine
	case '\t', '\v', '\f', '\r', ' ', 0x85, 0xA0:

		//Ignore all whitespace
		l.acceptRun("\t\v\f\r \x85\xA0")
		l.ignore()

		next := l.next()
		switch next {
		case '\n':
			l.ignore()
			return lexLine
		case eof:
			l.emit(itemEOF)
			return nil
		default:
			if unicode.IsLetter(next) {
				l.backup()
				return lexDirective
			}

			return l.errorf("Invalid start of line, should be comment, whitespace or directive. found: '%s'", string(first))
		}
	case eof:
		l.emit(itemEOF)
		return nil

	default:
		if unicode.IsLetter(first) {
			l.backup()
			return lexDirective
		}
		return l.errorf("Invalid start of line, should be comment, whitespace or directive. found: '%s'", first)
	}
}

func lexCommentStart(l *lexer) stateFn {

	l.emit(itemCommentStart)

	for {
		next := l.next()
		switch next {
		case '\n':
			//Emit all that came before as a comment
			l.backup()
			if l.pos > l.start {
				l.emit(itemComment)
			}

			//Ignore the newline
			l.next()
			l.ignore()

			return lexLine
		case eof:
			//Emit all that came before as a comment
			l.backup()
			if l.pos > l.start {
				l.emit(itemComment)
			}

			l.next()
			l.emit(itemEOF)
			return nil
		}
	}
}

func lexDirective(l *lexer) stateFn {
	for {
		next := l.next()
		switch next {
		case eof:
			//Emit all that came before as a directive
			l.backup()
			if l.pos > l.start {
				l.emit(itemDirective)
			}

			l.next()
			l.emit(itemEOF)
			return nil
		case '\n':
			//Emit all that came before as a directive
			l.backup()
			if l.pos > l.start {
				l.emit(itemDirective)
			}
			//Ignore the newline
			l.next()
			l.ignore()
			return lexLine
		case '\t', '\v', '\f', '\r', ' ', 0x85, 0xA0:
			//Emit all that came before as a directive
			l.backup()
			l.emit(itemDirective)

			return lexDirectiveArgument
		default:
			if unicode.IsLetter(next) {
				continue
			}

			return l.errorf("Directives should only contain letters, found: '%s'", string(next))
		}
	}
}

//Lex an directive argument
func lexDirectiveArgument(l *lexer) stateFn {
	for {
		next := l.next()
		switch next {
		case '\n':
			l.ignore()
			return lexLine

		case eof:
			l.emit(itemEOF)
			return nil

		case '\t', '\v', '\f', '\r', ' ', 0x85, 0xA0:
			continue

		case '\\':

			//Escape char
			switch l.next() {
			case '\n':
				//Escped newline, ignore escape char and newline
				l.ignore()
				continue
			}

			l.backup()

			return l.errorf("invalid backslash")

		case '"':
			//Ignore any whitespace
			l.backup()
			l.ignore()

			//emit quote as start of argument
			l.next()
			l.emit(itemArgumentStart)

			return lexQuotedDirectiveArgument

		default:
			//Emit whitespace as start of argument
			l.backup()
			l.emit(itemArgumentStart)

			return lexUnquotedDirectiveArgument
		}
	}
}

//Lex an unquoted directive
func lexUnquotedDirectiveArgument(l *lexer) stateFn {
	emitIdent := func() {
		//emit chars as ident
		l.backup()
		if l.pos > l.start {
			l.emit(itemIdent)
		}
	}

	for {
		next := l.next()
		switch next {
		case '\n':
			emitIdent()

			//Ignore the newline
			l.next()
			l.ignore()

			return lexLine
		case '\t', '\v', '\f', '\r', ' ', 0x85, 0xA0:
			emitIdent()

			//Emit the first whitespace char as the stop for the argument
			l.next()
			l.emit(itemArgumentStop)

			return lexDirectiveArgument

		case eof:
			emitIdent()

			//Ignore the newline
			l.next()
			l.emit(itemEOF)

			return nil
		case '\\':
			emitIdent()

			l.next()
			switch l.next() {
			case '\n':
				//Escaped newline

				//Ignore the backslash and newline char
				l.ignore()
			}
		case '&':
			emitIdent()

			l.next()
			l.emit(itemAmpresant)
			return lexUnquotedDirectiveArgument
		case ':':
			emitIdent()

			l.next()
			l.emit(itemColon)
			return lexUnquotedDirectiveArgument
		case '|':
			emitIdent()

			l.next()
			l.emit(itemPipe)
			return lexUnquotedDirectiveArgument
		case '@':
			emitIdent()

			l.next()
			l.emit(itemAt)
			return lexUnquotedDirectiveArgument
		case ',':
			emitIdent()

			l.next()
			l.emit(itemComma)
			return lexUnquotedDirectiveArgument
		case '.':
			emitIdent()

			l.next()
			l.emit(itemDot)
			return lexUnquotedDirectiveArgument
		case '\'':
			emitIdent()

			l.next()
			l.emit(itemSingleQuote)
			return lexUnquotedDirectiveArgument
		case '=':
			emitIdent()

			l.next()
			l.emit(itemEquals)
			return lexUnquotedDirectiveArgument
		case ';':
			emitIdent()

			l.next()
			l.emit(itemSemicolon)
			return lexUnquotedDirectiveArgument
		case '%':
			emitIdent()

			l.next()
			l.emit(itemPercent)
			return lexUnquotedDirectiveArgument
		case '{':
			emitIdent()

			l.next()
			l.emit(itemCurlyBraceOpen)
			return lexUnquotedDirectiveArgument
		case '}':
			emitIdent()

			l.next()
			l.emit(itemCurlyBraceClose)
			return lexUnquotedDirectiveArgument
		case '+':
			emitIdent()

			l.next()
			l.emit(itemPlus)
			return lexUnquotedDirectiveArgument
		case '-':
			emitIdent()

			l.next()
			l.emit(itemMinus)
			return lexUnquotedDirectiveArgument
		case '!':
			emitIdent()

			l.next()
			l.emit(itemExclamation)
			return lexUnquotedDirectiveArgument
		case '/':
			emitIdent()

			l.next()
			l.emit(itemForwardSlash)
			return lexUnquotedDirectiveArgument
		default:
			// If none of the above, then the char is part of an identifer
		}
	}
}

func lexQuotedDirectiveArgument(l *lexer) stateFn {
	emitIdent := func() {
		//emit prev chars as ident
		l.backup()
		if l.pos > l.start {
			l.emit(itemIdent)
		}
	}

	for {
		next := l.next()
		switch next {
		case '\n':
			emitIdent()

			//Ignore the newline
			l.next()
			l.ignore()

			return lexLine
		case '\t', '\v', '\f', '\r', ' ', 0x85, 0xA0:
			emitIdent()

			//Emit any whitespace as meaningful whitespace
			l.acceptRun("\t\v\f\r \x85\xA0")
			l.emit(itemWhitespace)

			return lexQuotedDirectiveArgument

		case '"':
			emitIdent()

			//Emit the quote as the stop for the argument
			l.next()
			l.emit(itemArgumentStop)

			return lexDirectiveArgument

		case eof:
			emitIdent()

			//Ignore the newline
			l.next()
			l.emit(itemEOF)

			return nil
		case '\\':
			emitIdent()

			l.next()
			switch l.next() {
			case '\n':
				//Escaped newline

				//Ignore the backslash and newline char
				l.ignore()
			case '"':
				//Escaped quote

				//Ignore the backslash
				l.backup()
				l.ignore()

				//Accept the quote as ident
				l.next()
			}
		case '&':
			emitIdent()

			l.next()
			l.emit(itemAmpresant)
			return lexQuotedDirectiveArgument
		case ':':
			emitIdent()

			l.next()
			l.emit(itemColon)
			return lexQuotedDirectiveArgument
		case '|':
			emitIdent()

			l.next()
			l.emit(itemPipe)
			return lexQuotedDirectiveArgument
		case '@':
			emitIdent()

			l.next()
			l.emit(itemAt)
			return lexQuotedDirectiveArgument
		case ',':
			emitIdent()

			l.next()
			l.emit(itemComma)
			return lexQuotedDirectiveArgument
		case '.':
			emitIdent()

			l.next()
			l.emit(itemDot)
			return lexQuotedDirectiveArgument
		case '\'':
			emitIdent()

			l.next()
			l.emit(itemSingleQuote)
			return lexQuotedDirectiveArgument
		case '=':
			emitIdent()

			l.next()
			l.emit(itemEquals)
			return lexQuotedDirectiveArgument
		case ';':
			emitIdent()

			l.next()
			l.emit(itemSemicolon)
			return lexQuotedDirectiveArgument
		case '%':
			emitIdent()

			l.next()
			l.emit(itemPercent)
			return lexQuotedDirectiveArgument
		case '{':
			emitIdent()

			l.next()
			l.emit(itemCurlyBraceOpen)
			return lexQuotedDirectiveArgument
		case '}':
			emitIdent()

			l.next()
			l.emit(itemCurlyBraceClose)
			return lexQuotedDirectiveArgument
		case '+':
			emitIdent()

			l.next()
			l.emit(itemPlus)
			return lexQuotedDirectiveArgument
		case '-':
			emitIdent()

			l.next()
			l.emit(itemMinus)
			return lexQuotedDirectiveArgument
		case '!':
			emitIdent()

			l.next()
			l.emit(itemExclamation)
			return lexQuotedDirectiveArgument
		case '/':
			emitIdent()

			l.next()
			l.emit(itemForwardSlash)
			return lexQuotedDirectiveArgument

		default:
			// If none of the above, then the char is part of an identifer
		}
	}
}

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dylandreimerink/go-modsec-parser/ast"
)

func parseDocument(lexer *lexer) (*ast.Document, error) {
	doc := &ast.Document{}

	tokens := []item{}

	for {
		item := lexer.nextItem()
		if item.typ == itemEOF {
			break
		}

		if item.typ == itemError {
			//TODO give error more details
			return doc, errors.New(item.val)
		}

		tokens = append(tokens, item)
	}

	for {
		if len(tokens) == 0 {
			break
		}

		var node ast.Node
		var err error

		switch tokens[0].typ {
		case itemCommentStart:
			node, tokens, err = parseComment(tokens)
		case itemDirective:
			node, tokens, err = parseDirective(tokens)
		default:
			err = fmt.Errorf("Unexpected '%s' at '%s', expected comment or directive", tokens[0].val, tokens[0].start)
		}

		if err != nil {
			return doc, err
		}

		if node != nil {
			node.SetParent(doc)
			doc.AddChild(node)
		}
	}

	return doc, nil
}

func parseComment(tokens []item) (*ast.Comment, []item, error) {
	comment := &ast.Comment{}

	//If a line has just a # there will be no comment item af the start
	if tokens[1].typ == itemComment {
		comment.Value = tokens[1].val
		return comment, tokens[2:], nil
	}

	return comment, tokens[1:], nil
}

func parseDirective(tokens []item) (ast.Directive, []item, error) {
	var directive ast.Directive
	var err error

	switch strings.ToLower(tokens[0].val) {
	case strings.ToLower((&ast.DirectiveSecAction{}).Name()):
		directive, tokens, err = parseDirectiveSecAction(tokens[1:])

	case strings.ToLower((&ast.DirectiveSecComponentSignature{}).Name()):
		directive, tokens, err = parseDirectiveSecComponentSignature(tokens[1:])

	case strings.ToLower((&ast.DirectiveSecMarker{}).Name()):
		secMarker := &ast.DirectiveSecMarker{}

		//Consume all tokens until the start of the first argument
		tokens = tokens[1:]
		for tokens[0].typ != itemArgumentStart {
			tokens = tokens[1:]
		}
		tokens = tokens[1:]

		for tokens[0].typ != itemArgumentStop {
			secMarker.Value += tokens[0].val
			tokens = tokens[1:]
		}
		tokens = tokens[1:]

		directive = secMarker

	case strings.ToLower((&ast.DirectiveSecRule{}).Name()):
		directive, tokens, err = parseDirectiveSecRule(tokens[1:])

	case strings.ToLower((&ast.DirectiveSecRuleEngine{}).Name()):
		secRuleEngine := &ast.DirectiveSecRuleEngine{}

		//Consume all tokens until the start of the first argument
		tokens = tokens[1:]
		for tokens[0].typ != itemArgumentStart {
			tokens = tokens[1:]
		}

		secRuleEngine.Value, tokens, err = parseDirectiveSecRuleEngineValue(tokens[1:])
		directive = secRuleEngine
	default:
		return nil, tokens, fmt.Errorf("Unknown directive '%s' at '%s'", tokens[0].val, tokens[0].start)
	}

	return directive, tokens, err
}

func parseDirectiveSecRuleEngineValue(tokens []item) (ast.SecRuleEngineValue, []item, error) {
	switch strings.ToLower(tokens[0].val) {
	case strings.ToLower(string(ast.SecRuleEngineOn)):
		return ast.SecRuleEngineOn, tokens[1:], nil

	case strings.ToLower(string(ast.SecRuleEngineOff)):
		return ast.SecRuleEngineOff, tokens[1:], nil

	case strings.ToLower(string(ast.SecRuleEngineDetectionOnly)):
		return ast.SecRuleEngineDetectionOnly, tokens[1:], nil

	default:
		return ast.SecRuleEngineValue(""), tokens, fmt.Errorf("Unknown SecRuleEngine value '%s' at '%s'", tokens[0].val, tokens[0].start)
	}
}

func parseDirectiveSecAction(tokens []item) (*ast.DirectiveSecAction, []item, error) {
	if tokens[0].typ != itemArgumentStart {
		return nil, tokens, fmt.Errorf("Unexpected '%s' as '%s', Expected start of argument", tokens[0].typ, tokens[0].start)
	}

	secAction := &ast.DirectiveSecAction{}
	var err error

	secAction.ActionNodes, tokens, err = parseActionList(tokens)

	return secAction, tokens, err
}

func parseDirectiveSecComponentSignature(tokens []item) (*ast.DirectiveSecComponentSignature, []item, error) {
	if tokens[0].typ != itemArgumentStart {
		return nil, tokens, fmt.Errorf("Unexpected '%s' as '%s', Expected start of argument", tokens[0].typ, tokens[0].start)
	}

	tokens = tokens[1:]

	secCompSig := &ast.DirectiveSecComponentSignature{}

	for {
		if len(tokens) == 0 {
			//TODO make unexpected end of argument error
			break
		}

		if tokens[0].typ == itemArgumentStop {
			tokens = tokens[1:]
			break
		}

		secCompSig.Signature += tokens[0].val

		tokens = tokens[1:]
	}

	return secCompSig, tokens, nil
}

//Parses a SecRule from a slice of tokens
// A rule has 3 components: a list of variables, a operator function and an action list
func parseDirectiveSecRule(tokens []item) (*ast.DirectiveSecRule, []item, error) {
	rule := &ast.DirectiveSecRule{}

	var err error

	rule.Variable, tokens, err = parseSecRuleVariableList(tokens)
	if err != nil {
		return nil, tokens, err
	}

	rule.Operator, tokens, err = parseSecRuleOperator(tokens)
	if err != nil {
		return nil, tokens, err
	}

	rule.ActionNodes, tokens, err = parseActionList(tokens)
	if err != nil {
		return nil, tokens, err
	}

	return rule, tokens, nil
}

func parseSecRuleOperator(tokens []item) (ast.Operator, []item, error) {

	//Remove all trailing tokens before the argument
	for {
		if tokens[0].typ == itemArgumentStart {
			tokens = tokens[1:]
			break
		}
		tokens = tokens[1:]
	}

	negative := false

	if tokens[0].typ == itemExclamation && tokens[1].typ == itemAt {
		negative = true
		tokens = tokens[1:]
	}

	//If there is no @ at the beginning it is a regex op
	if tokens[0].typ != itemAt {
		regexOp := &ast.OperatorRegex{}

		for {
			if len(tokens) == 0 {
				return regexOp, tokens[1:], nil
			}

			if tokens[0].typ == itemArgumentStop {
				return regexOp, tokens[1:], nil
			}

			regexOp.Value += tokens[0].val
			tokens = tokens[1:]
		}
	}

	tokens = tokens[1:]

	if tokens[0].typ != itemIdent {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected operator name", tokens[0].val, tokens[0].start)
	}

	var operator ast.Operator

	switch strings.ToLower(tokens[0].val) {
	case strings.ToLower((&ast.OperatorRegex{}).Name()):
		regexOp := &ast.OperatorRegex{}
		if tokens[1].typ == itemWhitespace {
			tokens = tokens[2:]
			for {
				if len(tokens) == 0 {
					break
				}

				if tokens[0].typ == itemArgumentStop {
					tokens = tokens[1:]
					break
				}

				regexOp.Value += tokens[0].val
				tokens = tokens[1:]
			}
		} else {
			return operator, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected operator argument", tokens[0].val, tokens[0].start)
		}
		operator = regexOp
	case strings.ToLower((&ast.OperatorEquals{}).Name()):
		op := &ast.OperatorEquals{}

		if tokens[1].typ == itemWhitespace {

			var err error
			op.Value, tokens, err = parseExpandableStringOperatorArgument(tokens[2:])
			if err != nil {
				return operator, tokens, err
			}

		} else {
			return operator, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected operator argument", tokens[0].val, tokens[0].start)
		}

		operator = op
	case strings.ToLower((&ast.OperatorLessThanOrEqual{}).Name()):
		op := &ast.OperatorLessThanOrEqual{}

		if tokens[1].typ == itemWhitespace {

			var err error
			op.Value, tokens, err = parseExpandableStringOperatorArgument(tokens[2:])
			if err != nil {
				return operator, tokens, err
			}

		} else {
			return operator, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected operator argument", tokens[0].val, tokens[0].start)
		}

		operator = op

	case strings.ToLower((&ast.OperatorLessThan{}).Name()):
		op := &ast.OperatorLessThan{}

		if tokens[1].typ == itemWhitespace {

			var err error
			op.Value, tokens, err = parseExpandableStringOperatorArgument(tokens[2:])
			if err != nil {
				return operator, tokens, err
			}

		} else {
			return operator, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected operator argument", tokens[0].val, tokens[0].start)
		}

		operator = op
	}

	if operator != nil {
		operator.SetNegative(negative)
	}

	return operator, tokens, nil
}

func parseExpandableStringOperatorArgument(tokens []item) (*ast.ExpandableString, []item, error) {
	expStr := &ast.ExpandableString{}

	for {
		if len(tokens) == 0 {
			break
		}

		if tokens[0].typ == itemArgumentStop {
			tokens = tokens[1:]
			break
		}

		var part ast.ExpandableStringPart

		if tokens[0].typ == itemPercent {
			var err error
			part, tokens, err = parseStringMacro(tokens)
			if err != nil {
				return expStr, tokens, err
			}
		} else {
			part = &ast.StringPart{
				Value: tokens[0].val,
			}
			tokens = tokens[1:]
		}

		expStr.Parts = append(expStr.Parts, part)
	}

	return expStr, tokens, nil
}

func parseSecRuleVariableList(tokens []item) (*ast.VariableList, []item, error) {
	varList := &ast.VariableList{}

	variableTokens := []item{}

	consumedTokens := 0

	var err error

	started := false
	for _, token := range tokens {

		consumedTokens++

		//Ignore any tokens before the start of the directive argument
		if !started {
			if token.typ == itemArgumentStart {
				started = true
			}
			continue
		}

		//If we reached the end of the argument we stop
		if token.typ == itemArgumentStop {
			break
		}

		variableTokens = append(variableTokens, token)
	}

	//TODO error if no tokens are found

	for {
		if len(variableTokens) == 0 {
			break
		}

		var variableSelector *ast.VariableSelector
		variableSelector, variableTokens, err = parseSecRuleVariableSelector(variableTokens)
		if err != nil {
			return nil, tokens, err
		}

		varList.AddSelector(variableSelector)

		if len(variableTokens) > 0 {
			if variableTokens[0].typ != itemPipe {
				return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected variable seperator or end of argument", variableTokens[0].val, variableTokens[0].start)
			}

			variableTokens = variableTokens[1:]
		}
	}

	return varList, tokens[consumedTokens:], nil
}

func parseSecRuleVariableSelector(tokens []item) (*ast.VariableSelector, []item, error) {
	selector := &ast.VariableSelector{
		SelectorOperation: ast.VARIABLE_SELECTION_ADD,
	}

	if tokens[0].typ == itemExclamation {
		selector.SelectorOperation = ast.VARIABLE_SELECTION_REMOVE
		tokens = tokens[1:]
	} else if tokens[0].typ == itemAmpresant {
		selector.SelectorOperation = ast.VARIABLE_SELECTION_COUNT
		tokens = tokens[1:]
	}

	var err error

	selector.Variable, tokens, err = parseVariable(tokens)
	if err != nil {
		return nil, tokens, err
	}

	//If this variable is not a collection we don't have to look for a collection selector
	if !selector.Variable.IsCollection() {
		return selector, tokens, nil
	}

	//If there are no more tokens, we are done parsing
	if len(tokens) < 2 {
		return selector, tokens, nil
	}

	if tokens[0].typ == itemColon {
		tokens = tokens[1:]

		//Regex
		if tokens[0].typ == itemForwardSlash {

			colSel := &ast.RegexVariableCollectionSelection{}

			tokens = tokens[1:]
			for {
				if len(tokens) == 0 || tokens[0].typ == itemForwardSlash {
					break
				}

				colSel.Value += tokens[0].val

				tokens = tokens[1:]
			}

			colSel.SetParent(selector)
			selector.CollectionSelector = colSel
		} else {

			colSel := &ast.KeyVariableCollectionSelection{}

			for {
				if len(tokens) == 0 || tokens[0].typ == itemPipe {
					break
				}

				colSel.Value += tokens[0].val

				tokens = tokens[1:]
			}

			colSel.SetParent(selector)
			selector.CollectionSelector = colSel
		}
	}

	return selector, tokens, nil
}

func parseVariable(tokens []item) (ast.Variable, []item, error) {
	if tokens[0].typ != itemIdent {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected variable or collection name", tokens[0].val, tokens[0].start)
	}

	switch strings.ToLower(tokens[0].val) {
	case strings.ToLower((&ast.VariableDuration{}).Name()):
		return &ast.VariableDuration{}, tokens[1:], nil

	case strings.ToLower((&ast.VariableRequestBodyProcessor{}).Name()):
		return &ast.VariableRequestBodyProcessor{}, tokens[1:], nil

	case strings.ToLower((&ast.VariableRequestHeaders{}).Name()):
		return &ast.VariableRequestHeaders{}, tokens[1:], nil

	case strings.ToLower((&ast.VariableTransientTransactionCollection{}).Name()):
		return &ast.VariableTransientTransactionCollection{}, tokens[1:], nil

	case strings.ToLower((&ast.VariableUniqueID{}).Name()):
		return &ast.VariableUniqueID{}, tokens[1:], nil
	}

	return nil, tokens, fmt.Errorf("Unknown variable name '%s' at '%s'", tokens[0].val, tokens[0].start)
}

func parseActionList(tokens []item) ([]ast.Action, []item, error) {
	actions := []ast.Action{}

	if tokens[0].typ != itemArgumentStart {
		return actions, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected directive argument", tokens[0].val, tokens[0].start)
	}

	tokens = tokens[1:]

	for {
		switch tokens[0].typ {
		case itemArgumentStop:
			return actions, tokens[1:], nil
		case itemEOF:
			return actions, tokens, fmt.Errorf("Unexpected EOF at '%s', expected end of directive argument", tokens[0].start)
		case itemComma, itemWhitespace:
			//Comma's and whitespace should be skipped, they are not actions
			//TODO validate that action arguments are separated by comma's for validation sake
			tokens = tokens[1:]
		case itemIdent:
			var action ast.Action
			var err error

			action, tokens, err = parseAction(tokens)
			if err != nil {
				return actions, tokens, err
			}

			actions = append(actions, action)
		default:
			return actions, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected action name", tokens[0].val, tokens[0].start)
		}
	}

	panic("Last token was not EOF")
}

func parseAction(tokens []item) (ast.Action, []item, error) {
	var action ast.Action
	var err error

	switch strings.ToLower(tokens[0].val) {

	case (&ast.ActionAccuracy{}).Name():
		action, tokens, err = parseActionAccuracy(tokens)

	case (&ast.ActionAllow{}).Name():
		action = &ast.ActionAllow{}
		tokens = tokens[1:]

	case (&ast.ActionAppend{}).Name():
		action, tokens, err = parseActionAppend(tokens)

	case (&ast.ActionAuditLog{}).Name():
		action = &ast.ActionAuditLog{}
		tokens = tokens[1:]

	case (&ast.ActionCapture{}).Name():
		action = &ast.ActionCapture{}
		tokens = tokens[1:]

	case (&ast.ActionChain{}).Name():
		action = &ast.ActionChain{}
		tokens = tokens[1:]

	case (&ast.ActionCTL{}).Name():
		action, tokens, err = parseActionCTL(tokens)

	case (&ast.ActionDeny{}).Name():
		action = &ast.ActionDeny{}
		tokens = tokens[1:]

	case (&ast.ActionID{}).Name():
		action, tokens, err = parseActionID(tokens)

	case (&ast.ActionInitcol{}).Name():
		action, tokens, err = parseActionInitcol(tokens)

	case (&ast.ActionLog{}).Name():
		action = &ast.ActionLog{}
		tokens = tokens[1:]

	case (&ast.ActionMessage{}).Name():
		action, tokens, err = parseActionMessage(tokens)

	case (&ast.ActionNoAuditLog{}).Name():
		action = &ast.ActionNoAuditLog{}
		tokens = tokens[1:]

	case (&ast.ActionNoLog{}).Name():
		action = &ast.ActionNoLog{}
		tokens = tokens[1:]

	case (&ast.ActionPass{}).Name():
		action = &ast.ActionPass{}
		tokens = tokens[1:]

	case (&ast.ActionPhase{}).Name():
		action, tokens, err = parseActionPhase(tokens)

	case (&ast.ActionSeverity{}).Name():
		action, tokens, err = parseActionSeverity(tokens)

	case (&ast.ActionSetVar{}).Name():
		action, tokens, err = parseActionSetVar(tokens)

	case (&ast.ActionSkipAfter{}).Name():
		action, tokens, err = parseActionSkipAfter(tokens)

	case (&ast.ActionStatus{}).Name():
		action, tokens, err = parseActionStatus(tokens)

	case (&ast.ActionTransform{}).Name():
		action, tokens, err = parseActionTransform(tokens)

	case (&ast.ActionTag{}).Name():
		action, tokens, err = parseActionTag(tokens)

	case (&ast.ActionVer{}).Name():
		action, tokens, err = parseActionVer(tokens)

	default:
		err = fmt.Errorf("Unknown action '%s' at '%s'", tokens[0].val, tokens[0].start)
	}

	return action, tokens, err
}

func parseActionMessage(tokens []item) (*ast.ActionMessage, []item, error) {
	action := &ast.ActionMessage{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	var err error
	action.Value, tokens, err = parseExpandableStringActionArgument(tokens[2:])
	if err != nil {
		return action, tokens, err
	}

	return action, tokens, nil
}

func parseActionSkipAfter(tokens []item) (*ast.ActionSkipAfter, []item, error) {
	action := &ast.ActionSkipAfter{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	var err error
	action.Value, tokens, err = parseExpandableStringActionArgument(tokens[2:])
	if err != nil {
		return action, tokens, err
	}

	return action, tokens, nil
}

func parseActionTag(tokens []item) (*ast.ActionTag, []item, error) {
	action := &ast.ActionTag{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	var err error
	action.Value, tokens, err = parseExpandableStringActionArgument(tokens[2:])
	if err != nil {
		return action, tokens, err
	}

	return action, tokens, nil
}

func parseActionVer(tokens []item) (*ast.ActionVer, []item, error) {
	action := &ast.ActionVer{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	var err error
	action.Value, tokens, err = parseExpandableStringActionArgument(tokens[2:])
	if err != nil {
		return action, tokens, err
	}

	return action, tokens, nil
}

func parseActionCTL(tokens []item) (*ast.ActionCTL, []item, error) {
	action := &ast.ActionCTL{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	switch strings.ToLower(tokens[2].val) {
	case strings.ToLower((&ast.ActionCTLForceRequestBodyVariable{}).Name()):
		if tokens[3].typ != itemEquals {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a equals sign", tokens[3].val, tokens[3].start)
		}

		action.Option = &ast.ActionCTLForceRequestBodyVariable{
			Enabled: strings.ToLower(tokens[4].val) == "on",
		}

		tokens = tokens[5:]

	case strings.ToLower((&ast.ActionCTLRequestBodyProcessor{}).Name()):
		if tokens[3].typ != itemEquals {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a equals sign", tokens[3].val, tokens[3].start)
		}

		option := &ast.ActionCTLRequestBodyProcessor{}

		switch strings.ToLower(tokens[4].val) {
		case strings.ToLower(string(ast.RequestBodyProcessorTypeURLEncoded)):
			option.Processor = ast.RequestBodyProcessorTypeURLEncoded

		case strings.ToLower(string(ast.RequestBodyProcessorTypeMultipart)):
			option.Processor = ast.RequestBodyProcessorTypeMultipart

		case strings.ToLower(string(ast.RequestBodyProcessorTypeJSON)):
			option.Processor = ast.RequestBodyProcessorTypeJSON

		case strings.ToLower(string(ast.RequestBodyProcessorTypeXML)):
			option.Processor = ast.RequestBodyProcessorTypeXML
		default:
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected: URLENCODED, MULTIPART, JSON or XML", tokens[4].val, tokens[4].start)
		}

		action.Option = option

		tokens = tokens[5:]

	case strings.ToLower("ruleEngine"):
		if tokens[3].typ != itemEquals {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a equals sign", tokens[3].val, tokens[3].start)
		}

		option := &ast.DirectiveSecRuleEngine{}

		var err error
		option.Value, tokens, err = parseDirectiveSecRuleEngineValue(tokens[4:])
		if err != nil {
			return nil, tokens, err
		}

		action.Option = option

	default:
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a ctl config option", tokens[2].val, tokens[2].start)
	}

	return action, tokens, nil
}

func parseActionAppend(tokens []item) (*ast.ActionAppend, []item, error) {
	action := &ast.ActionAppend{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	var err error
	action.Value, tokens, err = parseExpandableStringActionArgument(tokens[2:])
	if err != nil {
		return action, tokens, err
	}

	return action, tokens, nil
}

func parseExpandableStringActionArgument(tokens []item) (*ast.ExpandableString, []item, error) {
	expString := &ast.ExpandableString{}

	stringTokens := []item{}

	if tokens[0].typ == itemSingleQuote {
		tokens = tokens[1:]
		for {
			if len(tokens) == 0 {
				break
			}

			//TODO handle escaped single quote

			if tokens[0].typ == itemSingleQuote {
				tokens = tokens[1:]
				break
			}

			stringTokens = append(stringTokens, tokens[0])
			tokens = tokens[1:]
		}
	} else {
		for {
			if len(tokens) == 0 {
				break
			}

			//A unquoted action argument ends at the end of the Directive argument end or at a comma in the action list
			if tokens[0].typ == itemArgumentStop || tokens[0].typ == itemComma {
				break
			}

			stringTokens = append(stringTokens, tokens[0])
			tokens = tokens[1:]
		}
	}

	for {
		if len(stringTokens) == 0 {
			break
		}

		var part ast.ExpandableStringPart

		//If the token is % it indicates a string macro
		if stringTokens[0].typ == itemPercent {
			var err error
			part, stringTokens, err = parseStringMacro(stringTokens)
			if err != nil {
				return nil, tokens, err
			}
		} else {
			part = &ast.StringPart{
				Value: stringTokens[0].val,
			}

			stringTokens = stringTokens[1:]
		}

		expString.Parts = append(expString.Parts, part)
	}

	return expString, tokens, nil
}

func parseActionAccuracy(tokens []item) (*ast.ActionAccuracy, []item, error) {
	action := &ast.ActionAccuracy{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	var accStr string

	switch tokens[2].typ {
	case itemSingleQuote:
		if tokens[3].typ != itemIdent {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected number between 0 and 9", tokens[1].val, tokens[1].start)
		}

		if tokens[4].typ != itemSingleQuote {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected single quote (')", tokens[1].val, tokens[1].start)
		}

		accStr = tokens[3].val
		tokens = tokens[5:]
	case itemIdent:
		accStr = tokens[2].val
		tokens = tokens[3:]
	default:
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected number between 0 and 9 or start of string", tokens[0].val, tokens[0].start)
	}

	acc, err := strconv.Atoi(accStr)
	if err != nil || acc < 0 || acc > 9 {
		return nil, tokens, fmt.Errorf("Value of accuracy action must be a number between 0 and 9, got: '%s' at '%s'", accStr, tokens[0].start)
	}

	action.Value = acc

	return action, tokens, nil
}

func parseActionID(tokens []item) (*ast.ActionID, []item, error) {
	action := &ast.ActionID{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	if tokens[2].typ != itemIdent {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected id number", tokens[2].val, tokens[2].start)
	}

	id, err := strconv.Atoi(tokens[2].val)
	if err != nil {
		return nil, tokens, fmt.Errorf("Value of id action must be a number, got: '%s' at '%s'", tokens[2].val, tokens[2].start)
	}

	action.Value = id

	return action, tokens[3:], nil
}

func parseActionStatus(tokens []item) (*ast.ActionStatus, []item, error) {
	action := &ast.ActionStatus{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	if tokens[2].typ != itemIdent {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected status number", tokens[2].val, tokens[2].start)
	}

	status, err := strconv.Atoi(tokens[2].val)
	if err != nil || status < 100 || status > 599 {
		return nil, tokens, fmt.Errorf("Value of status action must be a number following the pattern 1xx, 2xx, 3xx, 4xx or 5xx, got: '%s' at '%s'", tokens[2].val, tokens[2].start)
	}
	action.Value = status

	return action, tokens[3:], nil
}

func parseActionPhase(tokens []item) (*ast.ActionPhase, []item, error) {
	action := &ast.ActionPhase{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	var phaseStr string

	switch tokens[2].typ {
	case itemSingleQuote:
		if tokens[3].typ != itemIdent {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected phase number or string", tokens[3].val, tokens[3].start)
		}

		if tokens[4].typ != itemSingleQuote {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected single quote (')", tokens[4].val, tokens[4].start)
		}

		phaseStr = tokens[3].val
		tokens = tokens[5:]
	case itemIdent:
		phaseStr = tokens[2].val
		tokens = tokens[3:]
	default:
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected phase number or start of string", tokens[0].val, tokens[0].start)
	}

	switch strings.ToLower(phaseStr) {
	case "request":
		action.Value = 2
	case "response":
		action.Value = 4
	case "logging":
		action.Value = 5
	default:
		phase, err := strconv.Atoi(phaseStr)
		if err != nil || phase < 1 || phase > 5 {
			return nil, tokens, fmt.Errorf("Value of phase action must be a number between 1 and 5, got: '%s' at '%s'", phaseStr, tokens[0].start)
		}
		action.Value = phase
	}

	return action, tokens, nil
}

func parseActionSeverity(tokens []item) (*ast.ActionSeverity, []item, error) {
	action := &ast.ActionSeverity{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	var severityStr string

	switch tokens[2].typ {
	case itemSingleQuote:
		if tokens[3].typ != itemIdent {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected severity number or string", tokens[3].val, tokens[3].start)
		}

		if tokens[4].typ != itemSingleQuote {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected single quote (')", tokens[4].val, tokens[4].start)
		}

		severityStr = tokens[3].val
		tokens = tokens[5:]
	case itemIdent:
		severityStr = tokens[2].val
		tokens = tokens[3:]
	default:
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected severity number or start of string", tokens[0].val, tokens[0].start)
	}

	switch strings.ToLower(severityStr) {
	case "emergency":
		action.Value = 0
	case "alert":
		action.Value = 1
	case "critical":
		action.Value = 2
	case "error":
		action.Value = 3
	case "warning":
		action.Value = 4
	case "notice":
		action.Value = 5
	case "info":
		action.Value = 6
	case "debug":
		action.Value = 7
	default:
		severity, err := strconv.Atoi(severityStr)
		if err != nil || severity < 0 || severity > 7 {
			return nil, tokens, fmt.Errorf("Value of severity action must be a number between 0 and 7, got: '%s' at '%s'", severityStr, tokens[0].start)
		}
		action.Value = severity
	}

	return action, tokens, nil
}

func parseActionInitcol(tokens []item) (*ast.ActionInitcol, []item, error) {
	action := &ast.ActionInitcol{}

	action.Collection = &ast.ExpandableString{}
	action.Collection.SetParent(action)
	action.Modifier = &ast.ExpandableString{}
	action.Modifier.SetParent(action)

	var err error

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	actionValueTokens := []item{}

	//The action name + the colon
	consumedTokens := 2

	//If the first token is a single quote, all tokens until the next single quote are part of the action value
	if tokens[2].typ == itemSingleQuote {
		for _, token := range tokens[3:] {
			if token.typ == itemSingleQuote {
				break
			}

			actionValueTokens = append(actionValueTokens, token)
		}

		//TODO handle non existant second single quote

		//Two single quotes
		consumedTokens += 2
	} else {
		//all tokens until the next comma are part of the action value
		for _, token := range tokens[2:] {
			if token.typ == itemComma {
				break
			}

			actionValueTokens = append(actionValueTokens, token)
		}
	}

	consumedTokens += len(actionValueTokens)

	foundOp := false

	for {
		if len(actionValueTokens) == 0 {
			break
		}

		var part ast.ExpandableStringPart

		//If the token is % it indicates a string macro
		switch actionValueTokens[0].typ {
		case itemPercent:
			part, actionValueTokens, err = parseStringMacro(actionValueTokens)
			if err != nil {
				return nil, tokens, err
			}
		case itemEquals:

			foundOp = true
			actionValueTokens = actionValueTokens[1:]

			//There is no string part on this iteration, so continue the loop
			continue
		default:

			//If the token has no special meaning in this context, add it as a plain string part
			part = &ast.StringPart{Value: actionValueTokens[0].val}
			actionValueTokens = actionValueTokens[1:]
		}

		if foundOp {
			action.Modifier.Parts = append(action.Modifier.Parts, part)
		} else {
			action.Collection.Parts = append(action.Collection.Parts, part)
		}
	}

	return action, tokens[consumedTokens:], nil
}

func parseActionSetVar(tokens []item) (*ast.ActionSetVar, []item, error) {
	action := &ast.ActionSetVar{}

	action.Variable = &ast.ExpandableString{}
	action.Variable.SetParent(action)

	var err error

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	actionValueTokens := []item{}

	//The action name + the colon
	consumedTokens := 2

	//If the first token is a single quote, all tokens until the next single quote are part of the action value
	if tokens[2].typ == itemSingleQuote {
		for _, token := range tokens[3:] {
			if token.typ == itemSingleQuote {
				break
			}

			actionValueTokens = append(actionValueTokens, token)
		}

		//TODO handle non existant second single quote

		//Two single quotes
		consumedTokens += 2
	} else {
		//all tokens until the next comma are part of the action value
		for _, token := range tokens[2:] {
			if token.typ == itemComma {
				break
			}

			actionValueTokens = append(actionValueTokens, token)
		}
	}

	consumedTokens += len(actionValueTokens)

	//If the first item is an ! the operator is 'delete'
	if actionValueTokens[0].typ == itemExclamation {
		action.Op = ast.SET_VAR_DELETE
		actionValueTokens = actionValueTokens[1:]
	}

	for {
		if len(actionValueTokens) == 0 {
			break
		}

		var part ast.ExpandableStringPart

		//If the token is % it indicates a string macro
		switch actionValueTokens[0].typ {
		case itemPercent:
			part, actionValueTokens, err = parseStringMacro(actionValueTokens)
			if err != nil {
				return nil, tokens, err
			}
		case itemDot:

			if action.Collection == nil {
				action.Collection = &ast.ExpandableString{}
				action.Collection.SetParent(action)
			}

			//If there is no collection, this dot indicates that all we have parsed before was part of the collection not the variable
			if len(action.Collection.Parts) == 0 {
				//Move parts from variable to collection
				for _, part := range action.Variable.Parts {
					action.Collection.Parts = append(action.Collection.Parts, part)
				}

				//shrink slice to 0
				action.Variable.Parts = action.Variable.Parts[:0]
			} else {
				part = &ast.StringPart{Value: actionValueTokens[0].val}
			}

			actionValueTokens = actionValueTokens[1:]

			//There is no string part on this iteration, so continue the loop
			continue
		case itemEquals:

			if actionValueTokens[1].typ == itemPlus {
				action.Op = ast.SET_VAR_ADD
				actionValueTokens = actionValueTokens[2:]
			} else if actionValueTokens[1].typ == itemMinus {
				action.Op = ast.SET_VAR_SUB
				actionValueTokens = actionValueTokens[2:]
			} else {
				action.Op = ast.SET_VAR_SET
				actionValueTokens = actionValueTokens[1:]
			}

			//There is no string part on this iteration, so continue the loop
			continue
		default:

			//If the token has no special meaning in this context, add it as a plain string part
			part = &ast.StringPart{Value: actionValueTokens[0].val}
			actionValueTokens = actionValueTokens[1:]
		}

		//If the operator is 0 we have not yet encountered an operator so we add the part to the variable
		//if the operator is delete, there is no modifier so we also append any part to the variable
		if action.Op == 0 || action.Op == ast.SET_VAR_DELETE {
			action.Variable.Parts = append(action.Variable.Parts, part)
		} else {
			if action.Modifier == nil {
				action.Modifier = &ast.ExpandableString{}
				action.Modifier.SetParent(action)
			}

			action.Modifier.Parts = append(action.Modifier.Parts, part)
		}
	}

	return action, tokens[consumedTokens:], nil
}

func parseStringMacro(tokens []item) (*ast.StringMacro, []item, error) {
	if tokens[0].typ != itemPercent {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected %% as start of string macro", tokens[0].val, tokens[0].start)
	}

	if tokens[1].typ != itemCurlyBraceOpen {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected { as start of string macro", tokens[1].val, tokens[1].start)
	}

	if tokens[2].typ != itemIdent {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected variable or collection name", tokens[2].val, tokens[2].start)
	}

	if tokens[3].typ == itemCurlyBraceClose {
		return &ast.StringMacro{Variable: tokens[2].val}, tokens[4:], nil

		//if token is dot the macro has the {collection}.{variable} format
	} else if tokens[3].typ == itemDot {

		if tokens[4].typ != itemIdent {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected variable name", tokens[4].val, tokens[4].start)
		}

		if tokens[5].typ != itemCurlyBraceClose {
			return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected } as end of string macro", tokens[5].val, tokens[5].start)
		}

		return &ast.StringMacro{Collection: tokens[2].val, Variable: tokens[4].val}, tokens[6:], nil
	}

	return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected dot or } as end of string macro", tokens[3].val, tokens[3].start)
}

func parseActionTransform(tokens []item) (*ast.ActionTransform, []item, error) {
	action := &ast.ActionTransform{}

	if tokens[1].typ != itemColon {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a colon", tokens[1].val, tokens[1].start)
	}

	if tokens[2].typ != itemIdent {
		return nil, tokens, fmt.Errorf("Unexpected '%s' at '%s', expected a transfrom name", tokens[2].val, tokens[2].start)
	}

	switch strings.ToLower(tokens[2].val) {

	case strings.ToLower((&ast.TransformBase64Decode{}).Name()):
		action.Value = &ast.TransformBase64Decode{}

	case strings.ToLower((&ast.TransformHexEncode{}).Name()):
		action.Value = &ast.TransformHexEncode{}

	case strings.ToLower((&ast.TransformNone{}).Name()):
		action.Value = &ast.TransformNone{}

	case strings.ToLower((&ast.TransformUrlDecodeUni{}).Name()):
		action.Value = &ast.TransformUrlDecodeUni{}

	case strings.ToLower((&ast.TransformSHA1{}).Name()):
		action.Value = &ast.TransformSHA1{}

	default:
		return nil, tokens, fmt.Errorf("Unknown transform type '%s' at '%s'", tokens[2].val, tokens[2].start)
	}

	return action, tokens[3:], nil
}

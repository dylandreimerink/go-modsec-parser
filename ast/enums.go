package ast

import (
	"errors"
	"strconv"
)

type ModsecPhase int

const (
	ModsecPhaseRequestHeaders  ModsecPhase = 1
	ModsecPhaseRequestBody     ModsecPhase = 2
	ModsecPhaseResponseHeaders ModsecPhase = 3
	ModsecPhaseResponseBody    ModsecPhase = 4
	ModsecPhaseLogging         ModsecPhase = 5
)

func (phase ModsecPhase) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("Phase should be a singular value")
	}

	value := values[0]

	switch value {
	case "request":
		phase = ModsecPhaseRequestBody
		break
	case "response":
		phase = ModsecPhaseResponseBody
		break
	case "logging":
		phase = ModsecPhaseLogging
		break
	default:
		num, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("Invalid phase must be between 1 and 5")
		}

		if num < int(ModsecPhaseRequestHeaders) || num > int(ModsecPhaseLogging) {
			return errors.New("Invalid phase must be between 1 and 5")
		}

		phase = ModsecPhase(num)
	}

	return nil
}

func (phase ModsecPhase) String() string {
	names := [...]string{
		"INVALID_PHASE",
		"REQUEST_HEADERS",
		"REQUEST_BODY",
		"RESPONSE_HEADERS",
		"RESPONSE_BODY",
		"LOGGING",
	}

	if phase < ModsecPhaseRequestHeaders || phase > ModsecPhaseLogging {
		return "INVALID_PHASE"
	}

	return names[phase]
}

type ModsecSeverity int

const (
	ModsecSeverityEmergency ModsecSeverity = iota
	ModsecSeverityAlert
	ModsecSeverityCritical
	ModsecSeverityError
	ModsecSeverityWarning
	ModsecSeverityNotice
	ModsecSeverityInfo
	ModsecSeverityDebug
)

func (severity ModsecSeverity) String() string {
	names := [...]string{
		"EMERGENCY",
		"ALERT",
		"CRITICAL",
		"ERROR",
		"WARNING",
		"NOTICE",
		"INFO",
		"DEBUG",
	}

	if severity < ModsecSeverityEmergency || severity > ModsecSeverityDebug {
		return "UNKNOWN"
	}

	return names[severity]
}

func (severity ModsecSeverity) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("Severity should be a singular value")
	}

	value := values[0]

	switch value {
	case "EMERGENCY":
		severity = ModsecSeverityEmergency
		break
	case "ALERT":
		severity = ModsecSeverityAlert
		break
	case "CRITICAL":
		severity = ModsecSeverityCritical
		break
	case "ERROR":
		severity = ModsecSeverityError
		break
	case "WARNING":
		severity = ModsecSeverityWarning
		break
	case "NOTICE":
		severity = ModsecSeverityNotice
		break
	case "INFO":
		severity = ModsecSeverityInfo
		break
	case "DEBUG":
		severity = ModsecSeverityDebug
		break
	default:
		num, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("Invalid phase must be between 1 and 5")
		}

		if num < int(ModsecSeverityEmergency) || num > int(ModsecSeverityDebug) {
			return errors.New("Invalid severity must be between 0 and 7")
		}

		severity = ModsecSeverity(num)
	}

	return nil
}

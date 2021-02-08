package ovmgmt

import (
	"fmt"
	"reflect"
	"strings"
)

type eventEndMarker string

const (
	emSingleLine eventEndMarker = ""
	emClient                    = clientEventKW + eventSep + clientEnvMarker + fieldSep + endMessage
)

const eventSep = ":"
const fieldSep = ","
const byteCountEventKW = "BYTECOUNT"
const byteCountCliEventKW = "BYTECOUNT_CLI"
const echoEventKW = "ECHO"
const fatalEventKW = "FATAL"
const holdEventKW = "HOLD"
const infoEventKW = "INFO"
const logEventKW = "LOG"
const needOkEventKW = "NEED-OK"
const needStrEventKW = "NEED-STR"
const passwordEventKW = "PASSWORD"
const stateEventKW = "STATE"

const clientEventKW = "CLIENT"

var ErrNoMsgFieldSep = NewOVpnError("no field sep '" + fieldSep + "' found")

type Event interface {
	String() string
	Raw() string
}

type MultilineEvent interface {
	Event
}

type SimpleEvent struct {
	keyword string
	body    string
}

func NewSimpleEvent(keyword, body string) SimpleEvent {
	return SimpleEvent{keyword, body}
}

func (e SimpleEvent) Raw() string {
	return e.keyword + eventSep + e.body
}

func (e SimpleEvent) Type() string {
	return e.keyword
}

func (e SimpleEvent) Body() string {
	return e.body
}

func (e SimpleEvent) String() string {
	return fmt.Sprintf("%s: %s", e.keyword, e.body)
}

// UnknownEvent represents an event of a type that this package doesn't
// know about.
//
// Future versions of this library may learn about new event types, so a
// caller should exercise caution when making use of events of this type
// to access unsupported behavior. Backward-compatibility is *not*
// guaranteed for events of this type.
type UnknownEvent struct {
	keyword string
	body    string
}

func NewUnknownEvent(keyword, body string) UnknownEvent {
	return UnknownEvent{keyword, body}
}

func (e UnknownEvent) Raw() string {
	return e.keyword + eventSep + e.body
}

func (e UnknownEvent) Type() string {
	return e.keyword
}

func (e UnknownEvent) Body() string {
	return e.body
}

func (e UnknownEvent) String() string {
	return fmt.Sprintf("Unknown event %s: %s", e.keyword, e.body)
}

// MalformedEvent represents a message from the OpenVPN process that is
// presented as an event but does not comply with the expected event syntax.
//
// Events of this type should never be seen but robust callers will accept
// and ignore them, possibly generating some kind of debugging message.
//
// One reason for potentially seeing events of this type is when the target
// program is actually not an OpenVPN process at all, but in fact this client
// has been connected to a different sort of server by mistake.
type MalformedEvent struct {
	raw string
}

func NewMalformedEvent(raw string) MalformedEvent {
	return MalformedEvent{raw}
}

func (e MalformedEvent) Raw() string {
	return e.raw
}

func (e MalformedEvent) String() string {
	return fmt.Sprintf("Malformed Event %q", e.raw)
}

// InvalidEvent represents a message from the OpenVPN process that is
// presented as an knowable event but does not comply with the specific
// event syntax.
type InvalidEvent struct {
	orig       Event
	firstError error
}

func NewInvalidEvent(evt Event, err error) InvalidEvent {
	return InvalidEvent{evt, err}
}

func (e InvalidEvent) Raw() string {
	if e.orig == nil {
		return ""
	}
	return e.orig.Raw()
}

func (e InvalidEvent) String() string {
	return fmt.Sprintf("Invalid %q Event: %s; data: %s", reflect.TypeOf(e.Origin()), e.firstError, e.Raw())
}

func (e InvalidEvent) Origin() Event {
	return e.orig
}

func (e InvalidEvent) Error() string {
	return e.firstError.Error()
}

func (e InvalidEvent) FirstError() error {
	return e.firstError
}

func splitEvent(line string) (eventEndMarker, string, string) {
	splitIdx := strings.Index(line, eventSep)
	if splitIdx == -1 {
		// Should never happen, but we'll handle it robustly if it does.
		return emSingleLine, "", line
	}

	keyword := line[:splitIdx]
	body := line[splitIdx+1:]

	if keyword == clientEventKW {
		// >CLIENT:{notificationType},{notificationParams}
		if strings.HasPrefix(body, string(CEConnect)) || strings.HasPrefix(body, string(CEReauth)) ||
			strings.HasPrefix(body, string(CEEstablished)) || strings.HasPrefix(body, string(CEDisconnect)) ||
			strings.HasPrefix(body, string(clientEnvMarker)) {
			return emClient, keyword, body
		}
	}
	return emSingleLine, keyword, body
}

func upgradeEvent(keyword, body string) Event {
	var evt Event
	var err error

	switch keyword {
	case "":
		evt = NewMalformedEvent(body)
	case logEventKW:
		evt, err = NewLogEvent(body)
	case stateEventKW:
		evt, err = NewStateEvent(body)
	case holdEventKW:
		evt = NewHoldEvent(body)
	case echoEventKW:
		evt, err = NewEchoEvent(body)
	case byteCountEventKW:
		evt, err = NewByteCountEvent(body)
	case byteCountCliEventKW:
		evt, err = NewByteCountClientEvent(body)
	case clientEventKW:
		evt, err = NewClientEvent([]string{body})
	case infoEventKW:
		evt = NewSimpleEvent(keyword, body)
	case needOkEventKW:
		evt = NewSimpleEvent(keyword, body)
	case needStrEventKW:
		evt = NewSimpleEvent(keyword, body)
	case passwordEventKW:
		evt = NewSimpleEvent(keyword, body)
	case fatalEventKW:
		evt = NewSimpleEvent(keyword, body)
	default:
		evt = NewUnknownEvent(keyword, body)
	}

	if err != nil {
		return NewInvalidEvent(evt, err)
	}
	return evt
}

func upgradeMultilineEvent(keyword string, body []string) MultilineEvent {
	var evt Event
	var err error

	switch keyword {
	case "":
		evt = NewMalformedEvent(strings.Join(body, newlineSep))
	case clientEventKW:
		evt, err = NewClientEvent(body)
	default:
		evt = NewUnknownEvent(keyword, strings.Join(body, newlineSep))
	}

	if err != nil {
		return NewInvalidEvent(evt, err)
	}
	return evt
}

// stringsSplitNK behaves the same as strings.SplitN, except the result
// will either contain at least K subslices (padded with zero value,
// if needed), or it will be nil if n == k == 0
func stringsSplitNK(s, sep string, n, k int) []string {
	parts := strings.SplitN(s, sep, n)

	if len(parts) >= k {
		return parts
	}
	expanded := make([]string, k)
	copy(expanded, parts)
	return expanded
}

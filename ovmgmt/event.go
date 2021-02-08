package ovmgmt

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// HoldEvent is a notification that the OpenVPN process is in a management
// hold and will not continue connecting until the hold is released, e.g.
// by calling client.HoldRelease()
type HoldEvent struct {
	body string
}

func NewHoldEvent(body string) HoldEvent {
	return HoldEvent{body}
}

func (e HoldEvent) Raw() string {
	return e.body
}

func (e HoldEvent) String() string {
	return e.body
}

// LogEvent
// Real-time output of log messages.
//
// Real-time log messages begin with the ">LOG:" prefix followed
// by the following comma-separated fields:
//  (a) unix integer date/time,
//  (b) zero or more message flags in a single string:
//      I -- informational
//      F -- fatal error
//      N -- non-fatal error
//      W -- warning
//      D -- debug, and
//  (c) message text.
type LogEvent struct {
	body      string
	bodyParts []string
	ts        int64
}

func NewLogEvent(body string) (LogEvent, error) {
	e := LogEvent{body: body}
	e.bodyParts = stringsSplitNK(body, fieldSep, 3, 3)

	var err error
	e.ts, err = strconv.ParseInt(e.bodyParts[0], 10, 64)
	if err != nil {
		return e, err
	}

	return e, nil
}

func (e LogEvent) Raw() string {
	return e.body
}

func (e LogEvent) Timestamp() int64 {
	return e.ts
}

func (e LogEvent) Time() time.Time {
	return time.Unix(e.ts, 0)
}

func (e LogEvent) RawFlags() string {
	return e.bodyParts[1]
}

func (e LogEvent) Message() string {
	return e.bodyParts[2]
}

func (e LogEvent) String() string {
	return fmt.Sprintf("LOG[%s]: %s", e.RawFlags(), e.Message())
}

// StateEvent is a notification of a change of connection state. It can be
// used, for example, to detect if the OpenVPN connection has been interrupted
// and the OpenVPN process is attempting to reconnect.
// The output format consists of up to 9 comma-separated parameters:
//   (a) the integer unix date/time,
//   (b) the state name,
//   (c) optional descriptive string (used mostly on RECONNECTING
//       and EXITING to show the reason for the disconnect),
//   (d) optional TUN/TAP local IPv4 address
//   (e) optional address of remote server,
//   (f) optional port of remote server,
//   (g) optional local address,
//   (h) optional local port, and
//   (i) optional TUN/TAP local IPv6 address.
//
// Fields (e)-(h) are shown for CONNECTED state,
// (d) and (i) are shown for ASSIGN_IP and CONNECTED states.
//
// (e) is available starting from OpenVPN 2.1
// (f)-(i) are available starting from OpenVPN 2.4
type StateEvent struct {
	body      string
	bodyParts []string
	ts        int64
}

func NewStateEvent(body string) (StateEvent, error) {
	e := StateEvent{body: body}
	e.bodyParts = stringsSplitNK(body, fieldSep, 9, 5)

	var err error
	e.ts, err = strconv.ParseInt(e.bodyParts[0], 10, 64)
	if err != nil {
		return e, err
	}
	return e, nil
}

func (e StateEvent) Raw() string {
	return e.body
}

func (e StateEvent) Timestamp() int64 {
	return e.ts
}

func (e StateEvent) Time() time.Time {
	return time.Unix(e.ts, 0)
}

// Replaces NewState method with more descriptive one
func (e StateEvent) Name() string {
	return e.bodyParts[1]
}

// Keep this method for compatibility. It's not a State factory, just Name()
func (e StateEvent) NewState() string {
	return e.Name()
}

func (e StateEvent) Description() string {
	return e.bodyParts[2]
}

// LocalTunnelAddr returns the IP address of the local interface within
// the tunnel, as a string that can be parsed using net.ParseIP.
//
// This field is only populated for events whose Name returns
// either ASSIGN_IP or CONNECTED.
func (e StateEvent) LocalTunnelAddr() string {
	return e.bodyParts[3]
}

// RemoteAddr returns the non-tunnel IP address of the remote
// system that has connected to the local OpenVPN process.
//
// This field is only populated for events whose Name returns
// CONNECTED.
func (e StateEvent) RemoteAddr() string {
	return e.bodyParts[4]
}

func (e StateEvent) String() string {
	stateName := e.Name()
	switch stateName {
	case "ASSIGN_IP":
		return fmt.Sprintf("%s: %s", stateName, e.LocalTunnelAddr())
	case "CONNECTED":
		return fmt.Sprintf("%s: %s", stateName, e.RemoteAddr())
	default:
		desc := e.Description()
		if desc != "" {
			return fmt.Sprintf("%s: %s", stateName, desc)
		} else {
			return stateName
		}
	}
}

// EchoEvent is emitted by an OpenVPN process running in client mode when
// an "echo" command is pushed to it by the server it has connected to.
//
// The format of the echo message is free-form, since this message type is
// intended to pass application-specific data from the server-side config
// into whatever client is consuming the management prototcol.
//
// This event is emitted only if the management client has turned on events
// of this type using client.SetEchoEvents(true)
type EchoEvent struct {
	body string
	ts   int64
	msg  string
}

func NewEchoEvent(body string) (EchoEvent, error) {
	e := EchoEvent{body: body}
	sepIndex := strings.Index(e.body, fieldSep)
	if sepIndex == -1 {
		return e, ErrNoMsgFieldSep
	}
	e.msg = e.body[sepIndex+1:]

	var err error
	e.ts, err = strconv.ParseInt(e.body[:sepIndex], 10, 64)
	if err != nil {
		return e, err
	}

	return e, nil
}

func (e EchoEvent) Raw() string {
	return e.body
}

func (e EchoEvent) Timestamp() int64 {
	return e.ts
}

func (e EchoEvent) Time() time.Time {
	return time.Unix(e.ts, 0)
}

func (e EchoEvent) Message() string {
	return e.msg
}

func (e EchoEvent) String() string {
	return fmt.Sprintf("ECHO: %s", e.Message())
}

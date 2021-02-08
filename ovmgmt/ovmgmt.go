package ovmgmt

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const newlineSep = "\n"
const successPrefix = "SUCCESS: "
const errorPrefix = "ERROR: "
const endMessage = "END"

// preallocate buffer for big responses
const bigMessageLines = 100

type MgmtClient struct {
	wr             io.Writer
	rawReplyCh     chan string
	rawEventCh     chan string
	doneStatus3Gen chan bool
	eventSink      chan<- Event
}

// NewMgmtClient creates a new MgmtClient that communicates via the given
// io.ReadWriter and emits events on the given channel.
//
// eventCh should be a buffered channel with a sufficient buffer depth
// such that it cannot be filled under the expected event volume. Event
// volume depends on which events are enabled and how they are configured;
// some of the event-enabling functions have further discussion how frequently
// events are likely to be emitted, but the caller should also factor in
// how long its own event *processing* will take, since slow event
// processing will create back-pressure that could cause this buffer to
// fill faster.
//
// It probably goes without saying given the previous paragraph, but the
// caller *must* constantly read events from eventCh to avoid its buffer
// becoming full. Events and replies are received on the same channel
// from OpenVPN, so if writing to eventCh blocks then this will also block
// responses from the client's various command methods.
//
// eventCh will be closed to signal the closing of the client connection,
// whether due to graceful shutdown or to an error. In the case of error,
// a FatalEvent will be emitted on the channel as the last event before it
// is closed. Connection errors may also concurrently surface as error
// responses from the client's various command methods, should an error
// occur while we await a reply.
func NewMgmtClient(conn io.ReadWriter, eventCh chan<- Event) *MgmtClient {
	c := &MgmtClient{
		wr:         conn,
		rawReplyCh: make(chan string),
		rawEventCh: make(chan string), // not buffered because eventCh should be
		eventSink:  eventCh,
	}
	// initial status for 'done' channel (so we can safely close it and make new)
	c.doneStatus3Gen = make(chan bool, 1)

	go Demultiplex(conn, c.rawReplyCh, c.rawEventCh)
	go c.eventScanner()

	return c
}

func (c *MgmtClient) eventScanner() {
	buf := make([]string, 0, bigMessageLines)
	bufKW := ""

	flushMultilineBuf := func() {
		defer func() {
			bufKW = ""
			buf = buf[:0]
		}()
		c.eventSink <- upgradeMultilineEvent(bufKW, buf)
	}

	// Get raw events and upgrade them into proper event types before
	// passing them on to the caller's event channel.

	for raw := range c.rawEventCh {
		endMarker, keyword, body := splitEvent(raw)
		//logDebugf("raw: %s; endMarker: %s, kw: %s, body: %s; bufKW: %s; buf: %#v\n", raw, endMarker, keyword, body, bufKW, buf)

		if endMarker == emSingleLine {
			// fetched single-line event
			c.eventSink <- upgradeEvent(keyword, body)
			if len(buf) > 0 || bufKW != "" {
				// should never-ever happen
				logErrorf("It is a single-line message, but buffer or bufKeyword not empty!")
				flushMultilineBuf()
			}
		} else if raw == string(endMarker) {
			// fetched multi-line event
			flushMultilineBuf()
		} else {
			// multi-line event, save lines to buf until endMarker
			if bufKW == "" {
				bufKW = keyword
			} else if bufKW != keyword {
				// all multi-line event lines must start with first fetched bufKW
				// this should never happen
				logErrorf("Current keyword != first keyword for a multi-line message!")
				flushMultilineBuf()
				c.eventSink <- upgradeEvent(keyword, body)
				continue
			}
			buf = append(buf, body)
		}
	}
	close(c.eventSink)
}

// Dial is a convenience wrapper around NewMgmtClient that handles the common
// case of opening an TCP/IP socket to an OpenVPN management port and creating
// a client for it.
//
// See the NewMgmtClient docs for discussion about the requirements for eventCh.
//
// OpenVPN will create a suitable management port if launched with the
// following command line option:
//
//    --management <ipaddr> <port>
//
// Address may an IPv4 address, an IPv6 address, or a hostname that resolves
// to either of these, followed by a colon and then a port number.
//
// When running on Unix systems it's possible to instead connect to a Unix
// domain socket. To do this, pass an absolute path to the socket as
// the target address, having run OpenVPN with the following options:
//
//    --management /path/to/socket unix
//
func Dial(addr string, eventCh chan<- Event) (*MgmtClient, error) {
	proto := "tcp"
	if len(addr) > 0 && strings.Contains(addr, "/") {
		proto = "unix"
	}
	conn, err := net.Dial(proto, addr)
	if err != nil {
		return nil, err
	}

	return NewMgmtClient(conn, eventCh), nil
}

// HoldRelease instructs OpenVPN to release any management hold preventing
// it from proceeding, but to retain the state of the hold flag such that
// the daemon will hold again if it needs to reconnect for any reason.
//
// OpenVPN can be instructed to activate a management hold on startup by
// running it with the following option:
//
//     --management-hold
//
// Instructing OpenVPN to hold gives your client a chance to connect and
// do any necessary configuration before a connection proceeds, thus avoiding
// the problem of missed events.
//
// When OpenVPN begins holding, or when a new management client connects while
// a hold is already in effect, a HoldEvent will be emitted on the event
// channel.
func (c *MgmtClient) HoldRelease() error {
	_, err := c.simpleCommand("hold release")
	return err
}

// SetLogEvents either enables or disables asynchronous events for changes
// in the OpenVPN connection state.
//
// When enabled, a LogEvent will be emitted from the event channel each
// time the log message arrives. See LogEvent for more information
// on the event structure.
func (c *MgmtClient) SetLogEvents(on bool) error {
	var err error
	if on {
		_, err = c.simpleCommand("log on")
	} else {
		_, err = c.simpleCommand("log off")
	}
	return err
}

// Change the OpenVPN --verb parameter.  The verb parameter
// controls the output verbosity, and may range from 0 (no output)
// to 15 (maximum output).  See the OpenVPN man page for additional
// info on verbosity levels.
func (c *MgmtClient) SetVerbosityLevel(level int) error {
	var err error = fmt.Errorf("bad verbosity level '%d', should be from 0 to 15", level)
	if level > 0 && level < 16 {
		_, err = c.simpleCommand("verb " + strconv.Itoa(level))
	}
	return err
}

// Get the OpenVPN --verb parameter
func (c *MgmtClient) VerbosityLevel() (int, error) {
	result, err := c.simpleCommand("verb")
	if !strings.HasPrefix(result, "verb=") {
		return 0, err
	}
	level, err := strconv.Atoi(result[len("verb="):])
	return level, err
}

// SetStateEvents either enables or disables asynchronous events for changes
// in the OpenVPN connection state.
//
// When enabled, a StateEvent will be emitted from the event channel each
// time the connection state changes. See StateEvent for more information
// on the event structure.
func (c *MgmtClient) SetStateEvents(on bool) error {
	var err error
	if on {
		_, err = c.simpleCommand("state on")
	} else {
		_, err = c.simpleCommand("state off")
	}
	return err
}

// SetEchoEvents either enables or disables asynchronous events for "echo"
// commands sent from a remote server to our managed OpenVPN client.
//
// When enabled, an EchoEvent will be emitted from the event channel each
// time the server sends an echo command. See EchoEvent for more information.
func (c *MgmtClient) SetEchoEvents(on bool) error {
	var err error
	if on {
		_, err = c.simpleCommand("echo on")
	} else {
		_, err = c.simpleCommand("echo off")
	}
	return err
}

// SetByteCountEvents either enables or disables ongoing asynchronous events
// for information on OpenVPN bandwidth usage.
//
// When enabled, a ByteCountEvent will be emitted at given time interval,
// (which may only be whole seconds) describing how many bytes have been
// transferred in each direction See ByteCountEvent for more information.
//
// Set the time interval to zero in order to disable byte count events.
func (c *MgmtClient) SetByteCountEvents(interval time.Duration) error {
	msg := fmt.Sprintf("bytecount %d", int(interval.Seconds()))
	_, err := c.simpleCommand(msg)
	return err
}

// SendSignal sends a signal to the OpenVPN process via the management
// channel. In effect this causes the OpenVPN process to send a signal to
// itself on our behalf.
//
// OpenVPN accepts a subset of the usual UNIX signal names, including
// "SIGHUP", "SIGTERM", "SIGUSR1" and "SIGUSR2". See the OpenVPN manual
// page for the meaning of each.
//
// Behavior is undefined if the given signal name is not entirely uppercase
// letters. In particular, including newlines in the string is likely to
// cause very unpredictable behavior.
func (c *MgmtClient) SendSignal(name string) error {
	msg := fmt.Sprintf("signal %q", name)
	_, err := c.simpleCommand(msg)
	return err
}

// LatestState retrieves the most recent StateEvent from the server. This
// can either be used to poll the state or it can be used to determine the
// initial state after calling SetStateEvents(true) but before the first
// state event is delivered.
func (c *MgmtClient) LatestState() (*StateEvent, error) {
	err := c.sendCommand("state")
	if err != nil {
		return nil, err
	}

	payload, err := c.readCommandResponsePayload()
	if err != nil {
		return nil, err
	}

	if len(payload) != 1 {
		return nil, fmt.Errorf("Malformed OpenVPN 'state' response")
	}

	s, err := NewStateEvent(payload[0])
	return &s, err
}

// Pid retrieves the process id of the connected OpenVPN process.
func (c *MgmtClient) Pid() (int, error) {
	raw, err := c.simpleCommand("pid")
	if err != nil {
		return 0, err
	}

	if !strings.HasPrefix(raw, "pid=") {
		return 0, fmt.Errorf("malformed response from OpenVPN")
	}

	pid, err := strconv.Atoi(raw[4:])
	if err != nil {
		return 0, fmt.Errorf("error parsing pid from OpenVPN: %s", err)
	}

	return pid, nil
}

func (c *MgmtClient) sendCommand(cmd string) error {
	_, err := c.wr.Write([]byte(cmd + newlineSep))
	return err
}

// sendMultilineCommand can be called for commands that expect
// a multi-line input payload.
// func (c *MgmtClient) sendMultilineCommand(payload []string) error {
// 	var err error
// 	for _, cmd := range payload {
// 		if err = c.sendCommand(cmd); err != nil {
// 			return err
// 		}
// 	}
// 	_, err = c.wr.Write([]byte(endMessage + newlineSep))
// 	return err
// }

func (c *MgmtClient) readCommandResult() (string, error) {
	reply, ok := <-c.rawReplyCh
	if !ok {
		return "", fmt.Errorf("connection closed while awaiting result")
	}

	if strings.HasPrefix(reply, successPrefix) {
		result := reply[len(successPrefix):]
		return result, nil
	}

	if strings.HasPrefix(reply, errorPrefix) {
		message := reply[len(errorPrefix):]
		return "", NewOVpnError(message)
	}

	return "", fmt.Errorf("malformed result message")
}

func (c *MgmtClient) readCommandResponsePayload() ([]string, error) {
	lines := make([]string, 0, bigMessageLines)

	for {
		line, ok := <-c.rawReplyCh
		if !ok {
			// We'll give the caller whatever we got before the connection
			// closed, in case it's useful for debugging.
			return lines, fmt.Errorf("connection closed before END recieved")
		}

		if line == endMessage {
			break
		}

		lines = append(lines, line)
	}

	return lines, nil
}

func (c *MgmtClient) simpleCommand(cmd string) (string, error) {
	err := c.sendCommand(cmd)
	if err != nil {
		return "", err
	}
	return c.readCommandResult()
}

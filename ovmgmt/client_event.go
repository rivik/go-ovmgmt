package ovmgmt

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// CLIENT notification types:
//
// (1) Notify new client connection ("CONNECT") or existing client TLS session
//     renegotiation ("REAUTH").  Information about the client is provided
//     by a list of environmental variables which are documented in the OpenVPN
//     man page.  The environmental variables passed are equivalent to those
//     that would be passed to an --auth-user-pass-verify script.
//
//     >CLIENT:CONNECT|REAUTH,{CID},{KID}
//     >CLIENT:ENV,name1=val1
//     >CLIENT:ENV,name2=val2
//     >CLIENT:ENV,...
//     >CLIENT:ENV,END
//
// (2) Notify successful client authentication and session initiation.
//     Called after CONNECT.
//
//     >CLIENT:ESTABLISHED,{CID}
//     >CLIENT:ENV,name1=val1
//     >CLIENT:ENV,name2=val2
//     >CLIENT:ENV,...
//     >CLIENT:ENV,END
//
// (3) Notify existing client disconnection.  The environmental variables passed
//     are equivalent to those that would be passed to a --client-disconnect
//     script.
//
//     >CLIENT:DISCONNECT,{CID}
//     >CLIENT:ENV,name1=val1
//     >CLIENT:ENV,name2=val2
//     >CLIENT:ENV,...
//     >CLIENT:ENV,END
//
// (4) Notify that a particular virtual address or subnet
//     is now associated with a specific client.
//
//     >CLIENT:ADDRESS,{CID},{ADDR},{PRI}
//
// Variables:
//
// CID --  Client ID, numerical ID for each connecting client, sequence = 0,1,2,...
// KID --  Key ID, numerical ID for the key associated with a given client TLS session,
//         sequence = 0,1,2,...
// PRI --  Primary (1) or Secondary (0) VPN address/subnet.  All clients have at least
//         one primary IP address.  Secondary address/subnets are associated with
//         client-specific "iroute" directives.
// ADDR -- IPv4 address/subnet in the form 1.2.3.4 or 1.2.3.0/255.255.255.0
//
// In the unlikely scenario of an extremely long-running OpenVPN server,
// CID and KID should be assumed to recycle to 0 after (2^32)-1, however this
// recycling behavior is guaranteed to be collision-free.

const clientEnvMarker = "ENV"
const clientEnvKVSep = "="

type ClientEventNotification string

const (
	CEUnknown     ClientEventNotification = "UNKNOWN"
	CEConnect     ClientEventNotification = "CONNECT"
	CEReauth      ClientEventNotification = "REAUTH"
	CEEstablished ClientEventNotification = "ESTABLISHED"
	CEDisconnect  ClientEventNotification = "DISCONNECT"
	CEAddress     ClientEventNotification = "ADDRESS"
)

type OVpnEnvironment map[string]string

type ClientEvent struct {
	rawHeader string
	ceType    ClientEventNotification
	cid       int64
	kid       int64
	addr      string
	isAddrPri bool
	envs      OVpnEnvironment
}

func NewClientEvent(payload []string) (ClientEvent, error) {
	//     >CLIENT:CONNECT|REAUTH,{CID},{KID}
	c := ClientEvent{}

	c.rawHeader = payload[0]
	params := stringsSplitNK(payload[0], fieldSep, 4, 4)

	switch ClientEventNotification(params[0]) {
	case CEConnect:
		c.ceType = CEConnect
	case CEReauth:
		c.ceType = CEReauth
	case CEEstablished:
		c.ceType = CEEstablished
	case CEDisconnect:
		c.ceType = CEDisconnect
	case CEAddress:
		c.ceType = CEAddress
	default:
		c.ceType = CEUnknown
		return c, errors.New("unknown client event type: " + params[0])
	}

	var err error
	// first param is always cid
	c.cid, err = strconv.ParseInt(params[1], 10, 64)
	if err != nil {
		return c, err
	}

	// >CLIENT:CONNECT|REAUTH,{CID},{KID}
	if c.ceType == CEConnect || c.ceType == CEReauth {
		c.kid, err = strconv.ParseInt(params[2], 10, 64)
		if err != nil {
			return c, err
		}
	}

	// >CLIENT:ADDRESS,{CID},{ADDR},{PRI}
	if c.ceType == CEAddress {
		c.addr = params[2]
		c.isAddrPri, err = strconv.ParseBool(params[3])
		// single-line event, just return it
		return c, err
	}

	// multiline client events
	c.envs = make(OVpnEnvironment, bigMessageLines)
	for _, line := range payload[1:] {
		if !strings.HasPrefix(line, clientEnvMarker+fieldSep) {
			return c, errors.New("no env prefix in client event line: " + line)
		}
		kvLine := line[len(clientEnvMarker+fieldSep):]
		parts := stringsSplitNK(kvLine, clientEnvKVSep, 2, 2)
		c.envs[parts[0]] = parts[1]
	}

	return c, nil
}

func (c ClientEvent) Raw() string {
	return fmt.Sprintf("%s\t%s", c.rawHeader, c.envs)
}

func (c ClientEvent) Type() ClientEventNotification {
	return c.ceType
}

func (c ClientEvent) ClientId() int64 {
	return c.cid
}

func (c ClientEvent) KeyId() int64 {
	return c.kid
}

func (c ClientEvent) Addr() string {
	return c.addr
}

func (c ClientEvent) IsAddrPrimary() bool {
	return c.isAddrPri
}

func (c ClientEvent) RawEnv(key string) string {
	return c.envs[key]
}

func (c ClientEvent) String() string {
	switch c.Type() {
	case CEConnect, CEReauth:
		return fmt.Sprintf("[%s]cid:%d,kid:%d,env:%v", c.Type(), c.ClientId(), c.KeyId(), c.envs)
	case CEEstablished, CEDisconnect:
		return fmt.Sprintf("[%s]cid:%d,envs:%v", c.Type(), c.ClientId(), c.envs)
	case CEAddress:
		return fmt.Sprintf("[%s]cid:%d,addr:%s,isPrimary:%t", c.Type(), c.ClientId(), c.Addr(), c.IsAddrPrimary())
	default:
		return fmt.Sprintf("[%s]%s", c.Type(), c.Raw())
	}
}
